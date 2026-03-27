# ethercat_scanner.py
"""
EtherCAT scanner oparty na bibliotece pysoem (SOEM).
Wymaga: pip install pysoem
Wymaga w systemie: Npcap (tryb WinPcap compatible) lub WinPcap.
"""

import threading
import time
import pysoem
from debug_utils import get_logger, log_exception

log = get_logger(__name__)




# ─── Mapowanie adapter_name → NPF device path ─────────────────────────────────

def _get_pcap_name(adapter_name: str) -> str | None:
    if pysoem is None: return None
    
    # Opcjonalnie: zmniejsz poziom logowania dla mapowania, by nie śmiecić w konsoli
    # log.debug(f"Mapowanie adaptera: '{adapter_name}'")
    
    target_description = adapter_name
    try:
        from scanner import get_adapters
        for adp in get_adapters():
            if adp.get("name") == adapter_name:
                target_description = adp.get("description", adapter_name)
                break
    except Exception: pass

    try:
        interfaces = pysoem.find_adapters()
    except Exception: return None

    def _s(v):
        if hasattr(v, 'name'): return getattr(v, 'name').decode('utf-8', errors='replace') if isinstance(getattr(v, 'name'), bytes) else str(getattr(v, 'name'))
        if isinstance(v, bytes): return v.decode("utf-8", errors="replace")
        return str(v)
    
    def _d(v):
        if hasattr(v, 'desc'): return getattr(v, 'desc').decode('utf-8', errors='replace') if isinstance(getattr(v, 'desc'), bytes) else str(getattr(v, 'desc'))
        if isinstance(v, bytes): return v.decode("utf-8", errors="replace")
        return str(v)

    for iface in interfaces:
        pcap_name = _s(iface)
        pcap_desc = _d(iface)
        if target_description and target_description == pcap_desc: return pcap_name
        if adapter_name in pcap_name: return pcap_name
        if target_description and target_description in pcap_desc: return pcap_name
            
    return None


# ─── Pomocnicze dekodowanie ───────────────────────────────────────────────────

def _decode(v) -> str:
    if isinstance(v, (bytes, bytearray)):
        return v.decode("utf-8", errors="replace").strip("\x00").strip()
    return str(v).strip()

SDO_TIMEOUT_US = 300_000  # 300 ms per SDO read — prevents blocking on unresponsive slaves

def _sdo_string(slave, index: int, subindex: int = 0) -> str:
    """Bezpieczny odczyt SDO string z limitem czasu."""
    try:
        data = slave.sdo_read(index, subindex)
        return _decode(data)
    except Exception:
        return ""


def _sdo_string_retry(slave, index: int, subindex: int = 0, attempts: int = 4, sleep_s: float = 0.03) -> str:
    """Ponawia odczyt SDO, bo mailbox bywa chwilowo niedostepny zaraz po przejsciu do PRE-OP."""
    value = ""
    for n in range(max(1, attempts)):
        value = _sdo_string(slave, index, subindex)
        if value:
            return value
        if n < attempts - 1:
            time.sleep(sleep_s)
    return value


def _is_generic_ecat_name(name: str) -> bool:
    """Wykrywa ogolne nazwy urzadzenia, ktore nie wskazuja konkretnego modelu."""
    if not name:
        return True
    lowered = name.lower().replace(" ", "")
    generic_tokens = (
        "ethercatfieldbusmodules",
        "ethercat",
        "fieldbusmodule",
    )
    return any(token in lowered for token in generic_tokens)


def _pick_product_name(device_name: str, sii_name: str, slave_index: int) -> str:
    """Preferuje konkretna nazwe modelu (SII) zamiast ogolnego opisu z 0x1008."""
    if sii_name and not _is_generic_ecat_name(sii_name):
        return sii_name
    if device_name and not _is_generic_ecat_name(device_name):
        return device_name
    if sii_name:
        return sii_name
    if device_name:
        return device_name
    return f"EtherCAT Slave #{slave_index}"


def _pick_product_name_with_source(device_name: str, sii_name: str, slave_index: int) -> tuple[str, str]:
    """Zwraca nazwe produktu i zrodlo tej nazwy (SII/SDO/FALLBACK)."""
    if sii_name and not _is_generic_ecat_name(sii_name):
        return sii_name, "SII"
    if device_name and not _is_generic_ecat_name(device_name):
        return device_name, "SDO_0x1008"
    if sii_name:
        return sii_name, "SII_GENERIC"
    if device_name:
        return device_name, "SDO_0x1008_GENERIC"
    return f"EtherCAT Slave #{slave_index}", "FALLBACK"

# ─── Główna logika skanowania ─────────────────────────────────────────────────

def _active_scan(adapter_name: str, callback, stop_event):
    if pysoem is None or stop_event.is_set(): return

    log.info(f"--- Skanowanie EtherCAT: {adapter_name} ---")

    pcap_name = _get_pcap_name(adapter_name)
    if not pcap_name: return

    master = pysoem.Master()
    
    # Zmniejszamy timeouty, aby przycisk Stop reagował szybciej
    try:
        master.open(pcap_name)
        master.sdo_read_timeout = SDO_TIMEOUT_US
        master.sdo_write_timeout = SDO_TIMEOUT_US
        if stop_event.is_set(): 
            master.close()
            return

        # 1. Wykrycie slave'ów
        slave_count = master.config_init()
        log.info(f"config_init: {slave_count} slave(s)")
        
        if slave_count <= 0:
            master.close()
            return

        # 2. Przejście do PRE-OP
        # Timeout skalowany liniowo: 300 ms * liczba slave'ów (minimum 300 ms)
        preop_timeout_us = 300_000 * max(1, slave_count)
        for slave in master.slaves:
            slave.state = pysoem.PREOP_STATE
        master.write_state()
        master.state_check(pysoem.PREOP_STATE, preop_timeout_us)
        log.debug(f"state_check PRE-OP timeout={preop_timeout_us//1000} ms dla {slave_count} slave(s)")
        
        if stop_event.is_set(): 
            master.close()
            return

        # 3. Odczyt danych
        for i, slave in enumerate(master.slaves):
            if stop_event.is_set(): break

            # Identity
            vid = getattr(slave, "man", 0) or 0
            pid = getattr(slave, "id",  0) or 0
            rev = getattr(slave, "rev", 0) or 0
            
            # SDO (tylko jesli slave w PRE-OP)
            device_name = ""
            sw_version = ""
            
            # Sprawdź stan przed próbą odczytu
            if slave.state == pysoem.PREOP_STATE:
                device_name = _sdo_string_retry(slave, 0x1008)
                if stop_event.is_set(): break
                sw_version  = _sdo_string_retry(slave, 0x100A)
            
            # Fallback
            sii_name = _decode(getattr(slave, "name", ""))
            product_name, product_name_source = _pick_product_name_with_source(device_name, sii_name, i)

            info = {
                "mac":          "N/A",
                "ip":           "",
                "product_name": product_name,
                "sw_version":   sw_version or f"Rev: {rev:#x}",
                "device_name_sdo": device_name,
                "sii_name":     sii_name,
                "product_name_source": product_name_source,
                "slave_count":  slave_count,
                "slave_index":  i,
                "name":         product_name,
                "protocol":     "EtherCAT",
                "adapter":      adapter_name,
                "vendor_id":    f"0x{vid:08X}",
                "product_code": f"0x{pid:08X}",
                "revision":     f"0x{rev:08X}",
                "serial":       f"0x{getattr(slave, 'serial', 0):08X}",
                "vendor_id_dec": vid,
                "product_code_dec": pid,
                "revision_dec": rev,
                "serial_dec": getattr(slave, 'serial', 0),
                "_update":      False,
            }

            if not stop_event.is_set():
                callback(info)

    except Exception as e:
        # Nie loguj błędów przerwania (np. gdy close() w trakcie read())
        log_exception(log, "Wyjątek EtherCAT", e, ["reset by peer", "socket"])
    finally:
        try: master.close()
        except: pass


# ─── Public API ───────────────────────────────────────────────────────────────

def start_ecat_scan(adapter_name: str, callback, stop_event):
    """
    Skanuje pojedynczy adapter.
    """
    # Pierwsze skanowanie
    _active_scan(adapter_name, callback, stop_event)

    # Pętla odświeżania (co 10 sekund)
    while not stop_event.is_set():
        # Reagujemy na stop co 0.1s, nie musimy czekać pełne 10s
        for _ in range(100):
            if stop_event.is_set(): return
            time.sleep(0.1)
        
        # Ponów skanowanie
        _active_scan(adapter_name, callback, stop_event)


def start_ecat_scan_all(callback, stop_event):
    """Skanuje wszystkie dostępne adaptery jednocześnie."""
    if pysoem is None: return []

    from scanner import get_adapters
    adapters = get_adapters()
    threads = []
    for adapter in adapters:
        name = adapter.get("name", "")
        if not name: continue
        
        t = threading.Thread(
            target=start_ecat_scan,
            args=(name, callback, stop_event),
            daemon=True,
        )
        t.start()
        threads.append(t)
    return threads