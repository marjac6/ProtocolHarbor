# scanner.py
from scapy.all import sniff, ARP, Ether
from scapy.arch.windows import get_windows_if_list
import threading
from debug_utils import get_logger, log_exception
from vendor_registry import VENDOR_OUI, VENDOR_KEYWORDS

logger = get_logger(__name__)

IGNORE_SUFFIXES = [
    "WFP Native MAC Layer LightWeight Filter",
    "WFP 802.3 MAC Layer LightWeight Filter",
    "QoS Packet Scheduler",
    "VirtualBox NDIS Light-Weight Filter",
    "Sentech Dfa Driver",
    "Native WiFi Filter Driver",
    "Virtual WiFi Filter Driver",
    "Npcap Packet Driver (NPCAP)",
]

IGNORE_DESCRIPTIONS = [
    "WAN Miniport",
    "Teredo",
    "6to4",
    "IP-HTTPS",
    "Loopback",
    "Kernel Debug",
    "Bluetooth",
    "VirtualBox",
    "Host-Only",
    "Tailscale",
    "Wintun",
    "Wi-Fi Direct",
]

ALLOWED_IF_TYPES = {6, 71}  # Ethernet, Wi-Fi


def is_useful_adapter(adapter):
    desc = (adapter.get("description", "") or "")
    desc_l = desc.lower()
    for suffix in IGNORE_SUFFIXES:
        if suffix.lower() in desc_l:
            return False
    for keyword in IGNORE_DESCRIPTIONS:
        if keyword.lower() in desc_l:
            return False
    return True


def is_available_adapter(adapter):
    """Heurystycznie wykrywa adaptery, które są aktualnie dostępne/podłączone."""
    if adapter.get("type") not in ALLOWED_IF_TYPES:
        return False

    if not adapter.get("mac"):
        return False

    ips = [ip for ip in adapter.get("ips", []) if ip and ip not in ("127.0.0.1", "::1")]
    if not ips:
        return False

    ipv4_metric = int(adapter.get("ipv4_metric", 0) or 0)
    ipv6_metric = int(adapter.get("ipv6_metric", 0) or 0)
    if ipv4_metric == 0 and ipv6_metric == 0:
        return False

    return True


def get_adapters():
    adapters = []
    try:
        win_ifaces = get_windows_if_list()
        for iface in win_ifaces:
            adapter = {
                "name": iface.get("name", ""),
                "description": iface.get("description", ""),
                "ips": iface.get("ips", []),
                "type": iface.get("type", 0),
                "mac": iface.get("mac", ""),
                "ipv4_metric": iface.get("ipv4_metric", 0),
                "ipv6_metric": iface.get("ipv6_metric", 0),
            }
            if is_useful_adapter(adapter) and is_available_adapter(adapter):
                adapters.append(adapter)
    except Exception as e:
        log_exception(logger, "Błąd pobierania adapterów", e)
    return adapters


def get_oui(mac: str) -> str:
    """Zwraca pierwsze 3 oktety MAC jako OUI, np. '00:19:31'."""
    parts = mac.lower().replace("-", ":").split(":")
    if len(parts) >= 3:
        return ":".join(parts[:3])
    return ""


def check_arp_packet(packet, callback):
    """Skanuje pakiet ARP i wywołuje callback dla każdego urządzenia.
    Pole vendor_match=True oznacza znany vendor (OUI/keyword).
    Filtrowanie wyświetlania odbywa się w GUI.
    """
    if not packet.haslayer(ARP):
        return

    arp = packet[ARP]
    src_mac = arp.hwsrc.lower()

    # Pomijamy broadcast i zerowy MAC
    if src_mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
        return

    device_ip = arp.pdst if arp.psrc == "0.0.0.0" else arp.psrc
    if not device_ip or device_ip in ("0.0.0.0", "255.255.255.255"):
        return

    oui = get_oui(src_mac)
    vendor = VENDOR_OUI.get(oui)
    arp_type = "ARP Probe" if arp.psrc == "0.0.0.0" else "ARP"

    # Sprawdź keyword w surowych bajtach (fallback)
    keyword_match = None
    if not vendor:
        raw_bytes = bytes(packet).lower()
        for kw in VENDOR_KEYWORDS:
            if kw.encode() in raw_bytes:
                keyword_match = kw.upper()
                break

    vendor_match = bool(vendor or keyword_match)
    keyword_label = vendor or keyword_match or oui or "Unknown"

    callback({
        "ip":           device_ip,
        "mac":          arp.hwsrc,
        "keyword":      keyword_label,
        "vendor_match": vendor_match,
        "adapter":      getattr(packet, "sniffed_on", "?"),
        "type":         arp_type,
    })


def start_scan(adapter_name, callback, stop_event):
    def handler(packet):
        if stop_event.is_set():
            return
        check_arp_packet(packet, callback)

    try:
        sniff(
            iface=adapter_name,
            filter="arp",
            prn=handler,
            stop_filter=lambda x: stop_event.is_set(),
            store=False
        )
    except Exception as e:
        log_exception(logger, f"Błąd skanowania {adapter_name}", e, ["not found"])


def start_scan_all(callback, stop_event):
    adapters = get_adapters()
    threads = []
    for adapter in adapters:
        name = adapter["name"]
        if not name:
            continue
        t = threading.Thread(
            target=start_scan,
            args=(name, callback, stop_event),
            daemon=True
        )
        t.start()
        threads.append(t)
    return threads

def send_arp_probe(adapter_name, stop_event):
    """
    Wysyła ARP Probe (src=0.0.0.0) na broadcast do wszystkich adapterów.
    Urządzenie odpowie niezależnie od swojej podsieci.
    """
    from scapy.all import sendp, ARP, Ether
    import time

    # Wysyłamy do różnych potencjalnych IP żeby sprowokować odpowiedź
    target_ips = [
        "255.255.255.255",
        "192.168.0.1",
        "192.168.1.1",
        "10.0.0.1",
        "172.16.0.1",
    ]

    for target_ip in target_ips:
        if stop_event.is_set():
            return
        try:
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                op=1,           # request
                hwsrc="00:00:00:00:00:00",
                psrc="0.0.0.0",
                hwdst="00:00:00:00:00:00",
                pdst=target_ip
            )
            sendp(pkt, iface=adapter_name, verbose=False)
            time.sleep(0.1)
        except Exception as e:
            log_exception(logger, f"Błąd wysyłania probe na {adapter_name}", e)


def start_active_scan(callback, stop_event):
    """
    Łączy nasłuchiwanie pasywne + aktywne wysyłanie ARP Probe
    na wszystkich adapterach.
    """
    adapters = get_adapters()
    threads = []

    for adapter in adapters:
        name = adapter["name"]
        if not name:
            continue

        # Wątek nasłuchujący
        t_sniff = threading.Thread(
            target=start_scan,
            args=(name, callback, stop_event),
            daemon=True
        )
        t_sniff.start()
        threads.append(t_sniff)

        # Wątek wysyłający probe
        t_probe = threading.Thread(
            target=send_arp_probe,
            args=(name, stop_event),
            daemon=True
        )
        t_probe.start()
        threads.append(t_probe)

    return threads