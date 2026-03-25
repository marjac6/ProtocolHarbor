# scanner.py
from scapy.all import sniff, ARP, Ether
from scapy.arch.windows import get_windows_if_list
import threading

# OUI producentów — pierwsze 3 bajty MAC
VENDOR_OUI = {
    "00:19:31": "Balluff",
    # BNI to też Balluff — dodamy jeśli znajdziemy inny OUI
}

# Fallback — słowa kluczowe w surowych bajtach (na wszelki wypadek)
KEYWORDS = ["balluff", "bni"]

IGNORE_SUFFIXES = [
    "WFP Native MAC Layer LightWeight Filter",
    "WFP 802.3 MAC Layer LightWeight Filter",
    "QoS Packet Scheduler",
    "VirtualBox NDIS Light-Weight Filter",
    "Sentech Dfa Driver",
    "Native WiFi Filter Driver",
    "Virtual WiFi Filter Driver",
    "Npcap Packet Driver (NPCAP)",
    "Balluff Engineering Tool Network Driver",
]

IGNORE_DESCRIPTIONS = [
    "WAN Miniport",
    "Teredo",
    "6to4",
    "IP-HTTPS",
    "Loopback",
    "Kernel Debug",
    "Bluetooth",
    "Tailscale",
    "Wintun",
    "Wi-Fi Direct",
]


def is_useful_adapter(adapter):
    desc = adapter.get("description", "")
    for suffix in IGNORE_SUFFIXES:
        if suffix in desc:
            return False
    for keyword in IGNORE_DESCRIPTIONS:
        if keyword in desc:
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
                "ips": iface.get("ips", [])
            }
            if is_useful_adapter(adapter):
                adapters.append(adapter)
    except Exception as e:
        print(f"Błąd pobierania adapterów: {e}")
    return adapters


def get_oui(mac: str) -> str:
    """Zwraca pierwsze 3 oktety MAC jako OUI, np. '00:19:31'."""
    parts = mac.lower().replace("-", ":").split(":")
    if len(parts) >= 3:
        return ":".join(parts[:3])
    return ""


def check_arp_packet(packet, callback):
    """Wykrywa urządzenia Balluff/BNI po OUI lub słowie kluczowym."""
    if not packet.haslayer(ARP):
        return

    arp = packet[ARP]
    src_mac = arp.hwsrc.lower()
    oui = get_oui(src_mac)

    # Metoda 1: OUI match
    vendor = VENDOR_OUI.get(oui)
    if vendor:
        # Dla ARP Probe: target IP to właściwe IP urządzenia
        # Dla normalnego ARP: sender IP
        device_ip = arp.pdst if arp.psrc == "0.0.0.0" else arp.psrc
        info = {
            "ip":      device_ip,
            "mac":     arp.hwsrc,
            "keyword": vendor,
            "adapter": getattr(packet, "sniffed_on", "?"),
            "type":    "ARP Probe" if arp.psrc == "0.0.0.0" else "ARP"
        }
        callback(info)
        return

    # Metoda 2: fallback — słowa kluczowe w surowych bajtach
    raw_bytes = bytes(packet).lower()
    for keyword in KEYWORDS:
        if keyword.encode() in raw_bytes:
            device_ip = arp.pdst if arp.psrc == "0.0.0.0" else arp.psrc
            info = {
                "ip":      device_ip,
                "mac":     arp.hwsrc,
                "keyword": keyword.upper(),
                "adapter": getattr(packet, "sniffed_on", "?"),
                "type":    "ARP Probe" if arp.psrc == "0.0.0.0" else "ARP"
            }
            callback(info)
            return


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
        if "not found" not in str(e).lower():
            print(f"Błąd skanowania {adapter_name}: {e}")


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
            print(f"Błąd wysyłania probe na {adapter_name}: {e}")


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