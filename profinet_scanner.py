# profinet_scanner.py
import threading
import struct
from scapy.all import sendp, sniff, Ether, Raw

PROFINET_MULTICAST = "01:0e:cf:00:00:00"
PROFINET_ETHERTYPE = 0x8892


def build_dcp_identify_request():
    frame_id       = 0xFEFE
    service_id     = 0x05
    service_type   = 0x00
    xid            = 0x00000001
    response_delay = 0x0001
    data_length    = 0x0004
    all_selector   = struct.pack(">BBH", 0xFF, 0xFF, 0x0000)
    header = struct.pack(">HBBHHHH",
        frame_id,
        service_id, service_type,
        xid & 0xFFFF, (xid >> 16) & 0xFFFF,
        response_delay,
        data_length
    )
    return header + all_selector


def extract_profinet_payload(packet):
    """Wyciąga payload Profinet z ramki — obsługuje zwykłe i VLAN (0x8100)."""
    raw = bytes(packet)
    idx = raw.find(b'\x88\x92')
    if idx == -1:
        return None, None
    src_mac = packet[Ether].src
    payload = raw[idx + 2:]
    return src_mac, payload


def parse_dcp_payload(src_mac, payload):
    """Parsuje payload DCP Identify Response."""
    try:
        offset = 0

        # Frame ID
        frame_id = struct.unpack_from(">H", payload, offset)[0]
        offset += 2
        if frame_id not in (0xFEFD, 0xFEFF):
            return None

        # Service ID + Type
        service_id   = payload[offset]
        service_type = payload[offset + 1]
        offset += 2
        if service_id != 0x05 or service_type != 0x01:
            return None

        # XID (4 bajty) + response_delay (2) + data_length (2)
        offset += 4  # xid
        offset += 2  # response delay
        data_length = struct.unpack_from(">H", payload, offset)[0]
        offset += 2

        result = {
            "mac":             src_mac,
            "ip":              "",
            "name_of_station": "",
            "vendor_id":       "",
            "device_id":       "",
            "device_family":   "",
            "firmware":        "",
            "protocol":        "Profinet DCP",
            "adapter":         "",
        }

        end = offset + data_length
        while offset + 4 <= end and offset + 4 <= len(payload):
            opt    = payload[offset]
            subopt = payload[offset + 1]
            length = struct.unpack_from(">H", payload, offset + 2)[0]
            offset += 4
            block_data = payload[offset:offset + length]
            offset += length + (length % 2)  # padding

            if (opt, subopt) == (0x01, 0x02):  # IP
                if len(block_data) >= 8:
                    ip_bytes = block_data[2:6]
                    result["ip"] = ".".join(str(b) for b in ip_bytes)

            elif (opt, subopt) == (0x02, 0x01):  # NameOfStation
                result["name_of_station"] = block_data[2:].decode("ascii", errors="ignore").rstrip("\x00")

            elif (opt, subopt) == (0x02, 0x02):  # VendorID + DeviceID
                if len(block_data) >= 6:
                    vendor = struct.unpack_from(">H", block_data, 2)[0]
                    device = struct.unpack_from(">H", block_data, 4)[0]
                    result["vendor_id"] = f"0x{vendor:04X}"
                    result["device_id"] = f"0x{device:04X}"

            elif (opt, subopt) == (0x03, 0x04):  # NameOfFamily
                result["device_family"] = block_data[2:].decode("ascii", errors="ignore").rstrip("\x00")

            elif (opt, subopt) == (0x02, 0x07):  # firmware
                result["firmware"] = block_data[2:].decode("ascii", errors="ignore").rstrip("\x00")

            elif (opt, subopt) == (0x02, 0x03):  # NameOfDevice
                result["firmware"] = block_data[2:].decode("ascii", errors="ignore").rstrip("\x00")

        return result if result["mac"] else None

    except Exception as e:
        print(f"Błąd parsowania DCP: {e}")
        return None


def send_dcp_identify(adapter_name, stop_event):
    try:
        payload = build_dcp_identify_request()
        pkt = Ether(dst=PROFINET_MULTICAST, type=PROFINET_ETHERTYPE) / Raw(load=payload)
        sendp(pkt, iface=adapter_name, verbose=False)
    except Exception as e:
        print(f"Błąd wysyłania DCP na {adapter_name}: {e}")


def listen_dcp_responses(adapter_name, callback, stop_event, timeout=5):
    def handler(packet):
        if stop_event.is_set():
            return
        if not packet.haslayer(Ether):
            return
        src_mac, payload = extract_profinet_payload(packet)
        if payload is None:
            return
        result = parse_dcp_payload(src_mac, payload)
        if result:
            result["adapter"] = adapter_name
            callback(result)

    try:
        sniff(
            iface=adapter_name,
            prn=handler,
            stop_filter=lambda x: stop_event.is_set(),
            timeout=timeout,
            store=False
        )
    except Exception as e:
        if "not found" not in str(e).lower():
            print(f"Błąd nasłuchiwania DCP na {adapter_name}: {e}")


def start_dcp_scan(adapter_name, callback, stop_event):
    send_dcp_identify(adapter_name, stop_event)
    listen_dcp_responses(adapter_name, callback, stop_event)


def start_dcp_scan_all(callback, stop_event):
    from scanner import get_adapters
    adapters = get_adapters()
    threads = []
    for adapter in adapters:
        name = adapter["name"]
        if not name:
            continue
        t = threading.Thread(
            target=start_dcp_scan,
            args=(name, callback, stop_event),
            daemon=True
        )
        t.start()
        threads.append(t)
    return threads