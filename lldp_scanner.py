"""LLDP (Link Layer Discovery Protocol) scanner."""

import re
from scapy.all import sniff, Ether
from debug_utils import get_logger, log_exception
from vendor_registry import VENDOR_OUI

LOGGER = get_logger(__name__)

LLDP_MULTICAST = "01:80:c2:00:00:0e"
LLDP_ETHERTYPE = 0x88cc


def parse_lldp_system_name(system_name_str: str) -> dict:
    """
    Parse LLDP System Name field into structured data.
    Example format: "Vendor Name, I/O, Model XG5-538-0B5-R067, HW: X, FW: V X X X, SN: ..."
    """
    result = {
        "producer": "",
        "device_family": "",
        "model": "",
        "firmware": "",
        "serial": "",
    }

    if not system_name_str:
        return result

    # Producer: zwykle pierwszy segment przed przecinkiem bywa nazwą firmy.
    head = system_name_str.split(",", 1)[0].strip()
    if head and len(head) >= 3 and not re.search(r"\b(io|device|port|fw|sw)\b", head, re.IGNORECASE):
        result["producer"] = head

    # Model: tokeny z liter/cyfr i myślnikami, np. XG5-538-0B5-R067.
    model_match = re.search(r"\b([A-Z]{2,}\s*[A-Z0-9]{1,}[A-Z0-9\-]{4,})\b", system_name_str)
    if model_match:
        result["model"] = model_match.group(1).strip()

    # Firmware: FW/Firmware/Rev/Version i warianty 1.2.3 / 1 2 3 / v1.2.3.
    fw_match = re.search(r"(?:FW|Firmware|SW|Version|Rev)\s*[:=]?\s*V?\s*([0-9][0-9 ._-]*[0-9])", system_name_str, re.IGNORECASE)
    if not fw_match:
        fw_match = re.search(r"\bv\s*([0-9]+(?:[ ._-][0-9]+){1,3})\b", system_name_str, re.IGNORECASE)
    if not fw_match:
        fw_match = re.search(r"\b([0-9]+(?:\.[0-9]+){1,3})\b", system_name_str)
    if fw_match:
        fw_clean = fw_match.group(1).strip()
        fw_clean = re.sub(r"[ _-]+", ".", fw_clean)
        fw_clean = re.sub(r"\s+", ".", fw_clean)
        fw_clean = re.sub(r"\.+", ".", fw_clean)
        result["firmware"] = fw_clean

    # Serial: SN: HU00959913600013 or similar
    sn_match = re.search(r"SN:\s*([A-Za-z0-9]+)", system_name_str, re.IGNORECASE)
    if sn_match:
        result["serial"] = sn_match.group(1)

    return result


def _oui_from_mac(mac: str) -> str:
    parts = (mac or "").lower().replace("-", ":").split(":")
    if len(parts) >= 3:
        return ":".join(parts[:3])
    return ""


def extract_lldp_payload(packet) -> dict | None:
    """Extract LLDP TLVs from packet."""
    try:
        if not packet.haslayer(Ether):
            LOGGER.debug("LLDP drop: packet without Ethernet layer")
            return None

        src_mac = packet[Ether].src
        raw = bytes(packet)

        # Find LLDP ethertype
        idx = raw.find(b"\x88\xcc")
        if idx == -1:
            LOGGER.debug("LLDP drop: ethertype 0x88cc not found in frame from %s", src_mac)
            return None

        payload = raw[idx + 2:]
        if len(payload) < 2:
            LOGGER.debug("LLDP drop: payload too short from %s", src_mac)
            return None

        result = {
            "mac": src_mac,
            "source_mac": src_mac,
            "system_name": "",
            "system_description": "",
            "port_description": "",
            "chassis_id": "",
            "producer": "",
            "model": "",
            "firmware": "",
            "serial": "",
            "ip": "",
        }

        offset = 0
        while offset + 2 <= len(payload):
            tlv_header = (payload[offset] << 8) | payload[offset + 1]
            tlv_type = (tlv_header >> 9) & 0x7F
            tlv_length = tlv_header & 0x1FF
            offset += 2

            if offset + tlv_length > len(payload):
                LOGGER.debug(
                    "LLDP drop: TLV length overflow (type=%s len=%s frame_len=%s src=%s)",
                    tlv_type,
                    tlv_length,
                    len(payload),
                    src_mac,
                )
                break

            tlv_value = payload[offset : offset + tlv_length]
            offset += tlv_length

            # TLV Type 5: System Name
            if tlv_type == 5 and tlv_length > 0:
                result["system_name"] = tlv_value.decode("ascii", errors="ignore")
                parsed = parse_lldp_system_name(result["system_name"])
                result.update(parsed)

            # TLV Type 6: System Description
            elif tlv_type == 6 and tlv_length > 0:
                result["system_description"] = tlv_value.decode("ascii", errors="ignore")
                # Czasem FW/model są tylko w System Description.
                parsed = parse_lldp_system_name(result["system_description"])
                if not result.get("model") and parsed.get("model"):
                    result["model"] = parsed["model"]
                if not result.get("firmware") and parsed.get("firmware"):
                    result["firmware"] = parsed["firmware"]
                if not result.get("producer") and parsed.get("producer"):
                    result["producer"] = parsed["producer"]
                if not result.get("serial") and parsed.get("serial"):
                    result["serial"] = parsed["serial"]

            # TLV Type 4: Port Description
            elif tlv_type == 4 and tlv_length > 0:
                result["port_description"] = tlv_value.decode("ascii", errors="ignore")

            # TLV Type 1: Chassis ID
            elif tlv_type == 1 and tlv_length > 1:
                chassis_subtype = tlv_value[0]
                if chassis_subtype == 4:  # MAC address
                    mac_bytes = tlv_value[1:7]
                    result["chassis_id"] = ":".join(f"{b:02x}" for b in mac_bytes)
                    # Dla wielu urządzeń przemysłowych to jest "tożsamość" urządzenia,
                    # bardziej stabilna do korelacji niż source MAC ramki LLDP.
                    result["mac"] = result["chassis_id"]

            # TLV Type 8: Management Address
            elif tlv_type == 8 and tlv_length > 5:
                addr_len = tlv_value[0]
                addr_subtype = tlv_value[1]
                # W LLDP Management Address addr_len obejmuje też Address Subtype,
                # więc dla IPv4 ma zwykle wartość 5.
                if addr_subtype == 1 and addr_len >= 5 and len(tlv_value) >= 6:
                    ip_bytes = tlv_value[2:6]
                    result["ip"] = ".".join(str(b) for b in ip_bytes)

            # TLV Type 0: End of LLDPDU
            elif tlv_type == 0:
                break

        if not result.get("producer"):
            oui = _oui_from_mac(result.get("mac", ""))
            result["producer"] = VENDOR_OUI.get(oui, "")

        LOGGER.debug(
            "LLDP parsed: src=%s id_mac=%s ip=%s model=%s fw=%s producer=%s",
            result.get("source_mac", ""),
            result.get("mac", ""),
            result.get("ip", ""),
            result.get("model", ""),
            result.get("firmware", ""),
            result.get("producer", ""),
        )

        return result if result["mac"] else None
    except Exception as e:
        log_exception(LOGGER, "LLDP parse failed", e)
        return None


def listen_lldp_responses(adapter_name, callback, stop_event, burst_timeout=3):
    """Listen for LLDP advertisements on interface."""

    LOGGER.debug("LLDP listen start on adapter=%s timeout=%s", adapter_name, burst_timeout)
    packet_count = 0
    emitted_count = 0

    def handler(packet):
        nonlocal packet_count, emitted_count
        if stop_event.is_set():
            return
        packet_count += 1
        if not packet.haslayer(Ether):
            return
        result = extract_lldp_payload(packet)
        if result:
            result["adapter"] = adapter_name
            emitted_count += 1
            LOGGER.debug(
                "LLDP emit #%s (seen=%s) adapter=%s mac=%s ip=%s fw=%s",
                emitted_count,
                packet_count,
                adapter_name,
                result.get("mac", ""),
                result.get("ip", ""),
                result.get("firmware", ""),
            )
            callback(result)

    while not stop_event.is_set():
        try:
            sniff(
                iface=adapter_name,
                filter="ether dst 01:80:c2:00:00:0e and ether proto 35020",
                prn=handler,
                stop_filter=lambda x: stop_event.is_set(),
                timeout=burst_timeout,
                store=False,
            )
        except Exception as e:
            log_exception(LOGGER, f"LLDP listen failed on {adapter_name}", e, ["not found"])
            break

    LOGGER.debug(
        "LLDP listen stop on adapter=%s seen=%s emitted=%s",
        adapter_name,
        packet_count,
        emitted_count,
    )


def start_lldp_scan(adapter_name, callback, stop_event):
    """Start LLDP listener on single adapter."""
    LOGGER.debug("LLDP single-adapter scan requested: %s", adapter_name)
    listen_lldp_responses(adapter_name, callback, stop_event)


def start_lldp_scan_all(callback, stop_event):
    """Start LLDP listeners on all adapters."""
    import threading

    from scanner import get_adapters

    adapters = get_adapters()
    LOGGER.debug("LLDP scan_all adapters=%s", len(adapters))
    threads = []
    for adapter in adapters:
        name = adapter["name"]
        if not name:
            continue
        t = threading.Thread(
            target=listen_lldp_responses,
            args=(name, callback, stop_event),
            daemon=True,
        )
        t.start()
        threads.append(t)
    return threads
