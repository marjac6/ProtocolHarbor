"""EtherNet/IP identity probing."""

import socket
import struct

from debug_utils import get_logger, log_exception
from vendor_registry import lookup_vendor_name


LOGGER = get_logger(__name__)

ENCAP_HEADER = struct.Struct("<HHII8sI")
LIST_IDENTITY_COMMAND = 0x0063


def _build_list_identity_request() -> bytes:
    return ENCAP_HEADER.pack(LIST_IDENTITY_COMMAND, 0, 0, 0, b"Scanner0", 0)


def _parse_identity_payload(payload: bytes, fallback_ip: str) -> dict | None:
    if len(payload) < 6:
        return None

    item_count = struct.unpack_from("<H", payload, 0)[0]
    offset = 2

    for _ in range(item_count):
        if offset + 4 > len(payload):
            break

        _item_type, item_length = struct.unpack_from("<HH", payload, offset)
        offset += 4
        item_end = offset + item_length
        if item_end > len(payload):
            break

        item_data = payload[offset:item_end]
        offset = item_end

        if len(item_data) < 33:
            continue

        protocol_version = struct.unpack_from("<H", item_data, 0)[0]
        vendor_id = struct.unpack_from("<H", item_data, 18)[0]
        device_type = struct.unpack_from("<H", item_data, 20)[0]
        product_code = struct.unpack_from("<H", item_data, 22)[0]
        major_revision = item_data[24]
        minor_revision = item_data[25]
        status = struct.unpack_from("<H", item_data, 26)[0]
        serial_number = struct.unpack_from("<I", item_data, 28)[0]
        name_length = item_data[32]
        name_start = 33
        name_end = name_start + name_length
        if name_end > len(item_data):
            continue

        product_name = item_data[name_start:name_end].decode("latin-1", errors="replace").strip()
        state = item_data[name_end] if name_end < len(item_data) else None
        vendor_label = lookup_vendor_name(vendor_id, protocol="ethernet/ip")

        return {
            "ip": fallback_ip,
            "protocol": "EtherNet/IP",
            "vendor_id": f"0x{vendor_id:04X}",
            "device_id": f"0x{product_code:04X}",
            "device_type": f"0x{device_type:04X}",
            "version": f"{major_revision}.{minor_revision}",
            "module_name": product_name,
            "product_name": product_name,
            "producer": vendor_label,
            "serial_number": f"0x{serial_number:08X}",
            "status_word": f"0x{status:04X}",
            "encapsulation_version": protocol_version,
            "state": state,
            "vendor_match": bool(vendor_label),
            "type": "enip_identity",
        }

    return None


def _read_response(sock: socket.socket) -> dict | None:
    header = sock.recv(ENCAP_HEADER.size)
    if len(header) < ENCAP_HEADER.size:
        return None

    command, length, _session, status, _context, _options = ENCAP_HEADER.unpack(header)
    if command != LIST_IDENTITY_COMMAND or status != 0:
        return None

    payload = b""
    while len(payload) < length:
        chunk = sock.recv(length - len(payload))
        if not chunk:
            break
        payload += chunk
    return {"payload": payload}


def _probe_tcp(ip: str, timeout: float) -> dict | None:
    with socket.create_connection((ip, 44818), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(_build_list_identity_request())
        response = _read_response(sock)
        if not response:
            return None
        return _parse_identity_payload(response["payload"], ip)


def _probe_udp(ip: str, timeout: float) -> dict | None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(_build_list_identity_request(), (ip, 44818))
        payload, addr = sock.recvfrom(2048)
        if addr[0] != ip or len(payload) < ENCAP_HEADER.size:
            return None
        command, length, _session, status, _context, _options = ENCAP_HEADER.unpack(payload[:ENCAP_HEADER.size])
        if command != LIST_IDENTITY_COMMAND or status != 0:
            return None
        return _parse_identity_payload(payload[ENCAP_HEADER.size:ENCAP_HEADER.size + length], ip)


def probe_enip_device(ip: str, adapter_name: str, callback, timeout: float = 0.8) -> bool:
    try:
        info = None
        try:
            info = _probe_tcp(ip, timeout)
        except OSError:
            LOGGER.debug("EtherNet/IP TCP probe failed for %s", ip)

        if info is None:
            try:
                info = _probe_udp(ip, timeout)
            except OSError:
                LOGGER.debug("EtherNet/IP UDP probe failed for %s", ip)

        if info is None:
            return False

        info["adapter"] = adapter_name
        callback(info)
        return True
    except Exception as exc:
        log_exception(LOGGER, "EtherNet/IP probe failed for %s", ip, exc=exc)
        return False