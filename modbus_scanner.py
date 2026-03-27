"""Modbus TCP device identification probing."""

import socket
import struct

from debug_utils import get_logger, log_exception


LOGGER = get_logger(__name__)

MBAP_HEADER = struct.Struct(">HHHB")
READ_DEVICE_ID_FUNCTION = 0x2B
MEI_TYPE = 0x0E

OBJECT_NAMES = {
    0x00: "vendor_name",
    0x01: "product_code",
    0x02: "version",
    0x03: "vendor_url",
    0x04: "product_name",
    0x05: "model_name",
    0x06: "user_application_name",
}


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            break
        data += chunk
    return data


def _send_device_id_request(sock: socket.socket, transaction_id: int, unit_id: int, read_code: int, object_id: int) -> dict | None:
    pdu = bytes((READ_DEVICE_ID_FUNCTION, MEI_TYPE, read_code, object_id))
    request = MBAP_HEADER.pack(transaction_id, 0, len(pdu) + 1, unit_id) + pdu
    sock.sendall(request)

    header = _recv_exact(sock, MBAP_HEADER.size)
    if len(header) != MBAP_HEADER.size:
        return None

    rx_transaction_id, _protocol_id, length, rx_unit_id = MBAP_HEADER.unpack(header)
    if rx_transaction_id != transaction_id or rx_unit_id != unit_id or length <= 1:
        return None

    body = _recv_exact(sock, length - 1)
    if len(body) != length - 1:
        return None

    if len(body) < 7 or body[0] != READ_DEVICE_ID_FUNCTION or body[1] != MEI_TYPE:
        return None

    if body[0] & 0x80:
        return None

    more_follows = body[4]
    next_object_id = body[5]
    object_count = body[6]
    objects = {}
    offset = 7

    for _ in range(object_count):
        if offset + 2 > len(body):
            break
        current_object_id = body[offset]
        value_length = body[offset + 1]
        offset += 2
        value_end = offset + value_length
        if value_end > len(body):
            break
        value = body[offset:value_end].decode("latin-1", errors="replace").strip()
        objects[current_object_id] = value
        offset = value_end

    return {
        "more_follows": more_follows,
        "next_object_id": next_object_id,
        "objects": objects,
    }


def _read_device_identification(sock: socket.socket, unit_id: int, read_code: int) -> dict:
    transaction_id = 1
    next_object_id = 0
    collected = {}

    while True:
        result = _send_device_id_request(sock, transaction_id, unit_id, read_code, next_object_id)
        if not result:
            return {}

        collected.update(result["objects"])
        if not result["more_follows"]:
            return collected

        next_object_id = result["next_object_id"]
        transaction_id += 1


def probe_modbus_device(ip: str, adapter_name: str, callback, timeout: float = 1.8) -> bool:
    try:
        objects = {}
        used_unit_id = None

        # Część urządzeń odrzuca pierwsze kombinacje Unit ID / read code.
        # Próbujemy kilka wariantów i nie przerywamy na pierwszym błędzie transportowym.
        for unit_id in (0xFF, 0x01, 0x00, 0x02):
            for read_code in (0x01, 0x02, 0x03):
                try:
                    with socket.create_connection((ip, 502), timeout=timeout) as sock:
                        sock.settimeout(timeout)
                        objects = _read_device_identification(sock, unit_id, read_code)
                except OSError:
                    objects = {}
                    continue

                if objects:
                    used_unit_id = unit_id
                    break
            if objects:
                break

        if not objects:
            LOGGER.debug("Modbus TCP identity not available for %s", ip)
            return False

        info = {
            "ip": ip,
            "protocol": "Modbus TCP",
            "vendor_id": "",
            "device_id": objects.get(0x01, ""),
            "version": objects.get(0x02, ""),
            "module_name": objects.get(0x04) or objects.get(0x05) or objects.get(0x01, ""),
            "product_name": objects.get(0x04, ""),
            "model_name": objects.get(0x05, ""),
            "producer": objects.get(0x00, ""),
            "vendor_name": objects.get(0x00, ""),
            "vendor_url": objects.get(0x03, ""),
            "user_application_name": objects.get(0x06, ""),
            "modbus_unit_id": used_unit_id,
            "adapter": adapter_name,
            "vendor_match": bool(objects.get(0x00)),
            "type": "modbus_identity",
        }
        callback(info)
        return True
    except Exception as exc:
        log_exception(LOGGER, "Modbus TCP probe failed for %s", ip, exc=exc)
        return False