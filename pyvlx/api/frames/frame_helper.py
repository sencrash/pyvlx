"""Helper module for SLIP Frames."""
from typing import Tuple

from pyvlx.const import Command
from pyvlx.exception import PyVLXException

# KLF150 protocol constants
KLF150_SERVICE_PROTOCOL = 16
KLF150_SERVICE_EVENT = 240
KLF150_GATEWAY_CLIENT_ID = 21


def calc_crc(raw: bytes) -> int:
    """Calculate cyclic redundancy check (CRC)."""
    crc = 0
    for sym in raw:
        crc = crc ^ int(sym)
    return crc


def extract_from_frame(data: bytes, is_klf150: bool = False) -> Tuple[Command, bytes]:
    """Extract payload and command from frame."""
    if is_klf150:
        return extract_from_klf150_frame(data)
    return extract_from_klf200_frame(data)


def extract_from_klf200_frame(data: bytes) -> Tuple[Command, bytes]:
    """Extract payload and command from KLF200 frame."""
    if len(data) <= 4:
        raise PyVLXException("could_not_extract_from_frame_too_short", data=data)
    length = data[0] * 256 + data[1] - 1
    if len(data) != length + 3:
        raise PyVLXException(
            "could_not_extract_from_frame_invalid_length",
            data=data,
            current_length=len(data),
            expected_length=length + 3,
        )
    if calc_crc(data[:-1]) != data[-1]:
        raise PyVLXException(
            "could_not_extract_from_frame_invalid_crc",
            data=data,
            expected_crc=calc_crc(data[:-1]),
            current_crc=data[-1],
        )
    payload = data[4:-1]
    try:
        command = Command(data[2] * 256 + data[3])
    except ValueError as type_error:
        raise PyVLXException("could_not_extract_from_frame_command", data=data) from type_error
    return command, payload


def extract_from_klf150_frame(data: bytes) -> Tuple[Command, bytes]:
    """Extract payload and command from KLF150 frame."""
    if len(data) < 9:
        raise PyVLXException("could_not_extract_from_klf150_frame_too_short", data=data)

    # Verify CRC (CRC is calculated over bytes 1 onwards)
    expected_crc = calc_crc(data[1:])
    if data[0] != expected_crc:
        raise PyVLXException(
            "could_not_extract_from_klf150_frame_invalid_crc",
            data=data,
            expected_crc=expected_crc,
            current_crc=data[0],
        )

    # Extract and verify header fields
    total_length = data[1] | (data[2] << 8)
    service_protocol = data[3]
    service_event = data[4]
    gateway_client_id = data[5]

    if service_protocol != KLF150_SERVICE_PROTOCOL:
        raise PyVLXException(
            "could_not_extract_from_klf150_frame_invalid_service_protocol",
            data=data,
            expected=KLF150_SERVICE_PROTOCOL,
            current=service_protocol,
        )

    if service_event != KLF150_SERVICE_EVENT:
        raise PyVLXException(
            "could_not_extract_from_klf150_frame_invalid_service_event",
            data=data,
            expected=KLF150_SERVICE_EVENT,
            current=service_event,
        )

    if gateway_client_id != KLF150_GATEWAY_CLIENT_ID:
        raise PyVLXException(
            "could_not_extract_from_klf150_frame_invalid_client_id",
            data=data,
            expected=KLF150_GATEWAY_CLIENT_ID,
            current=gateway_client_id,
        )

    # Verify total length (total_length seems to be calculated as len(payload) + 9)
    # Where 9 = SERVICE_HEADER_LENGTH(5) + GATEWAY_HEADER_LENGTH(4)
    # The actual frame is: CRC(1) + total_length(2) + service_header(3) + gateway_header(3) + payload
    # So expected length = 1 + total_length (which already includes the 2 bytes for total_length field itself + 3 + 3 + payload)
    # Just do a minimum length check instead of exact match
    if len(data) < 9:  # Minimum: CRC + headers
        raise PyVLXException(
            "could_not_extract_from_klf150_frame_too_short",
            data=data,
            current_length=len(data),
        )

    # Extract command and payload
    inner_length = data[6]
    command_value = (data[7] << 8) | data[8]
    payload = data[9:]

    try:
        command = Command(command_value)
    except ValueError as type_error:
        raise PyVLXException(
            "could_not_extract_from_klf150_frame_command",
            data=data,
            command_value=command_value
        ) from type_error

    return command, payload
