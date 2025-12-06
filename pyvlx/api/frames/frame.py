"""Module for Frames."""
import struct
from typing import ClassVar

from pyvlx.const import Command
from pyvlx.exception import PyVLXException

from .frame_helper import calc_crc, KLF150_SERVICE_PROTOCOL, KLF150_SERVICE_EVENT, KLF150_GATEWAY_CLIENT_ID


class FrameBase:
    """Class for Base Frame."""

    # Class variable to track gateway type (set by PyVLX during initialization)
    is_klf150: ClassVar[bool] = False

    def __init__(self, command: Command):
        """Initialize Base Frame."""
        self.command = command

    def __bytes__(self) -> bytes:
        """Get raw bytes of Frame."""
        payload = self.get_payload()
        self.validate_payload_len(payload)
        return self.build_frame(self.command, payload)

    def validate_payload_len(self, payload: bytes) -> None:
        """Validate payload len."""
        if not hasattr(self, "PAYLOAD_LEN"):
            # No fixed payload len, e.g. within FrameGetSceneListNotification
            return
        # pylint: disable=no-member
        if len(payload) != self.PAYLOAD_LEN:
            raise PyVLXException(
                "Invalid payload len",
                expected_len=self.PAYLOAD_LEN,
                current_len=len(payload),
                frame_type=type(self).__name__,
            )

    def get_payload(self) -> bytes:
        """Return Payload."""
        return b""

    def from_payload(self, payload: bytes) -> None:
        """Init frame from binary data."""

    def __str__(self) -> str:
        """Return human readable string."""
        return "<{}/>".format(type(self).__name__)

    @staticmethod
    def build_frame(command: Command, payload: bytes) -> bytes:
        """Build raw bytes from command and payload."""
        if FrameBase.is_klf150:
            return FrameBase.build_klf150_frame(command, payload)
        return FrameBase.build_klf200_frame(command, payload)

    @staticmethod
    def build_klf200_frame(command: Command, payload: bytes) -> bytes:
        """Build raw bytes from command and payload for KLF200."""
        packet_length = 2 + len(payload) + 1
        ret = struct.pack("BB", 0, packet_length)
        ret += struct.pack(">H", command.value)
        ret += payload
        ret += struct.pack("B", calc_crc(ret))
        return ret

    @staticmethod
    def build_klf150_frame(command: Command, payload: bytes) -> bytes:
        """Build raw bytes from command and payload for KLF150."""
        # GATEWAY_HEADER_LENGTH = 4 (inner_length + command_high + command_low + first_payload_byte)
        # SERVICE_HEADER_LENGTH = 5 (total_length_low + total_length_high + service_protocol + service_event + gateway_client_id)
        GATEWAY_HEADER_LENGTH = 4
        SERVICE_HEADER_LENGTH = 5

        # Calculate lengths
        total_length = len(payload) + GATEWAY_HEADER_LENGTH + SERVICE_HEADER_LENGTH
        inner_length = len(payload) + GATEWAY_HEADER_LENGTH

        # Build frame (CRC placeholder at position 0)
        frame = bytearray()
        frame.append(0)  # CRC placeholder

        # Service header (5 bytes)
        frame.append(total_length & 0xFF)  # total_length_low
        frame.append((total_length >> 8) & 0xFF)  # total_length_high
        frame.append(KLF150_SERVICE_PROTOCOL)
        frame.append(KLF150_SERVICE_EVENT)
        frame.append(KLF150_GATEWAY_CLIENT_ID)

        # Gateway header (4 bytes including command)
        frame.append(inner_length & 0xFF)  # inner_length
        frame.append((command.value >> 8) & 0xFF)  # command_high
        frame.append(command.value & 0xFF)  # command_low

        # Payload
        frame.extend(payload)

        # Calculate and set CRC (over all bytes except the CRC itself)
        crc = calc_crc(frame[1:])
        frame[0] = crc

        return bytes(frame)
