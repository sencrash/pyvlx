"""Module for handling the Serial connection with KLF 150 Gateway."""
import asyncio
import sys
from typing import Callable, Coroutine, List, Optional, Set

import serial_asyncio

from .api.frame_creation import frame_from_raw
from .api.frames import FrameBase
from .exception import PyVLXException
from .log import PYVLXLOG
from .slip import get_next_slip, is_slip, slip_pack


class SlipTokenizer:
    """Helper class for splitting up binary stream to slip packets."""

    def __init__(self) -> None:
        """Init Tokenizer."""
        self.data = bytes()

    def feed(self, chunk: bytes) -> None:
        """Feed chunk to tokenizer."""
        if not chunk:
            return
        self.data += chunk

    def has_tokens(self) -> bool:
        """Return True if Tokenizer has tokens."""
        return is_slip(self.data)

    def get_next_token(self) -> Optional[bytes]:
        """Get next token from Tokenizer."""
        slip, self.data = get_next_slip(self.data)
        return slip


class SerialTransport(asyncio.Protocol):
    """Class for handling asyncio serial connection transport."""

    def __init__(
        self,
        frame_received_cb: Callable[[FrameBase], None],
        connection_lost_cb: Callable[[], None],
        connection_made_event: Optional[asyncio.Event] = None,
    ):
        """Init SerialTransport."""
        self.frame_received_cb = frame_received_cb
        self.connection_lost_cb = connection_lost_cb
        self.tokenizer = SlipTokenizer()
        self.connection_made_event = connection_made_event

    def connection_made(self, transport: object) -> None:
        """Handle successful connection."""
        PYVLXLOG.debug("Serial connection to KLF 150 opened")
        if self.connection_made_event is not None:
            self.connection_made_event.set()

    def data_received(self, data: bytes) -> None:
        """Handle data received."""
        PYVLXLOG.debug("Serial data received: %d bytes: %s", len(data), data.hex())
        self.tokenizer.feed(data)
        while self.tokenizer.has_tokens():
            raw = self.tokenizer.get_next_token()
            assert raw is not None
            PYVLXLOG.debug("SLIP token extracted: %s", raw.hex())

            try:
                # KLF150 uses different frame structure
                frame = frame_from_raw(raw, is_klf150=True)
                if frame is not None:
                    self.frame_received_cb(frame)
            except PyVLXException:
                PYVLXLOG.error("Error in data_received", exc_info=sys.exc_info())

    def connection_lost(self, exc: object) -> None:
        """Handle lost connection."""
        PYVLXLOG.debug("Serial connection to KLF 150 has been lost")
        self.connection_lost_cb()


CallbackType = Callable[[FrameBase], Coroutine]


class SerialConnection:
    """Class for handling Serial connection to KLF 150."""

    # KLF 150 serial settings (from decompiled code)
    BAUD_RATE = 256000
    BYTESIZE = 8
    PARITY = "N"
    STOPBITS = 1

    def __init__(self, loop: asyncio.AbstractEventLoop, port: str):
        """Init Serial connection. """
        self.loop = loop
        self.port = port
        self.transport: Optional[asyncio.Transport] = None
        self.frame_received_cbs: List[CallbackType] = []
        self.connection_closed_cbs: List[Callable[[], Coroutine]] = []
        self.connection_opened_cbs: List[Callable[[], Coroutine]] = []
        self.connected = False
        self.connection_counter = 0
        self.tasks: Set[asyncio.Task] = set()

    def __del__(self) -> None:
        """Destruct connection."""
        self.disconnect()

    def disconnect(self) -> None:
        """Disconnect connection."""
        if self.transport is not None:
            self.transport.close()
            self.transport = None
        self.connected = False
        PYVLXLOG.debug("Serial transport closed.")
        for connection_closed_cb in self.connection_closed_cbs:
            if asyncio.iscoroutine(connection_closed_cb()):
                task = self.loop.create_task(connection_closed_cb())
                self.tasks.add(task)
                task.add_done_callback(self.tasks.remove)

    async def connect(self) -> None:
        """Connect to KLF 150 gateway via serial port."""
        connection_made_event = asyncio.Event()
        serial_client = SerialTransport(
            self.frame_received_cb,
            connection_lost_cb=self.on_connection_lost,
            connection_made_event=connection_made_event,
        )

        PYVLXLOG.debug("Opening serial port %s at %d baud", self.port, self.BAUD_RATE)

        self.transport, _ = await serial_asyncio.create_serial_connection(
            self.loop,
            lambda: serial_client,
            self.port,
            baudrate=self.BAUD_RATE,
            bytesize=self.BYTESIZE,
            parity=self.PARITY,
            stopbits=self.STOPBITS,
        )

        # Wait for connection to be fully established
        PYVLXLOG.debug("Waiting for serial connection to be ready...")
        await asyncio.wait_for(connection_made_event.wait(), timeout=5.0)

        self.connected = True
        self.connection_counter += 1
        PYVLXLOG.debug(
            "Amount of connections since last HA start: %s", self.connection_counter
        )
        for connection_opened_cb in self.connection_opened_cbs:
            if asyncio.iscoroutine(connection_opened_cb()):
                task = self.loop.create_task(connection_opened_cb())
                self.tasks.add(task)
                task.add_done_callback(self.tasks.remove)

    def register_frame_received_cb(self, callback: CallbackType) -> None:
        """Register frame received callback."""
        self.frame_received_cbs.append(callback)

    def unregister_frame_received_cb(self, callback: CallbackType) -> None:
        """Unregister frame received callback."""
        self.frame_received_cbs.remove(callback)

    def register_connection_closed_cb(self, callback: Callable[[], Coroutine]) -> None:
        """Register connection closed callback."""
        self.connection_closed_cbs.append(callback)

    def unregister_connection_closed_cb(self, callback: Callable[[], Coroutine]) -> None:
        """Unregister connection closed callback."""
        self.connection_closed_cbs.remove(callback)

    def register_connection_opened_cb(self, callback: Callable[[], Coroutine]) -> None:
        """Register connection opened callback."""
        self.connection_opened_cbs.append(callback)

    def unregister_connection_opened_cb(self, callback: Callable[[], Coroutine]) -> None:
        """Unregister connection opened callback."""
        self.connection_opened_cbs.remove(callback)

    def write(self, frame: FrameBase) -> None:
        """Write frame to serial port."""
        if not isinstance(frame, FrameBase):
            raise PyVLXException("Frame not of type FrameBase", *type(frame))
        PYVLXLOG.debug("SEND: %s", frame)
        raw_frame = bytes(frame)
        slip_frame = slip_pack(raw_frame)
        PYVLXLOG.debug("Sending raw frame: %s", raw_frame.hex())
        PYVLXLOG.debug("Sending SLIP frame: %s", slip_frame.hex())
        assert self.transport is not None
        self.transport.write(slip_frame)

    def frame_received_cb(self, frame: FrameBase) -> None:
        """Received message."""
        PYVLXLOG.debug("REC: %s", frame)
        for frame_received_cb in self.frame_received_cbs:
            # pylint: disable=not-callable
            task = self.loop.create_task(frame_received_cb(frame))
            self.tasks.add(task)
            task.add_done_callback(self.tasks.remove)

    def on_connection_lost(self) -> None:
        """Serial connection lost."""
        self.disconnect()
