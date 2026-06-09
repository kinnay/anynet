
from anynet import util
from typing import AsyncIterator, Awaitable, Callable

import anyio
import anyio.abc
import contextlib

import logging
logger = logging.getLogger(__name__)


class TCPClient:
    _stream: anyio.abc.SocketStream
    _lock: anyio.abc.Lock

    def __init__(self, stream: anyio.abc.SocketStream):
        self._stream = stream
        self._lock = anyio.Lock()
    
    async def send(self, data: bytes) -> None:
        async with self._lock:
            await self._stream.send(data)
    
    async def recv(self, num: int = 65536) -> bytes:
        return await self._stream.receive(num)
    
    async def close(self) -> None:
        await self._stream.aclose()
    
    def local_address(self) -> tuple[str, int]:
        address = self._stream.extra(anyio.abc.SocketAttribute.local_address)
        if not isinstance(address, tuple):
            raise RuntimeError("Socket has unexpected address type")
        return address
    
    def remote_address(self) -> tuple[str, int]:
        address = self._stream.extra(anyio.abc.SocketAttribute.remote_address)
        if not isinstance(address, tuple):
            raise RuntimeError("Socket has unexpected address type")
        return address


@contextlib.asynccontextmanager
async def connect(host: str, port: int) -> AsyncIterator[TCPClient]:
    logger.debug("Connecting TCP client to %s:%i", host, port)
    async with await anyio.connect_tcp(host, port) as stream:
        yield TCPClient(stream)

@contextlib.asynccontextmanager
async def serve(
    handler: Callable[[TCPClient], Awaitable[None]], host: str = "",
    port: int = 0
) -> AsyncIterator[None]:
    async def handle(stream) -> None:
        async with stream:
            with util.catch():
                await handler(TCPClient(stream))
        
    if not host:
        host = util.local_address()
    
    logger.info("Starting TCP server at %s:%i", host, port)
    
    listener = await anyio.create_tcp_listener(local_host=host, local_port=port)
    async with listener:
        async with util.create_task_group() as group:
            group.start_soon(listener.serve, handle)
            yield
