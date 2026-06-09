
from anynet import util
from typing import AsyncIterator

import anyio
import anyio.abc
import contextlib
import socket

import logging
logger = logging.getLogger(__name__)


class UDPSocket:
    _socket: anyio.abc.UDPSocket
    _lock: anyio.abc.Lock

    def __init__(self, socket: anyio.abc.UDPSocket):
        self._socket = socket
        self._lock = anyio.Lock()
    
    async def send(self, data: bytes, addr: tuple[str, int]) -> None:
        async with self._lock:
            await self._socket.sendto(data, addr[0], addr[1])
    
    async def recv(self) -> tuple[bytes, tuple[str, int]]:
        return await self._socket.receive()
    
    async def close(self) -> None:
        await self._socket.aclose()
    
    def local_address(self) -> tuple[str, int]:
        address = self._socket.extra(anyio.abc.SocketAttribute.local_address)
        if not isinstance(address, tuple):
            raise RuntimeError("Socket has unexpected address type")
        return address


class UDPClient:
    _socket: anyio.abc.ConnectedUDPSocket
    _lock: anyio.abc.Lock

    def __init__(self, socket: anyio.abc.ConnectedUDPSocket):
        self._socket = socket
        self._lock = anyio.Lock()
    
    async def send(self, data: bytes) -> None:
        async with self._lock:
            await self._socket.send(data)
    
    async def recv(self) -> bytes:
        return await self._socket.receive()
    
    async def close(self) -> None:
        await self._socket.aclose()
    
    def local_address(self) -> tuple[str, int]:
        address = self._socket.extra(anyio.abc.SocketAttribute.local_address)
        if not isinstance(address, tuple):
            raise RuntimeError("Socket has unexpected address type")
        return address
    
    def remote_address(self) -> tuple[str, int]:
        address = self._socket.extra(anyio.abc.SocketAttribute.remote_address)
        if not isinstance(address, tuple):
            raise RuntimeError("Socket has unexpected address type")
        return address


@contextlib.asynccontextmanager
async def bind(
    host: str = "", port: int = 0, *, broadcast: bool = False
) -> AsyncIterator[UDPSocket]:
    if not host:
        host = util.local_address()
    
    logger.debug("Creating UDP socket at %s:%i", host, port)
    
    sock = await anyio.create_udp_socket(local_host=host, local_port=port)
    async with sock:
        if broadcast:
            rawsock = sock.extra(anyio.abc.SocketAttribute.raw_socket)
            rawsock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, True)
        yield UDPSocket(sock)

@contextlib.asynccontextmanager
async def connect(host: str, port: int) -> AsyncIterator[UDPClient]:
    logger.debug("Connecting UDP client to %s:%i", host, port)
    
    sock = await anyio.create_connected_udp_socket(host, port)
    async with sock:
        yield UDPClient(sock)
