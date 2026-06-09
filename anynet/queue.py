
from typing import Self

import math
import anyio
import anyio.abc
import anyio.streams.stapled


class Queue[T]:
    _stream: anyio.abc.ObjectStream[T]

    def __init__(self, stream: anyio.abc.ObjectStream[T]):
        self._stream = stream
    
    async def __aenter__(self) -> Self:
        return self
    
    async def __aexit__(self, typ, val, tb) -> None:
        await self._stream.aclose()
    
    async def put(self, value: T) -> None:
        await self._stream.send(value)
    
    async def get(self) -> T:
        return await self._stream.receive()
    
    async def close(self) -> None:
        await self._stream.aclose()
    
    async def eof(self) -> None:
        await self._stream.send_eof()


def create[T](size: int | float = math.inf) -> Queue[T]:
    send, recv = anyio.create_memory_object_stream(size)
    stream = anyio.streams.stapled.StapledObjectStream(send, recv)
    return Queue[T](stream)
