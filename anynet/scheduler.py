
from anynet import util
from typing import Any, AsyncIterator, Callable

import anyio
import anyio.abc
import contextlib
import itertools
import time


class Scheduler:
    _group: anyio.abc.TaskGroup

    _handle: itertools.count[int]
    _event: anyio.abc.Event
    _events: dict[int, tuple[float, float | None, Callable, tuple]]

    def __init__(self, group: anyio.abc.TaskGroup):
        self._group = group
        
        self._handle = itertools.count()
        self._event = anyio.Event()
        self._events = {}
        
    def start(self) -> None:
        self._group.start_soon(self._process)
    
    async def _process(self) -> None:
        while True:
            timeout = self._process_timers()
            with anyio.move_on_after(timeout):
                await self._event.wait()
                self._event = anyio.Event()
    
    def _process_timers(self) -> float | None:
        current = time.monotonic()
        items = self._events.copy().items()
        for handle, (deadline, repeat, function, args) in items:
            if deadline <= current:
                del self._events[handle]
                if repeat is not None:
                    self._events[handle] = (deadline + repeat, repeat, function, args)
                self._group.start_soon(function, *args)
        
        timeouts = [event[0] - current for event in self._events.values()]
        return min(timeouts, default=None)
    
    def schedule(self, function: Callable, delay: float, *args) -> int:
        deadline = time.monotonic() + delay
        
        handle = next(self._handle)
        self._events[handle] = (deadline, None, function, args)
        self._event.set()
        return handle
    
    def repeat(self, function: Callable, delay: float, *args) -> int:
        deadline = time.monotonic() + delay
        
        handle = next(self._handle)
        self._events[handle] = (deadline, delay, function, args)
        self._event.set()
        return handle
        
    def remove(self, handle: int) -> None:
        if handle in self._events:
            del self._events[handle]
    
    def remove_all(self) -> None:
        self._events = {}


@contextlib.asynccontextmanager
async def create() -> AsyncIterator[Scheduler]:
    async with util.create_task_group() as group:
        scheduler = Scheduler(group)
        scheduler.start()
        yield scheduler
