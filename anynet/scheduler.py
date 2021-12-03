
from anynet import util
import contextlib
import itertools
import anyio
import time


class Scheduler:
	def __init__(self, group):
		self.group = group
		
		self.handle = itertools.count()
		self.event = anyio.Event()
		self.events = {}
		
	def start(self):
		self.group.start_soon(self.process)
	
	async def process(self):
		while True:
			timeout = self.process_timers()
			with anyio.move_on_after(timeout):
				await self.event.wait()
				self.event = anyio.Event()
	
	def process_timers(self):
		minimum = None
		current = time.monotonic()
		items = self.events.copy().items()
		for handle, (deadline, repeat, function, args) in items:
			if deadline <= current:
				del self.events[handle]
				if repeat is not None:
					self.events[handle] = (deadline + repeat, repeat, function, args)
				self.group.start_soon(function, *args)
			else:
				if minimum is None or minimum > deadline - current:
					minimum = deadline - current
		return minimum
	
	def schedule(self, function, delay, *args):
		deadline = time.monotonic() + delay
		
		handle = next(self.handle)
		self.events[handle] = (deadline, None, function, args)
		self.event.set()
		return handle
	
	def repeat(self, function, delay, *args):
		deadline = time.monotonic() + delay
		
		handle = next(self.handle)
		self.events[handle] = (deadline, delay, function, args)
		self.event.set()
		return handle
		
	def remove(self, handle):
		if handle in self.events:
			del self.events[handle]
	
	def remove_all(self):
		self.events = {}


@contextlib.asynccontextmanager
async def create():
	async with util.create_task_group() as group:
		scheduler = Scheduler(group)
		scheduler.start()
		yield scheduler
