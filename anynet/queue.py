
import math
import anyio


class Queue:
	def __init__(self, stream):
		self.stream = stream
	
	async def __aenter__(self): return self
	async def __aexit__(self, typ, val, tb):
		await self.stream.aclose()
	
	async def put(self, value):
		await self.stream.send(value)
	
	async def get(self):
		return await self.stream.receive()
	
	async def close(self):
		await self.stream.aclose()


def create(size=math.inf):
	send, recv = anyio.create_memory_object_stream(size)
	stream = anyio.streams.stapled.StapledObjectStream(send, recv)
	return Queue(stream)
