
from anynet import util
import contextlib
import socket
import anyio

import logging
logger = logging.getLogger(__name__)


class TCPClient:
	def __init__(self, stream):
		self.stream = stream
		self.lock = anyio.Lock()
	
	async def send(self, data):
		async with self.lock:
			await self.stream.send(data)
	async def recv(self, num=65536):
		return await self.stream.receive(num)
	
	def local_address(self):
		return self.stream.extra(anyio.abc.SocketAttribute.local_address)
	def remote_address(self):
		return self.stream.extra(anyio.abc.SocketAttribute.remote_address)


@contextlib.asynccontextmanager
async def connect(host, port):
	logger.debug("Connecting TCP client to %s:%i", host, port)
	async with await anyio.connect_tcp(host, port) as stream:
		yield TCPClient(stream)

@contextlib.asynccontextmanager
async def serve(handler, host="", port=0):
	async def handle(stream):
		async with stream:
			with util.catch(Exception):
				await handler(TCPClient(stream))
		
	if not host:
		host = util.local_address()
	
	logger.info("Starting TCP server at %s:%i", host, port)
	
	listener = await anyio.create_tcp_listener(local_host=host, local_port=port)
	async with listener:
		async with util.create_task_group() as group:
			group.start_soon(listener.serve, handle)
			yield
