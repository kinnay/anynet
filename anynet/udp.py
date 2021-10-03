
from anynet import util
import contextlib
import socket
import anyio

import logging
logger = logging.getLogger(__name__)


class UDPSocket:
	def __init__(self, sock):
		self.sock = sock
		self.lock = anyio.Lock()
	
	async def send(self, data, addr):
		async with self.lock:
			await self.sock.sendto(data, addr[0], addr[1])
	async def recv(self):
		return await self.sock.receive()
	
	async def broadcast(self, data, port):
		host = util.broadcast_address()
		await self.send(data, (host, port))
	
	def local_address(self):
		return self.sock.extra(anyio.abc.SocketAttribute.local_address)


class UDPClient:
	def __init__(self, sock):
		self.sock = sock
		self.lock = anyio.Lock()
	
	async def send(self, data):
		async with self.lock:
			await self.sock.send(data)
	async def recv(self):
		return await self.sock.receive()
	
	def local_address(self):
		return self.sock.extra(anyio.abc.SocketAttribute.local_address)
	def remote_address(self):
		return self.sock.extra(anyio.abc.SocketAttribute.remote_address)


@contextlib.asynccontextmanager
async def bind(host="", port=0):
	if not host:
		host = util.local_address()
	
	logger.debug("Creating UDP socket at %s:%i", host, port)
	
	sock = await anyio.create_udp_socket(local_host=host, local_port=port)
	async with sock:
		rawsock = sock.extra(anyio.abc.SocketAttribute.raw_socket)
		rawsock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, True)
		yield UDPSocket(sock)

@contextlib.asynccontextmanager
async def connect(host, port):
	logger.debug("Connecting UDP client to %s:%i", host, port)
	
	sock = await anyio.create_connected_udp_socket(host, port)
	async with sock:
		yield UDPClient(sock)
