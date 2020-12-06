
from anynet import tls, http, util, queue
import contextlib
import secrets
import hashlib
import base64
import struct
import anyio

import logging
logger = logging.getLogger(__name__)


OPCODE_CONTINUE = 0
OPCODE_TEXT = 1
OPCODE_BINARY = 2
OPCODE_DISCONNECT = 8
OPCODE_PING = 9
OPCODE_PONG = 10


def calculate_key_hash(key):
	string = key.encode("ascii") + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	hash = hashlib.sha1(string).digest()
	return base64.b64encode(hash).decode()
	
def apply_mask(data, key):
	return bytes([data[i] ^ key[i % 4] for i in range(len(data))])


class WSError(Exception): pass


class WSPacket:
	def __init__(self, opcode, payload=b""):
		self.opcode = opcode
		self.payload = payload


class WSPacketClient:
	def __init__(self, client, group):
		self.client = client
		self.group = group
	
		self.packets = queue.create()
		
		self.buffer = b""
		self.fragments = None
		self.message_type = None # For continuation frames
		
		self.server_mode = False
	
	async def start_handshake(self, host, path, protocols):
		logger.debug("Performing WS handshake")
		
		self.server_mode = False
		
		key = secrets.token_urlsafe()
		
		request = http.HTTPRequest.get(path)
		request.headers["Host"] = host
		request.headers["Upgrade"] = "websocket"
		request.headers["Connection"] = "upgrade"
		request.headers["Sec-WebSocket-Key"] = key
		request.headers["Sec-WebSocket-Version"] = 13
		if protocols is not None:
			request.headers["Sec-WebSocket-Protocol"] = ", ".join(protocols)
		
		response = await self.client.request(request)
		if response.status_code != 101:
			raise WSError("WS server replied with status code %i" %response.status_code)
		
		if "Sec-WebSocket-Accept" not in response.headers:
			raise WSError("Sec-WebSocket-Accept header is missing")
		if response.headers["Sec-WebSocket-Accept"] != calculate_key_hash(key):
			raise WSError("Sec-WebSocket-Accept check failed")
		
		logger.debug("WS handshake succeeded")
		await self.group.spawn(self.process)
		
	async def accept_handshake(self, path, protocol):
		logger.debug("Accepting WS handshake")
		
		self.server_mode = True
		
		while b"\r\n\r\n" not in self.buffer:
			self.buffer += await self.client.recv()
		index = self.buffer.index(b"\r\n\r\n")
		header = self.buffer[:index + 4]
		self.buffer = self.buffer[index + 4:]
		
		request = http.HTTPRequest.parse(header)
		status = self.check_handshake(request, path, protocol)
		if status != 101:
			logger.info("WS handshake error: %i" %status)
			
			response = http.HTTPResponse(status)
			response.headers["Content-Type"] = "text/html"
			response.text = "<h1>%i</h1><p>%s</p>" %(response.status_code, response.status_name)
			await self.client.send(response.encode())
			return False
			
		accept = calculate_key_hash(request.headers["Sec-WebSocket-Key"])
		
		response = http.HTTPResponse(101)
		response.headers["Connection"] = "upgrade"
		response.headers["Upgrade"] = "WebSocket"
		response.headers["Sec-WebSocket-Accept"] = accept
		if protocol is not None:
			response.headers["Sec-WebSocket-Protocol"] = protocol
		await self.client.send(response.encode())
		
		logger.debug("WS handshake succeeded")
		await self.group.spawn(self.process)
		
		return True
	
	def check_handshake(self, request, path, protocol):
		if request.method != "GET": return 405
		if request.path != path: return 404
		
		if request.headers.get("Connection").lower() != "upgrade": return 400
		if request.headers.get("Upgrade") != "websocket": return 400
		
		if "Sec-WebSocket-Key" not in request.headers: return 400
		
		if protocol is not None:
			if "Sec-WebSocket-Protocol" not in request.headers:
				return 400
			
			protocols = request.headers["Sec-WebSocket-Protocol"].split(", ")
			if protocol not in protocols:
				return 400
		return 101
		
	async def process(self):
		while True:
			await self.process_buffer()
			try:
				self.buffer += await self.client.recv()
			except anyio.EndOfStream:
				logger.debug("WS: connection was closed")
				await self.packets.close()
				return
			
	async def process_buffer(self):
		while self.buffer:
			if len(self.buffer) < 2: return
			
			fin = self.buffer[0] >> 7
			opcode = self.buffer[0] & 0xF
			mask = self.buffer[1] >> 7
			size = self.buffer[1] & 0x7F
			
			offset = 2
			if size == 126:
				if len(self.buffer) < offset + 2: return
				size = struct.unpack_from(">H", self.buffer, offset)[0]
				offset += 2
			elif size == 127:
				if len(self.buffer) < offset + 8: return
				size = struct.unpack_from(">Q", self.buffer, 2)[0]
				offset += 8

			mask_key = b"\0\0\0\0"
			if mask:
				if len(self.buffer) < offset + 4: return
				mask_key = self.buffer[offset : offset + 4]
				offset += 4
				
			if len(self.buffer) < offset + size: return
			payload = apply_mask(self.buffer[offset : offset + size], mask_key)
			
			self.buffer = self.buffer[offset + size:]
			
			await self.process_packet(opcode, payload, fin)
			
	async def process_packet(self, opcode, payload, fin):
		if opcode in [OPCODE_TEXT, OPCODE_BINARY, OPCODE_CONTINUE]:
			if opcode in [OPCODE_TEXT, OPCODE_BINARY]:
				if self.message_type is not None:
					raise WSError("Expected continuation frame")
				self.message_type = opcode
				self.fragments = payload
			else:
				if self.message_type is None:
					raise WSError("Received unexpected continuation frame")
				self.fragments += payload
			
			if fin:
				packet = WSPacket(self.message_type, self.fragments)
				self.message_type = None
				self.fragments = None
				await self.packets.put(packet)
		else:
			if not fin:
				raise WSError("Control frame must have FIN set")
			packet = WSPacket(opcode, payload)
			await self.packets.put(packet)
			
	async def send(self, opcode, payload=b""):
		data = bytes([0x80 | opcode])
		
		mask = 0x80 if not self.server_mode else 0
		
		length = len(payload)
		if length < 126:
			data += bytes([mask | length])
		elif length <= 0xFFFF:
			data += struct.pack(">BH", mask | 0x7E, length)
		else:
			data += struct.pack(">BQ", mask | 0x7F, length)
			
		if not self.server_mode:
			mask = secrets.token_bytes(4)
			payload = mask + apply_mask(payload, mask)
		data += payload

		await self.client.send(data)
		
	async def recv(self):
		return await self.packets.get()
	
	def local_address(self): return self.client.local_address()
	def remote_address(self): return self.client.remote_address()
	def remote_certificate(self): return self.client.remote_certificate()


class WebSocketClient:
	def __init__(self, client, group):
		self.client = WSPacketClient(client, group)
		self.group = group
		
		self.binary_packets = queue.create()
		self.text_packets = queue.create()
	
	async def __aenter__(self): return self
	async def __aexit__(self, typ, exc, tb):
		await self.stop()
		
	async def start_handshake(self, host, path, protocols):
		await self.client.start_handshake(host, path, protocols)
		await self.group.spawn(self.process)
		
	async def accept_handshake(self, path, protocol):
		if await self.client.accept_handshake(path, protocol):
			await self.group.spawn(self.process)
			return True
		return False
		
	async def process(self):
		while True:
			try:
				packet = await self.client.recv()
			except anyio.ClosedResourceError:
				await self.stop()
				return
			await self.process_packet(packet.opcode, packet.payload)
	
	async def process_packet(self, opcode, payload):
		if opcode == OPCODE_BINARY:
			await self.binary_packets.put(payload)
		elif opcode == OPCODE_TEXT:
			await self.text_packets.put(payload.decode())
		elif opcode == OPCODE_PING:
			await self.client.send(OPCODE_PONG, payload)
		elif opcode == OPCODE_DISCONNECT:
			await self.client.send(OPCODE_DISCONNECT)
			await self.stop()
		else:
			raise ValueError("WS packet has unknown opcode: %i" %opcode)
	
	async def stop(self):
		await self.binary_packets.close()
		await self.text_packets.close()
		
	async def close(self):
		logger.debug("Closing WS connection")
		await self.stop()
		try:
			await self.client.send(OPCODE_DISCONNECT)
		except BrokenPipeError:
			pass
		logger.debug("WS connection is closed")
			
	async def send(self, data):
		await self.client.send(OPCODE_BINARY, data)
	async def send_text(self, text):
		await self.client.send(OPCODE_TEXT, text.encode())

	async def recv(self):
		return await self.binary_packets.get()
	async def recv_text(self):
		return await self.text_packets.get()
		
	def local_address(self): return self.client.local_address()
	def remote_address(self): return self.client.remote_address()
	def remote_certificate(self): return self.client.remote_certificate()


@contextlib.asynccontextmanager
async def connect(url, context=None, *, protocols=None):
	logger.debug("Connecting WS client to %s", url)
	
	scheme, host, port, path = util.parse_url(url)
		
	if scheme == "ws":
		context = None
	elif scheme == "wss":
		if context is None:
			context = tls.TLSClientContext()
	elif scheme is not None:
		raise ValueError("Invalid WS url scheme: %s" %scheme)
	
	if path is None:
		path = "/"
	
	server = util.make_url(None, host, port, None)
	async with http.connect(server, context) as client:
		async with util.create_task_group() as group:
			client = WebSocketClient(client, group)
			async with client:
				await client.start_handshake(host, path, protocols)
				yield client
				await client.close()
	
	logger.debug("WS client is closed")

@contextlib.asynccontextmanager
async def serve(handler, host="", port=0, context=None, *, path="/", protocol=None):
	async def handle(client):
		host, port = client.remote_address()
		logger.debug("New WS connection: %s:%i", host, port)
		
		async with util.create_task_group() as group:
			async with WebSocketClient(client, group) as client:
				if await client.accept_handshake(path, protocol):
					await handler(client)
					await client.close()
	
	logger.info("Starting WS server at %s:%i", host, port)
	async with tls.serve(handle, host, port, context):
		yield
	logger.info("WS server is closed")
