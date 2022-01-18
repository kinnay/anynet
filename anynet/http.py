
from anynet import tls, util, xml, scheduler
from multidict import MultiDict, CIMultiDict
import urllib.parse
import contextlib
import datetime
import anyio
import json

import logging
logger = logging.getLogger(__name__)


STATUS_NAMES = {
	100: "Continue",
	101: "Switching Protocols",
	102: "Processing",
	103: "Early Hints",
	200: "OK",
	201: "Created",
	202: "Accepted",
	203: "Non-Authoritative Information",
	204: "No Content",
	205: "Reset Content",
	206: "Partial Content",
	207: "Multi-Status",
	208: "Already Reported",
	226: "IM Used",
	300: "Multiple Choices",
	301: "Moved Permanently",
	302: "Found",
	303: "See Other",
	304: "Not Modified",
	305: "Use Proxy",
	307: "Temporary Redirect",
	308: "Permanent Redirect",
	400: "Bad Request",
	401: "Unauthorized",
	402: "Payment Required",
	403: "Forbidden",
	404: "Not Found",
	405: "Method Not Allowed",
	406: "Not Acceptable",
	407: "Proxy Authentication Required",
	408: "Request Timeout",
	409: "Conflict",
	410: "Gone",
	411: "Length Required",
	412: "Precondition Failed",
	413: "Payload Too Large",
	414: "URI Too Long",
	415: "Unsupported Media Type",
	416: "Range Not Satisfiable",
	417: "Expectation Failed",
	421: "Misdirected Request",
	422: "Unprocessable Content",
	423: "Locked",
	424: "Failed Dependency",
	425: "Too Early",
	426: "Upgrade Required",
	428: "Precondition Required",
	429: "Too Many Requests",
	431: "Request Header Fields Too Large",
	451: "Unavailable For Legal Reasons",
	500: "Internal Server Error",
	501: "Not Implemented",
	502: "Bad Gateway",
	503: "Service Unavailable",
	504: "Gateway Timeout",
	505: "HTTP Version Not Supported",
	506: "Variant Also Negotiates",
	507: "Insufficient Storage",
	508: "Loop Detected",
	510: "Not Extended",
	511: "Network Authentication Required"
}


XML_TYPES = [
	"application/xml",
	"text/xml"
]

TEXT_TYPES = [
	"application/json",
	"application/x-www-form-urlencoded",
	"application/xml"
]


class HTTPError(Exception): pass

class HTTPResponseError(HTTPError):
	def __init__(self, response):
		self.response = response
	
	def __str__(self):
		return "HTTP request failed: %i (%s)" %(self.response.status_code, self.response.status_name)


def parse_date(text):
	dt = datetime.datetime.strptime(text, "%a, %d %b %Y %H:%M:%S GMT")
	return dt.replace(tzinfo=datetime.timezone.utc)

def format_date(date):
	date = date.astimezone(datetime.timezone.utc)
	return date.strftime("%a, %d %b %Y %H:%M:%S GMT")

def current_date():
	return format_date(datetime.datetime.now())


def urlencode(data):
	return urllib.parse.quote(data)
def urldecode(data):
	return urllib.parse.unquote(data)

def formencode(data, url=True):
	fields = []
	for key, value in data.items():
		if value is None:
			if url:
				key = urlencode(str(key))
			fields.append(key)
		else:
			if url:
				key = urlencode(str(key))
				value = urlencode(str(value))
			fields.append("%s=%s" %(key, value))
	return "&".join(fields)

def formdecode(data, url=True):
	if not data: return MultiDict()
	
	fields = MultiDict()
	for field in data.split("&"):
		if "=" in field:
			key, value = field.split("=", 1)
			if url:
				key = urldecode(key)
				value = urldecode(value)
			fields[key] = value
		else:
			key = field
			if url:
				key = urldecode(key)
			fields[key] = None
	return fields


def parseheader(header):
	fields = header.split(";")
	type = fields[0].strip()
	
	param = {}
	for field in fields[1:]:
		field = field.strip()
		if not "=" in field:
			raise HTTPError("Malformed parameter in header")
		
		key, value = field.split("=", 1)
		if value.startswith('"'):
			if not value.endswith('"'):
				raise HTTPError("Malformed parameter in header")
			value = value[1:-1]
		
		param[key] = value
	return type, param


class HTTPMessage:
	def __init__(self):
		self.version = "HTTP/1.1"
	
		self.headers = CIMultiDict()
		self.body = b""
		
		self.rawform = None
		self.form = None
		self.json = None
		self.xml = None
		self.files = None
		self.text = None
		
		self.boundary = "--------BOUNDARY--------"
		
	def check_version(self):
		if not self.version.startswith("HTTP/"):
			raise HTTPError("HTTP version must start with HTTP/")
		if self.version not in ["HTTP/1.0", "HTTP/1.1"]:
			raise HTTPError("HTTP version not supported")
	
	def transfer_encodings(self):
		encoding = self.headers.get("Transfer-Encoding", "identity")
		return [enc.strip() for enc in encoding.split(",")]
	
	def is_chunked(self):
		return "chunked" in self.transfer_encodings()
		
	def parse_body(self):
		type, param = parseheader(self.headers.get("Content-Type", ""))
		
		is_json = type == "application/json" or type.endswith("+json")
		is_xml = type in XML_TYPES or type.endswith("+xml")
		is_text = type in TEXT_TYPES or type.startswith("text/") or is_json or is_xml
		
		if is_text:
			try:
				self.text = self.body.decode(param.get("charset", "UTF-8"))
			except UnicodeDecodeError:
				raise HTTPError("Failed to decode HTTP body")
		
		if type == "application/x-www-form-urlencoded":
			self.form = formdecode(self.text)
			self.rawform = formdecode(self.text, False)
		
		if is_json:
			try:
				self.json = json.loads(self.text)
			except json.JSONDecodeError:
				raise HTTPError("Failed to decode JSON body")
		
		if is_xml:
			try:
				self.xml = xml.parse(self.text)
			except ValueError as e:
				raise HTTPError("Failed to decode XML body: %s" %e)
		
		if type.startswith("multipart/form-data"):
			if "boundary" not in param:
				raise HTTPError("multipart/form-data required boundary parameter")
			self.boundary = param["boundary"]
			self.files = self.parse_files(self.body)
	
	def parse_files(self, data):
		split = b"--%s" %self.boundary.encode()
		parts = data.split(split)
		
		if parts[-1] != b"--\r\n" or parts[0] != b"":
			raise HTTPError("Failed to decode multipart body")
		
		files = MultiDict()
		for part in parts[1:-1]:
			if part[:2] != b"\r\n" or part[-2:] != b"\r\n":
				raise HTTPError("Failed to decode multipart body")
			part = part[2:-2]
			
			if not b"\r\n\r\n" in part:
				raise HTTPError("Failed to decode multipart body")
			
			head, body = part.split(b"\r\n\r\n", 1)
			try:
				lines = head.decode().split("\r\n")
			except UnicodeDecodeError:
				raise HTTPError("Failed to decode multipart body")
			
			headers = {}
			for header in lines:
				if not ": " in header:
					raise HTTPError("Invalid line in multipart headers")
				key, value = header.split(": ", 1)
				headers[key] = value
			
			if "Content-Disposition" not in headers:
				raise HTTPError("Expected Content-Disposition header in multipart data")
				
			type, param = parseheader(headers["Content-Disposition"])
			if type != "form-data":
				raise HTTPError("Expected form-data header in multipart data")
			
			if "name" not in param:
				raise HTTPError("Expected name parameter in Content-Disposition header")
			files[param["name"]] = body
				
		return files
		
	def encode_body(self):
		text = self.text
		body = self.body
		
		if self.rawform is not None:
			if "Content-Type" not in self.headers:
				self.headers["Content-Type"] = "application/x-www-form-urlencoded"
			text = formencode(self.rawform, False)
		
		elif self.form is not None:
			if "Content-Type" not in self.headers:
				self.headers["Content-Type"] = "application/x-www-form-urlencoded"
			text = formencode(self.form)
		
		elif self.json is not None:
			if "Content-Type" not in self.headers:
				self.headers["Content-Type"] = "application/json"
			text = json.dumps(self.json)
			
		elif self.xml is not None:
			if "Content-Type" not in self.headers:
				self.headers["Content-Type"] = "application/xml"
			text = self.xml.encode()
			
		elif self.files is not None:
			if "Content-Type" not in self.headers:
				self.headers["Content-Type"] = "multipart/form-data"
			self.headers["Content-Type"] += "; boundary=%s" %self.boundary
			
			text = None
			body = b""
			for name, data in self.files.items():
				name = name.replace('"', '\\"')
				body += b"--%s\r\n" %self.boundary.encode()
				body += b"Content-Disposition: form-data; name=\"%s\"\r\n\r\n" %name.encode()
				body += data + b"\r\n"
			body += b"--%s--\r\n" %self.boundary.encode()
		
		if text is not None:
			if "Content-Type" not in self.headers:
				self.headers["Content-Type"] = "text/plain"
			body = text.encode()
		
		if body and "Content-Type" not in self.headers:
			self.headers["Content-Type"] = "application/octet-stream"
		
		if self.is_chunked():
			if not body:
				return b"0\r\n\r\n"
			return b"%x\r\n" %len(body) + body + b"\r\n0\r\n\r\n"
		else:
			if body:
				self.headers["Content-Length"] = len(body)
			return body
	
	def encode_start_line(self):
		raise NotImplementedError("%s.encode_start_line" %self.__class__.__name__)
	
	def encode_headers(self):
		self.encode_body()
		
		lines = [self.encode_start_line()]
		for key, value in self.headers.items():
			lines.append("%s: %s" %(key, value))
		
		text = "\r\n".join(lines) + "\r\n\r\n"
		return text.encode()
	
	def encode(self):
		return self.encode_headers() + self.encode_body()
	
	@classmethod
	def parse(cls, data, head=False):
		parser = HTTPParser(cls, head)
		parser.update(data)
		parser.eof()
		
		if parser.buffer:
			raise HTTPError("Got more data than expected")
		
		return parser.message


class HTTPRequest(HTTPMessage):
	def __init__(self):
		super().__init__()
		self.method = "GET"
		self.path = "/"
		
		self.params = None
		self.continue_threshold = 1024
	
	def check_path(self):
		if "?" in self.path:
			self.path, params = self.path.split("?", 1)
			self.params = formdecode(params)
		
	def encode_start_line(self):
		path = self.path
		if self.params is not None:
			path += "?" + formencode(self.params)
		return "%s %s %s" %(self.method, path, self.version)
	
	def parse_start_line(self, line):
		fields = line.split(maxsplit=2)
		if len(fields) != 3:
			raise HTTPError("Failed to parse HTTP request start line")
		
		self.method = fields[0]
		self.path = fields[1]
		self.version = fields[2]
		
		self.check_version()
		self.check_path()
		
	def encode_body(self):
		body = super().encode_body()
		if self.continue_threshold is not None:
			if len(body) > self.continue_threshold:
				self.headers["Expect"] = "100-continue"
		return body
	
	@classmethod
	def build(cls, method, path):
		params = None
		if "?" in path:
			path, data = path.split("?", 1)
			params = formdecode(data)
		
		request = cls()
		request.method = method
		request.path = path
		request.params = params
		return request
		
	@classmethod
	def get(cls, path):
		return cls.build("GET", path)
	@classmethod
	def post(cls, path):
		return cls.build("POST", path)
	@classmethod
	def put(cls, path):
		return cls.build("PUT", path)
	@classmethod
	def patch(cls, path):
		return cls.build("PATCH", path)
	@classmethod
	def delete(cls, path):
		return cls.build("DELETE", path)


class HTTPResponse(HTTPMessage):
	def __init__(self, status_code=500):
		super().__init__()
		self.status_code = status_code
		self.status_name = STATUS_NAMES.get(status_code, "Unknown")
		self.upgrade = None
	
	def success(self):
		return self.status_code // 100 == 2
		
	def error(self):
		return not self.success()
	
	def raise_if_error(self):
		if self.error():
			raise HTTPResponseError(self)
		
	def encode_start_line(self):
		return "%s %i %s" %(self.version, self.status_code, self.status_name)
		
	def parse_start_line(self, line):
		fields = line.split(maxsplit=2)
		if len(fields) not in [2, 3]:
			raise HTTPError("Failed to parse HTTP response start line")
		
		self.version = fields[0]
		self.check_version()
		
		if not fields[1].isdecimal():
			raise HTTPError("HTTP response has invalid status code")
		
		self.status_code = int(fields[1])
		
		self.status_name = ""
		if len(fields) == 3:
			self.status_name = fields[2]
		

class HTTPParser:
	def __init__(self, cls, head):
		self.message = cls()
		self.head = head
		
		self.buffer = b""
		self.state = self.state_header
	
	def complete(self): return self.state is None
	def header_complete(self): return self.state != self.state_header
	
	def update(self, data):
		self.buffer += data
		while not self.state():
			pass

	def eof(self):
		if self.state != self.state_body:
			raise HTTPError("Got unexpected EOF while parsing HTTP message")
		self.finish()
	
	def finish(self):
		self.message.parse_body()
		self.state = None
	
	def is_head(self):
		if self.head: return True
		if isinstance(self.message, HTTPResponse):	
			if self.message.status_code // 100 == 1: return True
			if self.message.status_code in [204, 304]: return True
		return False
	
	def state_header(self):
		if not b"\r\n\r\n" in self.buffer:
			return True
		
		header, self.buffer = self.buffer.split(b"\r\n\r\n", 1)
		
		try:
			lines = header.decode().split("\r\n")
		except UnicodeDecodeError:
			raise HTTPError("Failed to decode HTTP header")
			
		if len(lines) == 0:
			raise HTTPError("HTTP message must start with header line")
		
		self.message.parse_start_line(lines[0])
		
		for header in lines[1:]:
			if not ": " in header:
				raise HTTPError("Invalid line in HTTP headers")
			key, value = header.split(": ", 1)
			self.message.headers[key] = value
		
		if self.is_head():
			self.state = None
			return True
		
		if self.message.is_chunked():
			self.state = self.state_chunk_header
			return False
		elif "Content-Length" in self.message.headers:
			if not self.message.headers["Content-Length"].isdecimal():
				raise HTTPError("Invalid Content-Length header")
			self.state = self.state_fixed_body
			return False
		elif isinstance(self.message, HTTPResponse):
			self.state = self.state_body
			return False
		
		self.finish()
		return True
	
	def state_chunk_header(self):
		if not b"\r\n" in self.buffer:
			return True
			
		line, self.buffer = self.buffer.split(b"\r\n", 1)
		try:
			line = line.decode()
		except UnicodeDecodeError:
			raise HTTPError("Failed to decode chunk length")

		if not util.is_hexadecimal(line):
			raise HTTPError("Invalid HTTP chunk length")
		
		self.chunk_length = int(line, 16)
		
		self.state = self.state_chunk_body
		return False
		
	def state_chunk_body(self):
		if len(self.buffer) < self.chunk_length + 2:
			return True
			
		if self.buffer[self.chunk_length : self.chunk_length + 2] != b"\r\n":
			raise HTTPError("HTTP chunk should be terminated with \\r\\n")
		
		self.message.body += self.buffer[:self.chunk_length]
		
		self.buffer = self.buffer[self.chunk_length + 2:]
		
		if self.chunk_length == 0:
			self.finish()
			return True
			
		self.state = self.state_chunk_header
		return False
		
	def state_fixed_body(self):
		length = int(self.message.headers["Content-Length"])
		if len(self.buffer) < length:
			return True
			
		self.message.body = self.buffer[:length]
		self.buffer = self.buffer[length:]
		self.finish()
		return True
	
	def state_body(self):
		self.message.body += self.buffer
		self.buffer = b""
		return True


class HTTPClient:
	def __init__(self, sock):
		self.sock = sock
		self.buffer = b""
	
	async def send(self, data):
		await self.sock.send(data)
	
	async def recv(self):
		if self.buffer:
			buffer = self.buffer
			self.buffer = b""
			return buffer
		return await self.sock.recv()
	
	async def request(self, req, *, headerfunc=None, writefunc=None):
		logger.debug("Sending HTTP request headers")
		await self.send(req.encode_headers())
		
		if req.headers.get("Expect") == "100-continue":
			logger.debug("Waiting for 100-continue")
			response = await self.receive_response(True)
			if response.status_code != 100:
				raise HTTPError("Expected 100-continue response")
		
		body = req.encode_body()
		if body:
			logger.debug("Sending HTTP request body")
			await self.send(req.encode_body())
		
		response = await self.receive_response(req.method == "HEAD", headerfunc, writefunc)
		return response
			
	async def receive_response(self, head, headerfunc=None, writefunc=None):
		parser = HTTPParser(HTTPResponse, head)
		
		while not parser.header_complete():
			parser.update(await self.recv())
		
		if headerfunc:
			await headerfunc(parser.message)
		
		if writefunc:
			if parser.message.body:
				await writefunc(parser.message.body)
			offset = len(parser.message.body)
		
		while not parser.complete():
			try:
				parser.update(await self.recv())
			except util.StreamError:
				parser.eof()
			
			if writefunc and len(parser.message.body) > offset:
				await writefunc(parser.message.body[offset:])
				offset = len(parser.message.body)
		
		self.buffer += parser.buffer
		return parser.message
	
	def local_address(self):
		return self.sock.local_address()
	def remote_address(self):
		return self.sock.remote_address()
	def remote_certificate(self):
		return self.sock.remote_certificate()
		
		
class HTTPServerClient:
	def __init__(self, handler, client):
		self.handler = handler
		self.client = client
	
	async def process(self):
		try:
			parser = HTTPParser(HTTPRequest, False)
			while not parser.header_complete():
				data = await self.client.recv()
				parser.update(data)
			
			if parser.message.headers.get("Expect") == "100-continue":
				await self.client.send(HTTPResponse(100).encode())
			
			while not parser.complete():
				data = await self.client.recv()
				parser.update(data)
			
			response = await self.handle_request(parser.message)
			
			logger.info("Sending HTTP response (%i)", response.status_code)
			await self.client.send(response.encode())
			
			if response.upgrade:
				await response.upgrade()
		except Exception:
			logger.exception("Failed to process HTTP request")
	
	async def handle_request(self, request):
		logger.info("Received HTTP request: %s %s", request.method, request.path)
		
		try:
			response = await self.handler(self.client, request)
			if not isinstance(response, HTTPResponse):
				logger.error("HTTP handler must return HTTPResponse")
				response = HTTPResponse(500)
		except Exception:
			logger.exception("HTTP handler raised an exception")
			response = HTTPResponse(500)
		
		return response
		
		
class HTTPRoute:
	def __init__(self, router, path):
		self.router = router
		self.path = path
	
	def __enter__(self): return self
	def __exit__(self, typ, val, tb):
		self.router.remove(self.path)
		
		
class HTTPRouter:
	def __init__(self):
		self.routes = {}

	def route(self, path, handler):
		if path in self.routes:
			raise ValueError("Path is already routed")
		
		self.routes[path] = handler
		return HTTPRoute(self, path)
	
	def remove(self, path):
		del self.routes[path]
	
	async def handle(self, client, request):
		if request.path not in self.routes:
			logger.warning("HTTP router received unmapped request: %s" %request.path)
			return HTTPResponse(404)
		
		handler = self.routes[request.path]
		return await handler(client, request)
		

@contextlib.asynccontextmanager
async def connect(url, context=None):
	scheme, host, port, path = util.parse_url(url)
	
	if scheme == "http":
		context = None
	elif scheme == "https":
		if context is None:
			context = tls.TLSContext()
	elif scheme is not None:
		raise ValueError("Invalid HTTP url scheme: %s" %scheme)
	
	if path is not None:
		raise ValueError("URL must not contain a path")
	
	if port is None:
		port = 443 if context else 80
	
	logger.debug("Establishing HTTP connection with %s:%i", host, port)
	async with tls.connect(host, port, context) as client:
		yield HTTPClient(client)

async def request(url, req, context=None, **kwargs):
	logger.info("Performing HTTP request: %s %s", req.method, req.path)
	async with connect(url, context) as client:
		response = await client.request(req, **kwargs)
	logger.info("Received HTTP response: %i", response.status_code)
	return response

REQUEST_ARGS = [
	"headers", "body", "text", "files", "boundary", "form",
	"rawform", "json", "xml", "params", "continue_threshold"
]

async def call(url, method, **kwargs):
	scheme, host, port, path = util.parse_url(url)
	if path is None:
		path = "/"
	
	req = HTTPRequest.build(method, path)
	
	for var in REQUEST_ARGS:
		if var in kwargs:
			setattr(req, var, kwargs.pop(var))
	
	if "Host" not in req.headers:
		req.headers["Host"] = util.make_url(None, host, port, None)
	
	url = util.make_url(scheme, host, port, None)
	return await request(url, req, **kwargs)

async def get(url, **kwargs): return await call(url, "GET", **kwargs)
async def post(url, **kwargs): return await call(url, "POST", **kwargs)
async def put(url, **kwargs): return await call(url, "PUT", **kwargs)
async def patch(url, **kwargs): return await call(url, "PATCH", **kwargs)
async def delete(url, **kwargs): return await call(url, "DELETE", **kwargs)

@contextlib.asynccontextmanager
async def serve(handler, host="", port=0, context=None):
	async def handle(client):
		host, port = client.remote_address()
		logger.debug("New HTTP connection: %s:%i", host, port)
		
		client = HTTPServerClient(handler, client)
		await client.process()
	
	logger.info("Starting HTTP server at %s:%i", host, port)
	async with tls.serve(handle, host, port, context):
		yield
	logger.info("HTTP server is closed")

@contextlib.asynccontextmanager
async def serve_router(host="", port=0, context=None):
	router = HTTPRouter()
	async with serve(router.handle, host, port, context):
		yield router
