
from OpenSSL import crypto
from anynet import util
import contextlib
import tempfile
import anyio
import ssl
import os

import logging
logger = logging.getLogger(__name__)


TYPE_DER = 0
TYPE_PEM = 1

VERSION_TLS = 0
VERSION_TLS11 = 1
VERSION_TLS12 = 2

TypeMap = {
	TYPE_DER: crypto.FILETYPE_ASN1,
	TYPE_PEM: crypto.FILETYPE_PEM
}

VersionMap = {
	VERSION_TLS: ssl.PROTOCOL_TLS,
	VERSION_TLS11: ssl.PROTOCOL_TLSv1_1,
	VERSION_TLS12: ssl.PROTOCOL_TLSv1_2
}


def set_certificate(context, cert, key):
	certfile = tempfile.NamedTemporaryFile(delete=False)
	keyfile = tempfile.NamedTemporaryFile(delete=False)
	
	certfile.write(cert.encode(TYPE_PEM))
	keyfile.write(key.encode(TYPE_PEM))
	
	certfile.close()
	keyfile.close()
	
	context.load_cert_chain(certfile.name, keyfile.name)
	
	os.remove(certfile.name)
	os.remove(keyfile.name)


class X509Name:
	ITEMS = {
		"C": "country_name",
		"ST": "state_or_province_name",
		"L": "locality_name",
		"O": "organization_name",
		"OU": "organizational_unit_name",
		"CN": "common_name",
		"E": "email_address"
	}
	
	ATTRS = {
		"country_name": "countryName",
		"state_or_province_name": "stateOrProvinceName",
		"locality_name": "localityName",
		"organization_name": "organizationName",
		"organizational_unit_name": "organizationalUnitName",
		"common_name": "commonName",
		"email_address": "emailAddress"
	}
	
	def __init__(self):
		self.obj = crypto.X509().get_subject()
	
	def __getitem__(self, key):
		return getattr(self, self.ITEMS[key])
	def __setitem__(self, key, value):
		setattr(self, self.ITEMS[key], value)
		
	def __getattr__(self, name):
		return getattr(self.__dict__["obj"], X509Name.ATTRS[name])
	def __setattr__(self, name, value):
		if name == "obj":
			self.__dict__["obj"] = value
		else:
			setattr(self.obj, X509Name.ATTRS[name], value)


class TLSCertificate:
	def __init__(self, obj):
		self.obj = obj
		self.subject = X509Name()
		self.subject.obj = obj.get_subject()
		self.issuer = X509Name()
		self.issuer.obj = obj.get_issuer()
		
	def public_key(self):
		pkey = self.obj.get_pubkey()
		rsakey = pkey.to_cryptography_key()
		return rsakey.public_numbers()
		
	def encode(self, format):
		return crypto.dump_certificate(TypeMap[format], self.obj)
		
	def save(self, filename, format):
		with open(filename, "wb") as f:
			f.write(self.encode(format))
		
	def sign(self, key, alg="sha256"):
		self.obj.sign(key.obj, alg)
	
	@classmethod
	def load(cls, filename, format):
		with open(filename, "rb") as f:
			data = f.read()
		return cls.parse(data, format)
		
	@classmethod
	def parse(cls, data, format):
		cert = crypto.load_certificate(TypeMap[format], data)
		return cls(cert)
		
	@classmethod
	def generate(cls, key):
		cert = crypto.X509()
		cert.set_pubkey(key.obj)
		
		cert.set_notBefore(b"20000101000000Z")
		cert.set_notAfter(b"29990101000000Z")
		
		return cls(cert)

	
class TLSPrivateKey:
	def __init__(self, obj):
		self.obj = obj
		
	def encode(self, format):
		return crypto.dump_privatekey(TypeMap[format], self.obj)
	
	def save(self, filename, format):
		with open(filename, "wb") as f:
			f.write(self.encode(format))
	
	@classmethod
	def load(cls, filename, format):
		with open(filename, "rb") as f:
			data = f.read()
		return cls.parse(data, format)
		
	@classmethod
	def parse(cls, data, format):
		pkey = crypto.load_privatekey(TypeMap[format], data)
		return cls(pkey)
		
	@classmethod
	def generate(cls, size=2048):
		pkey = crypto.PKey()
		pkey.generate_key(crypto.TYPE_RSA, size)
		return cls(pkey)


class TLSClientContext:
	def __init__(self, version=VERSION_TLS):
		self.version = version
		self.authority = None
		self.cert = None
		self.key = None

	def set_certificate(self, cert, key):
		self.cert = cert
		self.key = key
	
	def set_authority(self, authority):
		self.authority = authority
	
	def get(self):
		context = ssl.SSLContext(VersionMap[self.version])
		if self.cert and self.key:
			set_certificate(context, self.cert, self.key)
		
		context.verify_mode = ssl.CERT_REQUIRED
		if self.authority:
			data = self.authority.encode(TYPE_DER)
			context.load_verify_locations(cadata=data)
		else:
			context.load_default_certs()
		
		context.check_hostname = True
		return context

		
class TLSServerContext:
	def __init__(self, version=VERSION_TLS):
		self.version = version
		self.authority = None
		self.cert = None
		self.key = None

	def set_certificate(self, cert, key):
		self.cert = cert
		self.key = key
	
	def set_authority(self, authority):
		self.authority = authority
	
	def get(self):
		context = ssl.SSLContext(VersionMap[self.version])
		if self.cert and self.key:
			set_certificate(context, self.cert, self.key)
		else:
			raise ValueError("Please provide a server certificate")
		
		context.verify_mode = ssl.CERT_NONE
		if self.authority:
			data = self.authority.encode(TYPE_DER)
			context.load_verify_locations(cadata=data)
			context.verify_mode = ssl.CERT_REQUIRED

		context.check_hostname = False
		return context


class TLSClient:
	def __init__(self, stream):
		self.stream = stream
		self.lock = anyio.create_lock()
		
	async def send(self, data):
		async with self.lock:
			await self.stream.send(data)
	async def recv(self, num=65536):
		return await self.stream.receive(num)
	
	def local_address(self):
		return self.stream.extra(anyio.abc.SocketAttribute.local_address)
	def remote_address(self):
		return self.stream.extra(anyio.abc.SocketAttribute.remote_address)
	
	def remote_certificate(self):
		cert = self.stream.extra(anyio.streams.tls.TLSAttribute.peer_certificate_binary, None)
		if cert:
			return TLSCertificate.parse(cert, TYPE_DER)


@contextlib.asynccontextmanager
async def connect(host, port, context=None):
	logger.debug("Connecting TLS client to %s:%s", host, port)
	if context:
		context = context.get()
	async with await anyio.connect_tcp(host, port, ssl_context=context, tls_standard_compatible=False) as stream:
		yield TLSClient(stream)

@contextlib.asynccontextmanager
async def create_listener(host, port, context):
	listener = await anyio.create_tcp_listener(local_host=host, local_port=port)
	async with listener:
		if context:
			listener = anyio.streams.tls.TLSListener(listener, context.get(), False)
			async with listener:
				yield listener
		else:
			yield listener

@contextlib.asynccontextmanager
async def serve(handler, host="", port=0, context=None):
	async def handle(stream):
		async with stream:
			with util.catch(Exception):
				await handler(TLSClient(stream))
			logger.debug("Closing TLS connection")
	
	if not host:
		host = util.local_address()
	
	logger.info("Starting TLS server at %s:%i", host, port)
	async with create_listener(host, port, context) as listener:
		async with util.create_task_group() as group:
			await group.spawn(listener.serve, handle)
			yield
