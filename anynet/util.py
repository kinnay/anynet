
import contextlib
import netifaces
import struct
import socket
import string
import anyio
import math

import logging
logger = logging.getLogger(__name__)


def is_decimal(s):
	return s.isdecimal()

def is_hexadecimal(s):
	return s and all(c in string.hexdigits for c in s)

def ip_to_hex(ip):
	try:
		data = socket.inet_aton(ip)
	except OSError:
		raise ValueError("IP address is invalid")
	return struct.unpack(">I", data)[0]

def ip_from_hex(value):
	return socket.inet_ntoa(struct.pack(">I", value))
	
def local_address():
	interface = netifaces.gateways()["default"][netifaces.AF_INET][1]
	addresses = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]
	return addresses["addr"]
	
def broadcast_address():
	interface = netifaces.gateways()["default"][netifaces.AF_INET][1]
	addresses = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]
	return addresses["broadcast"]

def parse_url(url):
	scheme = None
	if "://" in url:
		scheme, url = url.split("://", 1)
	
	path = None
	if "/" in url:
		url, path = url.split("/", 1)
		path = "/" + path
	
	host = url
	port = None
	if ":" in url:
		host, port = url.split(":", 1)
		port = int(port)
	
	return scheme, host, port, path

def make_url(scheme, host, port, path):
	url = ""
	if scheme is not None:
		url += scheme + "://"
	url += host
	if port is not None:
		url += ":%i" %port
	if path is not None:
		if not path.startswith("/"):
			raise ValueError("Path must start with '/'")
		url += path
	return url

def create_queue():
	send, recv = anyio.create_memory_object_stream(math.inf)
	return anyio.streams.stapled.StapledObjectStream(send, recv)

@contextlib.contextmanager
def catch(cls):
	try:
		yield
	except anyio.ExceptionGroup as e:
		filtered = []
		for exc in e.exceptions:
			if isinstance(exc, cls):
				logger.error("An exception occurred: %r", exc)
			else:
				filtered.append(exc)
		e.exceptions = filtered
		if filtered:
			raise
	except cls as e:
		logger.error("An exception occurred: %r", e)
