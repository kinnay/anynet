
from anynet import util
import pytest

def test_is_decimal():
	assert util.is_decimal("0")
	assert util.is_decimal("0123456789")
	assert util.is_decimal("999999")
	assert not util.is_decimal("")
	assert not util.is_decimal("12345a")
	assert not util.is_decimal("0x12345")
	assert not util.is_decimal("-100")
	assert not util.is_decimal("1.2")

def test_is_hexadecimal():
	assert util.is_hexadecimal("0")
	assert util.is_hexadecimal("ABCDEF")
	assert util.is_hexadecimal("c0a8b2bc")
	assert util.is_hexadecimal("0A1b2C3d")
	assert not util.is_hexadecimal("")
	assert not util.is_hexadecimal("ABCDEFG")
	assert not util.is_hexadecimal("0x12345")
	assert not util.is_hexadecimal("1.2")

def test_ip_to_hex():
	assert util.ip_to_hex("192.168.178.188") == 0xC0A8B2BC
	
	with pytest.raises(ValueError):
		util.ip_to_hex("")
	with pytest.raises(ValueError):
		util.ip_to_hex("192.168.178.256")
	with pytest.raises(ValueError):
		util.ip_to_hex("a.b.c.d")
	with pytest.raises(ValueError):
		util.ip_to_hex("1.1.1.")

def test_ip_from_hex():
	assert util.ip_from_hex(0xC0A8B2BC) == "192.168.178.188"
	
def test_local_address():
	addr = util.local_address()
	util.ip_to_hex(addr) # Raises exception if ip address is invalid

def test_broadcast_address():
	addr = util.local_address()
	util.ip_to_hex(addr) # Raises exception if ip address is invalid

def test_parse_url():
	assert util.parse_url("example.com") == (None, "example.com", None, None)
	assert util.parse_url("https://example.com/test/test.php?x=1") == (
		"https", "example.com", None, "/test/test.php?x=1"
	)
	assert util.parse_url("kdp://example.com:8080/test") == (
		"kdp", "example.com", 8080, "/test"
	)
	
	with pytest.raises(ValueError):
		util.parse_url("example.com:abcd")
		
def test_make_url():
	assert util.make_url(None, "example.com", None, None) == "example.com"
	assert util.make_url("kdp", "example.com", 8080, "/test") == "kdp://example.com:8080/test"
