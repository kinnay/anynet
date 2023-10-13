
from anynet import tls
import pytest
import ssl


NAME = "localhost"
IP = "127.0.0.1"


def test_constants():
	assert tls.TYPE_DER == 0
	assert tls.TYPE_PEM == 1


@pytest.mark.anyio
async def test_tls():
	async def handler(client):
		assert await client.recv() == b"hi"
		await client.send(b"hello")

	# Create a self signed certificate
	pkey = tls.TLSPrivateKey.generate()
	cert = tls.TLSCertificate.generate(pkey)
	cert.subject["CN"] = NAME
	cert.issuer["CN"] = NAME
	cert.sign(pkey)
	
	context = tls.TLSContext()
	context.set_certificate(cert, pkey)
	async with tls.serve(handler, IP, 12345, context):
		context = tls.TLSContext()
		context.set_authority(cert)
		async with tls.connect(NAME, 12345, context) as client:
			assert client.remote_address() == (IP, 12345)
			
			await client.send(b"hi")
			assert await client.recv() == b"hello"


@pytest.mark.anyio
async def test_handshake_failure():
	async def handler(client):
		assert await client.recv() == b"hi"
		await client.send(b"hello")
	
	pkey = tls.TLSPrivateKey.generate()
	cert = tls.TLSCertificate.generate(pkey)
	cert.subject["CN"] = NAME
	cert.issuer["CN"] = NAME
	cert.sign(pkey)
	
	context = tls.TLSContext()
	context.set_certificate(cert, pkey)
	async with tls.serve(handler, IP, 12345, context):
		context = tls.TLSContext()
		with pytest.raises(ssl.SSLCertVerificationError):
			async with tls.connect(NAME, 12345, context) as client:
				pass
		
		context.set_authority(cert)
		async with tls.connect(NAME, 12345, context) as client:
			await client.send(b"hi")
			assert await client.recv() == b"hello"
