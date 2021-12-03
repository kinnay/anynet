
from anynet import udp
import pytest


HOST = "127.0.0.1"


@pytest.mark.anyio
async def test_socket():
	async with udp.bind(HOST, 12345) as sock1:
		async with udp.bind(HOST, 12346) as sock2:
			assert sock1.local_address() == (HOST, 12345)
			assert sock2.local_address() == (HOST, 12346)
			
			await sock1.send(b"hi", (HOST, 12346))
			await sock2.send(b"hello", (HOST, 12345))
			assert (await sock1.recv())[0] == b"hello"
			assert (await sock2.recv())[0] == b"hi"


@pytest.mark.anyio
async def test_client():
	async with udp.bind(HOST, 12345) as server:
		async with udp.connect(HOST, 12345) as client:
			assert server.local_address() == (HOST, 12345)
			assert client.remote_address() == (HOST, 12345)
			
			await client.send(b"hi")
			
			data, addr = await server.recv()
			assert data == b"hi"
			
			await server.send(b"hello", addr)
			assert await client.recv() == b"hello"
