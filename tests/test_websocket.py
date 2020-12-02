
from anynet import websocket
import pytest


@pytest.mark.anyio
async def test_websocket():
	async def handler(client):
		assert await client.recv() == b"hi"
		await client.send(b"hello")
	
	async with websocket.serve(handler, "localhost", 12345):
		async with websocket.connect("ws://localhost:12345") as client:
			await client.send(b"hi")
			assert await client.recv() == b"hello"


@pytest.mark.anyio
async def test_text():
	async def handler(client):
		assert await client.recv_text() == "hi"
		await client.send_text("hello")
	
	async with websocket.serve(handler, "localhost", 12345):
		async with websocket.connect("ws://localhost:12345") as client:
			await client.send_text("hi")
			assert await client.recv_text() == "hello"
