
# Module: <code>anynet.tcp</code>

Provides a TCP client and server.

<code>**class** [TCPClient](#tcpclient)</code><br>
<span class="docs">A simple TCP client.</span>

<code>**async with connect**(host: str, port: int) -> [TCPClient](#tcpclient)</code><br>
<span class="docs">Creates a TCP client and connects it to the given address. Blocks until the connection is ready.</span>

<code>**async with serve**(handler: Callable, host: str = "", port: int = 0) -> None</code><br>
<span class="docs">Creates a TCP server and binds it to the given address. If `host` is empty, the local address of the default gateway is used. If `port` is 0, it is chosen by the operating system. `handler` must be an `async` function that accepts a [`TCPClient`](#tcpclient). The client is closed automatically when `handler` returns.</span>

## TCPClient
<code>**async def send**(data: bytes) -> None</code><br>
<span class="docs">Sends data through the connection. Blocks if the send buffer is full.</span>

<code>**async def recv**(num: int = 65536) -> bytes</code><br>
<span class="docs">Receives at most `num` bytes. Blocks if no data is available.</span>

<code>**async def close**() -> None</code><br>
<span class="docs">Closes the connection.</span>

<code>**def local_address**() -> tuple[str, int]</code><br>
<span class="docs">Returns the local address of the client.</span>

<code>**def remote_address**() -> tuple[str, int]</code><br>
<span class="docs">Returns the remote address of the client.</span>
