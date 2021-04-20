
# Module: <code>anynet.websocket</code>

Provides a client and server for the websocket protocol.

<code>**class** WSError(Exception)</code><br>
<span class="docs">Raised when a websocket error occurs.</span>

<code>**class** [WebSocketClient](#websocketclient)</code><br>
<span class="docs">A websocket client.</span>

<code>**async with connect**(url: str, context: [TLSContext](../tls#tlscontext) = None, *, protocols: list[str] = None) -> [WebSocketClient](#websocketclient)</code><br>
<span class="docs">Creates a websocket client and connects it to the given address. Blocks until the connection is ready and the handshake has been performed.<br><br>`url` must contain at least the hostname or IP address of the server, and the path. Scheme and port are optional. Example: `wss://example.com:8080/test`.<br><br>If no scheme is provided, the connection is secured with TLS precisely if a TLS context is provided. If the scheme is `wss` but no TLS context is provided the connection is secured with the default TLS context.</span>

<code>**async with serve**(handler: Callable, host: str = "", port: int = 0, context: [TLSContext](../tls#tlscontext) = None, *, path: str = "/", protocol: str = None) -> None</code><br>
<span class="docs">Creates a websocket server and binds it to the given address. If `host` is empty, the local address of the default interface is used. If `port` is 0, it is chosen by the operating system. `handler` must be an `async` function that accepts a [`WebSocketClient`](#websocketclient). The client is closed automatically when `handler` returns. If `context` is provided, the server is secured with TLS.</span>

<code>**async with route**(handler: Callable, router: [HTTPRouter](../http#httprouter), path: str, *, protocol: str = None) -> None</code><br>
<span class="docs">Creates a websocket server and binds it to the given path. `handler` must be an `async` function that accepts a [`WebSocketClient`](#websocketclient). The client is closed automatically when `handler` returns.</span>

## WebSocketClient
<code>**async def send**(data: bytes) -> None</code><br>
<span class="docs">Sends a binary packet to the server. Blocks if the send buffer is full.</span>

<code>**async def recv**() -> bytes</code><br>
<span class="docs">Receives a single binary packet from the server. Blocks if no binary data is available.</span>

<code>**async def send_text**(data: str) -> None</code><br>
<span class="docs">Sends a text packet to the server. Blocks if the send buffer is full.</span>

<code>**async def recv_text**() -> str</code><br>
<span class="docs">Receives a single text packet from the server. Blocks if no text data is available.</span>

<code>**def local_address**() -> tuple[str, int]</code><br>
<span class="docs">Returns the local address of the client.</span>

<code>**def remote_address**() -> tuple[str, int]</code><br>
<span class="docs">Returns the address that the client is connected to.</span>
