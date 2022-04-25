
# Module: <code>anynet.websocket</code>

Provides a client and server for the websocket protocol.

<code>**class** WSError(Exception)</code><br>
<span class="docs">Raised when a websocket error occurs.</span>

<code>**class** [WebSocketClient](#websocketclient)</code><br>
<span class="docs">A websocket client.</span>

<code>**async with connect**(url: str, context: [TLSContext](tls.md#tlscontext) = None, *, protocols: list[str] = None, disconnect_timeout: float = None) -> [WebSocketClient](#websocketclient)</code><br>
<span class="docs">Creates a websocket client and connects it to the given address. Blocks until the connection is ready and the handshake has been performed.<br><br>`url` must contain at least the hostname or IP address of the server, and the path. Scheme and port are optional. Example: `wss://example.com:8080/test`.<br><br>If no scheme is provided, the connection is secured with TLS precisely if a TLS context is provided. If the scheme is `wss` but no TLS context is provided the connection is secured with the default TLS context.</span>

<code>**async with serve**(handler: Callable, host: str = "", port: int = 0, context: [TLSContext](tls.md#tlscontext) = None, *, path: str = "/", protocol: str = None, disconnect_timeout: float = None) -> None</code><br>
<span class="docs">Creates a websocket server and binds it to the given address. If `host` is empty, the local address of the default gateway is used. If `port` is 0, it is chosen by the operating system. `handler` must be an `async` function that accepts a [`WebSocketClient`](#websocketclient). When `handler` returns, the closing handshake is started with the given timeout. If `context` is provided, the server is secured with TLS.</span>

<code>**async with route**(handler: Callable, router: [HTTPRouter](http.md#httprouter), path: str, *, protocol: str = None, disconnect_timeout: float = None) -> None</code><br>
<span class="docs">Creates a websocket server and binds it to the given path. `handler` must be an `async` function that accepts a [`WebSocketClient`](#websocketclient). When `handler` returns, the closing handshake is started with the given timeout.</span>

## WebSocketClient
<code>**async def send**(data: bytes) -> None</code><br>
<span class="docs">Sends a binary packet to the server. Blocks if the send buffer is full.</span>

<code>**async def recv**() -> bytes</code><br>
<span class="docs">Receives a single binary packet from the server. Blocks if no binary data is available.</span>

<code>**async def send_text**(data: str) -> None</code><br>
<span class="docs">Sends a text packet to the server. Blocks if the send buffer is full.</span>

<code>**async def recv_text**() -> str</code><br>
<span class="docs">Receives a single text packet from the server. Blocks if no text data is available.</span>

<code>**async def disconnect**() -> None</code><br>
<span class="docs">Closes the connection gracefully by sending a Close frame and waiting for the response. Blocks until the closing handshake is complete. Then closes the underlying TCP connection.</span>

<code>**async def close**() -> None</code><br>
<span class="docs">Closes the underlying TCP connection.</span>

<code>**def local_address**() -> tuple[str, int]</code><br>
<span class="docs">Returns the local address of the client.</span>

<code>**def remote_address**() -> tuple[str, int]</code><br>
<span class="docs">Returns the address that the client is connected to.</span>

<code>**def remote_ceritifcate**() -> [TLSCertificate](#tlscertificate)</code><br>
<span class="docs">Returns the certificate that was provided by the other side of the connection. Returns `None` if the connection is not secured with TLS, or if the other side of the connection did not provide a client certificate.</span>
