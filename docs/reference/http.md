
# Module: <code>anynet.http</code>

Provides HTTP-related classes, including a client and a server. Note that this implementation is by no means complete. Only basic HTTP features are supported.

<code>**class** HTTPError(Exception)</code><br>
<span class="docs">General exception for errors related to HTTP.</span>

<code>**class** [HTTPResponseError](#httpresponseerror)(HTTPError)</code><br>
<span class="docs">May be raised when the status code of an HTTP response indicates an error.</span>

<code>**class** [HTTPMessage](#httpmessage)</code><br>
<span class="docs">Base class for HTTP messages. This class should not be instantiated directly. Instead, one of its subclasses should be used.

<code>**class** [HTTPRequest](#httprequest)([HTTPMessage](#httpmessage))</code><br>
<span class="docs">An HTTP request object.</span>

<code>**class** [HTTPResponse](#httpresponse)([HTTPMessage](#httpmessage))</code><br>
<span class="docs">An HTTP response object.</span>

<code>**class** [HTTPClient](#httpclient)</code><br>
<span class="docs">A reusable HTTP client.</span>

<code>**class** [HTTPRouter](#httprouter)</code><br>
<span class="docs">Routes incoming HTTP requests based on the request path.</span>

<code>**async def get**(url: str, \*\*kwargs) -> [HTTPResponse](#httpresponse)</code><br>
<code>**async def post**(url: str, \*\*kwargs) -> [HTTPResponse](#httpresponse)</code><br>
<code>**async def put**(url: str, \*\*kwargs) -> [HTTPResponse](#httpresponse)</code><br>
<code>**async def patch**(url: str, \*\*kwargs) -> [HTTPResponse](#httpresponse)</code><br>
<code>**async def delete**(url: str, \*\*kwargs) -> [HTTPResponse](#httpresponse)</code><br>
<span class="docs">Performs a `GET`, `POST`, `PUT`, `PATCH` or `DELETE` request. These methods are provided for convenience.<br><br>`url` must contain at least the hostname or IP address of the server, and the path of the HTTP request. Scheme and port are optional. Example: `https://example.com:8080/test.html`.<br><br>The following keyword arguments may be provided to initialize the HTTP request: `headers`, `body`, `text`, `files`, `boundary`, `form`, `rawform`, `json`, `xml`, `params`, and `continue_threshold`. If no `Host` header is given it is filled in automatically based on the given `url`.<br><br>Other keyword arguments are passed on to `request()`.</span>

<code>**async def request**(url: str, req: [HTTPRequest](#httprequest), context: [TLSContext](tls.md#tlscontext) = None, \*\*kwargs) -> [HTTPResponse](#httpresponse)</code><br>
<span class="docs">Performs an HTTP request on a new connection.<br><br>`url` must contain at least the hostname or IP address of the server. Scheme and port are optional. Example: `https://example.com:8080`.<br><br>If no scheme is provided, the connection is secured with TLS precisely if a TLS context is provided. If the scheme is `https` but no TLS context is provided the connection is secured with the default TLS context.<br><br>The keyword arguments are forwarded to [`HTTPClient.request`](#httpclient).</span>

<code>**async with connect**(url: str, context: [TLSContext](tls.md#tlscontext) = None) -> [HTTPClient](#httpclient)</code><br>
<span class="docs">Creates a reusable connection with the server. Blocks until the connection is ready. The parameters `url` and `context` have the same meaning as in `request()`.<br><br>[`HTTPClient`](#httpclient) is not task-safe. Do not try to perform multiple request on a single client concurrently.</span>

<code>**async with serve**(handler: Callable, host: str = "", port: int = 0, context: [TLSContext](tls.md#tlscontext) = None) -> None</code><br>
<span class="docs">Creates an HTTP server at the given address. If `host` is empty, the local address of the default gateway is used. If `port` is 0, it is chosen by the operating system. If `context` is provided, the server is secured with TLS.<br><br>
`handler` must be an `async` function that takes a [`TLSClient`](tls.md#tlsclient) and an [`HTTPRequest`](#httprequest) and returns an [`HTTPResponse`](#httpresponse). It's possible to call blocking functions in `handler`, because the HTTP server spawns a new task for each request. If `handler` raises an exception or returns anything other than a [`HTTPResponse`](#httpresponse), the server sends an empty HTTP response with status code `500` to the client.</span>

<code>**async with serve_router**(host: str = "", port: int = 0, context: [TLSContext](tls.md#tlscontext) = None) -> [HTTPRouter](#httprouter)</code><br>
<span class="docs">Creates an HTTP server at the given address. If `host` is empty, the local address of the default gateway is used. If `port` is 0, it is chosen by the operating system. If `context` is provided, the server is secured with TLS.<br><br>A [HTTPRouter](#httprouter) is returned that may be used to attach handlers to request paths.</span>

<code>**def current_date**() -> str</code><br>
<span class="docs">Returns the current date and time in the format of the Date header.</span>

<code>**def format_date**(date: datetime.datetime) -> str</code><br>
<span class="docs">Returns the given datetime in the format of the Date header.</span>

<code>**def parse_date**(text: str) -> datetime.datetime</code><br>
<span class="docs">Parses the given Date header text and returns a datetime object.</span>

<code>**def urlencode**(data: str) -> str</code><br>
<span class="docs">Applies url-encoding on the given string (i.e. replaces special characters by `%XX`).</span>

<code>**def urldecode**(data: str) -> str</code><br>
<span class="docs">Decodes the given url-encoded string.</span>

<code>**def formencode**(data: MultiDict[str, str], url: bool = True) -> str</code><br>
<span class="docs">Encodes `data` using form-encoding. If `url` is `True`, field names and values are url-encoded automatically.</span>

<code>**def formdecode**(data: str, url: bool = True) -> MultiDict[str, str]</code><br>
<span class="docs">Parses a form-encoded string. If `url` is `True`, field names and values are automatically url-decoded.</span>

## HTTPMessage
This is the base class of [`HTTPRequest`](#httprequest) and [`HTTPResponse`](#httpresponse). This class should not be instantiated directly. Instead, one of its subclasses should be used.

This class provides several attributes that define the body of the HTTP message. In general, only one of them should be used. When the HTTP message is encoded, the attributes are evaluated in the following order: `rawform`, `form`, `json`, `xml`, `files`, `text` and `body`. The first attribute that is not `None` defines the body of the HTTP request. The others are ignored.

Most headers are left unchanged when the HTTP message is encoded. However, if no `Content-Type` header is present, a default is chosen based on the attribute that defines the body, unless the body is empty. The `Content-Length` header is always overwritten, unless the `Transfer-Encoding` is `chunked` or the body is empty.

When an HTTP message is parsed, the `body` attribute is always filled in. The other attributes are only filled if they fit the `Content-Type` of the HTTP message.

<code>**version**: str = "HTTP/1.1"</code><br>
<span class="docs">The version of the HTTP message. Only `HTTP/1.1` is supported.</span>

<code>**headers**: CIMultiDict[str, str] = {}</code><br>
<span class="docs">The HTTP headers (case insensitive dictionary).</span>

<code>**body**: bytes = ""</code><br>
<span class="docs">The raw body of the HTTP message. The `Content-Type` defaults to `application/octet-stream`.</span>

<code>**text**: str = None</code><br>
<span class="docs">The decoded body of the HTTP message, if applicable. The `Content-Type` defaults to `text/plain`.</span>

<code>**form**: MultiDict[str, str] = None</code><br>
<span class="docs">The form parameters in the body. The parameters are url-encoded automatically. The `Content-Type` defaults to `application/x-www-form-urlencoded`.</span>

<code>**rawform**: MultiDict[str, str] = None</code><br>
<span class="docs">The form parameters in the body. The difference with the `form` attribute is that the names and values are *not* url-encoded automatically. The `Content-Type` defaults to `application/x-www-form-urlencoded`.</span>

<code>**json**: dict = None</code><br>
<span class="docs">The JSON body. The `Content-Type` defaults to `application/json`.

<code>**xml**: [XMLTree](xml.md#xmltree) = None</code><br>
<span class="docs">An [XMLTree](xml.md#xmltree) that represents the body. The `Content-Type` defaults to `application/xml`.

<code>**files**: MultiDict[str, bytes] = None</code><br>
<span class="docs">A list of binary files. The `Content-Type` defaults to `multipart/form-data`.

<code>**boundary**: str = "--------BOUNDARY--------"</code><br>
<span class="docs">The boundary string that's used if the body is encoded from `files`.</span>

<code>**def encode**() -> bytes</code><br>
<span class="docs">Encodes the HTTP message.</span>

<code>**def encode_headers**() -> bytes</code><br>
<span class="docs">Encodes only the headers of the HTTP message.</span>

<code>**def encode_body**() -> bytes</code><br>
<span class="docs">Encodes only the body of the HTTP message.</span>

<code style="color: blue">@classmethod</code><br>
<code>**def parse**(data: bytes, head: bool = False) -> [`HTTPMessage`](#httpmessage)</code><br>
<span class="docs">Parses an HTTP message. This method should not be called on the [`HTTPMessage`](#httpmessage) class. Instead, it should be called on one of its subclasses. Raises `HTTPError` if the given data does not contain a valid HTTP message. If `head` is `True`, only the headers of the HTTP message are parsed and `data` must not contain the body.</span>

## HTTPRequest
This class inherits [`HTTPMessage`](#httpmessage). During encoding, the `Expect` header is set to `100-continue` if the size of the body exceeds the given threshold.

<code>**method**: str = "GET"</code><br>
<span class="docs">The HTTP method.</span>

<code>**path**: str = "/"</code><br>
<span class="docs">The path of the HTTP request, without the parameters.</span>

<code>**params**: MultiDict[str, str] = None</code><br>
<span class="docs">The GET parameters behind the `path`. The parameters are url-encoded automatically.</span>

<code>**continue_threshold**: int = 1024</code><br>
<span class="docs">The size of the body after which the `Expect` header is set to `100-continue`. If set to `None`, the `Expect` header is never modified, regardless of the body size.

<code>**def _\_init__**()</code><br>
<span class="docs">Creates a new HTTP request.</span>

<code style="color: blue">@classmethod</code><br>
<code>**def get**(path: str) -> [HTTPRequest](#httprequest)</code><br>
<code>**def post**(path: str) -> [HTTPRequest](#httprequest)</code><br>
<code>**def put**(path: str) -> [HTTPRequest](#httprequest)</code><br>
<code>**def patch**(path: str) -> [HTTPRequest](#httprequest)</code><br>
<code>**def delete**(path: str) -> [HTTPRequest](#httprequest)</code><br>
<span class="docs">Creates a `GET`, `POST`, `PUT`, `PATCH` or `DELETE` request with the given path. If the given path contains form parameters, they are parsed and put into `params`.</span>

## HTTPResponse
This class inherits [`HTTPMessage`](#httpmessage).

<code>**status_code**: int</code><br>
<span class="docs">The status code of the HTTP response.</span>

<code>**status_name**: str</code><br>
<span class="docs">The reason string of the HTTP response.</span>

<code>**upgrade**: Callable = None</code><br>
<span class="docs">If set, this async function is called after the HTTP response is sent to the client. Only relevant on the server side.</span>

<code>**def _\_init__**(status_code: int = 500)</code><br>
<span class="docs">Creates a new HTTP response with the given status code. `status_name` is derived from the given status code. If the given status code is not recognized, `status_name` is set to `"Unknown"`</span>

<code>**def success**() -> bool</code><br>
<span class="docs">Returns `True` if the status code indicates success, i.e. if it has the form `2xx`.

<code>**def error**() -> bool</code><br>
<span class="docs">This is the reverse of `success`. Returns `True` if the status code does not indicate success.

<code>**def raise_if_error**() -> None</code><br>
<span class="docs">Raises [HTTPResponseError](#httpresponseerror) if the status code does not indicate success.</span>

## HTTPClient
<code>**async def request**(req: [HTTPRequest](#httprequest), \*, headerfunc: Callable = None, writefunc: Callable = None) -> [HTTPResponse](#httpresponse)</code><br>
<span class="docs">Performs an HTTP request.<br><br>If `headerfunc` is provided, it must be an async function that takes a [`HTTPResponse`](#httpresponse) object. It is called once after all HTTP headers are received.<br><br>If `writefunc` is provided, it must be an async function that takes a `bytes` object. It is called whenever a part of the body is received from the server.</span>

<code>**async def close**() -> None</code><br>
<span class="docs">Closes the connection.</span>

<code>**def local_address**() -> tuple[str, int]</code><br>
<span class="docs">Returns the local address of the client.</span>

<code>**def remote_address**() -> tuple[str, int]</code><br>
<span class="docs">Returns the remote address of the client.</span>

<code>**def remote_certificate**() -> [TLSCertificate](tls.md#tlscertificate)</code><br>
<span class="docs">Returns the certificate that was provided by the other side of the connection. Returns `None` if the connection is not secured with TLS.</span>

## HTTPRouter
<code>**def route**(path: str, handler: Callable)</code><br>
<span class="docs">Attaches `handler` to the given `path`. Incoming requests are routed to `handler` only if the paths are exactly the same. Raises `ValueError` if the given `path` is already in use.<br><br>This method may be called in a `with` statement to remove the handler automatically.</span>

<code>**def remove**(path: str)</code><br>
<span class="docs">Removes the handler that is attached to the given `path`.</span>

## HTTPResponseError
This is a subclass of `HTTPError`.

<code>**response**: [HTTPResponse](#httpresponse)</code><br>
<span class="docs">The HTTP response that caused the error.</span>

<code>**def _\_init__**(response: [HTTPResponse](#httpresponse))</code><br>
<span class="docs">Creates a new [HTTPResponseError](#httpresponseerror) for the given HTTP response.</span>
