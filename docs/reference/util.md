
# Module: <code>anynet.util</code>

Provides useful functions that didn't fit into another module.

<code>**StreamError**: tuple = (
    anyio.EndOfStream,
    anyio.ClosedResourceError,
    anyio.BrokenResourceError
)</code>

<code>**def is_decimal**(s: str) -> bool</code><br>
<span class="docs">Returns `True` if `s` is non-empty and only contains decimal digits.</span>

<code>**def is_hexadecimal**(s: str) -> bool</code><br>
<span class="docs">Returns `True` if `s` is non-empty and only contains hexadecimal digits.</span>

<code>**def ip_to_hex**(ip: str) -> int</code><br>
<span class="docs">Converts an IPv4 address string to an integer in big-endian byte order. Raises `ValueError` if the IP address is invalid.</span>

<code>**def ip_from_hex**(value: int) -> str</code><br>
<span class="docs">Converts an integer to an IPv4 address string in big-endian byte order.</span>

<code>**def local_address**() -> str</code><br>
<span class="docs">Returns the local IPv4 address of the default gateway. Raises `ConnectionError` if no IPv4 interface was found.</span>

<code>**def broadcast_address**() -> str</code><br>
<span class="docs">Returns the IPv4 broadcast address of the default gateway. Raises `ConnectionError` if no IPv4 interface was found.</span>

<code>**def parse_url**(url: str) -> tuple[str, str, int, str]</code><br>
<span class="docs">Parses the given URL and returns the tuple `(scheme, host, port, path)`. The `scheme`, `port` and `path` are set to `None` if they are not in the URL. Raises `ValueError` if the URL is invalid.</span>

<code>**def make_url**(scheme: str, host: str, port: int, path: str) -> str</code><br>
<span class="docs">Creates a URL string from the given parameters. `scheme`, `port` and `path` may be set to `None`.</span>
