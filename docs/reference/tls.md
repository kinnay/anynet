
# Module: <code>anynet.tls</code>

Provides classes to work with TCP/TLS connections.

<code>**class** [X509Name](#x509name)</code><br>
<span class="docs">Represents a subject or issuer name.</span>

<code>**class** [TLSCertificate](#tlscertificate)</code><br>
<span class="docs">An X.509 certificate.</span>

<code>**class** [TLSPrivateKey](#tlsprivatekey)</code><br>
<span class="docs">An RSA private key.</span>

<code>**class** [TLSContext](#tlscontext)</code><br>
<span class="docs">A TLS context.</span>

<code>**class** [TLSClient](#tlsclient)</code><br>
<span class="docs">A TCP client with TLS support.</span>

<code>**def load_certificate_chain**(filename: str) -> list[[TLSCertificate](#tlscertificate)]</code><br>
<span class="docs">Loads one or more certificates from a PEM-encoded certificate chain file.</span>

<code>**async with connect**(host: str, port: int, context: [TLSContext](#tlscontext) = None) -> [TLSClient](#tlsclient)</code><br>
<span class="docs">Creates a TCP/TLS client and connects it to the given address. Blocks until the connection is ready and the TLS handshake has been performed. If no context is provided, the client uses plain TCP without TLS.</span>

<code>**async with serve**(handler: Callable, host: str = "", port: int = 0, context: [TLSContext](#tlscontext) = None) -> None</code><br>
<span class="docs">Creates a TCP/TLS server and binds it to the given address. If `host` is empty, the local address of the default gateway is used. If `port` is 0, it is chosen by the operating system. `handler` must be an `async` function that accepts a [`TLSClient`](#tlsclient). The client is closed automatically when `handler` returns. If no context is provided, the server uses plain TCP without TLS.</span>

## Global Constants
`TYPE_DER (0)`<br>
<span class="docs">Specifies binary encoding (DER)</span><br>
`TYPE_PEM (1)`<br>
<span class="docs">Specifies text encoding (PEM)</span>

## X509Name
This class represents a subject or issuer name. There are two ways to access its fields: either by item lookup (`subject["CN"]`) or by attribute lookup (`subject.common_name`). The following items and attributes are currently defined:

| Item | Attribute |
| --- | --- |
| `C` | `country_name` |
| `ST` | `state_or_province_name` |
| `L` | `locality_name` |
| `O` | `organization_name` |
| `OU` | `organizational_unit_name` |
| `CN` | `common_name` |
| `E` | `email_address` |

## TLSCertificate
This class should not be instantiated directly. Instead, one of the static methods should be used.

<code>**subject**: [X509Name](#x509name) = [X509Name](#x509name)()</code><br>
<span class="docs">The subject name.</span>

<code>**issuer**: [X509Name](#x509name) = [X509Name](#x509name)()</code><br>
<span class="docs">The issuer name.</span>

<code>**def sign**(key: [TLSPrivateKey](#tlsprivatekey), alg: str = "sha256") -> None</code><br>
<span class="docs">Signs the certificate with the given private key and hash function.</span>

<code>**def save**(filename: str, format: int) -> None</code><br>
<span class="docs">Saves the certificate in the given `format`, which should be either [`TYPE_DER`](#global-constants) or [`TYPE_PEM`](#global-constants).

<code>**def encode**(format: int) -> bytes</code><br>
<span class="docs">Encodes the certificate in the given `format`, which should be either [`TYPE_DER`](#global-constants) or [`TYPE_PEM`](#global-constants).</span>

<code style="color: blue">@classmethod</code><br>
<code>**def load**(filename: str, format: int) -> [TLSCertificate](#tlscertificate)</code><br>
<span class="docs">Loads the certificate from a file with the given `format`, which should be either [`TYPE_DER`](#global-constants) or [`TYPE_PEM`](#global-constants).</span>

<code style="color: blue">@classmethod</code><br>
<code>**def parse**(data: bytes, format: int) -> [TLSCertificate](#tlscertificate)</code><br>
<span class="docs">Loads the certificate from a buffer with the given `format`, which should be either [`TYPE_DER`](#global-constants) or [`TYPE_PEM`](#global-constants).</span>

<code style="color: blue">@classmethod</code><br>
<code>**def generate**(key: [TLSPrivateKey](#tlsprivatekey)) -> [TLSCertificate](#tlscertificate)</code><br>
<span class="docs">Generates a certificate with the given private key. Subject and issuer name must be filled in manually, and the certificate must be signed with the `sign` method.</span>

## TLSPrivateKey
This class should not be instantiated directly. Instead, one of the static methods should be used.

<code>**def save**(filename: str, format: int) -> None</code><br>
<span class="docs">Saves the private key in the given `format`, which should be either [`TYPE_DER`](#global-constants) or [`TYPE_PEM`](#global-constants).

<code>**def encode**(format: int) -> bytes</code><br>
<span class="docs">Encodes the private key in the given `format`, which should be either [`TYPE_DER`](#global-constants) or [`TYPE_PEM`](#global-constants).</span>

<code style="color: blue">@classmethod</code><br>
<code>**def load**(filename: str, format: int) -> [TLSPrivateKey](#tlsprivatekey)</code><br>
<span class="docs">Loads the private key from a file with the given `format`, which should be either [`TYPE_DER`](#global-constants) or [`TYPE_PEM`](#global-constants).</span>

<code style="color: blue">@classmethod</code><br>
<code>**def parse**(data: bytes, format: int) -> [TLSPrivateKey](#tlsprivatekey)</code><br>
<span class="docs">Loads the private key from a buffer with the given `format`, which should be either [`TYPE_DER`](#global-constants) or [`TYPE_PEM`](#global-constants).</span>

<code style="color: blue">@classmethod</code><br>
<code>**def generate**(size: int = 2048) -> [TLSPrivateKey](#tlsprivatekey)</code><br>
<span class="docs">Generates a random private key with the given number of bits.</span>

## TLSContext
This class contains configuration for a TLS client or server.

By default, TLS clients verify the server certificate with the system's trusted CA store, unless `set_authority` is called, in which case only the given authority is trusted. TLS servers do not ask for a client certificate, unless `set_authority` is called.

If `disable_verification` is called, all certificates are trusted, regardless of whether `set_authority` has been called.

<code>**def _\_init__**()</code><br>
<span class="docs">Creates a new TLS context.</span>

<code>**def set_certificate**(cert: [TLSCertificate](#tlscertificate), key: [TLSPrivateKey](#tlsprivatekey)) -> None</code><br>
<span class="docs">Specifies the certificate and its private key. If you want to provide intermediate certificates as well, use the `set_certificate_chain` method instead.</span>

<code>**def set_certificate_chain**(certs: list[[TLSCertificate](#tlscertificate)], key: [TLSPrivateKey](#tlsprivatekey)) -> None</code><br>
<span class="docs">Specifies a list of certificates and the private key.</span>

<code>**def set_authority**(cert: [TLSCertificate](#tlscertificate)) -> None</code><br>
<span class="docs">Verifies the certificate with the given CA.</span>

<code>**def disable_verification**() -> None</code><br>
<span class="docs">Disables certificate verification. If both `set_authority` and `disable_verification` are called, the former is ignored.</span>

<code>**def get**(server: bool) -> ssl.SSLContext</code><br>
<span class="docs">Returns the TLS context as a standard `ssl.SSLContext`.</span>

## TLSClient
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

<code>**def remote_ceritifcate**() -> [TLSCertificate](#tlscertificate)</code><br>
<span class="docs">Returns the certificate that was provided by the other side of the connection. Returns `None` if the connection is not secured with TLS, or if the other side of the connection did not provide a client certificate.</span>
