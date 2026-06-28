
from OpenSSL import crypto

from anynet import util
from cryptography.hazmat.primitives.asymmetric import rsa
from typing import Any, AsyncIterator, Awaitable, Callable

import anyio
import anyio.abc
import anyio.streams.tls
import contextlib
import os
import ssl
import tempfile

import logging
logger = logging.getLogger(__name__)


TYPE_DER = 0
TYPE_PEM = 1

TypeMap = {
    TYPE_DER: crypto.FILETYPE_ASN1,
    TYPE_PEM: crypto.FILETYPE_PEM
}


def set_certificate_chain(
    context: ssl.SSLContext, certs: "list[TLSCertificate]", key: "TLSPrivateKey"
) -> None:
    certfile = tempfile.NamedTemporaryFile(delete=False)
    keyfile = tempfile.NamedTemporaryFile(delete=False)
    
    for cert in certs:
        certfile.write(cert.encode(TYPE_PEM))
    keyfile.write(key.encode(TYPE_PEM))
    
    certfile.close()
    keyfile.close()
    
    context.load_cert_chain(certfile.name, keyfile.name)
    
    os.remove(certfile.name)
    os.remove(keyfile.name)

def load_certificate_chain(filename: str) -> "list[TLSCertificate]":
    with open(filename, "rb") as f:
        data = f.read()
    
    header = b"-----BEGIN CERTIFICATE-----"
    
    certs = []
    for part in data.split(header)[1:]:
        certs.append(TLSCertificate.parse(header + part, TYPE_PEM))
    return certs


class X509Name:
    ITEMS = {
        "C": "country_name",
        "ST": "state_or_province_name",
        "L": "locality_name",
        "O": "organization_name",
        "OU": "organizational_unit_name",
        "CN": "common_name",
        "E": "email_address"
    }
    
    ATTRS = {
        "country_name": "countryName",
        "state_or_province_name": "stateOrProvinceName",
        "locality_name": "localityName",
        "organization_name": "organizationName",
        "organizational_unit_name": "organizationalUnitName",
        "common_name": "commonName",
        "email_address": "emailAddress"
    }
    
    def __init__(self):
        self.obj = crypto.X509().get_subject()
    
    def __getitem__(self, key: str) -> Any:
        return getattr(self, self.ITEMS[key])
    
    def __setitem__(self, key: str, value: Any) -> None:
        setattr(self, self.ITEMS[key], value)
        
    def __getattr__(self, name: str) -> Any:
        return getattr(self.__dict__["obj"], X509Name.ATTRS[name])
    
    def __setattr__(self, name: str, value: Any) -> None:
        if name == "obj":
            self.__dict__["obj"] = value
        else:
            setattr(self.obj, X509Name.ATTRS[name], value)


class TLSCertificate:
    obj: crypto.X509
    subject: X509Name
    issuer: X509Name

    def __init__(self, obj: crypto.X509):
        self.obj = obj
        self.subject = X509Name()
        self.subject.obj = obj.get_subject()
        self.issuer = X509Name()
        self.issuer.obj = obj.get_issuer()
        
    def public_key(self) -> Any:
        pkey = self.obj.get_pubkey()

        rsakey = pkey.to_cryptography_key()
        if not isinstance(rsakey, rsa.RSAPublicKey):
            raise RuntimeError("Only RSA keys are supported for now")
        
        return rsakey.public_numbers()
        
    def encode(self, format: int) -> bytes:
        return crypto.dump_certificate(TypeMap[format], self.obj)
        
    def save(self, filename: str, format: int) -> None:
        with open(filename, "wb") as f:
            f.write(self.encode(format))
        
    def sign(self, key: "TLSPrivateKey", alg: str = "sha256") -> None:
        self.obj.sign(key.obj, alg)

    @classmethod
    def load(cls, filename: str, format: int) -> "TLSCertificate":
        with open(filename, "rb") as f:
            data = f.read()
        return cls.parse(data, format)

    @classmethod
    def parse(cls, data: bytes, format: int) -> "TLSCertificate":
        cert = crypto.load_certificate(TypeMap[format], data)
        return cls(cert)

    @classmethod
    def generate(cls, key: "TLSPrivateKey") -> "TLSCertificate":
        cert = crypto.X509()
        cert.set_pubkey(key.obj)
        
        cert.set_notBefore(b"20000101000000Z")
        cert.set_notAfter(b"29990101000000Z")
        
        return cls(cert)

    
class TLSPrivateKey:
    obj: crypto.PKey

    def __init__(self, obj: crypto.PKey):
        self.obj = obj
        
    def encode(self, format: int) -> bytes:
        return crypto.dump_privatekey(TypeMap[format], self.obj)
    
    def save(self, filename: str, format: int) -> None:
        with open(filename, "wb") as f:
            f.write(self.encode(format))
    
    @classmethod
    def load(cls, filename: str, format: int) -> "TLSPrivateKey":
        with open(filename, "rb") as f:
            data = f.read()
        return cls.parse(data, format)

    @classmethod
    def parse(cls, data: bytes, format: int) -> "TLSPrivateKey":
        pkey = crypto.load_privatekey(TypeMap[format], data)
        return cls(pkey)

    @classmethod
    def generate(cls, size: int = 2048) -> "TLSPrivateKey":
        pkey = crypto.PKey()
        pkey.generate_key(crypto.TYPE_RSA, size)
        return cls(pkey)


class TLSContext:
    _authority: TLSCertificate | None
    _certs: list[TLSCertificate] | None
    _key: TLSPrivateKey | None
    _verification_enabled: bool

    def __init__(self):
        self._authority = None
        self._certs = None
        self._key = None
        self._verification_enabled = True
    
    def set_certificate(self, cert: TLSCertificate, key: TLSPrivateKey) -> None:
        self._certs = [cert]
        self._key = key
    
    def set_certificate_chain(
        self, certs: list[TLSCertificate], key: TLSPrivateKey\
    ) -> None:
        self._certs = certs
        self._key = key
    
    def set_authority(self, authority: TLSCertificate):
        self._authority = authority
    
    def disable_verification(self) -> None:
        self._verification_enabled = False
    
    def get(self, server: bool) -> ssl.SSLContext:
        if server:
            return self._make_server_context()
        return self._make_client_context()
    
    def _make_server_context(self) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        if self._certs and self._key:
            set_certificate_chain(context, self._certs, self._key)
        else:
            raise ValueError("Please provide a server certificate")
        
        context.verify_mode = ssl.CERT_NONE

        if self._authority and self._verification_enabled:
            data = self._authority.encode(TYPE_DER)
            context.load_verify_locations(cadata=data)
            context.verify_mode = ssl.CERT_REQUIRED

        context.check_hostname = False
        return context
    
    def _make_client_context(self) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if self._certs and self._key:
            set_certificate_chain(context, self._certs, self._key)
        
        if not self._verification_enabled:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        if self._authority:
            data = self._authority.encode(TYPE_DER)
            context.load_verify_locations(cadata=data)
        else:
            context.load_default_certs()
        
        return context


class TLSClient:
    _stream: anyio.abc.ByteStream
    _lock: anyio.abc.Lock

    def __init__(self, stream: anyio.abc.ByteStream):
        self._stream = stream
        self._lock = anyio.Lock()
        
    async def send(self, data: bytes) -> None:
        async with self._lock:
            await self._stream.send(data)
    
    async def recv(self, num: int = 65536) -> bytes:
        return await self._stream.receive(num)
    
    async def close(self) -> None:
        await self._stream.aclose()
    
    def local_address(self) -> tuple[str, int]:
        address = self._stream.extra(anyio.abc.SocketAttribute.local_address)
        if not isinstance(address, tuple):
            raise RuntimeError("Socket has unexpected address type")
        return address
    
    def remote_address(self) -> tuple[str, int]:
        address = self._stream.extra(anyio.abc.SocketAttribute.remote_address)
        if not isinstance(address, tuple):
            raise RuntimeError("Socket has unexpected address type")
        return address
    
    def remote_certificate(self) -> TLSCertificate | None:
        cert = self._stream.extra(anyio.streams.tls.TLSAttribute.peer_certificate_binary, None)
        if cert:
            return TLSCertificate.parse(cert, TYPE_DER)
        return None


@contextlib.asynccontextmanager
async def connect(
    host: str, port: int, context: TLSContext | None = None
) -> AsyncIterator[TLSClient]:
    logger.debug("Connecting TCP/TLS client to %s:%s", host, port)

    if context:
        ssl_context = context.get(False)
        async with await anyio.connect_tcp(
            host, port, ssl_context=ssl_context, tls_standard_compatible=False
        ) as stream:
            yield TLSClient(stream)
    
    else:
        async with await anyio.connect_tcp(host, port) as stream:
            yield TLSClient(stream)
    

@contextlib.asynccontextmanager
async def create_listener(
    host: str, port: int, context: TLSContext | None
) -> AsyncIterator[anyio.abc.Listener[anyio.abc.ByteStream]]:
    listener = await anyio.create_tcp_listener(local_host=host, local_port=port)
    async with listener:
        if context:
            tls_listener = anyio.streams.tls.TLSListener(
                listener, context.get(True), False
            )
            async with tls_listener:
                yield tls_listener
        else:
            yield listener

@contextlib.asynccontextmanager
async def serve(
    handler: Callable[[TLSClient], Awaitable[None]], host: str = "",
    port: int = 0, context: TLSContext | None = None
) -> AsyncIterator[None]:
    async def handle(stream: anyio.abc.ByteStream) -> None:
        with util.catch():
            if context:
                try:
                    stream = await anyio.streams.tls.TLSStream.wrap(
                        stream, ssl_context=context.get(True), standard_compatible=False
                    )
                except util.StreamError:
                    logger.warning("Failed to accept TLS handshake")
                    return
            
            async with stream:
                await handler(TLSClient(stream))
                logger.debug("Closing TCP/TLS connection")
    
    if not host:
        host = util.local_address()
    
    logger.info("Starting TCP/TLS server at %s:%i", host, port)
    async with await anyio.create_tcp_listener(local_host=host, local_port=port) as listener:
        async with util.create_task_group() as group:
            group.start_soon(listener.serve, handle)
            yield
