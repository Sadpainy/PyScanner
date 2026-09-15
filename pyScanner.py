import socket
import struct
import ssl
import sys
import signal
import time
import enum
import typing
import asyncio
import re
import threading
import argparse
import ipaddress
import dataclasses
from dataclasses import dataclass, field
from typing import Optional, Iterable, Iterator, Sequence, Mapping, Any, Callable, Awaitable
from contextlib import asynccontextmanager, suppress
from collections import OrderedDict
from enum import IntEnum, IntFlag, auto
from functools import lru_cache, cached_property, partial
from pathlib import PurePosixPath
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor

# Windows NTSTATUS
STATUS_SUCCESS: typing.Final[int] = 0x00000000
STATUS_UNSUCCESSFUL: typing.Final[int] = 0xC0000001
STATUS_INVALID_PARAMETER: typing.Final[int] = 0xC000000D
STATUS_ACCESS_DENIED: typing.Final[int] = 0xC0000022

# Define Offsets
OFF_MAGIC: typing.Final[int] = 0x0000
OFF_VERSION: typing.Final[int] = 0x0004
OFF_FLAGS: typing.Final[int] = 0x0006
OFF_STATUS: typing.Final[int] = 0x0008
OFF_RESOLVE_MS: typing.Final[int] = 0x000C
OFF_CONNECT_MS: typing.Final[int] = 0x0010
OFF_TLS_MS: typing.Final[int] = 0x0014
OFF_HTTP_MS: typing.Final[int] = 0x0018
OFF_TOTAL_MS: typing.Final[int] = 0x001C
OFF_IP: typing.Final[int] = 0x0020
OFF_HTTP_CODE: typing.Final[int] = 0x0024
OFF_TLS_VERSION: typing.Final[int] = 0x0026
OFF_PORT_COUNT: typing.Final[int] = 0x0028
OFF_ADDR_COUNT: typing.Final[int] = 0x002A
OFF_HOST_LEN: typing.Final[int] = 0x002C
OFF_WHOIS_LEN: typing.Final[int] = 0x002E
OFF_SERVER_LEN: typing.Final[int] = 0x0030
OFF_TITLE_LEN: typing.Final[int] = 0x0032
OFF_HOST: typing.Final[int] = 0x0040
OFF_SERVER: typing.Final[int] = 0x0140
OFF_TITLE: typing.Final[int] = 0x01C0
OFF_WHOIS: typing.Final[int] = 0x02C0

RECORD_SIZE: typing.Final[int] = 0x06C0
MAGIC: typing.Final[int] = 0x50595343
VERSION: typing.Final[int] = 0x0100

DEFAULT_TIMEOUT: typing.Final[float] = 3.0
DEFAULT_PORTS: typing.Final[tuple[int, ...]] = (80, 443, 22, 21, 25, 3306, 3389, 8080, 8443, 6379, 27017)


class Flag(IntFlag):
    NONE = 0
    DNS_OK = 0x0001
    TCP_OK = 0x0002
    TLS_OK = 0x0004
    HTTP_OK = 0x0008
    WHOIS_OK = 0x0010
    TITLE_OK = 0x0020
    REDIRECT = 0x0040
    CDN = 0x0080


class Severity(IntEnum):
    SUCCESS = 0x0
    INFO = 0x1
    WARNING = 0x2
    ERROR = 0x3


class Field(IntEnum):
    MAGIC = OFF_MAGIC
    VERSION = OFF_VERSION
    FLAGS = OFF_FLAGS
    STATUS = OFF_STATUS
    RESOLVE_MS = OFF_RESOLVE_MS
    CONNECT_MS = OFF_CONNECT_MS
    TLS_MS = OFF_TLS_MS
    HTTP_MS = OFF_HTTP_MS
    TOTAL_MS = OFF_TOTAL_MS
    IP = OFF_IP
    HTTP_CODE = OFF_HTTP_CODE
    TLS_VERSION = OFF_TLS_VERSION
    PORT_COUNT = OFF_PORT_COUNT
    ADDR_COUNT = OFF_ADDR_COUNT
    HOST_LEN = OFF_HOST_LEN
    WHOIS_LEN = OFF_WHOIS_LEN
    SERVER_LEN = OFF_SERVER_LEN
    TITLE_LEN = OFF_TITLE_LEN


class Encoding(IntEnum):
    U16 = 0x0002
    U32 = 0x0004


class Endian(IntEnum):
    BIG = 0x00
    LITTLE = 0x01

# Layout
@dataclass(frozen=True, slots=True)
class Layout:
    offset: int
    encoding: Encoding
    count: int = 1

    @cached_property
    def size(self) -> int:
        return int(self.encoding) * self.count

    @cached_property
    def fmt(self) -> str:
        ch = "H" if self.encoding is Encoding.U16 else "I"
        return f">{ch * self.count}"

    def pack(self, *values: int) -> bytes:
        return struct.pack(self.fmt, *values)

    def unpack(self, data: bytes) -> tuple[int, ...]:
        return struct.unpack(self.fmt, data)


FIXED_LAYOUT: typing.Final[Mapping[Field, Layout]] = {
    Field.MAGIC: Layout(OFF_MAGIC, Encoding.U32),
    Field.VERSION: Layout(OFF_VERSION, Encoding.U16),
    Field.FLAGS: Layout(OFF_FLAGS, Encoding.U16),
    Field.STATUS: Layout(OFF_STATUS, Encoding.U32),
    Field.RESOLVE_MS: Layout(OFF_RESOLVE_MS, Encoding.U32),
    Field.CONNECT_MS: Layout(OFF_CONNECT_MS, Encoding.U32),
    Field.TLS_MS: Layout(OFF_TLS_MS, Encoding.U32),
    Field.HTTP_MS: Layout(OFF_HTTP_MS, Encoding.U32),
    Field.TOTAL_MS: Layout(OFF_TOTAL_MS, Encoding.U32),
    Field.IP: Layout(OFF_IP, Encoding.U32),
    Field.HTTP_CODE: Layout(OFF_HTTP_CODE, Encoding.U16),
    Field.TLS_VERSION: Layout(OFF_TLS_VERSION, Encoding.U16),
    Field.PORT_COUNT: Layout(OFF_PORT_COUNT, Encoding.U16),
    Field.ADDR_COUNT: Layout(OFF_ADDR_COUNT, Encoding.U16),
    Field.HOST_LEN: Layout(OFF_HOST_LEN, Encoding.U16),
    Field.WHOIS_LEN: Layout(OFF_WHOIS_LEN, Encoding.U16),
    Field.SERVER_LEN: Layout(OFF_SERVER_LEN, Encoding.U16),
    Field.TITLE_LEN: Layout(OFF_TITLE_LEN, Encoding.U16),
}

VARIABLE_LAYOUT: typing.Final[Mapping[str, tuple[int, int, Field]]] = {
    "host": (OFF_HOST, OFF_SERVER - OFF_HOST, Field.HOST_LEN),
    "server": (OFF_SERVER, OFF_TITLE - OFF_SERVER, Field.SERVER_LEN),
    "title": (OFF_TITLE, OFF_WHOIS - OFF_TITLE, Field.TITLE_LEN),
    "whois": (OFF_WHOIS, RECORD_SIZE - OFF_WHOIS, Field.WHOIS_LEN),
}

# Recording
class RecordError(Exception):
    pass


class RecordOverflow(RecordError):
    pass


class RecordMagicMismatch(RecordError):
    pass


class Record:
    __slots__ = ("_buf", "_view")

    def __init__(self, size: int = RECORD_SIZE) -> None:
        self._buf = bytearray(size)
        self._view = memoryview(self._buf)
        self[Field.MAGIC] = MAGIC
        self[Field.VERSION] = VERSION
        self[Field.STATUS] = STATUS_SUCCESS

    @property
    def buf(self) -> memoryview:
        return self._view

    @property
    def raw(self) -> bytes:
        return bytes(self._buf)

    def __len__(self) -> int:
        return len(self._buf)

    def __getitem__(self, field: Field) -> int:
        layout = FIXED_LAYOUT[field]
        return int.from_bytes(self._view[layout.offset:layout.offset + layout.size], "big")

    def __setitem__(self, field: Field, value: int) -> None:
        layout = FIXED_LAYOUT[field]
        mask = (1 << (layout.size * 8)) - 1
        self._view[layout.offset:layout.offset + layout.size] = int(value & mask).to_bytes(layout.size, "big")

    def __contains__(self, field: Field) -> bool:
        return field in FIXED_LAYOUT

    def get_bytes(self, name: str) -> bytes:
        offset, capacity, len_field = VARIABLE_LAYOUT[name]
        n = self[len_field]
        if n > capacity:
            n = capacity
        return bytes(self._view[offset:offset + n])

    def set_bytes(self, name: str, data: bytes) -> None:
        offset, capacity, len_field = VARIABLE_LAYOUT[name]
        truncated = bytes(data[:capacity])
        self._view[offset:offset + len(truncated)] = truncated
        self[len_field] = len(truncated)

    def verify(self) -> None:
        if self[Field.MAGIC] != MAGIC:
            raise RecordMagicMismatch(f"expected 0x{MAGIC:08X}, got 0x{self[Field.MAGIC]:08X}")
        if self[Field.VERSION] != VERSION:
            raise RecordMagicMismatch(f"expected 0x{VERSION:04X}, got 0x{self[Field.VERSION]:04X}")

    def flag(self, flag: Flag) -> bool:
        return bool(Flag(self[Field.FLAGS]) & flag)

    def set_flag(self, flag: Flag, on: bool = True) -> None:
        current = Flag(self[Field.FLAGS])
        self[Field.FLAGS] = int(current | flag if on else current & ~flag)

    def hexdump(self, base: int = 0x0000, width: int = 0x10, limit: Optional[int] = None) -> str:
        data = self._buf if limit is None else self._buf[:limit]
        lines: list[str] = []
        for row in range(0, len(data), width):
            chunk = data[row:row + width]
            addr = base + row
            hx = " ".join(f"{b:02X}" for b in chunk).ljust(width * 3 - 1)
            asc = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in chunk)
            lines.append(f"0x{addr:08X}  {hx}  |{asc}|")
        return "\n".join(lines)

    def clone(self) -> "Record":
        new = Record(len(self._buf))
        new._buf[:] = self._buf
        return new

    def __repr__(self) -> str:
        host = self.get_bytes("host").decode(errors="ignore")
        return f"<Record host={host!r} status=0x{self[Field.STATUS]:08X} flags=0x{self[Field.FLAGS]:04X}>"

# Status Code Back
class StatusView:
    __slots__ = ("_record",)

    def __init__(self, record: Record) -> None:
        self._record = record

    @property
    def code(self) -> int:
        return self._record[Field.STATUS]

    @property
    def severity(self) -> Severity:
        return Severity((self.code >> 30) & 0x3)

    @property
    def is_success(self) -> bool:
        return self.code == STATUS_SUCCESS

    @property
    def name(self) -> str:
        return NTSTATUS_NAMES.get(self.code, "STATUS_UNKNOWN")

    def __str__(self) -> str:
        return f"0x{self.code:08X} {self.name}"


NTSTATUS_NAMES: typing.Final[Mapping[int, str]] = {
    STATUS_SUCCESS: "STATUS_SUCCESS",
    STATUS_UNSUCCESSFUL: "STATUS_UNSUCCESSFUL",
    STATUS_INVALID_PARAMETER: "STATUS_INVALID_PARAMETER",
    STATUS_ACCESS_DENIED: "STATUS_ACCESS_DENIED",
}

# Time Durations
class Duration:
    __slots__ = ("_start",)

    def __init__(self) -> None:
        self._start = time.perf_counter()

    def ms(self) -> int:
        return int((time.perf_counter() - self._start) * 1000)

    def reset(self) -> None:
        self._start = time.perf_counter()

    def __enter__(self) -> "Duration":
        self.reset()
        return self

    def __exit__(self, *exc: object) -> None:
        return None

# Address
@dataclass(slots=True)
class Address:
    ip: str
    family: int
    socktype: int
    proto: int
    canonname: str
    port: int = 0

    @property
    def packed(self) -> int:
        try:
            return int.from_bytes(socket.inet_aton(self.ip), "big")
        except OSError:
            return 0

    @property
    def version(self) -> int:
        return 4 if self.family == socket.AF_INET else 6

@dataclass(slots=True)
class PortResult:
    port: int
    open: bool
    connect_ms: int
    banner: Optional[str] = None
    error: Optional[str] = None


@dataclass(slots=True)
class TLSResult:
    version: Optional[str]
    cipher: Optional[str]
    connect_ms: int
    peer_cert_subject: Optional[str] = None
    peer_cert_issuer: Optional[str] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    san: tuple[str, ...] = ()


@dataclass(slots=True)
class HTTPResult:
    status_code: Optional[int]
    reason: Optional[str]
    server: Optional[str]
    title: Optional[str]
    headers: Mapping[str, str]
    redirect: Optional[str]
    elapsed_ms: int
    body_size: int


@dataclass(slots=True)
class WhoisResult:
    server: str
    raw: str
    elapsed_ms: int
    fields: Mapping[str, str]


@dataclass(slots=True)
class ScanReport:
    host: str
    addresses: tuple[Address, ...]
    ports: tuple[PortResult, ...]
    tls: Optional[TLSResult]
    http: Optional[HTTPResult]
    whois: Optional[WhoisResult]
    resolve_ms: int
    total_ms: int
    status: int
    flags: Flag

    @property
    def open_ports(self) -> tuple[int, ...]:
        return tuple(p.port for p in self.ports if p.open)

    @property
    def primary_ip(self) -> Optional[str]:
        return self.addresses[0].ip if self.addresses else None

    def to_record(self) -> Record:
        rec = Record()
        rec.set_bytes("host", self.host.encode())
        rec[Field.STATUS] = self.status
        rec[Field.FLAGS] = int(self.flags)
        rec[Field.RESOLVE_MS] = self.resolve_ms
        rec[Field.TOTAL_MS] = self.total_ms
        rec[Field.ADDR_COUNT] = len(self.addresses)
        rec[Field.PORT_COUNT] = len(self.open_ports)
        if self.addresses:
            rec[Field.IP] = self.addresses[0].packed
        if self.tls:
            rec[Field.TLS_MS] = self.tls.connect_ms
            rec[Field.TLS_VERSION] = _tls_version_code(self.tls.version)
        if self.http:
            rec[Field.HTTP_MS] = self.http.elapsed_ms
            if self.http.status_code is not None:
                rec[Field.HTTP_CODE] = self.http.status_code
            if self.http.server:
                rec.set_bytes("server", self.http.server.encode())
            if self.http.title:
                rec.set_bytes("title", self.http.title.encode())
        if self.whois:
            rec.set_bytes("whois", self.whois.raw.encode())
        connect_sum = sum(p.connect_ms for p in self.ports if p.open)
        rec[Field.CONNECT_MS] = connect_sum
        return rec


def _tls_version_code(name: Optional[str]) -> int:
    if name is None:
        return 0
    table = {
        "TLSv1": 0x0301,
        "TLSv1.1": 0x0302,
        "TLSv1.2": 0x0303,
        "TLSv1.3": 0x0304,
    }
    return table.get(name, 0)
    
class CacheEntry:
    __slots__ = ("value", "expires_at", "hits")

    def __init__(self, value: Any, ttl: float) -> None:
        self.value = value
        self.expires_at = time.monotonic() + ttl
        self.hits = 0

    @property
    def expired(self) -> bool:
        return time.monotonic() >= self.expires_at

    def touch(self) -> Any:
        self.hits += 1
        return self.value


class LRUCache:
    __slots__ = ("_data", "_capacity", "_lock", "_hits", "_misses")

    def __init__(self, capacity: int = 512) -> None:
        self._data: OrderedDict[str, CacheEntry] = OrderedDict()
        self._capacity = capacity
        self._lock = asyncio.Lock()
        self._hits = 0
        self._misses = 0

    async def get(self, key: str) -> Optional[Any]:
        async with self._lock:
            entry = self._data.get(key)
            if entry is None:
                self._misses += 1
                return None
            if entry.expired:
                del self._data[key]
                self._misses += 1
                return None
            self._data.move_to_end(key)
            self._hits += 1
            return entry.touch()

    async def put(self, key: str, value: Any, ttl: float) -> None:
        async with self._lock:
            self._data[key] = CacheEntry(value, ttl)
            self._data.move_to_end(key)
            while len(self._data) > self._capacity:
                self._data.popitem(last=False)

    async def invalidate(self, key: str) -> bool:
        async with self._lock:
            return self._data.pop(key, None) is not None

    async def clear(self) -> None:
        async with self._lock:
            self._data.clear()

    @property
    def stats(self) -> Mapping[str, int]:
        return {
            "size": len(self._data),
            "capacity": self._capacity,
            "hits": self._hits,
            "misses": self._misses,
        }

# Define DNS Resolver
class ResolverMetrics:
    __slots__ = ("_calls", "_failures", "_total_ms", "_lock")

    def __init__(self) -> None:
        self._calls = 0
        self._failures = 0
        self._total_ms = 0
        self._lock = threading.Lock()

    def record(self, elapsed_ms: int, ok: bool) -> None:
        with self._lock:
            self._calls += 1
            self._total_ms += elapsed_ms
            if not ok:
                self._failures += 1

    @property
    def average_ms(self) -> float:
        with self._lock:
            return self._total_ms / self._calls if self._calls else 0.0

    @property
    def summary(self) -> Mapping[str, float]:
        with self._lock:
            return {
                "calls": self._calls,
                "failures": self._failures,
                "total_ms": self._total_ms,
                "average_ms": self._total_ms / self._calls if self._calls else 0.0,
            }


class Resolver:
    __slots__ = ("_cache", "_metrics", "_ttl", "_timeout", "_loop", "_executor")

    def __init__(
        self,
        ttl: float = 300.0,
        timeout: float = 5.0,
        cache_capacity: int = 512,
        executor: Optional[ThreadPoolExecutor] = None,
    ) -> None:
        self._cache = LRUCache(cache_capacity)
        self._metrics = ResolverMetrics()
        self._ttl = ttl
        self._timeout = timeout
        self._executor = executor
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    async def __aenter__(self) -> "Resolver":
        self._loop = asyncio.get_running_loop()
        return self

    async def __aexit__(self, *exc: object) -> None:
        self._loop = None

    async def resolve(self, host: str, port: Optional[int] = None, family: int = 0) -> tuple[Address, ...]:
        key = f"{host}|{port}|{family}"
        cached = await self._cache.get(key)
        if cached is not None:
            return cached
        start = time.perf_counter()
        try:
            result = await asyncio.wait_for(
                self._loop.run_in_executor(self._executor, self._blocking_resolve, host, port, family),
                timeout=self._timeout,
            )
        except (asyncio.TimeoutError, socket.gaierror, OSError):
            self._metrics.record(int((time.perf_counter() - start) * 1000), False)
            return ()
        elapsed = int((time.perf_counter() - start) * 1000)
        self._metrics.record(elapsed, bool(result))
        await self._cache.put(key, result, self._ttl)
        return result

    @staticmethod
    def _blocking_resolve(host: str, port: Optional[int], family: int) -> tuple[Address, ...]:
        try:
            infos = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)
        except socket.gaierror:
            return ()
        except OSError:
            return ()
        seen: set[str] = set()
        out: list[Address] = []
        for fam, stype, proto, canon, sa in infos:
            ip = sa[0]
            if ip in seen:
                continue
            seen.add(ip)
            out.append(Address(ip=ip, family=fam, socktype=stype, proto=proto, canonname=canon, port=sa[1]))
        return tuple(out)

    async def reverse(self, ip: str) -> Optional[str]:
        key = f"ptr|{ip}"
        cached = await self._cache.get(key)
        if cached is not None:
            return cached
        try:
            host, _, _ = await asyncio.wait_for(
                self._loop.run_in_executor(self._executor, socket.gethostbyaddr, ip),
                timeout=self._timeout,
            )
        except (asyncio.TimeoutError, socket.herror, socket.gaierror, OSError):
            return None
        await self._cache.put(key, host, self._ttl)
        return host

    @property
    def metrics(self) -> ResolverMetrics:
        return self._metrics

    @property
    def cache(self) -> LRUCache:
        return self._cache


class AsyncProbe:
    __slots__ = ("_timeout", "_sem", "_executor", "_sockopts")

    def __init__(
        self,
        timeout: float = 3.0,
        concurrency: int = 256,
        executor: Optional[ThreadPoolExecutor] = None,
        sockopts: Optional[Mapping[int, int]] = None,
    ) -> None:
        self._timeout = timeout
        self._sem = asyncio.Semaphore(concurrency)
        self._executor = executor
        self._sockopts = dict(sockopts) if sockopts else {}

    async def tcp_connect(self, ip: str, port: int) -> PortResult:
        async with self._sem:
            loop = asyncio.get_running_loop()
            start = time.perf_counter()
            try:
                result = await asyncio.wait_for(
                    loop.run_in_executor(self._executor, self._blocking_connect, ip, port),
                    timeout=self._timeout,
                )
            except asyncio.TimeoutError:
                return PortResult(port=port, open=False, connect_ms=int((time.perf_counter() - start) * 1000), error="timeout")
            elapsed = int((time.perf_counter() - start) * 1000)
            return PortResult(port=port, open=result, connect_ms=elapsed)

    def _blocking_connect(self, ip: str, port: int) -> bool:
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(self._timeout)
        for opt, val in self._sockopts.items():
            try:
                s.setsockopt(socket.SOL_SOCKET, opt, val)
            except OSError:
                continue
        try:
            s.connect((ip, port))
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False
        finally:
            with suppress(OSError):
                s.close()
        return True

    async def grab_banner(self, ip: str, port: int, read_size: int = 1024) -> Optional[str]:
        async with self._sem:
            loop = asyncio.get_running_loop()
            try:
                return await asyncio.wait_for(
                    loop.run_in_executor(self._executor, self._blocking_banner, ip, port, read_size),
                    timeout=self._timeout,
                )
            except asyncio.TimeoutError:
                return None

    def _blocking_banner(self, ip: str, port: int, read_size: int) -> Optional[str]:
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(self._timeout)
        try:
            s.connect((ip, port))
            s.settimeout(min(self._timeout, 2.0))
            data = s.recv(read_size)
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None
        finally:
            with suppress(OSError):
                s.close()
        if not data:
            return None
        return data.decode(errors="ignore").strip()

    async def scan_ports(self, ip: str, ports: Sequence[int]) -> tuple[PortResult, ...]:
        tasks = [asyncio.create_task(self.tcp_connect(ip, p)) for p in ports]
        try:
            results = await asyncio.gather(*tasks, return_exceptions=False)
        except asyncio.CancelledError:
            for t in tasks:
                t.cancel()
            raise
        return tuple(results)

    async def tls_handshake(self, ip: str, port: int, server_hostname: str, alpn: Optional[Sequence[str]] = None) -> Optional[TLSResult]:
        async with self._sem:
            loop = asyncio.get_running_loop()
            try:
                return await asyncio.wait_for(
                    loop.run_in_executor(self._executor, self._blocking_tls, ip, port, server_hostname, alpn),
                    timeout=self._timeout * 2,
                )
            except asyncio.TimeoutError:
                return None

    def _blocking_tls(
        self,
        ip: str,
        port: int,
        server_hostname: str,
        alpn: Optional[Sequence[str]],
    ) -> Optional[TLSResult]:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if alpn:
            with suppress(NotImplementedError):
                ctx.set_alpn_protocols(list(alpn))
        start = time.perf_counter()
        raw = socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(self._timeout)
        try:
            raw.connect((ip, port))
            tls = ctx.wrap_socket(raw, server_hostname=server_hostname)
        except (ssl.SSLError, socket.timeout, OSError):
            with suppress(OSError):
                raw.close()
            return None
        elapsed = int((time.perf_counter() - start) * 1000)
        try:
            version = tls.version()
            cipher = tls.cipher()
            cipher_name = cipher[0] if cipher else None
            cert = tls.getpeercert()
            subject = _name_to_str(cert.get("subject", ()))
            issuer = _name_to_str(cert.get("issuer", ()))
            san = tuple(item[1] for item in cert.get("subjectAltName", ()))
            not_before = cert.get("notBefore")
            not_after = cert.get("notAfter")
        except (ValueError, OSError):
            version = None
            cipher_name = None
            subject = None
            issuer = None
            san = ()
            not_before = None
            not_after = None
        finally:
            with suppress(OSError):
                tls.close()
        return TLSResult(
            version=version,
            cipher=cipher_name,
            connect_ms=elapsed,
            peer_cert_subject=subject,
            peer_cert_issuer=issuer,
            not_before=not_before,
            not_after=not_after,
            san=san,
        )


def _name_to_str(name: Any) -> Optional[str]:
    if not name:
        return None
    parts: list[str] = []
    for rdn in name:
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts) if parts else None


class SocketFactory:
    __slots__ = ("_timeout", "_family", "_sockopts")

    def __init__(
        self,
        timeout: float = 3.0,
        family: int = socket.AF_UNSPEC,
        sockopts: Optional[Mapping[int, int]] = None,
    ) -> None:
        self._timeout = timeout
        self._family = family
        self._sockopts = dict(sockopts) if sockopts else {}

    def tcp(self, ip: str) -> socket.socket:
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(self._timeout)
        for opt, val in self._sockopts.items():
            with suppress(OSError):
                s.setsockopt(socket.SOL_SOCKET, opt, val)
        return s

    def tls_context(self, alpn: Optional[Sequence[str]] = None, verify: bool = False) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        if alpn:
            with suppress(NotImplementedError):
                ctx.set_alpn_protocols(list(alpn))
        return ctx

    def http(self, ip: str, port: int, use_tls: bool, server_hostname: Optional[str] = None) -> socket.socket:
        s = self.tcp(ip)
        s.connect((ip, port))
        if use_tls:
            ctx = self.tls_context(verify=False)
            s = ctx.wrap_socket(s, server_hostname=server_hostname)
        return s

# Define HTTP Response and Parser
@dataclass(slots=True)
class RawHTTPResponse:
    version: str
    status: int
    reason: str
    headers: Mapping[str, str]
    body: bytes
    elapsed_ms: int


class HTTPParser:
    __slots__ = ("_max_header", "_max_body")

    def __init__(self, max_header: int = 65536, max_body: int = 4 * 1024 * 1024) -> None:
        self._max_header = max_header
        self._max_body = max_body

    def parse(self, sock: socket.socket, host: str, elapsed_start: float) -> Optional[RawHTTPResponse]:
        data = bytearray()
        sock.settimeout(5.0)
        while b"\r\n\r\n" not in data:
            try:
                chunk = sock.recv(4096)
            except (socket.timeout, OSError):
                return None
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > self._max_header:
                return None
        head, sep, rest = bytes(data).partition(b"\r\n\r\n")
        if not sep:
            return None
        lines = head.split(b"\r\n")
        if not lines:
            return None
        status_line = lines[0].decode(errors="ignore")
        parts = status_line.split(" ", 2)
        if len(parts) < 2:
            return None
        version = parts[0]
        try:
            status = int(parts[1])
        except ValueError:
            return None
        reason = parts[2] if len(parts) > 2 else ""
        headers = self._parse_headers(lines[1:])
        body = self._read_body(sock, headers, rest)
        elapsed = int((time.perf_counter() - elapsed_start) * 1000)
        return RawHTTPResponse(version=version, status=status, reason=reason, headers=headers, body=body, elapsed_ms=elapsed)

    def _parse_headers(self, lines: Sequence[bytes]) -> Mapping[str, str]:
        out: dict[str, str] = {}
        current_key: Optional[str] = None
        for line in lines:
            if not line:
                continue
            if line[:1] in (b" ", b"\t") and current_key is not None:
                out[current_key] += " " + line.strip().decode(errors="ignore")
                continue
            if b":" not in line:
                continue
            key, _, value = line.partition(b":")
            key_str = key.decode(errors="ignore").strip()
            value_str = value.decode(errors="ignore").strip()
            out[key_str] = value_str
            current_key = key_str
        return out

    def _read_body(self, sock: socket.socket, headers: Mapping[str, str], initial: bytes) -> bytes:
        lower = {k.lower(): v for k, v in headers.items()}
        transfer = lower.get("transfer-encoding", "").lower()
        if "chunked" in transfer:
            return self._read_chunked(sock, initial)
        length_str = lower.get("content-length")
        if length_str is None:
            return initial
        try:
            length = int(length_str)
        except ValueError:
            return initial
        if length > self._max_body:
            length = self._max_body
        body = bytearray(initial)
        sock.settimeout(5.0)
        while len(body) < length:
            try:
                chunk = sock.recv(min(4096, length - len(body)))
            except (socket.timeout, OSError):
                break
            if not chunk:
                break
            body.extend(chunk)
        return bytes(body[:length])

    def _read_chunked(self, sock: socket.socket, initial: bytes) -> bytes:
        buf = bytearray(initial)
        out = bytearray()
        sock.settimeout(5.0)
        while True:
            while b"\r\n" not in buf:
                try:
                    chunk = sock.recv(4096)
                except (socket.timeout, OSError):
                    return bytes(out)
                if not chunk:
                    return bytes(out)
                buf.extend(chunk)
            raw = bytes(buf)
            line, _, rest = raw.partition(b"\r\n")
            buf = bytearray(rest)
            size_str = line.split(b";", 1)[0].strip()
            try:
                size = int(size_str, 16)
            except ValueError:
                return bytes(out)
            if size == 0:
                return bytes(out)
            while len(buf) < size + 2:
                try:
                    chunk = sock.recv(4096)
                except (socket.timeout, OSError):
                    return bytes(out)
                if not chunk:
                    return bytes(out)
                buf.extend(chunk)
            out.extend(buf[:size])
            buf = buf[size + 2:]

# Whois            
class WhoisServerTable:
    __slots__ = ("_table", "_fallback")

    def __init__(self, fallback: str = "whois.iana.org") -> None:
        self._fallback = fallback
        self._table: Mapping[str, str] = {
            "com": "whois.verisign-grs.com",
            "net": "whois.verisign-grs.com",
            "org": "whois.pir.org",
            "edu": "whois.educause.edu",
            "gov": "whois.dotgov.gov",
            "int": "whois.iana.org",
            "io": "whois.nic.io",
            "ai": "whois.nic.ai",
            "co": "whois.nic.co",
            "me": "whois.nic.me",
            "dev": "whois.nic.google",
            "app": "whois.nic.google",
            "page": "whois.nic.google",
            "xyz": "whois.nic.xyz",
            "top": "whois.nic.top",
            "site": "whois.nic.site",
            "online": "whois.nic.online",
            "store": "whois.nic.store",
            "tech": "whois.nic.tech",
            "cloud": "whois.nic.cloud",
            "cn": "whois.cnnic.cn",
            "uk": "whois.nic.uk",
            "de": "whois.denic.de",
            "fr": "whois.nic.fr",
            "jp": "whois.jprs.jp",
            "kr": "whois.kr",
            "ru": "whois.tcinet.ru",
            "br": "whois.registro.br",
            "au": "whois.auda.org.au",
            "ca": "whois.cira.ca",
            "in": "whois.registry.in",
            "it": "whois.nic.it",
            "nl": "whois.domain-registry.nl",
            "se": "whois.iis.se",
            "no": "whois.norid.no",
            "ch": "whois.nic.ch",
            "at": "whois.nic.at",
            "be": "whois.dns.be",
            "pl": "whois.dns.pl",
            "es": "whois.nic.es",
            "mx": "whois.mx",
            "ar": "whois.nic.ar",
            "za": "whois.registry.net.za",
        }

    def lookup(self, domain: str) -> str:
        tld = domain.rsplit(".", 1)[-1].lower() if "." in domain else ""
        return self._table.get(tld, self._fallback)

    def contains(self, tld: str) -> bool:
        return tld.lower() in self._table

    def __len__(self) -> int:
        return len(self._table)

    def __iter__(self) -> Iterator[str]:
        return iter(self._table)

    def __getitem__(self, tld: str) -> str:
        return self._table[tld.lower()]


class WhoisParser:
    __slots__ = ("_fields", "_skip_prefixes")

    def __init__(self) -> None:
        self._fields: Mapping[str, str] = {
            "registrar": "registrar",
            "registrant": "registrant",
            "creation date": "created",
            "created": "created",
            "created on": "created",
            "registry expiry date": "expires",
            "expiry date": "expires",
            "expiration date": "expires",
            "expires": "expires",
            "expires on": "expires",
            "updated date": "updated",
            "last updated": "updated",
            "last updated on": "updated",
            "updated": "updated",
            "name server": "nameserver",
            "nserver": "nameserver",
            "domain status": "status",
            "status": "status",
            "dnssec": "dnssec",
            "registrant organization": "org",
            "org": "org",
            "registrant country": "country",
            "country": "country",
        }
        self._skip_prefixes = ("%", "#", ">>>", "--", "NOTICE", "TERMS", "by")

    def parse(self, raw: str) -> Mapping[str, str]:
        out: dict[str, str] = {}
        nameservers: list[str] = []
        statuses: list[str] = []
        for line in raw.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith(self._skip_prefixes):
                continue
            if ":" not in stripped:
                continue
            key, _, value = stripped.partition(":")
            key_norm = key.strip().lower()
            value_norm = value.strip()
            if not value_norm:
                continue
            mapped = self._fields.get(key_norm)
            if mapped is None:
                continue
            if mapped == "nameserver":
                if value_norm not in nameservers:
                    nameservers.append(value_norm)
                continue
            if mapped == "status":
                if value_norm not in statuses:
                    statuses.append(value_norm)
                continue
            if mapped not in out:
                out[mapped] = value_norm
        if nameservers:
            out["nameservers"] = " | ".join(nameservers)
        if statuses:
            out["statuses"] = " | ".join(statuses)
        return out

    def registrar_from_referral(self, raw: str) -> Optional[str]:
        for line in raw.splitlines():
            lowered = line.lower()
            if "registrar whois server" in lowered and ":" in line:
                return line.split(":", 1)[1].strip()
        return None


class WhoisClient:
    __slots__ = ("_table", "_parser", "_timeout", "_max_bytes", "_port")

    def __init__(
        self,
        table: Optional[WhoisServerTable] = None,
        parser: Optional[WhoisParser] = None,
        timeout: float = 8.0,
        max_bytes: int = 262144,
        port: int = 43,
    ) -> None:
        self._table = table if table is not None else WhoisServerTable()
        self._parser = parser if parser is not None else WhoisParser()
        self._timeout = timeout
        self._max_bytes = max_bytes
        self._port = port

    async def query(self, domain: str, follow_referral: bool = True) -> Optional[WhoisResult]:
        loop = asyncio.get_running_loop()
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(None, self._blocking_query, domain, follow_referral),
                timeout=self._timeout * 3,
            )
        except asyncio.TimeoutError:
            return None
        return result

    def _blocking_query(self, domain: str, follow_referral: bool) -> Optional[WhoisResult]:
        server = self._table.lookup(domain)
        start = time.perf_counter()
        raw = self._fetch(server, domain)
        if not raw:
            return None
        if follow_referral:
            referral = self._parser.registrar_from_referral(raw)
            if referral and referral.lower() != server.lower():
                more = self._fetch(referral, domain)
                if more:
                    raw = raw + "\n" + more
                    server = referral
        elapsed = int((time.perf_counter() - start) * 1000)
        fields = self._parser.parse(raw)
        return WhoisResult(server=server, raw=raw, elapsed_ms=elapsed, fields=fields)

    def _fetch(self, server: str, domain: str) -> str:
        try:
            info = socket.getaddrinfo(server, self._port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except (socket.gaierror, OSError):
            return ""
        if not info:
            return ""
        fam, stype, proto, _, sa = info[0]
        s = socket.socket(fam, stype, proto)
        s.settimeout(self._timeout)
        try:
            s.connect(sa)
            s.sendall((domain + "\r\n").encode("ascii", errors="ignore"))
            chunks = bytearray()
            while len(chunks) < self._max_bytes:
                try:
                    data = s.recv(4096)
                except (socket.timeout, OSError):
                    break
                if not data:
                    break
                chunks.extend(data)
        except (socket.timeout, OSError):
            return ""
        finally:
            with suppress(OSError):
                s.close()
        return chunks.decode(errors="ignore")


class HTTPProbe:
    __slots__ = ("_factory", "_parser", "_timeout", "_user_agent", "_accept")

    def __init__(
        self,
        factory: Optional[SocketFactory] = None,
        parser: Optional[HTTPParser] = None,
        timeout: float = 5.0,
        user_agent: str = "pyScanner/1.0",
        accept: str = "*/*",
    ) -> None:
        self._factory = factory if factory is not None else SocketFactory(timeout=timeout)
        self._parser = parser if parser is not None else HTTPParser()
        self._timeout = timeout
        self._user_agent = user_agent
        self._accept = accept

    async def request(
        self,
        ip: str,
        port: int,
        host: str,
        use_tls: bool = False,
        path: str = "/",
        method: str = "GET",
        extra_headers: Optional[Mapping[str, str]] = None,
    ) -> Optional[HTTPResult]:
        loop = asyncio.get_running_loop()
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, self._blocking_request, ip, port, host, use_tls, path, method, extra_headers),
                timeout=self._timeout * 3,
            )
        except asyncio.TimeoutError:
            return None

    def _blocking_request(
        self,
        ip: str,
        port: int,
        host: str,
        use_tls: bool,
        path: str,
        method: str,
        extra_headers: Optional[Mapping[str, str]],
    ) -> Optional[HTTPResult]:
        start = time.perf_counter()
        try:
            sock = self._factory.http(ip, port, use_tls, host)
        except (socket.timeout, ssl.SSLError, OSError):
            return None
        try:
            request_bytes = self._build_request(method, path, host, extra_headers)
            sock.sendall(request_bytes)
            raw = self._parser.parse(sock, host, start)
        except (socket.timeout, ssl.SSLError, OSError):
            raw = None
        finally:
            with suppress(OSError):
                sock.close()
        if raw is None:
            return None
        headers_lower = {k.lower(): v for k, v in raw.headers.items()}
        server = headers_lower.get("server")
        redirect = headers_lower.get("location")
        title = _extract_title(raw.body)
        return HTTPResult(
            status_code=raw.status,
            reason=raw.reason,
            server=server,
            title=title,
            headers=raw.headers,
            redirect=redirect,
            elapsed_ms=raw.elapsed_ms,
            body_size=len(raw.body),
        )

    def _build_request(
        self,
        method: str,
        path: str,
        host: str,
        extra_headers: Optional[Mapping[str, str]],
    ) -> bytes:
        lines = [f"{method} {path} HTTP/1.1"]
        headers: dict[str, str] = {
            "Host": host,
            "User-Agent": self._user_agent,
            "Accept": self._accept,
            "Connection": "close",
        }
        if extra_headers:
            headers.update(extra_headers)
        for key, value in headers.items():
            lines.append(f"{key}: {value}")
        return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1", errors="replace")

    async def follow_redirects(
        self,
        ip: str,
        port: int,
        host: str,
        use_tls: bool,
        max_hops: int = 5,
    ) -> Optional[HTTPResult]:
        current_ip = ip
        current_port = port
        current_host = host
        current_tls = use_tls
        current_path = "/"
        last: Optional[HTTPResult] = None
        for _ in range(max_hops):
            result = await self.request(current_ip, current_port, current_host, current_tls, current_path)
            if result is None:
                return last
            last = result
            if result.status_code is None:
                return last
            if result.status_code < 300 or result.status_code >= 400:
                return last
            if not result.redirect:
                return last
            target = result.redirect
            if target.startswith("https://"):
                current_tls = True
                target = target[8:]
                current_port = 443
            elif target.startswith("http://"):
                current_tls = False
                target = target[7:]
                current_port = 80
            host_part, _, path_part = target.partition("/")
            if ":" in host_part:
                host_part, _, port_str = host_part.partition(":")
                with suppress(ValueError):
                    current_port = int(port_str)
            current_host = host_part
            current_path = "/" + path_part if path_part else "/"
            try:
                infos = socket.getaddrinfo(current_host, current_port, socket.AF_INET, socket.SOCK_STREAM)
                if infos:
                    current_ip = infos[0][4][0]
            except (socket.gaierror, OSError):
                return last
        return last


def _extract_title(body: bytes, max_len: int = 256) -> Optional[str]:
    if not body:
        return None
    lowered = body.lower()
    start = lowered.find(b"<title")
    if start == -1:
        return None
    gt = body.find(b">", start)
    if gt == -1:
        return None
    end = lowered.find(b"</title>", gt)
    if end == -1:
        return None
    raw = body[gt + 1:end]
    if len(raw) > max_len:
        raw = raw[:max_len]
    text = raw.decode(errors="ignore").strip()
    return text or None

# TLS Fingerprint
class TLSFingerprint:
    __slots__ = ("_alpn", "_ciphers")

    def __init__(self, alpn: Optional[Sequence[str]] = None) -> None:
        self._alpn = tuple(alpn) if alpn else ("h2", "http/1.1")
        self._ciphers = (
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-CHACHA20-POLY1305",
            "ECDHE-RSA-CHACHA20-POLY1305",
        )

    @property
    def alpn(self) -> tuple[str, ...]:
        return self._alpn

    @property
    def ciphers(self) -> tuple[str, ...]:
        return self._ciphers

    def context(self, verify: bool = False) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        with suppress(ssl.SSLError):
            ctx.set_ciphers(":".join(self._ciphers))
        with suppress(NotImplementedError):
            ctx.set_alpn_protocols(list(self._alpn))
        return ctx

    def describe(self) -> Mapping[str, Any]:
        return {
            "alpn": self._alpn,
            "ciphers": self._ciphers,
        }


class Fingerprint:
    __slots__ = ("_server", "_powered_by", "_cookies", "_hsts", "_csp")

    def __init__(self, headers: Mapping[str, str]) -> None:
        lower = {k.lower(): v for k, v in headers.items()}
        self._server = lower.get("server")
        self._powered_by = lower.get("x-powered-by")
        self._cookies = lower.get("set-cookie")
        self._hsts = lower.get("strict-transport-security")
        self._csp = lower.get("content-security-policy")

    @property
    def server(self) -> Optional[str]:
        return self._server

    @property
    def powered_by(self) -> Optional[str]:
        return self._powered_by

    @property
    def has_hsts(self) -> bool:
        return self._hsts is not None

    @property
    def has_csp(self) -> bool:
        return self._csp is not None

    @property
    def cookies(self) -> tuple[str, ...]:
        if not self._cookies:
            return ()
        return tuple(part.strip() for part in self._cookies.split(",") if part.strip())

    def guess_stack(self) -> tuple[str, ...]:
        tokens: list[str] = []
        haystack = " ".join(filter(None, [self._server, self._powered_by])).lower()
        table = {
            "nginx": "nginx",
            "apache": "apache",
            "iis": "iis",
            "cloudflare": "cloudflare",
            "openresty": "openresty",
            "caddy": "caddy",
            "gunicorn": "gunicorn",
            "uvicorn": "uvicorn",
            "express": "node-express",
            "php": "php",
            "asp.net": "aspnet",
            "tomcat": "tomcat",
            "jetty": "jetty",
        }
        for needle, label in table.items():
            if needle in haystack and label not in tokens:
                tokens.append(label)
        return tuple(tokens)

    def to_mapping(self) -> Mapping[str, Any]:
        return {
            "server": self._server,
            "powered_by": self._powered_by,
            "has_hsts": self.has_hsts,
            "has_csp": self.has_csp,
            "cookies": self.cookies,
            "stack": self.guess_stack(),
        }
        
class StageResult:
    __slots__ = ("name", "status", "elapsed_ms", "payload", "error")

    def __init__(
        self,
        name: str,
        status: int,
        elapsed_ms: int,
        payload: Any = None,
        error: Optional[str] = None,
    ) -> None:
        self.name = name
        self.status = status
        self.elapsed_ms = elapsed_ms
        self.payload = payload
        self.error = error

    @property
    def ok(self) -> bool:
        return self.status == STATUS_SUCCESS

    def to_mapping(self) -> Mapping[str, Any]:
        return {
            "name": self.name,
            "status": f"0x{self.status:08X}",
            "ok": self.ok,
            "elapsed_ms": self.elapsed_ms,
            "error": self.error,
        }


@dataclass(slots=True)
class ScanConfig:
    host: str
    ports: tuple[int, ...] = DEFAULT_PORTS
    timeout: float = DEFAULT_TIMEOUT
    concurrency: int = 256
    resolve_ttl: float = 300.0
    banner_ports: tuple[int, ...] = (22, 21, 25, 110, 143, 3306, 6379)
    enable_whois: bool = True
    enable_http: bool = True
    enable_tls: bool = True
    follow_redirects: bool = False
    max_redirect_hops: int = 5
    user_agent: str = "pyScanner/1.0"
    alpn: tuple[str, ...] = ("h2", "http/1.1")
    verbose: bool = False

    def validate(self) -> int:
        if not self.host or "." not in self.host:
            return STATUS_INVALID_PARAMETER
        if self.timeout <= 0 or self.timeout > 120:
            return STATUS_INVALID_PARAMETER
        if self.concurrency <= 0 or self.concurrency > 4096:
            return STATUS_INVALID_PARAMETER
        if not self.ports:
            return STATUS_INVALID_PARAMETER
        for port in self.ports:
            if port <= 0 or port > 65535:
                return STATUS_INVALID_PARAMETER
        return STATUS_SUCCESS


class StageTimer:
    __slots__ = ("_name", "_start", "_end")

    def __init__(self, name: str) -> None:
        self._name = name
        self._start = 0.0
        self._end = 0.0

    def __enter__(self) -> "StageTimer":
        self._start = time.perf_counter()
        return self

    def __exit__(self, *exc: object) -> None:
        self._end = time.perf_counter()

    @property
    def elapsed_ms(self) -> int:
        end = self._end if self._end else time.perf_counter()
        return int((end - self._start) * 1000)

    @property
    def name(self) -> str:
        return self._name


class ScanContext:
    __slots__ = (
        "config",
        "resolver",
        "probe",
        "whois",
        "http",
        "factory",
        "fingerprint",
        "stages",
        "started_at",
        "_executor",
    )

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self._executor = ThreadPoolExecutor(max_workers=min(64, config.concurrency))
        self.resolver = Resolver(
            ttl=config.resolve_ttl,
            timeout=config.timeout,
            executor=self._executor,
        )
        self.probe = AsyncProbe(
            timeout=config.timeout,
            concurrency=config.concurrency,
            executor=self._executor,
        )
        self.factory = SocketFactory(timeout=config.timeout)
        self.whois = WhoisClient(timeout=config.timeout)
        self.http = HTTPProbe(
            factory=self.factory,
            timeout=config.timeout,
            user_agent=config.user_agent,
        )
        self.fingerprint = TLSFingerprint(alpn=config.alpn)
        self.stages: list[StageResult] = []
        self.started_at = 0.0

    async def __aenter__(self) -> "ScanContext":
        await self.resolver.__aenter__()
        self.started_at = time.perf_counter()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.resolver.__aexit__(*exc)
        self._executor.shutdown(wait=False, cancel_futures=True)

    def record(self, result: StageResult) -> StageResult:
        self.stages.append(result)
        return result

    @property
    def total_elapsed_ms(self) -> int:
        if not self.started_at:
            return 0
        return int((time.perf_counter() - self.started_at) * 1000)


class ScanOrchestrator:
    __slots__ = ("_config", "_log")

    def __init__(self, config: ScanConfig, log: Optional[Callable[[str], None]] = None) -> None:
        self._config = config
        self._log = log if log is not None else (lambda msg: None)

    def _emit(self, msg: str) -> None:
        if self._config.verbose:
            self._log(msg)

    async def run(self) -> ScanReport:
        cfg = self._config
        validation = cfg.validate()
        if validation != STATUS_SUCCESS:
            return ScanReport(
                host=cfg.host,
                addresses=(),
                ports=(),
                tls=None,
                http=None,
                whois=None,
                resolve_ms=0,
                total_ms=0,
                status=validation,
                flags=Flag.NONE,
            )

        async with ScanContext(cfg) as ctx:
            addresses = await self._stage_resolve(ctx)
            if not addresses:
                return ScanReport(
                    host=cfg.host,
                    addresses=(),
                    ports=(),
                    tls=None,
                    http=None,
                    whois=None,
                    resolve_ms=self._last_stage_ms(ctx, "resolve"),
                    total_ms=ctx.total_elapsed_ms,
                    status=STATUS_UNSUCCESSFUL,
                    flags=Flag.NONE,
                )

            primary = addresses[0]
            ports = await self._stage_ports(ctx, primary.ip)
            open_ports = tuple(p.port for p in ports if p.open)

            tls_result: Optional[TLSResult] = None
            if cfg.enable_tls and 443 in open_ports:
                tls_result = await self._stage_tls(ctx, primary.ip)

            http_result: Optional[HTTPResult] = None
            if cfg.enable_http:
                http_result = await self._stage_http(ctx, primary.ip, open_ports)

            whois_result: Optional[WhoisResult] = None
            if cfg.enable_whois:
                whois_result = await self._stage_whois(ctx)

            flags = self._compute_flags(addresses, open_ports, tls_result, http_result, whois_result)
            status = STATUS_SUCCESS if open_ports or addresses else STATUS_UNSUCCESSFUL

            return ScanReport(
                host=cfg.host,
                addresses=addresses,
                ports=ports,
                tls=tls_result,
                http=http_result,
                whois=whois_result,
                resolve_ms=self._last_stage_ms(ctx, "resolve"),
                total_ms=ctx.total_elapsed_ms,
                status=status,
                flags=flags,
            )

    async def _stage_resolve(self, ctx: ScanContext) -> tuple[Address, ...]:
        with StageTimer("resolve") as timer:
            addresses = await ctx.resolver.resolve(self._config.host)
        self._emit(f"resolve: {len(addresses)} address(es) in {timer.elapsed_ms}ms")
        ctx.record(StageResult("resolve", STATUS_SUCCESS if addresses else STATUS_UNSUCCESSFUL, timer.elapsed_ms, addresses))
        return addresses

    async def _stage_ports(self, ctx: ScanContext, ip: str) -> tuple[PortResult, ...]:
        with StageTimer("ports") as timer:
            ports = await ctx.probe.scan_ports(ip, self._config.ports)
        open_ports = tuple(p for p in ports if p.open)
        self._emit(f"ports: {len(open_ports)}/{len(ports)} open in {timer.elapsed_ms}ms")
        ctx.record(StageResult("ports", STATUS_SUCCESS if ports else STATUS_UNSUCCESSFUL, timer.elapsed_ms, ports))
        return ports

    async def _stage_tls(self, ctx: ScanContext, ip: str) -> Optional[TLSResult]:
        with StageTimer("tls") as timer:
            result = await ctx.probe.tls_handshake(ip, 443, self._config.host, self._config.alpn)
        if result is not None:
            self._emit(f"tls: {result.version} {result.cipher} in {timer.elapsed_ms}ms")
        ctx.record(StageResult("tls", STATUS_SUCCESS if result else STATUS_UNSUCCESSFUL, timer.elapsed_ms, result))
        return result

    async def _stage_http(
        self,
        ctx: ScanContext,
        ip: str,
        open_ports: tuple[int, ...],
    ) -> Optional[HTTPResult]:
        target_port: Optional[int] = None
        use_tls = False
        if 443 in open_ports:
            target_port = 443
            use_tls = True
        elif 80 in open_ports:
            target_port = 80
            use_tls = False
        elif 8080 in open_ports:
            target_port = 8080
            use_tls = False
        elif 8443 in open_ports:
            target_port = 8443
            use_tls = True
        if target_port is None:
            ctx.record(StageResult("http", STATUS_UNSUCCESSFUL, 0, None, "no http port open"))
            return None

        with StageTimer("http") as timer:
            if self._config.follow_redirects:
                result = await ctx.http.follow_redirects(
                    ip,
                    target_port,
                    self._config.host,
                    use_tls,
                    self._config.max_redirect_hops,
                )
            else:
                result = await ctx.http.request(ip, target_port, self._config.host, use_tls)
        if result is not None:
            self._emit(f"http: {result.status_code} {result.server or '-'} in {timer.elapsed_ms}ms")
        ctx.record(StageResult("http", STATUS_SUCCESS if result else STATUS_UNSUCCESSFUL, timer.elapsed_ms, result))
        return result

    async def _stage_whois(self, ctx: ScanContext) -> Optional[WhoisResult]:
        with StageTimer("whois") as timer:
            result = await ctx.whois.query(self._config.host)
        if result is not None:
            self._emit(f"whois: {result.server} {len(result.fields)} field(s) in {timer.elapsed_ms}ms")
        ctx.record(StageResult("whois", STATUS_SUCCESS if result else STATUS_UNSUCCESSFUL, timer.elapsed_ms, result))
        return result

    def _compute_flags(
        self,
        addresses: tuple[Address, ...],
        open_ports: tuple[int, ...],
        tls: Optional[TLSResult],
        http: Optional[HTTPResult],
        whois: Optional[WhoisResult],
    ) -> Flag:
        flags = Flag.NONE
        if addresses:
            flags |= Flag.DNS_OK
        if open_ports:
            flags |= Flag.TCP_OK
        if tls is not None:
            flags |= Flag.TLS_OK
        if http is not None:
            flags |= Flag.HTTP_OK
            if http.title:
                flags |= Flag.TITLE_OK
            if http.redirect and http.status_code in (301, 302, 303, 307, 308):
                flags |= Flag.REDIRECT
        if whois is not None:
            flags |= Flag.WHOIS_OK
        return flags

    def _last_stage_ms(self, ctx: ScanContext, name: str) -> int:
        for stage in reversed(ctx.stages):
            if stage.name == name:
                return stage.elapsed_ms
        return 0


class BatchScanner:
    __slots__ = ("_configs", "_concurrency", "_log", "_results")

    def __init__(
        self,
        configs: Sequence[ScanConfig],
        concurrency: int = 8,
        log: Optional[Callable[[str], None]] = None,
    ) -> None:
        self._configs = tuple(configs)
        self._concurrency = concurrency
        self._log = log if log is not None else (lambda msg: None)
        self._results: list[ScanReport] = []

    async def run(self) -> tuple[ScanReport, ...]:
        sem = asyncio.Semaphore(self._concurrency)

        async def worker(cfg: ScanConfig) -> ScanReport:
            async with sem:
                orchestrator = ScanOrchestrator(cfg, self._log)
                return await orchestrator.run()

        tasks = [asyncio.create_task(worker(cfg)) for cfg in self._configs]
        try:
            results = await asyncio.gather(*tasks, return_exceptions=False)
        except asyncio.CancelledError:
            for task in tasks:
                task.cancel()
            raise
        self._results.extend(results)
        return tuple(results)

    @property
    def results(self) -> tuple[ScanReport, ...]:
        return tuple(self._results)

    def summary(self) -> Mapping[str, Any]:
        total = len(self._results)
        success = sum(1 for r in self._results if r.status == STATUS_SUCCESS)
        failed = total - success
        return {
            "total": total,
            "success": success,
            "failed": failed,
            "hosts": tuple(r.host for r in self._results),
        }


class ScanPipeline:
    __slots__ = ("_stages",)

    def __init__(self) -> None:
        self._stages: list[Callable[[ScanReport], Awaitable[ScanReport]]] = []

    def add(self, stage: Callable[[ScanReport], Awaitable[ScanReport]]) -> "ScanPipeline":
        self._stages.append(stage)
        return self

    def extend(self, stages: Sequence[Callable[[ScanReport], Awaitable[ScanReport]]]) -> "ScanPipeline":
        self._stages.extend(stages)
        return self

    async def execute(self, report: ScanReport) -> ScanReport:
        current = report
        for stage in self._stages:
            current = await stage(current)
        return current

    def __len__(self) -> int:
        return len(self._stages)

    def __iter__(self) -> Iterator[Callable[[ScanReport], Awaitable[ScanReport]]]:
        return iter(self._stages)


class ResultAggregator:
    __slots__ = ("_reports", "_lock")

    def __init__(self) -> None:
        self._reports: list[ScanReport] = []
        self._lock = asyncio.Lock()

    async def add(self, report: ScanReport) -> None:
        async with self._lock:
            self._reports.append(report)

    async def extend(self, reports: Sequence[ScanReport]) -> None:
        async with self._lock:
            self._reports.extend(reports)

    @property
    def reports(self) -> tuple[ScanReport, ...]:
        return tuple(self._reports)

    def by_status(self, status: int) -> tuple[ScanReport, ...]:
        return tuple(r for r in self._reports if r.status == status)

    def by_flag(self, flag: Flag) -> tuple[ScanReport, ...]:
        return tuple(r for r in self._reports if r.flags & flag)

    def open_port_histogram(self) -> Mapping[int, int]:
        histogram: dict[int, int] = {}
        for report in self._reports:
            for port in report.open_ports:
                histogram[port] = histogram.get(port, 0) + 1
        return dict(sorted(histogram.items(), key=lambda item: item[1], reverse=True))

    def server_histogram(self) -> Mapping[str, int]:
        histogram: dict[str, int] = {}
        for report in self._reports:
            if report.http and report.http.server:
                key = report.http.server
                histogram[key] = histogram.get(key, 0) + 1
        return dict(sorted(histogram.items(), key=lambda item: item[1], reverse=True))

    def as_records(self) -> tuple[Record, ...]:
        return tuple(r.to_record() for r in self._reports)

    def to_jsonable(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for report in self._reports:
            out.append(
                {
                    "host": report.host,
                    "status": f"0x{report.status:08X}",
                    "flags": f"0x{int(report.flags):04X}",
                    "addresses": [addr.ip for addr in report.addresses],
                    "open_ports": list(report.open_ports),
                    "resolve_ms": report.resolve_ms,
                    "total_ms": report.total_ms,
                    "tls": None if report.tls is None else {
                        "version": report.tls.version,
                        "cipher": report.tls.cipher,
                        "subject": report.tls.peer_cert_subject,
                        "issuer": report.tls.peer_cert_issuer,
                    },
                    "http": None if report.http is None else {
                        "status": report.http.status_code,
                        "server": report.http.server,
                        "title": report.http.title,
                        "redirect": report.http.redirect,
                        "body_size": report.http.body_size,
                    },
                    "whois": None if report.whois is None else {
                        "server": report.whois.server,
                        "fields": dict(report.whois.fields),
                    },
                }
            )
        return out  
                              
# ANSI Colors       
class ANSI:
    RESET = "\x1b[0m"
    BOLD = "\x1b[1m"
    DIM = "\x1b[2m"
    ITALIC = "\x1b[3m"
    UNDERLINE = "\x1b[4m"
    BLINK = "\x1b[5m"
    REVERSE = "\x1b[7m"
    HIDDEN = "\x1b[8m"

    BLACK = "\x1b[30m"
    RED = "\x1b[31m"
    GREEN = "\x1b[32m"
    YELLOW = "\x1b[33m"
    BLUE = "\x1b[34m"
    MAGENTA = "\x1b[35m"
    CYAN = "\x1b[36m"
    WHITE = "\x1b[37m"

    BRIGHT_BLACK = "\x1b[90m"
    BRIGHT_RED = "\x1b[91m"
    BRIGHT_GREEN = "\x1b[92m"
    BRIGHT_YELLOW = "\x1b[93m"
    BRIGHT_BLUE = "\x1b[94m"
    BRIGHT_MAGENTA = "\x1b[95m"
    BRIGHT_CYAN = "\x1b[96m"
    BRIGHT_WHITE = "\x1b[97m"

    BG_BLACK = "\x1b[40m"
    BG_RED = "\x1b[41m"
    BG_GREEN = "\x1b[42m"
    BG_YELLOW = "\x1b[43m"
    BG_BLUE = "\x1b[44m"

    @staticmethod
    def wrap(text: str, *codes: str) -> str:
        if not codes:
            return text
        return "".join(codes) + text + ANSI.RESET

    @staticmethod
    def enabled() -> bool:
        return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


class Palette:
    __slots__ = ("_on",)

    def __init__(self, enabled: Optional[bool] = None) -> None:
        self._on = ANSI.enabled() if enabled is None else enabled

    def _paint(self, text: str, *codes: str) -> str:
        if not self._on:
            return text
        return ANSI.wrap(text, *codes)

    def success(self, text: str) -> str:
        return self._paint(text, ANSI.BRIGHT_GREEN)

    def failure(self, text: str) -> str:
        return self._paint(text, ANSI.BRIGHT_RED)

    def warning(self, text: str) -> str:
        return self._paint(text, ANSI.BRIGHT_YELLOW)

    def info(self, text: str) -> str:
        return self._paint(text, ANSI.BRIGHT_CYAN)

    def muted(self, text: str) -> str:
        return self._paint(text, ANSI.BRIGHT_BLACK)

    def bold(self, text: str) -> str:
        return self._paint(text, ANSI.BOLD)

    def key(self, text: str) -> str:
        return self._paint(text, ANSI.BOLD, ANSI.BRIGHT_BLUE)

    def value(self, text: str) -> str:
        return self._paint(text, ANSI.WHITE)

    def port_open(self, text: str) -> str:
        return self._paint(text, ANSI.BOLD, ANSI.BRIGHT_GREEN)

    def port_closed(self, text: str) -> str:
        return self._paint(text, ANSI.BRIGHT_BLACK)

    def status_code(self, code: Optional[int]) -> str:
        if code is None:
            return self._paint("-", ANSI.BRIGHT_BLACK)
        text = str(code)
        if 200 <= code < 300:
            return self._paint(text, ANSI.BRIGHT_GREEN)
        if 300 <= code < 400:
            return self._paint(text, ANSI.BRIGHT_CYAN)
        if 400 <= code < 500:
            return self._paint(text, ANSI.BRIGHT_YELLOW)
        if 500 <= code < 600:
            return self._paint(text, ANSI.BRIGHT_RED)
        return self._paint(text, ANSI.WHITE)


class Column:
    __slots__ = ("header", "width", "align", "formatter")

    def __init__(
        self,
        header: str,
        width: int,
        align: str = "left",
        formatter: Optional[Callable[[Any], str]] = None,
    ) -> None:
        self.header = header
        self.width = width
        self.align = align
        self.formatter = formatter if formatter is not None else (lambda v: str(v))

    def render_header(self) -> str:
        return self._fit(self.header)

    def render_cell(self, value: Any) -> str:
        return self._fit(self.formatter(value))

    def _fit(self, text: str) -> str:
        visible = _strip_ansi(text)
        length = len(visible)
        if length > self.width:
            return text[: self.width]
        pad = self.width - length
        if self.align == "right":
            return " " * pad + text
        if self.align == "center":
            left = pad // 2
            right = pad - left
            return " " * left + text + " " * right
        return text + " " * pad


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


class Table:
    __slots__ = ("_columns", "_rows", "_separator", "_palette", "_border")

    def __init__(
        self,
        columns: Sequence[Column],
        separator: str = "  ",
        palette: Optional[Palette] = None,
        border: bool = False,
    ) -> None:
        self._columns = tuple(columns)
        self._rows: list[tuple[Any, ...]] = []
        self._separator = separator
        self._palette = palette if palette is not None else Palette(enabled=False)
        self._border = border

    def add(self, *values: Any) -> "Table":
        if len(values) != len(self._columns):
            raise ValueError(f"expected {len(self._columns)} values, got {len(values)}")
        self._rows.append(tuple(values))
        return self

    def extend(self, rows: Iterable[Sequence[Any]]) -> "Table":
        for row in rows:
            self.add(*row)
        return self

    def render(self) -> str:
        lines: list[str] = []
        header_cells = [self._palette.bold(col.render_header()) for col in self._columns]
        header_line = self._separator.join(header_cells)
        lines.append(header_line)
        if self._border:
            total_width = sum(col.width for col in self._columns) + len(self._separator) * (len(self._columns) - 1)
            lines.append(self._palette.muted("-" * total_width))
        for row in self._rows:
            cells: list[str] = []
            for col, value in zip(self._columns, row):
                cells.append(col.render_cell(value))
            lines.append(self._separator.join(cells))
        return "\n".join(lines)

    def __len__(self) -> int:
        return len(self._rows)


class HexDumpRenderer:
    __slots__ = ("_width", "_base", "_palette", "_show_ascii", "_show_offset")

    def __init__(
        self,
        width: int = 0x10,
        base: int = 0x0000,
        palette: Optional[Palette] = None,
        show_ascii: bool = True,
        show_offset: bool = True,
    ) -> None:
        self._width = width
        self._base = base
        self._palette = palette if palette is not None else Palette(enabled=False)
        self._show_ascii = show_ascii
        self._show_offset = show_offset

    def render(self, data: bytes, limit: Optional[int] = None) -> str:
        if limit is not None:
            data = data[:limit]
        lines: list[str] = []
        for row in range(0, len(data), self._width):
            chunk = data[row:row + self._width]
            parts: list[str] = []
            if self._show_offset:
                addr = self._base + row
                parts.append(self._palette.muted(f"0x{addr:08X}"))
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            hex_part = hex_part.ljust(self._width * 3 - 1)
            parts.append(self._palette.value(hex_part))
            if self._show_ascii:
                ascii_part = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in chunk)
                parts.append(self._palette.info("|" + ascii_part + "|"))
            lines.append("  ".join(parts))
        return "\n".join(lines)

class Renderer:
    __slots__ = ("_palette", "_width")

    def __init__(self, palette: Optional[Palette] = None, width: int = 78) -> None:
        self._palette = palette if palette is not None else Palette()
        self._width = width

    def _kv(self, key: str, value: str, key_width: int = 12) -> str:
        return f"{self._palette.key(key.ljust(key_width))} {value}"

    def render_report(self, report: ScanReport) -> str:
        lines: list[str] = []
        lines.append(self._palette.bold(report.host))
        lines.append(self._kv("status", self._render_status(report.status)))
        lines.append(self._kv("flags", self._render_flags(report.flags)))
        lines.append(self._kv("resolve", self._palette.value(f"{report.resolve_ms} ms")))
        lines.append(self._kv("total", self._palette.value(f"{report.total_ms} ms")))
        lines.append(self._kv("addresses", self._palette.value(str(len(report.addresses)))))
        for addr in report.addresses:
            lines.append(" " * 13 + self._palette.info(f"{addr.ip} (IPv{addr.version})"))
        lines.append(self._kv("open ports", self._render_ports(report.open_ports)))
        if report.tls is not None:
            lines.append(self._palette.key("tls".ljust(12)))
            lines.append(" " * 13 + self._palette.value(f"version  {report.tls.version or '-'}"))
            lines.append(" " * 13 + self._palette.value(f"cipher   {report.tls.cipher or '-'}"))
            if report.tls.peer_cert_subject:
                lines.append(" " * 13 + self._palette.value(f"subject  {report.tls.peer_cert_subject}"))
            if report.tls.peer_cert_issuer:
                lines.append(" " * 13 + self._palette.value(f"issuer   {report.tls.peer_cert_issuer}"))
            if report.tls.not_after:
                lines.append(" " * 13 + self._palette.value(f"expires  {report.tls.not_after}"))
        if report.http is not None:
            lines.append(self._palette.key("http".ljust(12)))
            lines.append(" " * 13 + self._palette.value("status   ") + self._palette.status_code(report.http.status_code))
            lines.append(" " * 13 + self._palette.value(f"server   {report.http.server or '-'}"))
            if report.http.title:
                lines.append(" " * 13 + self._palette.value(f"title    {report.http.title}"))
            if report.http.redirect:
                lines.append(" " * 13 + self._palette.value(f"redirect {report.http.redirect}"))
            lines.append(" " * 13 + self._palette.value(f"size     {report.http.body_size} bytes"))
        if report.whois is not None:
            lines.append(self._palette.key("whois".ljust(12)))
            lines.append(" " * 13 + self._palette.value(f"server   {report.whois.server}"))
            for field_key in ("registrar", "created", "expires", "updated", "org", "country"):
                if field_key in report.whois.fields:
                    value = report.whois.fields[field_key]
                    lines.append(" " * 13 + self._palette.value(f"{field_key:<8} {value}"))
            if "nameservers" in report.whois.fields:
                ns = report.whois.fields["nameservers"].split(" | ")
                lines.append(" " * 13 + self._palette.value("ns       " + ns[0]))
                for extra in ns[1:]:
                    lines.append(" " * 13 + self._palette.value("         " + extra))
        return "\n".join(lines)

    def _render_ports(self, ports: tuple[int, ...]) -> str:
        if not ports:
            return self._palette.muted("none")
        return " ".join(self._palette.port_open(str(p)) for p in ports)

    def render_ports_table(self, report: ScanReport) -> str:
        columns = [
            Column("PORT", 6, "right", lambda v: str(v.port)),
            Column("STATE", 6, "left", lambda v: self._palette.port_open("open") if v.open else self._palette.port_closed("closed")),
            Column("TIME", 8, "right", lambda v: f"{v.connect_ms}ms"),
            Column("BANNER", 48, "left", lambda v: (v.banner or "")[:48]),
        ]
        table = Table(columns, palette=self._palette)
        for port in report.ports:
            table.add(port)
        return table.render()

    def render_batch_table(self, reports: Sequence[ScanReport]) -> str:
        columns = [
            Column("HOST", 32, "left", lambda r: r.host),
            Column("IP", 16, "left", lambda r: r.primary_ip or "-"),
            Column("STATUS", 10, "left", lambda r: self._palette.success("OK") if r.status == STATUS_SUCCESS else self._palette.failure("FAIL")),
            Column("PORTS", 6, "right", lambda r: str(len(r.open_ports))),
            Column("HTTP", 5, "right", lambda r: str(r.http.status_code) if r.http and r.http.status_code else "-"),
            Column("MS", 6, "right", lambda r: str(r.total_ms)),
        ]
        table = Table(columns, palette=self._palette)
        for report in reports:
            table.add(report)
        return table.render()

    def render_hexdump(self, record: Record, limit: Optional[int] = 0x0100) -> str:
        renderer = HexDumpRenderer(width=0x10, base=0x0000, palette=self._palette)
        return renderer.render(record.raw, limit=limit)

    def _render_status(self, status: int) -> str:
        name = NTSTATUS_NAMES.get(status, "STATUS_UNKNOWN")
        text = f"0x{status:08X} {name}"
        if status == STATUS_SUCCESS:
            return self._palette.success(text)
        if status == STATUS_INVALID_PARAMETER:
            return self._palette.warning(text)
        return self._palette.failure(text)

    def _render_flags(self, flags: Flag) -> str:
        if flags == Flag.NONE:
            return self._palette.muted("0x0000")
        active = [f.name for f in Flag if f != Flag.NONE and flags & f]
        return self._palette.info(f"0x{int(flags):04X}") + " " + self._palette.muted("[" + ",".join(active) + "]")

    def render_stages(self, stages: Sequence[StageResult]) -> str:
        columns = [
            Column("STAGE", 10, "left", lambda s: s.name),
            Column("OK", 4, "center", lambda s: self._palette.success("yes") if s.ok else self._palette.failure("no")),
            Column("MS", 7, "right", lambda s: str(s.elapsed_ms)),
            Column("ERROR", 40, "left", lambda s: s.error or ""),
        ]
        table = Table(columns, palette=self._palette)
        for stage in stages:
            table.add(stage)
        return table.render()

class ReportExporter:
    __slots__ = ("_indent",)

    def __init__(self, indent: int = 2) -> None:
        self._indent = indent

    def to_json(self, reports: Sequence[ScanReport]) -> str:
        aggregator = ResultAggregator()
        for report in reports:
            aggregator._reports.append(report)
        return json.dumps(aggregator.to_jsonable(), indent=self._indent, ensure_ascii=False)

    def to_csv(self, reports: Sequence[ScanReport]) -> str:
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow([
            "host", "status", "flags", "primary_ip", "open_ports",
            "resolve_ms", "total_ms", "tls_version", "http_status", "server", "title",
        ])
        for report in reports:
            writer.writerow([
                report.host,
                f"0x{report.status:08X}",
                f"0x{int(report.flags):04X}",
                report.primary_ip or "",
                "|".join(str(p) for p in report.open_ports),
                report.resolve_ms,
                report.total_ms,
                report.tls.version if report.tls else "",
                report.http.status_code if report.http and report.http.status_code else "",
                report.http.server if report.http and report.http.server else "",
                report.http.title if report.http and report.http.title else "",
            ])
        return buffer.getvalue()

    def to_jsonl(self, reports: Sequence[ScanReport]) -> str:
        aggregator = ResultAggregator()
        for report in reports:
            aggregator._reports.append(report)
        return "\n".join(json.dumps(item, ensure_ascii=False) for item in aggregator.to_jsonable())

    def write(self, reports: Sequence[ScanReport], path: str, fmt: str = "json") -> int:
        fmt = fmt.lower()
        if fmt == "json":
            payload = self.to_json(reports)
        elif fmt == "csv":
            payload = self.to_csv(reports)
        elif fmt == "jsonl":
            payload = self.to_jsonl(reports)
        else:
            return STATUS_INVALID_PARAMETER
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(payload)
        except OSError:
            return STATUS_ACCESS_DENIED
        return STATUS_SUCCESS


class ProgressBar:
    __slots__ = ("_total", "_width", "_palette", "_start", "_count", "_label")

    def __init__(self, total: int, label: str = "", width: int = 40, palette: Optional[Palette] = None) -> None:
        self._total = max(total, 1)
        self._width = width
        self._palette = palette if palette is not None else Palette()
        self._start = time.perf_counter()
        self._count = 0
        self._label = label

    def update(self, n: int = 1) -> None:
        self._count += n
        self._draw()

    def _draw(self) -> None:
        ratio = min(self._count / self._total, 1.0)
        filled = int(ratio * self._width)
        bar = "=" * filled + "-" * (self._width - filled)
        pct = f"{ratio * 100:5.1f}%"
        elapsed = time.perf_counter() - self._start
        eta = (elapsed / ratio - elapsed) if ratio > 0 else 0.0
        line = f"{self._label} [{bar}] {pct} {self._count}/{self._total} eta {eta:5.1f}s"
        sys.stderr.write("\r" + line)
        sys.stderr.flush()

    def finish(self) -> None:
        self._count = self._total
        self._draw()
        sys.stderr.write("\n")
        sys.stderr.flush()


class Spinner:
    FRAMES = ("|", "/", "-", "\\")

    def __init__(self, label: str = "") -> None:
        self._label = label
        self._idx = 0
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def _spin(self) -> None:
        while self._running:
            frame = self.FRAMES[self._idx % len(self.FRAMES)]
            sys.stderr.write(f"\r{self._label} {frame}")
            sys.stderr.flush()
            self._idx += 1
            time.sleep(0.1)

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=1.0)
        sys.stderr.write("\r" + " " * (len(self._label) + 2) + "\r")
        sys.stderr.flush()  

class ArgParser:
    __slots__ = ("_parser",)

    def __init__(self) -> None:
        self._parser = argparse.ArgumentParser(
            prog="pyScanner",
            description="domain reconnaissance scanner",
            add_help=True,
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        self._build()

    def _build(self) -> None:
        self._parser.add_argument("hosts", nargs="*", help="one or more domains")
        self._parser.add_argument("-f", "--file", dest="host_file", default=None, help="read hosts from file")
        self._parser.add_argument("-p", "--ports", dest="ports", default=None, help="comma list or range, e.g. 80,443,8000-8100")
        self._parser.add_argument("-t", "--timeout", dest="timeout", type=float, default=DEFAULT_TIMEOUT, help="per-operation timeout in seconds")
        self._parser.add_argument("-c", "--concurrency", dest="concurrency", type=int, default=256, help="max concurrent operations")
        self._parser.add_argument("-b", "--batch", dest="batch", type=int, default=8, help="max concurrent hosts in batch mode")
        self._parser.add_argument("--no-whois", dest="no_whois", action="store_true", help="skip whois lookup")
        self._parser.add_argument("--no-http", dest="no_http", action="store_true", help="skip http probe")
        self._parser.add_argument("--no-tls", dest="no_tls", action="store_true", help="skip tls handshake")
        self._parser.add_argument("--follow-redirects", dest="follow_redirects", action="store_true", help="follow http redirects")
        self._parser.add_argument("--max-hops", dest="max_hops", type=int, default=5, help="max redirect hops")
        self._parser.add_argument("--user-agent", dest="user_agent", default="pyScanner/1.0", help="http user agent")
        self._parser.add_argument("-o", "--output", dest="output", default=None, help="write results to file")
        self._parser.add_argument("--format", dest="fmt", choices=("json", "csv", "jsonl"), default="json", help="output format")
        self._parser.add_argument("-d", "--dump", dest="dump", action="store_true", help="hexdump the record buffer")
        self._parser.add_argument("-v", "--verbose", dest="verbose", action="store_true", help="verbose logging")
        self._parser.add_argument("--no-color", dest="no_color", action="store_true", help="disable ansi colors")
        self._parser.add_argument("--no-progress", dest="no_progress", action="store_true", help="disable progress bar")
        self._parser.add_argument("--repl", dest="repl", action="store_true", help="start interactive shell")
        self._parser.add_argument("--version", action="version", version="pyScanner 1.0.0")

    def parse(self, argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
        return self._parser.parse_args(argv)

    @property
    def parser(self) -> argparse.ArgumentParser:
        return self._parser


def parse_ports(spec: str) -> Optional[tuple[int, ...]]:
    if not spec:
        return None
    out: list[int] = []
    seen: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            low, _, high = part.partition("-")
            try:
                start = int(low)
                end = int(high)
            except ValueError:
                return None
            if start > end or start <= 0 or end > 65535:
                return None
            for port in range(start, end + 1):
                if port not in seen:
                    seen.add(port)
                    out.append(port)
        else:
            try:
                port = int(part)
            except ValueError:
                return None
            if port <= 0 or port > 65535:
                return None
            if port not in seen:
                seen.add(port)
                out.append(port)
    return tuple(out) if out else None


def load_hosts_from_file(path: str) -> tuple[str, ...]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError:
        return ()
    out: list[str] = []
    seen: set[str] = set()
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped not in seen:
            seen.add(stripped)
            out.append(stripped)
    return tuple(out)


def build_configs(args: argparse.Namespace) -> tuple[ScanConfig, ...]:
    hosts: list[str] = list(args.hosts)
    if args.host_file:
        hosts.extend(load_hosts_from_file(args.host_file))
    seen: set[str] = set()
    unique: list[str] = []
    for host in hosts:
        if host and host not in seen:
            seen.add(host)
            unique.append(host)
    if not unique:
        return ()
    ports = parse_ports(args.ports) if args.ports else DEFAULT_PORTS
    if ports is None:
        return ()
    configs: list[ScanConfig] = []
    for host in unique:
        configs.append(
            ScanConfig(
                host=host,
                ports=ports,
                timeout=args.timeout,
                concurrency=args.concurrency,
                banner_ports=ports,
                enable_whois=not args.no_whois,
                enable_http=not args.no_http,
                enable_tls=not args.no_tls,
                follow_redirects=args.follow_redirects,
                max_redirect_hops=args.max_hops,
                user_agent=args.user_agent,
                verbose=args.verbose,
            )
        )
    return tuple(configs)


class InteractiveShell:
    __slots__ = ("_palette", "_renderer", "_running", "_history")

    BANNER = (
        "pyScanner interactive shell",
        "type 'help' for commands, 'quit' to exit",
    )

    def __init__(self, palette: Optional[Palette] = None) -> None:
        self._palette = palette if palette is not None else Palette()
        self._renderer = Renderer(palette=self._palette)
        self._running = True
        self._history: list[str] = []

    def _print(self, text: str = "") -> None:
        sys.stdout.write(text + "\n")
        sys.stdout.flush()

    def _show_banner(self) -> None:
        self._print(self._palette.bold("=" * 60))
        for line in self.BANNER:
            self._print(self._palette.info(line))
        self._print(self._palette.bold("=" * 60))

    def _show_help(self) -> None:
        rows = [
            ("scan <host>", "run a full scan against host"),
            ("resolve <host>", "resolve a hostname to addresses"),
            ("ports <host> [spec]", "scan ports on host"),
            ("http <host>", "fetch http response metadata"),
            ("whois <domain>", "query whois for domain"),
            ("dump <host>", "scan host and hexdump its record"),
            ("history", "show command history"),
            ("clear", "clear the screen"),
            ("help", "show this help"),
            ("quit", "exit the shell"),
        ]
        columns = [
            Column("COMMAND", 24, "left", lambda v: self._palette.key(v[0])),
            Column("DESCRIPTION", 40, "left", lambda v: self._palette.value(v[1])),
        ]
        table = Table(columns, palette=self._palette)
        for row in rows:
            table.add(row)
        self._print(table.render())

    def _run_scan(self, host: str) -> None:
        if not host or "." not in host:
            self._print(self._palette.failure("invalid host"))
            return
        cfg = ScanConfig(host=host, verbose=False)
        orchestrator = ScanOrchestrator(cfg, self._print)
        try:
            report = asyncio.run(orchestrator.run())
        except KeyboardInterrupt:
            self._print(self._palette.warning("interrupted"))
            return
        except Exception as exc:
            self._print(self._palette.failure(f"error: {exc}"))
            return
        self._print(self._renderer.render_report(report))

    def _run_resolve(self, host: str) -> None:
        if not host:
            self._print(self._palette.failure("usage: resolve <host>"))
            return

        async def _inner() -> tuple[Address, ...]:
            async with Resolver() as resolver:
                return await resolver.resolve(host)

        try:
            addresses = asyncio.run(_inner())
        except Exception as exc:
            self._print(self._palette.failure(f"error: {exc}"))
            return
        if not addresses:
            self._print(self._palette.failure("no addresses"))
            return
        for addr in addresses:
            self._print(self._palette.info(f"{addr.ip} IPv{addr.version}"))

    def _run_ports(self, host: str, spec: str) -> None:
        ports = parse_ports(spec) if spec else DEFAULT_PORTS
        if ports is None:
            self._print(self._palette.failure("invalid port spec"))
            return
        cfg = ScanConfig(host=host, ports=ports, enable_whois=False, enable_http=False, enable_tls=False)
        orchestrator = ScanOrchestrator(cfg)
        try:
            report = asyncio.run(orchestrator.run())
        except Exception as exc:
            self._print(self._palette.failure(f"error: {exc}"))
            return
        self._print(self._renderer.render_ports_table(report))

    def _run_http(self, host: str) -> None:
        if not host:
            self._print(self._palette.failure("usage: http <host>"))
            return

        async def _inner() -> Optional[HTTPResult]:
            async with Resolver() as resolver:
                addresses = await resolver.resolve(host)
                if not addresses:
                    return None
                probe = AsyncProbe()
                opened = await probe.scan_ports(addresses[0].ip, (80, 443))
                open_ports = tuple(p.port for p in opened if p.open)
                if not open_ports:
                    return None
                port = 443 if 443 in open_ports else open_ports[0]
                use_tls = port in (443, 8443)
                http = HTTPProbe()
                return await http.request(addresses[0].ip, port, host, use_tls)

        try:
            result = asyncio.run(_inner())
        except Exception as exc:
            self._print(self._palette.failure(f"error: {exc}"))
            return
        if result is None:
            self._print(self._palette.failure("no http response"))
            return
        self._print(self._palette.key("status") + " " + self._palette.status_code(result.status_code))
        self._print(self._palette.key("server") + " " + self._palette.value(result.server or "-"))
        self._print(self._palette.key("title ") + " " + self._palette.value(result.title or "-"))
        self._print(self._palette.key("size  ") + " " + self._palette.value(f"{result.body_size} bytes"))

    def _run_whois(self, domain: str) -> None:
        if not domain:
            self._print(self._palette.failure("usage: whois <domain>"))
            return

        async def _inner() -> Optional[WhoisResult]:
            client = WhoisClient()
            return await client.query(domain)

        try:
            result = asyncio.run(_inner())
        except Exception as exc:
            self._print(self._palette.failure(f"error: {exc}"))
            return
        if result is None:
            self._print(self._palette.failure("no whois response"))
            return
        self._print(self._palette.key("server") + " " + self._palette.value(result.server))
        for key, value in result.fields.items():
            self._print(self._palette.key(key.ljust(12)) + " " + self._palette.value(value))

    def _run_dump(self, host: str) -> None:
        if not host or "." not in host:
            self._print(self._palette.failure("invalid host"))
            return
        cfg = ScanConfig(host=host, verbose=False)
        orchestrator = ScanOrchestrator(cfg)
        try:
            report = asyncio.run(orchestrator.run())
        except Exception as exc:
            self._print(self._palette.failure(f"error: {exc}"))
            return
        record = report.to_record()
        self._print(self._renderer.render_report(report))
        self._print(self._renderer.render_hexdump(record, limit=0x0100))

    def _dispatch(self, line: str) -> None:
        parts = line.split()
        if not parts:
            return
        cmd = parts[0].lower()
        rest = parts[1:]
        if cmd in ("quit", "exit"):
            self._running = False
            return
        if cmd == "help":
            self._show_help()
            return
        if cmd == "clear":
            sys.stdout.write("\x1b[2J\x1b[H")
            sys.stdout.flush()
            return
        if cmd == "history":
            for idx, entry in enumerate(self._history, 1):
                self._print(f"{idx:4d}  {entry}")
            return
        if cmd == "scan":
            if not rest:
                self._print(self._palette.failure("usage: scan <host>"))
                return
            self._run_scan(rest[0])
            return
        if cmd == "resolve":
            if not rest:
                self._print(self._palette.failure("usage: resolve <host>"))
                return
            self._run_resolve(rest[0])
            return
        if cmd == "ports":
            if not rest:
                self._print(self._palette.failure("usage: ports <host> [spec]"))
                return
            spec = rest[1] if len(rest) > 1 else ""
            self._run_ports(rest[0], spec)
            return
        if cmd == "http":
            if not rest:
                self._print(self._palette.failure("usage: http <host>"))
                return
            self._run_http(rest[0])
            return
        if cmd == "whois":
            if not rest:
                self._print(self._palette.failure("usage: whois <domain>"))
                return
            self._run_whois(rest[0])
            return
        if cmd == "dump":
            if not rest:
                self._print(self._palette.failure("usage: dump <host>"))
                return
            self._run_dump(rest[0])
            return
        self._print(self._palette.warning(f"unknown command: {cmd}"))

    def run(self) -> int:
        self._show_banner()
        while self._running:
            try:
                line = input(self._palette.info("pyScanner> "))
            except EOFError:
                self._print("")
                break
            except KeyboardInterrupt:
                self._print("")
                continue
            stripped = line.strip()
            if not stripped:
                continue
            self._history.append(stripped)
            try:
                self._dispatch(stripped)
            except Exception as exc:
                self._print(self._palette.failure(f"unhandled error: {exc}"))
        return STATUS_SUCCESS


class SignalHandler:
    __slots__ = ("_interrupted", "_original")

    def __init__(self) -> None:
        self._interrupted = False
        self._original: dict[int, Any] = {}

    def install(self) -> None:
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                self._original[sig] = signal.getsignal(sig)
                signal.signal(sig, self._handle)
            except (ValueError, OSError):
                continue

    def restore(self) -> None:
        for sig, handler in self._original.items():
            try:
                signal.signal(sig, handler)
            except (ValueError, OSError):
                continue

    def _handle(self, signum: int, frame: Any) -> None:
        self._interrupted = True
        sys.stderr.write("\n")
        raise KeyboardInterrupt()

    @property
    def interrupted(self) -> bool:
        return self._interrupted


def run_batch(configs: Sequence[ScanConfig], args: argparse.Namespace, palette: Palette) -> int:
    renderer = Renderer(palette=palette)
    scanner = BatchScanner(configs, concurrency=args.batch)
    try:
        reports = asyncio.run(scanner.run())
    except KeyboardInterrupt:
        sys.stderr.write(palette.warning("interrupted") + "\n")
        return STATUS_UNSUCCESSFUL
    except Exception as exc:
        sys.stderr.write(palette.failure(f"error: {exc}") + "\n")
        return STATUS_UNSUCCESSFUL

    if not reports:
        sys.stderr.write(palette.failure("no results") + "\n")
        return STATUS_UNSUCCESSFUL

    if len(reports) == 1:
        print(renderer.render_report(reports[0]))
        if args.dump:
            print(renderer.render_hexdump(reports[0].to_record(), limit=0x0100))
    else:
        print(renderer.render_batch_table(reports))
        if args.dump:
            for report in reports:
                print(renderer.render_hexdump(report.to_record(), limit=0x0100))
                print()

    if args.output:
        exporter = ReportExporter()
        status = exporter.write(reports, args.output, args.fmt)
        if status != STATUS_SUCCESS:
            sys.stderr.write(palette.failure(f"failed to write {args.output}") + "\n")
            return status
        sys.stderr.write(palette.success(f"wrote {args.output}") + "\n")

    failures = sum(1 for r in reports if r.status != STATUS_SUCCESS)
    return STATUS_SUCCESS if failures < len(reports) else STATUS_UNSUCCESSFUL


def main(argv: Optional[Sequence[str]] = None) -> int:
    handler = SignalHandler()
    handler.install()
    try:
        parser = ArgParser()
        args = parser.parse(argv)
        palette = Palette(enabled=not args.no_color)

        if args.repl:
            shell = InteractiveShell(palette=palette)
            return shell.run()

        configs = build_configs(args)
        if not configs:
            sys.stderr.write(palette.failure("no valid hosts") + "\n")
            return STATUS_INVALID_PARAMETER

        return run_batch(configs, args, palette)
    except KeyboardInterrupt:
        sys.stderr.write("\n")
        return STATUS_UNSUCCESSFUL
    finally:
        handler.restore()

# Main
if __name__ == "__main__":
    sys.exit(main())
