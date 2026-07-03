import logging
import socketserver
import socket
import threading
from typing import Tuple

logger = logging.getLogger("netbox_dns_bridge.server")


class BoundedThreadingMixIn(socketserver.ThreadingMixIn):
    """ThreadingMixIn with a hard cap on concurrent request threads.

    Stock ThreadingMixIn spawns one unbounded thread per request; a burst of
    DNS traffic therefore means an unbounded number of live threads, each
    holding up to one DB connection while it works — enough of them and
    postgres max_connections is gone even with per-thread cleanup in place.

    A semaphore acquired in process_request() (the accept loop) and released
    when process_request_thread() finishes caps live threads at
    max_concurrent_requests. When saturated, the accept loop blocks: further
    TCP connections wait in the kernel listen backlog and UDP datagrams in the
    socket receive buffer, where overflow is dropped — normal DNS overload
    behavior; clients retry. Daemon-thread semantics and the stdlib
    finish_request/shutdown_request error handling are inherited unchanged
    (process_request_thread wraps them; verified against CPython 3.12
    Lib/socketserver.py).
    """

    max_concurrent_requests = 16

    def _request_slots(self):
        # Lazy init: the server __init__s in this module call the stdlib
        # server __init__ directly (not via MRO chaining), so there is no
        # mixin __init__ hook. Only the single accept-loop thread calls
        # process_request, so creation is race-free; instance overrides of
        # max_concurrent_requests set before serve_forever() are honored.
        slots = getattr(self, "_bounded_slots", None)
        if slots is None:
            slots = self._bounded_slots = threading.BoundedSemaphore(
                self.max_concurrent_requests
            )
        return slots

    def process_request(self, request, client_address):
        slots = self._request_slots()
        if not slots.acquire(blocking=False):
            logger.warning(
                "%s: %d concurrent requests reached — blocking accept loop "
                "until a slot frees (client %s)",
                type(self).__name__, self.max_concurrent_requests, client_address,
            )
            slots.acquire()
        try:
            super().process_request(request, client_address)
        except Exception:
            # Thread never started; serve_forever's handler takes it from here.
            slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._bounded_slots.release()


class DNSAddressMixin:
    def _resolve_address(self, server_address, socktype, proto) -> Tuple[str, int]:
        host, port = server_address

        infos = socket.getaddrinfo(
            host,
            port,
            socket.AF_UNSPEC,
            socktype,
            proto,
            socket.AI_PASSIVE
        )

        family, _, _, _, sockaddr = infos[0]
        self.address_family = family
        # getaddrinfo() can return sockaddr tuples for several address families;
        # we only ever bind to AF_INET/AF_INET6, where sockaddr is always the
        # (host, port[, ...]) form that socketserver expects.
        return (sockaddr[0], sockaddr[1])  # type: ignore[index]


class TCPDNSServer(DNSAddressMixin, BoundedThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address, handler_class, keyring, tsig_view_map,
                 ixfr_enabled=False, max_concurrent_requests=None):
        sockaddr = self._resolve_address(
            server_address,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP
        )

        socketserver.TCPServer.__init__(self, sockaddr, handler_class)

        self.keyring = keyring
        self.tsig_view_map = tsig_view_map
        self.ixfr_enabled = ixfr_enabled
        if max_concurrent_requests is not None:
            self.max_concurrent_requests = max_concurrent_requests


class UDPDNSServer(DNSAddressMixin, BoundedThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address, handler_class, keyring, tsig_view_map,
                 ixfr_enabled=False, max_concurrent_requests=None):
        sockaddr = self._resolve_address(
            server_address,
            socket.SOCK_DGRAM,
            socket.IPPROTO_UDP
        )

        socketserver.UDPServer.__init__(self, sockaddr, handler_class)

        self.keyring = keyring
        self.tsig_view_map = tsig_view_map
        self.ixfr_enabled = ixfr_enabled
        if max_concurrent_requests is not None:
            self.max_concurrent_requests = max_concurrent_requests


# Threaded variants for DDNS handlers (separate allowed_zones / ddns_tag config)
class ThreadingTCPDNSServer(DNSAddressMixin, BoundedThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address, handler_class, keyring, tsig_view_map,
                 allowed_zones=None, ddns_tag=None, max_concurrent_requests=None):
        sockaddr = self._resolve_address(
            server_address,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP
        )

        socketserver.TCPServer.__init__(self, sockaddr, handler_class)

        self.keyring = keyring
        self.tsig_view_map = tsig_view_map
        self.allowed_zones = allowed_zones or set()
        self.ddns_tag = ddns_tag
        if max_concurrent_requests is not None:
            self.max_concurrent_requests = max_concurrent_requests


class ThreadingUDPDNSServer(DNSAddressMixin, BoundedThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address, handler_class, keyring, tsig_view_map,
                 allowed_zones=None, ddns_tag=None, max_concurrent_requests=None):
        sockaddr = self._resolve_address(
            server_address,
            socket.SOCK_DGRAM,
            socket.IPPROTO_UDP
        )

        socketserver.UDPServer.__init__(self, sockaddr, handler_class)

        self.keyring = keyring
        self.tsig_view_map = tsig_view_map
        self.allowed_zones = allowed_zones or set()
        self.ddns_tag = ddns_tag
        if max_concurrent_requests is not None:
            self.max_concurrent_requests = max_concurrent_requests
