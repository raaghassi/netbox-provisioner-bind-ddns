import logging
import socketserver
import socket
from typing import Tuple

logger = logging.getLogger("netbox_dns_bridge.server")


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


class TCPDNSServer(DNSAddressMixin, socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address, handler_class, keyring, tsig_view_map,
                 ixfr_enabled=False):
        sockaddr = self._resolve_address(
            server_address,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP
        )

        socketserver.TCPServer.__init__(self, sockaddr, handler_class)

        self.keyring = keyring
        self.tsig_view_map = tsig_view_map
        self.ixfr_enabled = ixfr_enabled


class UDPDNSServer(DNSAddressMixin, socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address, handler_class, keyring, tsig_view_map,
                 ixfr_enabled=False):
        sockaddr = self._resolve_address(
            server_address,
            socket.SOCK_DGRAM,
            socket.IPPROTO_UDP
        )

        socketserver.UDPServer.__init__(self, sockaddr, handler_class)

        self.keyring = keyring
        self.tsig_view_map = tsig_view_map
        self.ixfr_enabled = ixfr_enabled


# Threaded variants for DDNS handlers (separate allowed_zones / ddns_tag config)
class ThreadingTCPDNSServer(DNSAddressMixin, socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address, handler_class, keyring, tsig_view_map,
                 allowed_zones=None, ddns_tag=None):
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


class ThreadingUDPDNSServer(DNSAddressMixin, socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address, handler_class, keyring, tsig_view_map,
                 allowed_zones=None, ddns_tag=None):
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
