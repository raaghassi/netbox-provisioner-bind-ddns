import logging
import socketserver
import socket

logger = logging.getLogger("netbox_bind_ddns.server")


class DNSAddressMixin:
    def _resolve_address(self, server_address, socktype, proto):
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
        return sockaddr


class TCPDNSServer(DNSAddressMixin, socketserver.TCPServer):
    allow_reuse_address = True

    def __init__(self, server_address, handler_class, keyring, tsig_view_map,
                 ixfr_as_axfr=False):
        sockaddr = self._resolve_address(
            server_address,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP
        )

        super().__init__(sockaddr, handler_class)

        self.keyring = keyring
        self.tsig_view_map = tsig_view_map
        self.ixfr_as_axfr = ixfr_as_axfr


class UDPDNSServer(DNSAddressMixin, socketserver.UDPServer):
    allow_reuse_address = True

    def __init__(self, server_address, handler_class, keyring, tsig_view_map,
                 ixfr_as_axfr=False):
        sockaddr = self._resolve_address(
            server_address,
            socket.SOCK_DGRAM,
            socket.IPPROTO_UDP
        )

        super().__init__(sockaddr, handler_class)

        self.keyring = keyring
        self.tsig_view_map = tsig_view_map
        self.ixfr_as_axfr = ixfr_as_axfr


# Threaded variants for DDNS handlers (DB writes during request processing)
class ThreadingTCPDNSServer(DNSAddressMixin, socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address, handler_class, keyring, tsig_view_map,
                 allowed_zones=None, notify_target=None, notify_port=53, ddns_tag=None):
        sockaddr = self._resolve_address(
            server_address,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP
        )

        socketserver.TCPServer.__init__(self, sockaddr, handler_class)

        self.keyring = keyring
        self.tsig_view_map = tsig_view_map
        self.allowed_zones = allowed_zones or set()
        self.notify_target = notify_target
        self.notify_port = notify_port
        self.ddns_tag = ddns_tag


class ThreadingUDPDNSServer(DNSAddressMixin, socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address, handler_class, keyring, tsig_view_map,
                 allowed_zones=None, notify_target=None, notify_port=53, ddns_tag=None):
        sockaddr = self._resolve_address(
            server_address,
            socket.SOCK_DGRAM,
            socket.IPPROTO_UDP
        )

        socketserver.UDPServer.__init__(self, sockaddr, handler_class)

        self.keyring = keyring
        self.tsig_view_map = tsig_view_map
        self.allowed_zones = allowed_zones or set()
        self.notify_target = notify_target
        self.notify_port = notify_port
        self.ddns_tag = ddns_tag
