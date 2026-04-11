"""
HTTP webhook handler for NetBox event rules.

Receives webhook POSTs from NetBox when DNS records change,
and sends DNS NOTIFY to secondary servers to trigger zone re-transfer.
"""
import hashlib
import hmac
import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import TYPE_CHECKING

from . import notify

logger = logging.getLogger("netbox_bind_ddns.webhook")


class WebhookHandler(BaseHTTPRequestHandler):
    """
    Handles NetBox webhook POST requests.

    Server attributes expected:
      self.server.notify_target   - str IP address for NOTIFY
      self.server.notify_port     - int port for NOTIFY
      self.server.tsig_keyring    - dict of {dns.name.Name: dns.tsig.Key}
      self.server.webhook_secret  - str shared secret for HMAC verification (optional)
    """
    if TYPE_CHECKING:
        server: "WebhookServer"  # type: ignore[assignment]

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            self._respond(400, "Empty request body")
            return

        body = self.rfile.read(content_length)

        # Verify HMAC signature if a secret is configured
        if self.server.webhook_secret:
            signature = self.headers.get("X-Hook-Signature", "")
            expected = hmac.new(
                key=self.server.webhook_secret.encode(),
                msg=body,
                digestmod=hashlib.sha512,
            ).hexdigest()
            if not hmac.compare_digest(signature, expected):
                logger.warning("Webhook rejected: invalid signature from %s", self.client_address[0])
                self._respond(403, "Invalid signature")
                return

        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            self._respond(400, "Invalid JSON")
            return

        zone_name = self._extract_zone_name(payload)
        if not zone_name:
            self._respond(422, "Could not extract zone name from payload")
            return

        event = payload.get("event", "unknown")
        logger.info("Webhook %s for zone %s from %s", event, zone_name, self.client_address[0])

        # Send NOTIFY in background thread
        threading.Thread(
            target=notify.send_notify,
            kwargs={
                "zone_name": zone_name,
                "target": self.server.notify_target,
                "port": self.server.notify_port,
                "tsig_keyring": self.server.tsig_keyring,
            },
            daemon=True,
        ).start()

        self._respond(200, "OK")

    def _extract_zone_name(self, payload):
        """Extract zone name from NetBox webhook payload."""
        try:
            zone_name = payload["data"]["zone"]["name"]
            return zone_name.rstrip(".")
        except (KeyError, TypeError):
            return None

    def _respond(self, status, message):
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(message.encode())

    def log_message(self, format, *args):
        """Route HTTP access logs through the plugin logger."""
        logger.debug(format, *args)


class WebhookServer(HTTPServer):
    """HTTP server for receiving NetBox webhooks."""

    def __init__(self, server_address, notify_target, notify_port,
                 tsig_keyring=None, webhook_secret=None):
        super().__init__(server_address, WebhookHandler)
        self.notify_target = notify_target
        self.notify_port = notify_port
        self.tsig_keyring = tsig_keyring
        self.webhook_secret = webhook_secret
