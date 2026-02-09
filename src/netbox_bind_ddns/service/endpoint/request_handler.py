import logging
import socketserver
import socket
import dns.query
import dns.message
import dns.tsigkeyring
import dns.name
import dns.zone
import dns.rdatatype
import dns.rdataclass
import dns.rdtypes
import dns.exception
import dns.renderer
from netbox_dns.models import Zone, Record
from netbox_dns.choices import ZoneStatusChoices, RecordStatusChoices
from . import catalog_zone_manager as catzm

logger = logging.getLogger("netbox_bind_ddns.transfer")


class DNSBaseRequestHandler(socketserver.BaseRequestHandler):
    def __init__(self, request, client_address, server) -> None:
        self.MAX_WIRE = 65535
        self.RESERVED_TSIG = 300
        super().__init__(request, client_address, server)

    def _getZoneFromNB(self, zone_name, view_name) -> dns.zone.Zone:
        try:
            nb_zone = Zone.objects.get(
                name=zone_name,
                view__name=view_name,
                status=ZoneStatusChoices.STATUS_ACTIVE,
            )
        except Zone.DoesNotExist:
            return None

        zone = dns.zone.Zone(zone_name, dns.name.root)
        zone.rdclass = dns.rdataclass.IN

        nb_records = Record.objects.filter(
            zone=nb_zone, status=RecordStatusChoices.STATUS_ACTIVE
        )

        rdatasets_dict = {}

        for record in nb_records:
            rdtype = dns.rdatatype.from_text(record.type)
            if not record.name:
                name = zone.origin
            elif record.name.endswith("."):
                name = dns.name.from_text(record.name)
            else:
                name = dns.name.from_text(record.name, origin=zone.origin)

            ttl = record.ttl or nb_zone.default_ttl

            value = record.value
            if rdtype == dns.rdatatype.TXT:
                if value.startswith('"') and value.endswith('"'):
                    value = value[1:-1].replace('" "', "").replace('"', '"')

                if len(value) > 255:
                    chunks = [
                        '"{}"'.format(value[i : i + 255])
                        for i in range(0, len(value), 255)
                    ]
                    value = " ".join(chunks)
                else:
                    value = f'"{value}"'

            rdata = dns.rdata.from_text(
                dns.rdataclass.IN,
                rdtype,
                value,
                relativize=False,
                origin=zone.origin,
            )

            if name not in rdatasets_dict:
                rdatasets_dict[name] = {}
            if rdtype not in rdatasets_dict[name]:
                rdatasets_dict[name][rdtype] = dns.rdataset.Rdataset(
                    dns.rdataclass.IN, rdtype
                )

            rdatasets_dict[name][rdtype].add(rdata, ttl)

        for name, rdtypes in rdatasets_dict.items():
            for rdtype, rdataset in rdtypes.items():
                if rdataset.rdclass != zone.rdclass:
                    raise ValueError(
                        f"rdataset rdclass {rdataset.rdclass} does not match zone rdclass {zone.rdclass}"
                    )

                if not rdataset:
                    logger.debug(f"Skipping empty rdataset for {name} {rdtype}")
                    continue

                zone.replace_rdataset(name, rdataset)
        return zone

    def _denyRequestBadTSIG(self, wire, tsig_error: dns.rcode) -> None:
        query = dns.message.from_wire(
            wire, keyring={}, ignore_trailing=True, continue_on_error=True
        )

        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.REFUSED)

        if query.had_tsig:
            response.use_tsig(
                keyring={},
                keyname=query.keyname,
                tsig_error=tsig_error,
            )
        self._deny_request(query)

    def _send_response(self, data) -> None:
        raise NotImplementedError

    def _deny_request(self, query, rcode: dns.rcode = dns.rcode.REFUSED) -> None:
        response = dns.message.make_response(query)
        response.set_rcode(rcode)
        wire = response.to_wire(multi=False)
        self._send_response(wire)

    def _handle_soa_request(self, query, soa_rrset, zone, peer, nb_view, dname) -> None:
        soa_rdata = soa_rrset[0]

        rrset = dns.rrset.from_rdata(zone.origin, soa_rrset.ttl, soa_rdata)

        response = dns.message.make_response(query)
        response.flags |= dns.flags.AA

        response.answer.append(rrset)

        if query.had_tsig:
            if query.keyname in self.server.keyring:
                response.use_tsig(
                    self.server.keyring, keyname=query.keyname, original_id=query.id
                )
            else:
                response.set_rcode(dns.rcode.REFUSED)
                response.use_tsig(
                    self.server.keyring,
                    keyname=query.keyname,
                    tsig_error=dns.rcode.BADKEY,
                )

        data = response.to_wire(max_size=512)
        self._send_response(data)
        logger.debug(f"{peer} SOA {nb_view.name}/{dname}")

    def _handle_axfr_request(self, query, zone, peer, nb_view, dname) -> None:
        rrsets = []
        soa_rrset = None
        for name, rdataset in zone.iterate_rdatasets():
            if not name.is_absolute():
                name = name.concatenate(zone.origin)
            rrset = dns.rrset.from_rdata_list(name, rdataset.ttl, rdataset)
            if rdataset.rdtype == dns.rdatatype.SOA and soa_rrset is None:
                soa_rrset = rrset
            else:
                rrsets.append(rrset)

        rrsets.insert(0, soa_rrset)  # Opening SOA
        rrsets.append(soa_rrset)  # Closing SOA

        r = dns.renderer.Renderer(
            id=query.id,
            flags=(dns.flags.QR | dns.flags.AA),
            max_size=self.MAX_WIRE,
            origin=None,
        )
        r.add_question(
            query.question[0].name,
            query.question[0].rdtype,
            query.question[0].rdclass,
        )

        tsig_ctx = None
        for rrset in rrsets:
            try:
                r.add_rrset(dns.renderer.ANSWER, rrset)
                if r.max_size - len(r.output.getvalue()) < self.RESERVED_TSIG:
                    raise dns.exception.TooBig("TSIG wont fit")
            except dns.exception.TooBig:
                r.write_header()
                tsig_ctx = r.add_multi_tsig(
                    ctx=tsig_ctx,
                    secret=self.server.keyring[query.keyname],
                    keyname=query.keyname,
                    fudge=300,
                    id=query.id,
                    tsig_error=0,
                    other_data=b"",
                    request_mac=r.mac if tsig_ctx else query.mac,
                )
                wire = r.get_wire()
                self.request.sendall(len(wire).to_bytes(2, "big") + wire)

                r = dns.renderer.Renderer(
                    id=query.id,
                    flags=(dns.flags.QR | dns.flags.AA),
                    max_size=self.MAX_WIRE,
                    origin=None,
                )
                r.add_question(
                    query.question[0].name,
                    query.question[0].rdtype,
                    query.question[0].rdclass,
                )
                r.add_rrset(dns.renderer.ANSWER, rrset)

        r.write_header()
        tsig_ctx = r.add_multi_tsig(
            ctx=tsig_ctx,
            secret=self.server.keyring[query.keyname],
            keyname=query.keyname,
            fudge=300,
            id=query.id,
            tsig_error=0,
            other_data=b"",
            request_mac=r.mac if tsig_ctx else query.mac,
        )
        wire = r.get_wire()
        self._send_response(wire)

        logger.debug(f"{peer} AXFR {nb_view.name}/{dname}")

    def _handle_dns_query(self, wire) -> None:
        peer = self.client_address[0]
        try:
            query = dns.message.from_wire(
                wire,
                keyring=self.server.keyring,
                continue_on_error=False,
                ignore_trailing=True
            )

        except dns.tsig.BadSignature as e:
            logger.warning(
                f"Request denied from {peer} failed TSIG verification: {e}"
            )
            self._denyRequestBadTSIG(wire, dns.rcode.BADSIG)
            return

        except (dns.message.UnknownTSIGKey, dns.tsig.BadAlgorithm) as e:
            logger.warning(f"Request denied from {peer} with bad TSIG key: {e}")
            self._denyRequestBadTSIG(wire, dns.rcode.BADKEY)
            return

        except Exception as e:
            logger.error("Error parsing query: ", e)
            return

        if len(query.question) != 1:
            self._deny_request(query)
            return

        question = query.question[0]
        qname = question.name
        qtype = question.rdtype
        dname = qname.to_text().rstrip(".")

        if qtype not in (dns.rdatatype.AXFR, dns.rdatatype.SOA):
            logger.warning(
                f"Request denied from {peer}: Request was not AXFR or SOA (Type: {qtype})"
            )
            self._deny_request(query)
            return

        if not query.had_tsig:
            logger.warning(f"Request denied from {peer}: No TSIG key used")
            self._deny_request(query)
            return

        key_name = query.keyname.canonicalize().to_text()

        nb_view = self.server.tsig_view_map.get(key_name)
        if not nb_view:
            logger.warning(
                f"Request denied from {peer}: {key_name} does not match a view"
            )
            self._deny_request(query)
            return

        if dname == "catz" or dname == f"{nb_view.name}.catz":
            zone = catzm.create_zone(dname, nb_view.name)
        else:
            zone = self._getZoneFromNB(dname, nb_view.name)
        if not zone:
            logger.warning(f"Zone {dname} not found in view {nb_view.name}")
            self._deny_request(query)
            return

        soa_rrset = zone.get_rdataset(zone.origin, dns.rdatatype.SOA)
        if soa_rrset is None:
            logger.error(f"Zone {dname} has no SOA -- aborting")
            return

        if qtype == dns.rdatatype.SOA:
            self._handle_soa_request(query, soa_rrset, zone, peer, nb_view, dname)
        elif qtype == dns.rdatatype.AXFR:
            self._handle_axfr_request(query, zone, peer, nb_view, dname)


class UDPRequestHandler(DNSBaseRequestHandler):
    def __init__(self, request, client_address, server) -> None:
        super().__init__(request, client_address, server)

    def _send_response(self, data) -> None:
        sock = self.request[1]
        sock.sendto(data, self.client_address)

    def handle(self) -> None:
        data, sock = self.request
        peer = self.client_address[0]
        try:
            self._handle_dns_query(data)
        except Exception as e:
            logger.error(f"Error handling request from {peer}: {e}")
            import traceback
            traceback.print_exc()


class TCPRequestHandler(DNSBaseRequestHandler):
    def __init__(self, request, client_address, server) -> None:
        super().__init__(request, client_address, server)

    def _send_response(self, data) -> None:
        length = len(data).to_bytes(2, byteorder="big")
        self.request.sendall(length + data)

    def handle(self) -> None:
        peer = self.client_address[0]
        sock = self.request
        sock.settimeout(10.0)
        try:
            while True:
                length_data = sock.recv(2)
                if not length_data:
                    return
                if len(length_data) < 2:
                    while len(length_data) < 2:
                        chunk = sock.recv(2 - len(length_data))
                        if not chunk:
                            return
                        length_data += chunk

                length = int.from_bytes(length_data, byteorder="big")
                wire = b""
                while len(wire) < length:
                    chunk = sock.recv(length - len(wire))
                    if not chunk:
                        return
                    wire += chunk
                self._handle_dns_query(wire)

        except socket.timeout:
            logger.debug(f"Connection from {peer} timed out")
        except Exception as e:
            logger.error(f"Error handling request from {peer}: {e}")
            import traceback
            traceback.print_exc()
