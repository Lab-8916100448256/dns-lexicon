"""Le Bureau hosted DNS, using TSIG-authenticated RFC 2136 and AXFR."""

import base64
import binascii
import hashlib
import ipaddress
from argparse import ArgumentParser
from typing import ClassVar

import dns.exception
import dns.name
import dns.query
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.ANY.TXT
import dns.resolver
import dns.tokenizer
import dns.tsig
import dns.update
import dns.zone

from lexicon.config import ConfigResolver
from lexicon.exceptions import AuthenticationError, LexiconError
from lexicon.interfaces import Provider as BaseProvider


class Provider(BaseProvider):
    """Manage a zone hosted by Le Bureau with a key permitted to update and AXFR."""

    VALID_TYPES: ClassVar[list[str]] = [
        "A",
        "AAAA",
        "CAA",
        "CNAME",
        "MX",
        "NS",
        "SOA",
        "SRV",
        "TXT",
    ]

    @staticmethod
    def get_nameservers():
        return ["lebureau.coop"]

    @staticmethod
    def configure_parser(parser: ArgumentParser):
        parser.add_argument(
            "--auth-token", help="TSIG key as algorithm:key_name:base64_secret"
        )
        parser.add_argument(
            "--ddns-server",
            help="update/AXFR server hostname or IP (default: ns2.lebureau.coop)",
        )
        parser.add_argument("--ddns-port", type=int, help="DNS TCP port (default: 53)")
        parser.add_argument(
            "--timeout",
            type=float,
            help="DNS operation timeout in seconds (default: 10)",
        )

    def __init__(self, config):
        self._ttl = (
            config.resolve("lexicon:ttl")
            if isinstance(config, ConfigResolver)
            else config.get("ttl")
        )
        # BaseProvider appends a default TTL source. Keep it local so reopening
        # a Client does not turn an omitted update TTL into an explicit 3600.
        if isinstance(config, ConfigResolver):
            local_config = ConfigResolver()
            for source in config._config_sources:
                local_config.with_config_source(source)
            config = local_config
        else:
            config = config.copy()
        super().__init__(config)
        self.zone = dns.name.from_text(self.domain).canonicalize()
        self.server = self._get_provider_option("ddns_server") or "ns2.lebureau.coop"
        try:
            port = self._get_provider_option("ddns_port")
            timeout = self._get_provider_option("timeout")
            self.port = int(53 if port in (None, "") else port)
            self.timeout = float(10 if timeout in (None, "") else timeout)
            if not 0 < self.port < 65536 or not 0 < self.timeout < float("inf"):
                raise ValueError
        except (TypeError, ValueError):
            raise ValueError("Invalid Le Bureau DNS port or timeout") from None
        try:
            algorithm, key_name, secret = (
                self._get_provider_option("auth_token") or ""
            ).split(":")
            if not algorithm or not key_name or not secret:
                raise ValueError
            secret_bytes = base64.b64decode(secret, validate=True)
            if not secret_bytes:
                raise ValueError
            self.key = dns.tsig.Key(key_name, secret_bytes, algorithm.lower())
            if self.key.algorithm == dns.tsig.GSS_TSIG:
                raise ValueError("GSS-TSIG requires a negotiated security context")
            # Validate the algorithm before any network I/O.
            dns.tsig.get_context(self.key)
            if self.key.name == dns.name.root:
                raise ValueError
        except (
            ValueError,
            binascii.Error,
            dns.exception.DNSException,
            NotImplementedError,
        ):
            raise AuthenticationError(
                "Invalid TSIG token; expected supported algorithm:key_name:base64_secret"
            ) from None
        self.keyring = {self.key.name: self.key}
        self.endpoint = None
        self._records = {}

    def _addresses(self):
        try:
            return [str(ipaddress.ip_address(self.server))]
        except ValueError:
            pass
        addresses = []
        for rtype in ("A", "AAAA"):
            try:
                addresses.extend(
                    str(answer)
                    for answer in dns.resolver.resolve(
                        self.server, rtype, lifetime=self.timeout
                    )
                )
            except dns.resolver.NoAnswer:
                continue
            except dns.exception.DNSException:
                # One address family may fail while the other is usable.
                continue
        if not addresses:
            raise LexiconError(
                "Cannot resolve Le Bureau DNS server; check --ddns-server"
            )
        return addresses

    def authenticate(self):
        try:
            self._load_zone()
        except LexiconError as error:
            raise AuthenticationError(str(error)) from None
        self.domain_id = self.zone.to_text()

    def _load_zone(self):
        # Retry reads only on transport failures. Writes always use the endpoint
        # selected by this signed transfer, and are never retried automatically.
        for endpoint in [self.endpoint] if self.endpoint else self._addresses():
            try:
                transfer = dns.query.xfr(
                    endpoint,
                    self.zone,
                    port=self.port,
                    timeout=self.timeout,
                    lifetime=self.timeout,
                    keyring=self.keyring,
                    keyname=self.key.name,
                    keyalgorithm=self.key.algorithm,
                    relativize=False,
                )
                zone = dns.zone.from_xfr(transfer, relativize=False)
                if zone.origin != self.zone:
                    raise LexiconError("Le Bureau AXFR returned an unexpected zone")
                self.endpoint = endpoint
                break
            except (OSError, EOFError, dns.exception.Timeout):
                continue
            except (dns.exception.DNSException, ValueError):
                raise LexiconError(
                    "Le Bureau AXFR failed; check zone, TSIG key and transfer permissions"
                ) from None
        else:
            raise LexiconError(
                "Le Bureau AXFR timed out or connection failed (TCP DNS required)"
            )
        records = {}
        for owner, rdataset in zone.iterate_rdatasets():
            for rdata in rdataset:
                content = self._content(rdata)
                # IDs identify exact DNS RDATA, including TXT string boundaries.
                # Logical TXT equality is used only for content comparisons.
                wire = rdata.to_digestable(self.zone)
                rtype = dns.rdatatype.to_text(rdata.rdtype)
                owner = owner.canonicalize()
                identifier = hashlib.sha256(
                    owner.to_wire() + rtype.encode("ascii") + b"\0" + wire
                ).hexdigest()
                records[identifier] = (
                    {
                        "id": identifier,
                        "type": rtype,
                        "name": owner.to_text(omit_final_dot=True),
                        "ttl": rdataset.ttl,
                        "content": content,
                    },
                    rdata,
                )
        self._records = records

    def _name(self, name):
        if name in ("", "@"):
            return self.zone
        parsed = dns.name.from_text(name, origin=None)
        if not parsed.is_absolute():
            # Lexicon accepts full names both with and without a trailing dot.
            absolute = parsed.derelativize(dns.name.root)
            parsed = (
                absolute
                if absolute.is_subdomain(self.zone)
                else parsed.derelativize(self.zone)
            )
        if not parsed.is_subdomain(self.zone):
            raise ValueError("Record name is outside the configured Le Bureau zone")
        return parsed.canonicalize()

    def _rdata(self, rtype, content):
        if rtype.upper() != "TXT":
            return dns.rdata.from_text(
                "IN", rtype, content, origin=self.zone, relativize=False
            )
        if content.startswith('"'):
            tokenizer = dns.tokenizer.Tokenizer(content)
            strings = []
            while True:
                token = tokenizer.get()
                if token.is_eof():
                    break
                if token.is_eol():
                    continue
                if not token.is_quoted_string():
                    raise ValueError("Expected quoted TXT character strings")
                strings.append(token.unescape_to_bytes().value)
        else:
            strings = [content.encode("utf-8")]
        chunks = []
        for value in strings:
            while len(value) > 255:
                boundary = 255
                # Avoid cutting a UTF-8 character. Arbitrary DNS octets remain
                # supported, including bytes expressed as decimal DNS escapes.
                while boundary > 252 and value[boundary] & 0xC0 == 0x80:
                    boundary -= 1
                chunks.append(value[:boundary])
                value = value[boundary:]
            chunks.append(value)
        return dns.rdtypes.ANY.TXT.TXT(dns.rdataclass.IN, dns.rdatatype.TXT, chunks)

    @staticmethod
    def _content(rdata):
        if rdata.rdtype == dns.rdatatype.TXT:
            value = b"".join(rdata.strings)
            try:
                text = value.decode("utf-8")
                if not text.startswith('"'):
                    return text
            except UnicodeDecodeError:
                pass
        return rdata.to_text(origin=None, relativize=False)

    def list_records(self, rtype=None, name=None, content=None):
        self._load_zone()
        owner = (
            self._name(name).to_text(omit_final_dot=True) if name is not None else None
        )
        records = []
        for record, rdata in self._records.values():
            if rtype and record["type"] != rtype.upper():
                continue
            if owner is not None and record["name"] != owner:
                continue
            if content is not None:
                try:
                    wanted = self._rdata(record["type"], content)
                except (dns.exception.DNSException, ValueError):
                    # A content-only filter need not be valid RDATA for every
                    # record type in the zone.
                    continue
                if record["type"] == "TXT":
                    if b"".join(wanted.strings) != b"".join(rdata.strings):
                        continue
                elif wanted != rdata:
                    continue
            records.append(record.copy())
        return records

    def _send(self, update):
        if not self.endpoint:
            self.authenticate()
        try:
            response = dns.query.tcp(
                update, self.endpoint, timeout=self.timeout, port=self.port
            )
        except (dns.exception.DNSException, OSError, EOFError):
            raise LexiconError(
                "Le Bureau update failed or reply was lost; verify records before retrying"
            ) from None
        if not response.had_tsig:
            raise AuthenticationError("Le Bureau returned an unsigned update response")
        if response.rcode() != dns.rcode.NOERROR:
            raise LexiconError(
                f"Le Bureau rejected DNS update: {dns.rcode.to_text(response.rcode())}"
            )
        self._records = {}
        return True

    def _update(self):
        return dns.update.Update(
            self.zone,
            keyring=self.keyring,
            keyname=self.key.name,
            keyalgorithm=self.key.algorithm,
        )

    def create_record(self, rtype, name, content):
        owner = self._name(name)
        data = self._rdata(rtype, content)
        if self.list_records(rtype, name, content):
            return True
        update = self._update()
        update.add(owner, int(self._ttl or 0) or 3600, data)
        return self._send(update)

    def update_record(self, identifier=None, rtype=None, name=None, content=None):
        matches = self.list_records(
            None if identifier else rtype, None if identifier else name
        )
        if identifier:
            matches = [record for record in matches if record["id"] == identifier]
        if len(matches) != 1:
            raise LexiconError(
                "Expected exactly one matching Le Bureau record to update"
            )
        record = matches[0]
        old_data = self._records[record["id"]][1]
        owner = self._name(name if name is not None else record["name"])
        if content is None and (rtype is None or rtype.upper() == record["type"]):
            data = old_data
        else:
            data = self._rdata(
                rtype or record["type"],
                content if content is not None else record["content"],
            )
        update = self._update()
        old_owner = self._name(record["name"])
        destination = [
            (existing, value)
            for existing, value in self._records.values()
            if self._name(existing["name"]) == owner and existing["id"] != record["id"]
        ]
        for existing, value in destination:
            if value.rdtype in (
                dns.rdatatype.RRSIG,
                dns.rdatatype.NSEC,
                dns.rdatatype.NSEC3,
                dns.rdatatype.SIG,
                dns.rdatatype.KEY,
                dns.rdatatype.NXT,
            ):
                continue
            if (data.rdtype == dns.rdatatype.CNAME) != (
                value.rdtype == dns.rdatatype.CNAME
            ) or (data.rdtype == dns.rdatatype.CNAME and data != value):
                raise LexiconError("Le Bureau update destination conflicts with CNAME")

        # Guard the AXFR snapshot as well as the selected RRset. RFC 2136 can
        # silently ignore conflicting additions even after deleting the source.
        # The SOA guard also covers changes of other types during a conversion
        # to CNAME at the same owner; unrelated zone changes may reject updates.
        for existing, value in self._records.values():
            if existing["type"] == "SOA" and self._name(existing["name"]) == self.zone:
                update.present(self.zone, value)
        source_data = [
            value
            for existing, value in self._records.values()
            if existing["name"] == record["name"] and existing["type"] == record["type"]
        ]
        update.present(old_owner, *source_data)
        if owner != old_owner and not destination:
            update.absent(owner)
        elif data.rdtype != dns.rdatatype.CNAME and not (
            owner == old_owner and old_data.rdtype == dns.rdatatype.CNAME
        ):
            update.absent(owner, "CNAME")
        elif owner != old_owner:
            update.present(
                owner,
                *[
                    value
                    for _, value in destination
                    if value.rdtype == dns.rdatatype.CNAME
                ],
            )
        update.delete(old_owner, old_data)
        ttl = record["ttl"] if self._ttl is None else (int(self._ttl or 0) or 3600)
        update.add(owner, ttl, data)
        return self._send(update)

    def delete_record(self, identifier=None, rtype=None, name=None, content=None):
        if not identifier and name is None:
            raise ValueError("Specify a record identifier or name for deletion")
        matches = self.list_records(
            None if identifier else rtype,
            None if identifier else name,
            None if identifier else content,
        )
        if identifier:
            matches = [record for record in matches if record["id"] == identifier]
        if not matches:
            return True
        update = self._update()
        for record in matches:
            update.delete(self._name(record["name"]), self._records[record["id"]][1])
        return self._send(update)
