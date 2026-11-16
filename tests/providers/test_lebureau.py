"""Le Bureau contract and protocol tests against an in-memory DNS authority.

Le Bureau's DNS automation interface uses DNS over TCP with TSIG authentication
(RFC 2136 updates and AXFR zone transfers). VCR.py records HTTP interactions,
not this DNS traffic, so the developer guide's cassette workflow does not apply.

These tests run the shared IntegrationTestsV2 contract and protocol regressions
against a disposable in-memory authority with a public dummy key. dnspython
still encodes and validates the DNS wire messages and TSIG signatures; only the
socket transport is substituted. No live credentials or private zone dumps are
needed by default. With LEXICON_LIVE_TESTS=true, the shared contract uses a real
server and LEXICON_LEBUREAU_TEST_DOMAIN plus LEXICON_LEBUREAU_AUTH_TOKEN. Each test
owns a random namespace and cleans up its records. Protocol error regressions
remain offline. DNS traffic is never recorded by VCR.py.
"""

import base64
import io
import os
import socket
import struct

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import dns.tsig
import dns.zone
import pytest
import tldextract
from integration_tests import IntegrationTestsV2
from lebureau_live import LiveZone, live_config, wait_until

from lexicon._private.discovery import find_providers
from lexicon._private.providers.lebureau import Provider
from lexicon.client import Client
from lexicon.config import ConfigResolver, DictConfigSource
from lexicon.exceptions import AuthenticationError, LexiconError

TOKEN = "hmac-sha512:test-key:" + base64.b64encode(b"public-test-secret").decode()
ZONE = """
@ 300 IN SOA ns.example.com. hostmaster.example.com. 1 3600 600 86400 300
@ 300 IN NS ns.example.com.
ns 300 IN A 192.0.2.53
"""


RECORD_CASES = [
    ("A", "192.0.2.1"),
    ("AAAA", "2001:db8::1"),
    ("MX", "10 mail.example.com."),
    ("TXT", "v=spf1 -all"),
    ("CNAME", "target.example.com."),
    ("SRV", "10 20 443 service.example.com."),
    ("CAA", '0 issue "letsencrypt.org"'),
]


@pytest.fixture(autouse=True)
def offline_suffix_list(monkeypatch):
    """Use the bundled public suffix snapshot; tests need no external network."""
    extractor = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
    monkeypatch.setattr(tldextract, "TLDExtract", lambda **_: extractor)
    monkeypatch.setattr(tldextract, "extract", extractor)


class DNSServer:
    """Minimal authoritative fixture: signed AXFR and RFC 2136 add/delete."""

    def __init__(self):
        self.server_address = ("127.0.0.1", 5353)
        self.zone = dns.zone.from_text(ZONE, origin="example.com.", relativize=False)
        self.key = dns.tsig.Key("test-key", b"public-test-secret", "hmac-sha512")
        self.keyring = {self.key.name: self.key}
        self.rcode = dns.rcode.NOERROR
        self.truncate = False
        self.unsigned = False
        self.corrupt = False
        self.messages = 0
        self.writes = 0
        self.before_update = None

    def changed(self):
        """Publish a new SOA serial after a fixture zone change."""
        soa = self.zone.find_rdataset(self.zone.origin, "SOA")
        data = next(iter(soa))
        soa.clear()
        soa.add(data.replace(serial=data.serial + 1))


class DNSHandler:
    """Use actual DNS wire messages, including chained TSIG transfer signatures."""

    def __init__(self, server, wire):
        self.server = server
        self.rfile = io.BytesIO(wire)
        self.wfile = io.BytesIO()

    def handle(self):
        server = self.server
        length = struct.unpack("!H", self.rfile.read(2))[0]
        query = dns.message.from_wire(self.rfile.read(length), keyring=server.keyring)
        response = dns.message.make_response(query)
        response.flags |= dns.flags.AA
        if query.question[0].name != server.zone.origin:
            response.set_rcode(dns.rcode.NOTAUTH)
        else:
            response.set_rcode(server.rcode)
        if response.rcode() != dns.rcode.NOERROR:
            self.send(response)
        elif query.opcode() == dns.opcode.UPDATE:
            server.writes += 1
            if server.before_update:
                callback, server.before_update = server.before_update, None
                callback()
            response.set_rcode(self.check_prerequisites(query))
            if response.rcode() != dns.rcode.NOERROR:
                self.send(response)
                return
            for rrset in query.authority:
                owner = rrset.name.derelativize(server.zone.origin)
                if rrset.deleting == dns.rdataclass.ANY:
                    node = server.zone.get_node(owner)
                    if node:
                        for dataset in list(node.rdatasets):
                            if rrset.rdtype not in (dns.rdatatype.ANY, dataset.rdtype):
                                continue
                            if owner == server.zone.origin and dataset.rdtype in (
                                dns.rdatatype.SOA,
                                dns.rdatatype.NS,
                            ):
                                continue
                            server.zone.delete_rdataset(owner, dataset.rdtype)
                elif rrset.deleting == dns.rdataclass.NONE:
                    rdataset = server.zone.get_rdataset(owner, rrset.rdtype)
                    if rdataset is not None:
                        for data in rrset:
                            if owner == server.zone.origin and (
                                rrset.rdtype == dns.rdatatype.SOA
                                or (
                                    rrset.rdtype == dns.rdatatype.NS
                                    and len(rdataset) == 1
                                )
                            ):
                                continue
                            rdataset.discard(data)
                        if not rdataset:
                            server.zone.delete_rdataset(owner, rrset.rdtype)
                else:
                    if rrset.rdtype == dns.rdatatype.SOA:
                        current = server.zone.get_rdataset(owner, "SOA")
                        if current is None:
                            continue
                        delta = (
                            next(iter(rrset)).serial - next(iter(current)).serial
                        ) % 2**32
                        if not 0 < delta < 2**31:
                            continue
                    node = server.zone.get_node(owner)
                    if node and any(
                        (rrset.rdtype == dns.rdatatype.CNAME)
                        != (dataset.rdtype == dns.rdatatype.CNAME)
                        for dataset in node.rdatasets
                    ):
                        # RFC 2136 3.4.2.2: silently ignore conflicting adds.
                        continue
                    rdataset = server.zone.find_rdataset(
                        owner, rrset.rdtype, create=True
                    )
                    for data in rrset:
                        rdataset.add(data)
                    rdataset.ttl = rrset.ttl
            server.changed()
            self.send(response)
        else:
            soa = server.zone.find_rrset(server.zone.origin, "SOA")
            rrsets = [soa]
            rrsets.extend(
                server.zone.find_rrset(owner, rdataset.rdtype)
                for owner, rdataset in server.zone.iterate_rdatasets()
                if rdataset.rdtype != dns.rdatatype.SOA
            )
            if not server.truncate:
                rrsets.append(soa)
            context = None
            # Deliberately send each RRset in its own TCP message.
            for rrset in rrsets:
                response = dns.message.make_response(query)
                response.flags |= dns.flags.AA
                response.answer.append(rrset)
                context = self.send(response, multi=True, context=context)

    def check_prerequisites(self, query):
        """Evaluate name/RRset existence and exact RDATA sets before any writes."""
        values = {}
        for rrset in query.prerequisite:
            owner = rrset.name.derelativize(self.server.zone.origin)
            node = self.server.zone.get_node(owner)
            dataset = self.server.zone.get_rdataset(owner, rrset.rdtype)
            exists = (
                bool(node and node.rdatasets)
                if rrset.rdtype == dns.rdatatype.ANY
                else bool(dataset)
            )
            if rrset.deleting == dns.rdataclass.NONE:
                if exists:
                    return (
                        dns.rcode.YXDOMAIN
                        if rrset.rdtype == dns.rdatatype.ANY
                        else dns.rcode.YXRRSET
                    )
            elif rrset.deleting == dns.rdataclass.ANY:
                if not exists:
                    return (
                        dns.rcode.NXDOMAIN
                        if rrset.rdtype == dns.rdatatype.ANY
                        else dns.rcode.NXRRSET
                    )
            else:
                values.setdefault((owner, rrset.rdtype), set()).update(rrset)
        for (owner, rtype), wanted in values.items():
            if set(self.server.zone.get_rdataset(owner, rtype) or ()) != wanted:
                return dns.rcode.NXRRSET
        return dns.rcode.NOERROR

    def send(self, response, multi=False, context=None):
        server = self.server
        if server.unsigned:
            response.tsig = None
        wire = response.to_wire(multi=multi, tsig_ctx=context)
        if server.corrupt:
            wire = wire[:-1] + bytes([wire[-1] ^ 1])
        server.messages += 1
        self.wfile.write(struct.pack("!H", len(wire)) + wire)
        self.wfile.flush()
        return response.tsig_ctx


class MemorySocket:
    """Only the transport is substituted; dnspython encodes and validates DNS.

    Fragment reads to exercise DNS TCP framing as well as multi-message AXFR.
    No query, transfer, signature validation or provider method is mocked.
    """

    def __init__(self, server):
        # dnspython inspects socket metadata when choosing the AXFR transport.
        self.type = socket.SOCK_STREAM
        self.family = socket.AF_INET
        self.proto = 0
        self.server = server
        self.pending = bytearray()
        self.replies = io.BytesIO()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def setblocking(self, _):
        pass

    def connect_ex(self, _):
        return 0

    def send(self, data):
        self.pending.extend(data)
        if len(self.pending) >= 2:
            length = struct.unpack("!H", self.pending[:2])[0]
            if len(self.pending) == length + 2:
                handler = DNSHandler(self.server, self.pending)
                handler.handle()
                self.replies = io.BytesIO(handler.wfile.getvalue())
        return len(data)

    def recv(self, count):
        return self.replies.read(min(count, 71))


@pytest.fixture
def authoritative_server(monkeypatch):
    server = DNSServer()
    monkeypatch.setattr(dns.query, "socket_factory", lambda *_: MemorySocket(server))
    yield server


def config(server, **options):
    return ConfigResolver().with_dict(
        {
            "provider_name": "lebureau",
            "domain": "example.com",
            "lebureau": {
                "auth_token": TOKEN,
                "ddns_server": "127.0.0.1",
                "ddns_port": server.server_address[1],
            },
            **options,
        }
    )


@pytest.fixture
def live_zone():
    try:
        zone = LiveZone(live_config())
    except ValueError as error:
        pytest.fail(str(error), pytrace=False)
    zone.prepare()  # No cleanup is needed if read-only preflight fails.
    try:
        yield zone
    finally:
        zone.cleanup()


class TestLeBureauProvider(IntegrationTestsV2):
    """Run Lexicon's shared contract against signed DNS wire messages."""

    provider_name = "lebureau"
    domain = "example.com"

    @pytest.fixture(autouse=True)
    def configure_server(self, request):
        self.live_zone = None
        if os.environ.get("LEXICON_LIVE_TESTS") == "true":
            self.live_zone = request.getfixturevalue("live_zone")
            self.domain = self.live_zone.domain
        else:
            self.server = request.getfixturevalue("authoritative_server")
            self.domain = "example.com"

    def _construct_authenticated_provider(self):
        if self.live_zone is not None:
            return self.live_zone.provider()
        return super()._construct_authenticated_provider()

    def _test_parameters_overrides(self):
        if self.live_zone is not None:
            return {}
        return {
            "auth_token": TOKEN,
            "ddns_server": "127.0.0.1",
            "ddns_port": self.server.server_address[1],
        }

    def _test_fallback_fn(self):
        return lambda _: None

    @pytest.mark.parametrize("rtype,content", RECORD_CASES)
    def test_public_client_round_trip(self, rtype, content):
        if self.live_zone is not None:
            settings = self.live_zone.config
            owner = self.live_zone.name("client")
            moved = self.live_zone.name("moved-client")
            # Register both possible owners before any potentially ambiguous write.
            self.live_zone.names.update((owner, moved))
        else:
            settings = config(self.server)
            owner = "client.example.com"
            moved = "moved-client.example.com"
        with Client(settings) as client:
            assert client.create_record(rtype, owner, content)
        settings.add_config_source(
            DictConfigSource({"action": "list", "type": rtype}), 0
        )

        def records(name):
            # Type-only listings via the public legacy API used by integrations.
            return [r for r in Client(settings).execute() if r["name"] == name]

        wait_until(lambda: records(owner))
        record = records(owner)[0]
        assert record["ttl"] == 3600
        if rtype == "MX":
            assert record["content"] == "mail.example.com."
            assert record["options"] == {"mx": {"priority": 10}}
        elif rtype == "CNAME":
            assert record["content"] == "target.example.com."
        with Client(settings) as client:
            assert client.update_record(record["id"], name=moved)
        wait_until(lambda: records(moved) and not records(owner))
        changed = records(moved)[0]
        with Client(settings) as client:
            assert client.delete_record(changed["id"])
        wait_until(lambda: not records(moved))

    def test_public_client_mx_priority_option(self):
        if self.live_zone is not None:
            base = self.live_zone.config
            owner = self.live_zone.name("mx-options")
            self.live_zone.names.add(owner)
        else:
            base = config(self.server)
            owner = "mx-options.example.com"

        def settings(priority):
            resolver = ConfigResolver().with_dict({"priority": priority})
            for source in base._config_sources:
                resolver.with_config_source(source)
            return resolver

        def records():
            with Client(base) as client:
                return client.list_records("MX", owner)

        with Client(settings(10)) as client:
            assert client.create_record("MX", owner, "mail.example.net.")
        wait_until(lambda: records())
        original = records()[0]
        assert original["content"] == "mail.example.net."
        assert original["options"] == {"mx": {"priority": 10}}
        with Client(settings(0)) as client:
            assert client.update_record(original["id"], content="new.example.net.")
        wait_until(lambda: records() and records()[0]["options"]["mx"]["priority"] == 0)
        updated = records()[0]
        assert updated["content"] == "new.example.net."
        with Client(base) as client:
            assert client.delete_record(updated["id"])
        wait_until(lambda: not records())

    @pytest.mark.parametrize(
        "value",
        [
            "v=DKIM1; p=" + "a" * 800,
            "é😀" * 130,
            '"first" "second"',
        ],
    )
    def test_txt_content_and_siblings(self, value):
        provider = self._construct_authenticated_provider()
        provider.create_record("TXT", "txt", value)
        provider.create_record("TXT", "txt", "keep-sibling")
        record = provider.list_records("TXT", "txt", value)[0]
        # A fresh authenticated provider must resolve the previous client's ID.
        provider = self._construct_authenticated_provider()
        assert provider.update_record(record["id"], content="replacement")
        assert provider.list_records("TXT", "txt", "keep-sibling")
        changed = provider.list_records("TXT", "txt", "replacement")[0]
        provider = self._construct_authenticated_provider()
        assert provider.delete_record(changed["id"])
        assert [r["content"] for r in provider.list_records("TXT", "txt")] == [
            "keep-sibling"
        ]


@pytest.mark.parametrize("rtype,content", RECORD_CASES)
def test_public_client_fresh_identifier_round_trip(
    authoritative_server, rtype, content
):
    server = authoritative_server
    with Client(config(server, ttl=120)) as client:
        assert client.create_record(rtype, "test", content)
    # Exercise Client.execute() used by existing integrations and its type validation.
    records = Client(config(server, action="list", type=rtype)).execute()
    record = next(record for record in records if record["name"] == "test.example.com")
    assert record["ttl"] == 120
    with Client(config(server)) as client:
        assert client.list_records(rtype, "TEST.example.com.")[0]["id"] == record["id"]
        assert client.update_record(record["id"], name="renamed")
        renamed = client.list_records(rtype, "renamed")[0]
        assert renamed["ttl"] == 120
    with Client(config(server)) as client:
        assert client.delete_record(renamed["id"])
        assert not client.list_records(rtype, "renamed")


def test_complete_multi_message_axfr(authoritative_server):
    server = authoritative_server
    for number in range(200):
        server.zone.replace_rdataset(
            f"record{number}.example.com.",
            dns.rrset.from_text(
                f"record{number}.example.com.", 120, "IN", "TXT", '"payload"'
            ),
        )
    provider = Provider(config(server))
    provider.authenticate()
    records = provider.list_records()
    assert len(records) == 203
    assert sum(record["type"] == "SOA" for record in records) == 1
    assert server.messages >= 408


@pytest.mark.parametrize(
    "value",
    [
        "v=DKIM1; p=" + "a" * 800,
        "é" * 300,
        '"' + "é" * 300 + '"',
        r'"quote\" slash\\ decimal\032" "suffix"',
        '"' + "x" * 255 + '" "second"',
        r'"\255\000binary"',
        "",
        '""',
    ],
)
def test_txt_round_trip_and_siblings(authoritative_server, value):
    server = authoritative_server
    with Client(config(server, ttl=120)) as client:
        client.create_record("TXT", "txt", value)
        client.create_record("TXT", "txt", "keep-me")
        found = client.list_records("TXT", "txt", value)
        assert len(found) == 1
        record = found[0]
        assert (
            client.list_records("TXT", "txt", record["content"])[0]["id"]
            == record["id"]
        )
    with Client(config(server, ttl=180)) as client:
        assert client.update_record(record["id"], content="changed")
        records = client.list_records("TXT", "txt")
        assert {record["content"] for record in records} == {"changed", "keep-me"}
        assert {record["ttl"] for record in records} == {180}
        client.delete_record(None, "TXT", "txt", "changed")
        assert [record["content"] for record in client.list_records("TXT", "txt")] == [
            "keep-me"
        ]


def test_txt_multipart_identity_and_duplicate(authoritative_server):
    provider = Provider(config(authoritative_server))
    provider.create_record("TXT", "txt", '"hello" "world"')
    first = provider.list_records("TXT", "txt")[0]
    provider.create_record("TXT", "txt", "helloworld")
    assert provider.list_records("TXT", "txt") == [first]
    data = authoritative_server.zone.find_rdataset("txt.example.com.", "TXT")
    assert next(iter(data)).strings == (b"hello", b"world")
    provider.update_record(first["id"])
    updated = authoritative_server.zone.find_rdataset("txt.example.com.", "TXT")
    assert next(iter(updated)).strings == (b"hello", b"world")


@pytest.mark.parametrize(
    "name", ["@", "", "example.com", "EXAMPLE.COM.", "*", "*.example.com."]
)
def test_owner_names(authoritative_server, name):
    provider = Provider(config(authoritative_server))
    provider.create_record("TXT", name, "test")
    assert len(provider.list_records("TXT", name)) == 1
    provider.delete_record(None, "TXT", name)
    assert not provider.list_records("TXT", name)


@pytest.mark.parametrize("operation", ["create", "update", "delete"])
def test_reject_outside_zone(authoritative_server, operation):
    provider = Provider(config(authoritative_server))
    with pytest.raises(ValueError, match="outside"):
        if operation == "create":
            provider.create_record("TXT", "other.example.", "test")
        elif operation == "delete":
            provider.delete_record(None, "TXT", "other.example.")
        else:
            provider.create_record("TXT", "orig", "test")
            record = provider.list_records("TXT", "orig")[0]
            provider.update_record(record["id"], name="other.example.")


@pytest.mark.parametrize(
    "token",
    [
        None,
        "",
        "broken",
        "hmac-foo:key:c2VjcmV0",
        "gss-tsig:key:c2VjcmV0",
        "hmac-sha512:key:!!!",
        "hmac-sha512::c2VjcmV0",
    ],
)
def test_invalid_credentials(authoritative_server, token):
    settings = config(
        authoritative_server,
        lebureau={
            "auth_token": token,
            "ddns_server": "127.0.0.1",
        },
    )
    with pytest.raises(AuthenticationError, match="Invalid TSIG"):
        Provider(settings)


@pytest.mark.parametrize(
    "rcode", [dns.rcode.REFUSED, dns.rcode.NOTAUTH, dns.rcode.SERVFAIL]
)
def test_refused_updates(authoritative_server, rcode):
    provider = Provider(config(authoritative_server))
    provider.authenticate()
    authoritative_server.rcode = rcode
    with pytest.raises(LexiconError, match=dns.rcode.to_text(rcode)):
        provider._send(provider._update())


@pytest.mark.parametrize("failure", ["truncate", "unsigned", "corrupt", "refused"])
def test_invalid_transfers(authoritative_server, failure):
    if failure == "refused":
        authoritative_server.rcode = dns.rcode.REFUSED
    else:
        setattr(authoritative_server, failure, True)
    with pytest.raises(AuthenticationError):
        Provider(config(authoritative_server)).authenticate()


def test_missing_identifiers_and_ambiguous_updates(authoritative_server):
    provider = Provider(config(authoritative_server))
    assert provider.delete_record("missing")
    with pytest.raises(LexiconError, match="exactly one"):
        provider.update_record("missing", content="value")
    provider.create_record("TXT", "txt", "one")
    provider.create_record("TXT", "txt", "two")
    with pytest.raises(LexiconError, match="exactly one"):
        provider.update_record(None, "TXT", "txt", "new")


def test_provider_discovery(monkeypatch):
    from lexicon._private.providers import auto

    assert "lebureau" in find_providers()
    monkeypatch.setattr(
        auto,
        "_get_ns_records_for_domain",
        lambda _: ["ns1.lebureau.coop.", "ns2.lebureau.coop."],
    )
    assert auto._relevant_provider_for_domain("example.com")[0] == "lebureau"


def test_delegated_zone(authoritative_server):
    server = authoritative_server
    server.zone = dns.zone.from_text(
        ZONE, origin="delegated.example.com.", relativize=False
    )
    with Client(config(server, delegated="delegated")) as client:
        client.create_record("CAA", "@", '0 issue "letsencrypt.org"')
        record = client.list_records("CAA")[0]
        assert record["name"] == "delegated.example.com"
    with Client(config(server, delegated="delegated.example.com.")) as client:
        client.delete_record(record["id"])
        assert not client.list_records("CAA")


def test_hostname_resolution_and_initial_failover(authoritative_server, monkeypatch):
    server = authoritative_server
    settings = config(
        server, lebureau={"auth_token": TOKEN, "ddns_server": "dns.example.com"}
    )
    lookups = []
    connections = []

    def resolve(name, rtype, lifetime):
        assert name == "dns.example.com"
        assert lifetime == 10
        lookups.append(rtype)
        return ["192.0.2.1"] if rtype == "A" else ["2001:db8::1"]

    def connect(sock, address):
        connections.append(address[0])
        if address[0] == "192.0.2.1":
            raise dns.exception.Timeout
        return 0

    monkeypatch.setattr(dns.resolver, "resolve", resolve)
    monkeypatch.setattr(MemorySocket, "connect_ex", connect)
    provider = Provider(settings)
    provider.authenticate()
    assert lookups == ["A", "AAAA"]
    assert connections == ["192.0.2.1", "2001:db8::1"]
    assert provider.endpoint == "2001:db8::1"
    provider.create_record("TXT", "test", "value")
    assert all(address == "2001:db8::1" for address in connections[2:])


def test_unresolvable_endpoint(authoritative_server, monkeypatch):
    def resolve(*_, **__):
        raise dns.resolver.NXDOMAIN

    monkeypatch.setattr(dns.resolver, "resolve", resolve)
    settings = config(
        authoritative_server,
        lebureau={"auth_token": TOKEN, "ddns_server": "absent.example.com"},
    )
    with pytest.raises(AuthenticationError, match="resolve"):
        Provider(settings).authenticate()


@pytest.mark.parametrize("failure", ["unsigned", "corrupt", "timeout"])
def test_update_failures_are_not_retried(authoritative_server, monkeypatch, failure):
    server = authoritative_server
    provider = Provider(config(server))
    provider.authenticate()
    if failure == "timeout":
        attempts = []

        def lost_reply(sock, count):
            attempts.append(count)
            raise dns.exception.Timeout

        monkeypatch.setattr(MemorySocket, "recv", lost_reply)
    else:
        setattr(server, failure, True)
    with pytest.raises(LexiconError):
        provider._send(provider._update())
    assert server.writes == 1
    if failure == "timeout":
        assert len(attempts) == 1


@pytest.mark.parametrize(
    "option,value",
    [
        ("ddns_port", 0),
        ("ddns_port", -1),
        ("ddns_port", 65536),
        ("timeout", 0),
        ("timeout", -1),
        ("timeout", "nan"),
        ("timeout", "inf"),
    ],
)
def test_invalid_connection_settings(authoritative_server, option, value):
    settings = config(
        authoritative_server,
        lebureau={
            "auth_token": TOKEN,
            "ddns_server": "127.0.0.1",
            option: value,
        },
    )
    with pytest.raises(ValueError, match="port or timeout"):
        Provider(settings)


@pytest.mark.parametrize("server", [None, ""])
def test_default_endpoint(authoritative_server, monkeypatch, server):
    settings = config(
        authoritative_server,
        lebureau={
            "auth_token": TOKEN,
            "ddns_server": server,
        },
    )
    lookups = []

    def resolve(name, rtype, lifetime):
        lookups.append((name, rtype))
        return ["127.0.0.1"]

    monkeypatch.setattr(dns.resolver, "resolve", resolve)
    with Client(settings) as client:
        client.create_record("TXT", "default-server", "test")
        assert client.list_records("TXT", "default-server")[0]["content"] == "test"
    assert lookups == [("ns2.lebureau.coop", "A"), ("ns2.lebureau.coop", "AAAA")]


@pytest.mark.parametrize("ttl", [0, "0"])
def test_ttl_reset_and_selected_value_move(authoritative_server, ttl):
    server = authoritative_server
    with Client(config(server, ttl=120)) as client:
        client.create_record("TXT", "original", "one")
        client.create_record("TXT", "original", "two")
        first = client.list_records("TXT", "original", "one")[0]
    with Client(config(server, ttl=ttl)) as client:
        client.update_record(first["id"], name="moved")
        assert client.list_records("TXT", "moved")[0]["ttl"] == 3600
        remaining = client.list_records("TXT", "original")
        assert [record["content"] for record in remaining] == ["two"]
        assert remaining[0]["ttl"] == 120


def test_txt_utf8_chunks_and_escaped_byte_boundaries(authoritative_server):
    provider = Provider(config(authoritative_server))
    value = "v=DKIM1; p=" + "😀" * 160
    provider.create_record("TXT", "utf8", value)
    data = next(
        iter(authoritative_server.zone.find_rdataset("utf8.example.com.", "TXT"))
    )
    assert all(len(chunk) <= 255 for chunk in data.strings)
    assert "".join(chunk.decode("utf-8") for chunk in data.strings) == value
    assert provider.list_records("TXT", "utf8")[0]["content"] == value


def test_reusing_client_preserves_omitted_ttl(authoritative_server):
    with Client(config(authoritative_server, ttl=120)) as operations:
        operations.create_record("TXT", "test", "value")
        record = operations.list_records("TXT", "test")[0]
    client = Client(config(authoritative_server))
    with client as operations:
        assert operations.list_records("TXT", "test")[0]["ttl"] == 120
    with client as operations:
        operations.update_record(record["id"], content="updated")
        assert operations.list_records("TXT", "test")[0]["ttl"] == 120


def test_content_only_filter(authoritative_server):
    provider = Provider(config(authoritative_server))
    provider.create_record("TXT", "test", "filter value")
    assert [
        record["name"] for record in provider.list_records(content="filter value")
    ] == ["test.example.com"]
    assert not provider.list_records("A", content="not an address")


def test_multiline_txt_input(authoritative_server):
    provider = Provider(config(authoritative_server))
    provider.create_record("TXT", "test", '"first"\n"second"')
    assert provider.list_records("TXT", "test")[0]["content"] == "firstsecond"


def test_live_configuration_requires_explicit_domain_and_key(monkeypatch):
    monkeypatch.delenv("LEXICON_LEBUREAU_TEST_DOMAIN", raising=False)
    monkeypatch.delenv("LEXICON_LEBUREAU_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("LEXICON_LEBUREAU_TOKEN", raising=False)
    with pytest.raises(ValueError, match="LEXICON_LEBUREAU_TEST_DOMAIN"):
        live_config()
    monkeypatch.setenv("LEXICON_LEBUREAU_TEST_DOMAIN", "example.com")
    with pytest.raises(ValueError, match="LEXICON_LEBUREAU_AUTH_TOKEN"):
        live_config()
    monkeypatch.setenv("LEXICON_LEBUREAU_AUTH_TOKEN", TOKEN)
    assert live_config().resolve("lexicon:domain") == "example.com"


def test_live_namespace_and_cleanup_preserve_existing_records(authoritative_server):
    backend = Provider(config(authoritative_server))
    backend.create_record("TXT", "existing", "untouched")
    original = backend.list_records()
    zone = LiveZone(config(authoritative_server))
    zone.prepare()
    provider = zone.provider()
    assert provider.list_records() == []
    provider.create_record("TXT", "docs", "one")
    provider.create_record("TXT", "docs", "two")
    record = provider.list_records("TXT", "docs")[0]
    assert record["name"] == f"docs.{zone.domain}"
    assert provider.list_records("TXT", f"docs.{zone.domain}.")
    existing = backend.list_records("TXT", "existing")[0]
    with pytest.raises(LexiconError, match="namespace"):
        provider.update_record(existing["id"], content="changed")
    assert provider.delete_record(existing["id"])
    assert backend.list_records("TXT", "existing") == [existing]
    zone.provider().update_record(record["id"], name="renamed")
    zone.cleanup()
    # Updates legitimately advance SOA serials; unrelated user RRs must survive.
    assert [r for r in backend.list_records() if r["type"] != "SOA"] == [
        r for r in original if r["type"] != "SOA"
    ]


@pytest.mark.parametrize(
    "name", ["example.com", "outside.example.com.", "outside.invalid."]
)
def test_live_namespace_rejects_external_owners(authoritative_server, name):
    zone = LiveZone(config(authoritative_server))
    with pytest.raises(ValueError, match="namespace"):
        zone.name(name)
    assert zone.name("@") == zone.domain
    assert not zone.owns("example.com")


def test_live_namespace_collision_stops_before_writes(authoritative_server):
    zone = LiveZone(config(authoritative_server), prefix="collision")
    backend = Provider(config(authoritative_server))
    backend.create_record("TXT", "existing.collision", "untouched")
    before = authoritative_server.writes
    with pytest.raises(LexiconError, match="already exists"):
        zone.prepare()
    assert authoritative_server.writes == before
    assert not zone.names


def test_live_cleanup_includes_write_with_lost_reply(authoritative_server, monkeypatch):
    zone = LiveZone(config(authoritative_server))
    zone.prepare()
    provider = zone.provider()
    original = provider.backend._send

    def lose_reply(update):
        original(update)
        raise LexiconError("reply lost")

    monkeypatch.setattr(provider.backend, "_send", lose_reply)
    with pytest.raises(LexiconError, match="reply lost"):
        provider.create_record("TXT", "uncertain", "value")
    assert zone.names == {zone.name("uncertain")}
    zone.cleanup()
    assert provider.list_records() == []


def test_live_cleanup_attempts_every_owner(authoritative_server, monkeypatch):
    zone = LiveZone(config(authoritative_server))
    zone.prepare()
    provider = zone.provider()
    provider.create_record("TXT", "first", "one")
    provider.create_record("TXT", "second", "two")
    original = zone._cleanup_name

    def refuse_first(name):
        if name == zone.name("first"):
            raise LexiconError("REFUSED")
        return original(name)

    monkeypatch.setattr(zone, "_cleanup_name", refuse_first)
    with pytest.raises(LexiconError, match="cleanup failed"):
        zone.cleanup()
    assert not provider.list_records("TXT", "second")
    assert provider.list_records("TXT", "first")
    monkeypatch.setattr(zone, "_cleanup_name", original)
    zone.cleanup()


def test_live_polling_timeout(monkeypatch):
    import lebureau_live

    ticks = iter([0, 2])
    monkeypatch.setattr(lebureau_live.time, "monotonic", lambda: next(ticks))
    with pytest.raises(AssertionError, match="converge"):
        wait_until(lambda: False, timeout=1)


def test_live_public_client_preserves_delegated_zone(authoritative_server, monkeypatch):
    authoritative_server.zone = dns.zone.from_text(
        ZONE,
        origin="delegated.example.com.",
        relativize=False,
    )
    monkeypatch.setenv("LEXICON_LEBUREAU_TEST_DOMAIN", "delegated.example.com")
    monkeypatch.setenv("LEXICON_LEBUREAU_AUTH_TOKEN", TOKEN)
    monkeypatch.setenv("LEXICON_LEBUREAU_DDNS_SERVER", "127.0.0.1")
    zone = LiveZone(live_config())
    zone.prepare()
    owner = zone.name("client")
    zone.names.add(owner)
    try:
        with Client(zone.config) as client:
            client.create_record("CAA", owner, '0 issue "example.org"')
            assert client.list_records("CAA", owner)[0]["name"] == owner
    finally:
        zone.cleanup()


def test_live_cleanup_accepts_delete_with_lost_reply(authoritative_server, monkeypatch):
    zone = LiveZone(config(authoritative_server))
    zone.prepare()
    zone.provider().create_record("TXT", "uncertain-delete", "value")
    original = Provider._send
    writes = authoritative_server.writes

    def lose_reply(provider, update):
        original(provider, update)
        raise LexiconError("reply lost")

    monkeypatch.setattr(Provider, "_send", lose_reply)
    zone.cleanup()
    assert authoritative_server.writes == writes + 1
    assert zone.provider().list_records() == []


def test_live_cleanup_retries_failed_verification_read(
    authoritative_server, monkeypatch
):
    import lebureau_live

    zone = LiveZone(config(authoritative_server))
    zone.prepare()
    zone.provider().create_record("TXT", "verification", "value")
    original = Provider.list_records
    writes = authoritative_server.writes
    interrupted = False

    def interrupt_read(provider, *args, **kwargs):
        nonlocal interrupted
        if authoritative_server.writes > writes and not interrupted:
            interrupted = True
            raise LexiconError("temporary AXFR failure after delete")
        return original(provider, *args, **kwargs)

    monkeypatch.setattr(Provider, "list_records", interrupt_read)
    monkeypatch.setattr(lebureau_live.time, "sleep", lambda _: None)
    zone.cleanup()
    assert interrupted
    assert authoritative_server.writes == writes + 1
    assert zone.provider().list_records() == []


def test_live_cleanup_retries_authentication_read(authoritative_server, monkeypatch):
    import lebureau_live

    zone = LiveZone(config(authoritative_server))
    zone.prepare()
    zone.provider().create_record("TXT", "auth-read", "value")
    original = Provider._load_zone
    interrupted = False

    def interrupt_read(provider):
        nonlocal interrupted
        if not interrupted:
            interrupted = True
            raise LexiconError("temporary authentication transfer failure")
        return original(provider)

    monkeypatch.setattr(Provider, "_load_zone", interrupt_read)
    monkeypatch.setattr(lebureau_live.time, "sleep", lambda _: None)
    zone.cleanup()
    assert interrupted
    assert zone.provider().list_records() == []


def test_live_cleanup_retains_delete_error_without_retry(
    authoritative_server, monkeypatch
):
    import itertools

    import lebureau_live

    zone = LiveZone(config(authoritative_server))
    zone.prepare()
    zone.provider().create_record("TXT", "refused", "value")
    original = Provider._send
    attempts = 0

    def refuse_delete(provider, update):
        nonlocal attempts
        attempts += 1
        raise LexiconError("Le Bureau rejected DNS update: REFUSED")

    ticks = itertools.count(step=60)
    monkeypatch.setattr(lebureau_live.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(Provider, "_send", refuse_delete)
    with pytest.raises(LexiconError, match="cleanup failed") as caught:
        zone.cleanup()
    assert "REFUSED" in str(caught.value)
    assert "TXT" in str(caught.value)
    assert zone.name("refused") in str(caught.value)
    assert attempts == 1
    monkeypatch.setattr(Provider, "_send", original)
    zone.cleanup()


def test_live_polling_retains_last_read_error(monkeypatch):
    import lebureau_live

    ticks = iter([0, 2])
    monkeypatch.setattr(lebureau_live.time, "monotonic", lambda: next(ticks))

    def failed_read():
        raise LexiconError("AXFR failed")

    with pytest.raises(
        AssertionError, match="last read error: LexiconError: AXFR failed"
    ):
        wait_until(failed_read, timeout=1)


@pytest.mark.parametrize(
    "operation", ["delete_set", "delete_content", "delete_id", "update_id"]
)
def test_distinct_txt_wire_values_survive_listing(authoritative_server, operation):
    server = authoritative_server
    server.zone.replace_rdataset(
        "txt.example.com.",
        dns.rrset.from_text(
            "txt.example.com.", 120, "IN", "TXT", '"ab" "cd"', '"abcd"'
        ),
    )
    provider = Provider(config(server))
    records = provider.list_records("TXT", "txt", "abcd")
    assert len(records) == 2
    assert len({record["id"] for record in records}) == 2
    assert sorted(records, key=lambda r: r["id"]) == sorted(
        Provider(config(server)).list_records("TXT", "txt", '"ab" "cd"'),
        key=lambda r: r["id"],
    )
    assert provider.create_record("TXT", "txt", "abcd")
    assert sorted(provider.list_records("TXT", "txt"), key=lambda r: r["id"]) == sorted(
        records, key=lambda r: r["id"]
    )
    selected, sibling = records
    if operation == "delete_set":
        assert provider.delete_record(rtype="TXT", name="txt")
    elif operation == "delete_content":
        assert provider.delete_record(rtype="TXT", name="txt", content="abcd")
    elif operation == "delete_id":
        assert provider.delete_record(selected["id"])
    else:
        assert provider.update_record(selected["id"], content="changed")
    remaining = provider.list_records("TXT", "txt")
    if operation in ("delete_set", "delete_content"):
        assert not remaining
        assert server.zone.get_rdataset("txt.example.com.", "TXT") is None
    else:
        assert sibling in remaining
        assert selected not in remaining
        assert len(remaining) == (2 if operation == "update_id" else 1)


@pytest.mark.parametrize("ttl,expected", [("0", 3600), ("180", 180)])
def test_environment_ttl_create_and_update(
    authoritative_server, monkeypatch, ttl, expected
):
    with Client(config(authoritative_server, ttl=120)) as client:
        client.create_record("TXT", "original", "value")
        original = client.list_records("TXT", "original")[0]
    monkeypatch.setenv("LEXICON_TTL", ttl)
    with Client(config(authoritative_server).with_env()) as client:
        client.create_record("TXT", "created", "value")
        assert client.list_records("TXT", "created")[0]["ttl"] == expected
        client.update_record(original["id"], name="moved")
        assert client.list_records("TXT", "moved")[0]["ttl"] == expected


@pytest.mark.parametrize(
    "source_type,source_value,target_type,target_value",
    [
        ("CNAME", "old.example.com.", "A", "192.0.2.1"),
        ("A", "192.0.2.1", "CNAME", "target.example.com."),
        ("CNAME", "old.example.com.", "CNAME", "other.example.com."),
    ],
)
def test_rename_rejects_conflicting_destination(
    authoritative_server, source_type, source_value, target_type, target_value
):
    provider = Provider(config(authoritative_server))
    provider.create_record(source_type, "source", source_value)
    provider.create_record(target_type, "destination", target_value)
    before = provider.list_records()
    source = provider.list_records(source_type, "source")[0]
    writes = authoritative_server.writes
    with pytest.raises(LexiconError, match="destination conflicts"):
        provider.update_record(source["id"], name="destination")
    assert authoritative_server.writes == writes
    assert provider.list_records() == before


@pytest.mark.parametrize("change", ["destination", "source", "source_sibling"])
def test_rename_prerequisites_reject_concurrent_change(authoritative_server, change):
    server = authoritative_server
    provider = Provider(config(server))
    provider.create_record("CNAME", "source", "old.example.com.")
    source = provider.list_records("CNAME", "source")[0]

    def concurrent_write():
        if change == "destination":
            # Do not advance SOA here: the name-absence prerequisite must catch
            # a conflicting add even when the server defers serial increments.
            server.zone.replace_rdataset(
                "destination.example.com.",
                dns.rrset.from_text(
                    "destination.example.com.", 120, "IN", "A", "192.0.2.1"
                ),
            )
        else:
            # Likewise, test the exact source prerequisite independently of SOA.
            server.zone.replace_rdataset(
                "source.example.com.",
                dns.rrset.from_text(
                    "source.example.com.", 120, "IN", "CNAME", "new.example.com."
                ),
            )

    if change == "source_sibling":
        provider.delete_record(source["id"])
        provider.create_record("TXT", "source", "one")
        source = provider.list_records("TXT", "source")[0]

        def concurrent_write():
            server.zone.find_rdataset("source.example.com.", "TXT").add(
                provider._rdata("TXT", "two")
            )

    server.before_update = concurrent_write
    writes = server.writes
    with pytest.raises(LexiconError, match="YXDOMAIN|NXRRSET"):
        provider.update_record(source["id"], name="destination")
    assert server.writes == writes + 1
    assert provider.list_records(name="source")
    if change == "destination":
        assert provider.list_records("CNAME", "source") == [source]
        assert provider.list_records("A", "destination")
    else:
        assert not provider.list_records(name="destination")


def test_wire_authority_silently_ignores_conflicting_add(authoritative_server):
    provider = Provider(config(authoritative_server))
    provider.create_record("CNAME", "source", "target.example.com.")
    provider.create_record("A", "destination", "192.0.2.1")
    update = provider._update()
    update.delete("source", "CNAME")
    update.add("destination", 120, "CNAME", "target.example.com.")
    # Reproduce the original data loss with an unguarded update: NOERROR does
    # not mean the replacement was added.
    assert provider._send(update)
    assert not provider.list_records("CNAME", "source")
    assert not provider.list_records("CNAME", "destination")
    assert provider.list_records("A", "destination")


@pytest.mark.parametrize(
    "rtype,content", [("A", "192.0.2.2"), ("CNAME", "target.example.com.")]
)
def test_rename_into_compatible_rrset(authoritative_server, rtype, content):
    provider = Provider(config(authoritative_server))
    provider.create_record(rtype, "source", content)
    provider.create_record(rtype, "destination", content)
    source = provider.list_records(rtype, "source")[0]
    assert provider.update_record(source["id"], name="destination")
    assert not provider.list_records(rtype, "source")
    assert len(provider.list_records(rtype, "destination")) == 1


@pytest.mark.parametrize(
    "rtype,content", [("A", "192.0.2.2"), ("CNAME", "target.example.com.")]
)
def test_cname_type_conversion_at_same_owner(authoritative_server, rtype, content):
    provider = Provider(config(authoritative_server))
    old_type, old_content = (
        ("CNAME", "target.example.com.") if rtype == "A" else ("A", "192.0.2.2")
    )
    provider.create_record(old_type, "source", old_content)
    source = provider.list_records(old_type, "source")[0]
    if rtype == "CNAME":
        writes = authoritative_server.writes
        with pytest.raises(LexiconError, match="cannot safely convert"):
            provider.update_record(source["id"], rtype=rtype, content=content)
        assert authoritative_server.writes == writes
        assert provider.list_records(name="source") == [source]
        return
    assert provider.update_record(source["id"], rtype=rtype, content=content)
    records = provider.list_records(name="source")
    assert len(records) == 1
    assert records[0]["type"] == rtype
    assert records[0]["content"] == content


@pytest.mark.parametrize("change", ["cname", "soa"])
def test_update_existing_destination_prerequisites(authoritative_server, change):
    server = authoritative_server
    provider = Provider(config(server))
    provider.create_record("A", "source", "192.0.2.1")
    provider.create_record("A", "destination", "192.0.2.2")
    source = provider.list_records("A", "source")[0]

    def concurrent_write():
        if change == "soa":
            server.changed()
        else:
            server.zone.delete_rdataset("destination.example.com.", "A")
            server.zone.replace_rdataset(
                "destination.example.com.",
                dns.rrset.from_text(
                    "destination.example.com.",
                    120,
                    "IN",
                    "CNAME",
                    "target.example.com.",
                ),
            )

    server.before_update = concurrent_write
    if change == "soa":
        assert provider.update_record(source["id"], name="destination")
        assert not provider.list_records("A", "source")
        assert provider.list_records("A", "destination", "192.0.2.1")
        return
    with pytest.raises(LexiconError, match="NXRRSET|YXRRSET"):
        provider.update_record(source["id"], name="destination")
    assert provider.list_records("A", "source") == [source]
    assert not provider.list_records("A", "destination", "192.0.2.1")


def test_conversion_to_cname_rejects_before_racing_txt_add(authoritative_server):
    server = authoritative_server
    provider = Provider(config(server))
    provider.create_record("A", "source", "192.0.2.1")
    source = provider.list_records("A", "source")[0]
    original_list = provider.list_records

    def list_then_race(*args, **kwargs):
        records = original_list(*args, **kwargs)
        server.zone.replace_rdataset(
            "source.example.com.",
            dns.rrset.from_text(
                "source.example.com.", 120, "IN", "TXT", '"concurrent"'
            ),
        )
        return records

    provider.list_records = list_then_race
    writes = server.writes
    with pytest.raises(LexiconError, match="cannot safely convert"):
        provider.update_record(
            source["id"], rtype="CNAME", content="target.example.com."
        )
    assert server.writes == writes
    assert original_list("A", "source") == [source]
    assert original_list("TXT", "source")


@pytest.mark.parametrize(
    "rtype,value,existing_type,existing_value",
    [
        ("CNAME", "target.example.com.", "A", "192.0.2.1"),
        ("A", "192.0.2.1", "CNAME", "target.example.com."),
        ("CNAME", "new.example.com.", "CNAME", "old.example.com."),
    ],
)
def test_create_rejects_existing_conflict(
    authoritative_server, rtype, value, existing_type, existing_value
):
    server = authoritative_server
    provider = Provider(config(server))
    provider.create_record(existing_type, "owner", existing_value)
    before = provider.list_records(name="owner")
    writes = server.writes
    with pytest.raises(LexiconError, match="destination conflicts"):
        provider.create_record(rtype, "owner", value)
    assert server.writes == writes
    assert provider.list_records(name="owner") == before


@pytest.mark.parametrize(
    "rtype,value,concurrent_type,concurrent_value",
    [
        ("CNAME", "target.example.com.", "A", "192.0.2.1"),
        ("CNAME", "target.example.com.", "TXT", '"concurrent"'),
        ("CNAME", "target.example.com.", "CNAME", "other.example.com."),
        ("A", "192.0.2.1", "CNAME", "target.example.com."),
    ],
)
def test_create_prerequisites_reject_racing_conflict(
    authoritative_server, rtype, value, concurrent_type, concurrent_value
):
    server = authoritative_server
    provider = Provider(config(server))

    def concurrent_write():
        server.zone.replace_rdataset(
            "owner.example.com.",
            dns.rrset.from_text(
                "owner.example.com.", 120, "IN", concurrent_type, concurrent_value
            ),
        )

    server.before_update = concurrent_write
    with pytest.raises(LexiconError, match="YXDOMAIN|YXRRSET"):
        provider.create_record(rtype, "owner", value)
    records = provider.list_records(name="owner")
    assert len(records) == 1
    assert records[0]["type"] == concurrent_type
    assert records[0]["content"] == concurrent_value.strip('"')


@pytest.mark.parametrize("by_id", [True, False])
@pytest.mark.parametrize("rtype", ["SOA", "NS"])
def test_delete_rejects_protected_apex(authoritative_server, rtype, by_id):
    server = authoritative_server
    provider = Provider(config(server))
    before = provider.list_records()
    record = provider.list_records(rtype, "@")[0]
    writes = server.writes
    with pytest.raises(LexiconError, match="apex SOA|last apex NS"):
        if by_id:
            provider.delete_record(record["id"])
        else:
            provider.delete_record(rtype=rtype, name="@")
    assert server.writes == writes
    assert provider.list_records() == before


def test_delete_all_apex_ns_rejected_but_one_sibling_allowed(authoritative_server):
    server = authoritative_server
    provider = Provider(config(server))
    provider.create_record("NS", "@", "second.example.com.")
    records = provider.list_records("NS", "@")
    writes = server.writes
    with pytest.raises(LexiconError, match="last apex NS"):
        provider.delete_record(rtype="NS", name="@")
    assert server.writes == writes
    assert provider.delete_record(records[0]["id"])
    assert provider.list_records("NS", "@") == [records[1]]


def test_delete_apex_ns_guards_concurrent_sibling_removal(authoritative_server):
    server = authoritative_server
    provider = Provider(config(server))
    provider.create_record("NS", "@", "second.example.com.")
    selected, sibling = provider.list_records("NS", "@")

    def concurrent_write():
        server.zone.find_rdataset(server.zone.origin, "NS").discard(
            provider._rdata("NS", sibling["content"])
        )

    server.before_update = concurrent_write
    with pytest.raises(LexiconError, match="NXRRSET"):
        provider.delete_record(selected["id"])
    assert provider.list_records("NS", "@") == [selected]


@pytest.mark.parametrize("deletion", ["soa_value", "ns_value", "ns_set", "owner"])
def test_wire_authority_ignores_protected_apex_deletions(
    authoritative_server, deletion
):
    provider = Provider(config(authoritative_server))
    soa = provider.list_records("SOA", "@")[0]
    ns = provider.list_records("NS", "@")[0]
    update = provider._update()
    if deletion == "soa_value":
        update.delete("@", provider._rdata("SOA", soa["content"]))
    elif deletion == "ns_value":
        update.delete("@", provider._rdata("NS", ns["content"]))
    elif deletion == "ns_set":
        update.delete("@", "NS")
    else:
        update.delete("@")
    assert provider._send(update)
    assert provider.list_records("SOA", "@")
    assert provider.list_records("NS", "@") == [ns]


def test_delete_mixed_apex_records_rejects_before_any_write(authoritative_server):
    provider = Provider(config(authoritative_server))
    provider.create_record("TXT", "@", "keep")
    before = provider.list_records()
    writes = authoritative_server.writes
    with pytest.raises(LexiconError, match="apex SOA|last apex NS"):
        provider.delete_record(name="@")
    assert authoritative_server.writes == writes
    assert provider.list_records() == before


def test_soa_mutations_rejected_and_identical_create_is_noop(authoritative_server):
    provider = Provider(config(authoritative_server))
    record = provider.list_records("SOA", "@")[0]
    data = provider._rdata("SOA", record["content"])
    changed = data.replace(serial=data.serial + 1).to_text()
    writes = authoritative_server.writes
    assert provider.create_record("SOA", "@", record["content"])
    with pytest.raises(LexiconError, match="read-only"):
        provider.create_record("SOA", "@", changed)
    with pytest.raises(LexiconError, match="read-only|apex SOA"):
        provider.update_record(record["id"], content=changed)
    assert authoritative_server.writes == writes


@pytest.mark.parametrize(
    "rtype,content,target_field",
    [
        ("CNAME", "target.example.net", "target"),
        ("NS", "target.example.net", "target"),
        ("MX", "10 target.example.net", "exchange"),
        ("SRV", "10 20 443 target.example.net", "target"),
    ],
)
@pytest.mark.parametrize("absolute", [False, True])
def test_hostname_content_uses_dns_presentation_semantics(
    authoritative_server, rtype, content, target_field, absolute
):
    provider = Provider(config(authoritative_server))
    supplied = content + ("." if absolute else "")
    expected = "target.example.net." if absolute else "target.example.net.example.com."
    assert provider.create_record(rtype, "owner", supplied)
    data = next(
        iter(authoritative_server.zone.find_rdataset("owner.example.com.", rtype))
    )
    assert getattr(data, target_field).to_text() == expected
    record = provider.list_records(rtype, "owner", supplied)[0]
    # Listings always expose absolute targets, including MX's exchange field.
    assert record["content"].endswith(expected)
    assert provider.list_records(rtype, "owner", record["content"]) == [record]
    assert provider.delete_record(rtype=rtype, name="owner", content=supplied)
    assert not provider.list_records(rtype, "owner")


@pytest.mark.parametrize("priority", [0, 10, "20"])
def test_mx_priority_option_and_listing(authoritative_server, priority):
    with Client(config(authoritative_server, priority=priority)) as client:
        assert client.create_record("MX", "mail", "mail.example.net.")
        record = client.list_records("MX", "mail")[0]
        assert record["content"] == "mail.example.net."
        assert record["options"] == {"mx": {"priority": int(priority)}}
        data = next(
            iter(authoritative_server.zone.find_rdataset("mail.example.com.", "MX"))
        )
        assert data.preference == int(priority)
        assert data.exchange.to_text() == "mail.example.net."


def test_mx_inline_priority_default_and_explicit_override(authoritative_server):
    provider = Provider(config(authoritative_server))
    assert provider.create_record("MX", "mail", "mail.example.net.")
    default = provider.list_records("MX", "mail")[0]
    assert default["options"]["mx"]["priority"] == 10
    assert provider.create_record("MX", "mail", "20 mail.example.net.")
    records = provider.list_records("MX", "mail", "mail.example.net.")
    assert {r["options"]["mx"]["priority"] for r in records} == {10, 20}
    assert len(provider.list_records("MX", "mail", "20 mail.example.net.")) == 1
    override = Provider(config(authoritative_server, priority=30))
    assert override.create_record("MX", "mail", "20 mail.example.net.")
    assert len(provider.list_records("MX", "mail")) == 3
    writes = authoritative_server.writes
    assert override.create_record("MX", "mail", "mail.example.net.")
    assert override.create_record("MX", "mail", "20 mail.example.net.")
    assert authoritative_server.writes == writes
    assert provider.delete_record(
        rtype="MX", name="mail", content="20 mail.example.net."
    )
    assert {
        r["options"]["mx"]["priority"] for r in provider.list_records("MX", "mail")
    } == {10, 30}
    assert provider.delete_record(rtype="MX", name="mail", content="mail.example.net.")
    assert not provider.list_records("MX", "mail")


def test_mx_updates_preserve_priority_and_siblings(authoritative_server):
    server = authoritative_server
    provider = Provider(config(server))
    provider.create_record("MX", "mail", "20 mail.example.net.")
    provider.create_record("MX", "mail", "30 mail.example.net.")
    selected = provider.list_records("MX", "mail", "20 mail.example.net.")[0]
    sibling = provider.list_records("MX", "mail", "30 mail.example.net.")[0]
    # Updating just the exchange preserves the selected preference.
    assert provider.update_record(selected["id"], content="new.example.net.")
    changed = provider.list_records("MX", "mail", "new.example.net.")[0]
    assert changed["options"]["mx"]["priority"] == 20
    # Full presentation input can change preference without a separate option.
    assert provider.update_record(changed["id"], content="25 newer.example.net.")
    changed = provider.list_records("MX", "mail", "newer.example.net.")[0]
    assert changed["options"]["mx"]["priority"] == 25
    # A priority-only update uses a fresh client's option, including zero.
    with Client(config(server, priority=0)) as client:
        assert client.update_record(changed["id"])
        changed = client.list_records("MX", "mail", "newer.example.net.")[0]
        assert changed["options"]["mx"]["priority"] == 0
        assert sibling in client.list_records("MX", "mail")
    # An independent client preserves that priority when moving by ID.
    with Client(config(server)) as client:
        assert client.update_record(changed["id"], name="moved")
        moved = client.list_records("MX", "moved")[0]
        assert moved["options"]["mx"]["priority"] == 0
        assert moved["content"] == "newer.example.net."
        assert client.list_records("MX", "mail") == [sibling]


@pytest.mark.parametrize("priority", [-1, 65536, "invalid", "1.5"])
def test_mx_invalid_priority_rejected_before_write(authoritative_server, priority):
    provider = Provider(config(authoritative_server, priority=priority))
    with pytest.raises((ValueError, dns.exception.DNSException)):
        provider.create_record("MX", "mail", "mail.example.net.")
    assert authoritative_server.writes == 0


@pytest.mark.parametrize("source", ["env", "file", "dict", "omitted"])
@pytest.mark.parametrize("ttl", [0, 180])
@pytest.mark.parametrize("provider_key", ["provider_name", "provider", None])
def test_legacy_dict_ttl_resolution(
    authoritative_server, monkeypatch, tmp_path, source, ttl, provider_key
):
    server = authoritative_server
    with Client(config(server, ttl=120)) as client:
        client.create_record("TXT", "original", "value")
        original = client.list_records("TXT", "original")[0]
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("LEXICON_TTL", raising=False)
    settings = {
        "domain": "example.com",
        "auth_token": TOKEN,
        "ddns_server": "127.0.0.1",
        "ddns_port": server.server_address[1],
    }
    if provider_key:
        settings[provider_key] = "lebureau"
    if source == "env":
        monkeypatch.setenv("LEXICON_TTL", str(ttl))
        (tmp_path / "lexicon.yml").write_text("ttl: 240\n")
    elif source == "file":
        (tmp_path / "lexicon.yml").write_text(f"ttl: {ttl}\n")
    elif source == "dict":
        settings["ttl"] = ttl
        monkeypatch.setenv("LEXICON_TTL", "240")
    before = settings.copy()
    with pytest.warns(DeprecationWarning, match="Legacy configuration"):
        provider = Provider(settings)
    assert settings == before
    assert provider.create_record("TXT", "created", "value")
    assert provider.list_records("TXT", "created")[0]["ttl"] == (
        3600 if source == "omitted" or ttl == 0 else ttl
    )
    assert provider.update_record(original["id"], content="changed")
    assert provider.list_records("TXT", "original")[0]["ttl"] == (
        120 if source == "omitted" else (ttl or 3600)
    )
    # Reusing the same caller dictionary must not acquire the base default.
    with pytest.warns(DeprecationWarning, match="Legacy configuration"):
        reopened = Provider(settings)
    changed = reopened.list_records("TXT", "original")[0]
    assert reopened.update_record(changed["id"], name="moved")
    assert reopened.list_records("TXT", "moved")[0]["ttl"] == changed["ttl"]
    assert settings == before


def test_live_adapter_mx_priority_update_preserves_same_exchange_sibling(
    authoritative_server,
):
    zone = LiveZone(config(authoritative_server))
    zone.prepare()
    try:
        provider = zone.provider()
        provider.create_record("MX", "mail", "10 mail.example.net.")
        provider.create_record("MX", "mail", "20 mail.example.net.")
        selected = provider.list_records("MX", "mail", "10 mail.example.net.")[0]
        sibling = provider.list_records("MX", "mail", "20 mail.example.net.")[0]
        assert provider.update_record(selected["id"], content="30 mail.example.net.")
        records = provider.list_records("MX", "mail")
        assert sibling in records
        assert {r["options"]["mx"]["priority"] for r in records} == {20, 30}
    finally:
        zone.cleanup()
