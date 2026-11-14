"""Le Bureau contract and protocol tests against an in-memory DNS authority.

Le Bureau's DNS automation interface uses DNS over TCP with TSIG authentication
(RFC 2136 updates and AXFR zone transfers). VCR.py records HTTP interactions,
not this DNS traffic, so the developer guide's cassette workflow does not apply.

These tests run the shared IntegrationTestsV2 contract and protocol regressions
against a disposable in-memory authority with a public dummy key. dnspython
still encodes and validates the DNS wire messages and TSIG signatures; only the
socket transport is substituted. No live credentials or private zone dumps are
needed. LEXICON_LIVE_TESTS=true does not switch these tests to Le Bureau's live
servers or generate DNS recordings; live validation uses a separate harness.
"""

import base64
import io
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

from lexicon._private.discovery import find_providers
from lexicon._private.providers.lebureau import Provider
from lexicon.client import Client
from lexicon.config import ConfigResolver
from lexicon.exceptions import AuthenticationError, LexiconError

TOKEN = "hmac-sha512:test-key:" + base64.b64encode(b"public-test-secret").decode()
ZONE = """
@ 300 IN SOA ns.example.com. hostmaster.example.com. 1 3600 600 86400 300
@ 300 IN NS ns.example.com.
ns 300 IN A 192.0.2.53
"""


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
            for rrset in query.authority:
                owner = rrset.name.derelativize(server.zone.origin)
                if rrset.deleting == dns.rdataclass.ANY:
                    server.zone.delete_rdataset(owner, rrset.rdtype)
                elif rrset.deleting == dns.rdataclass.NONE:
                    rdataset = server.zone.get_rdataset(owner, rrset.rdtype)
                    if rdataset is not None:
                        for data in rrset:
                            rdataset.discard(data)
                        if not rdataset:
                            server.zone.delete_rdataset(owner, rrset.rdtype)
                else:
                    rdataset = server.zone.find_rdataset(
                        owner, rrset.rdtype, create=True
                    )
                    for data in rrset:
                        rdataset.add(data)
                    rdataset.ttl = rrset.ttl
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


@pytest.mark.usefixtures("authoritative_server")
class TestLeBureauProvider(IntegrationTestsV2):
    """Run Lexicon's shared contract against signed DNS wire messages."""

    provider_name = "lebureau"
    domain = "example.com"

    @pytest.fixture(autouse=True)
    def configure_server(self, authoritative_server):
        self.server = authoritative_server

    def _test_parameters_overrides(self):
        return {
            "auth_token": TOKEN,
            "ddns_server": "127.0.0.1",
            "ddns_port": self.server.server_address[1],
        }

    def _test_fallback_fn(self):
        return lambda _: None


@pytest.mark.parametrize(
    "rtype,content",
    [
        ("A", "192.0.2.1"),
        ("AAAA", "2001:db8::1"),
        ("MX", "10 mail.example.com."),
        ("TXT", "v=spf1 -all"),
        ("CNAME", "target.example.com."),
        ("SRV", "10 20 443 service.example.com."),
        ("CAA", '0 issue "letsencrypt.org"'),
    ],
)
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


def test_ttl_reset_and_selected_value_move(authoritative_server):
    server = authoritative_server
    with Client(config(server, ttl=120)) as client:
        client.create_record("TXT", "original", "one")
        client.create_record("TXT", "original", "two")
        first = client.list_records("TXT", "original", "one")[0]
    with Client(config(server, ttl=0)) as client:
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
