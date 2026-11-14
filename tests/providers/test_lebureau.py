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
        with Client(settings) as client:
            assert client.update_record(record["id"], name=moved)
        wait_until(lambda: records(moved) and not records(owner))
        changed = records(moved)[0]
        with Client(settings) as client:
            assert client.delete_record(changed["id"])
        wait_until(lambda: not records(moved))

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
    assert backend.list_records() == original


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
