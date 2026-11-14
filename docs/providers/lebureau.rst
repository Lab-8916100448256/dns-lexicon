lebureau
    Manage zones hosted by `Le Bureau <https://lebureau.coop/docs/faq/>`_ using
    TSIG-authenticated DNS updates (RFC 2136) and zone transfers (AXFR).
    Ask Le Bureau for a key permitted to perform **both updates and AXFR** on
    your zone. Outbound TCP access to the DNS server is required.

    * ``auth_token`` TSIG credentials in the form
      ``algorithm:key_name:base64_secret``. For example, combine the algorithm,
      key name and secret supplied by Le Bureau as
      ``hmac-sha512:my-key:BASE64_SECRET``. The secret is the original base64
      value, not a second base64 encoding of it.

    * ``ddns_server`` Update and AXFR server hostname or IP address
      (default: ``ns2.lebureau.coop``). An omitted or empty setting uses the
      default. Override it to use another server supplied by Le Bureau;
      do not use the HTTPS administration URL.

    * ``ddns_port`` DNS TCP port (default: ``53``).

    * ``timeout`` Positive timeout in seconds (default: ``10``), applied to
      each address-family lookup and each complete transfer or update.

    Example (supply credentials through the environment)::

        export LEXICON_LEBUREAU_AUTH_TOKEN='hmac-sha512:my-key:BASE64_SECRET'
        lexicon lebureau list example.com TXT
        lexicon lebureau create example.com TXT --name _acme-challenge --content challenge

    Hostnames are resolved explicitly for A and AAAA addresses. Initial AXFR
    tries these addresses in order on transport failures; authentication or
    transfer-policy errors stop the operation. A successful signed AXFR selects
    the address used by subsequent operations in that provider instance.
    Updates are sent once. If a reply is lost, check the zone before retrying.

    The global ``domain`` option selects the zone; use Lexicon's ``delegated``
    option for a delegated subzone. Authentication reads the zone with a signed
    AXFR. Listings always consume a complete transfer, even with filters.
    Supported types include A, AAAA, CAA, CNAME, MX, NS, SRV and TXT. SOA records
    can be listed but are read-only. Removal or replacement of the last apex NS
    is rejected; deleting an apex NS is allowed when another remains.

    Hostname targets in content use DNS presentation syntax. A target without a
    final dot is relative to the configured zone: in ``example.com``, the CNAME
    content ``target.example.net`` means ``target.example.net.example.com.``.
    Use ``target.example.net.`` for an absolute target. This applies to CNAME and
    NS targets, MX exchanges and SRV targets. Listings return absolute targets.

    MX content can be an exchange hostname with the common ``priority`` option
    (CLI ``--priority``, environment ``LEXICON_PRIORITY``), or complete DNS syntax
    such as ``10 mail.example.net.``. An explicit priority overrides an embedded
    priority; otherwise a bare exchange defaults to 10 on creation. Updating only
    an existing MX exchange preserves its priority when no explicit or embedded
    priority is supplied. Listings return the exchange as ``content`` and the
    integer priority as ``options.mx.priority``. A content filter containing only
    an exchange matches all its priorities; complete MX syntax selects one.

    TXT content can be a plain logical value or DNS quoted character strings.
    Long values are split into strings of at most 255 bytes. Listings return
    concatenated logical content without surrounding quotes where possible;
    binary content and content starting with a quote use DNS quoted syntax.
    Record identifiers are stable across clients and identify exact DNS RDATA,
    including TXT string boundaries. Distinct wire values with the same logical
    TXT content are listed separately; content filters match all such values.
    Updates and deletes by ID or content preserve other values in the RRset.
    TTL applies to the entire RRset: an update without an explicit TTL preserves
    the selected record's TTL; zero resets it to the default of 3600 seconds.

    Creates and updates reject incompatible CNAME destinations. DNS prerequisites
    guard name absence, CNAME state and the exact source RRset without relying on
    SOA serial changes. Converting a non-CNAME record to CNAME at the same owner
    is rejected because concurrent additions of other types cannot be excluded
    safely. Use an empty destination name, or manage the conversion separately
    with appropriate coordination. Creating a different CNAME at an existing
    alias is rejected; use an update to change its target. Apex NS deletion also
    guards the exact NS RRset so concurrent changes cannot leave a protected last
    NS behind while reporting success. Check records before retrying a rejected
    update.

    The provider implements the protocol independently of ``ddns`` to keep
    existing DDNS consumers unchanged. Its tests run Lexicon's shared V2
    contract and DNS wire exchanges against a disposable in-memory authority.
    DNS signatures, TCP framing and multi-message transfer processing use
    dnspython; no HTTP VCR cassettes or live credentials are needed::

        pytest tests/providers/test_lebureau.py

    To run the shared V2 contract and additional Client/TXT integration cases
    against a live zone, explicitly select an authorized test domain and key::

        export LEXICON_LEBUREAU_TEST_DOMAIN='example.com'
        export LEXICON_LEBUREAU_AUTH_TOKEN='hmac-sha512:my-key:BASE64_SECRET'
        LEXICON_LIVE_TESTS=true pytest tests/providers/test_lebureau.py

    Live tests use the same server, port and timeout environment options as the
    provider, defaulting to ``ns2.lebureau.coop``. The domain must be the actual
    hosted zone (including a delegated zone when applicable). Missing domain or
    credentials fail before any network access; the tests never silently fall
    back to dummy credentials in live mode.

    Each integration test checks that a randomly generated namespace is unused,
    places its fixture names beneath it, and attempts cleanup during teardown,
    including after a failed test or a write with a lost reply. Cleanup failures
    fail the test and report the affected owners and underlying provider errors.
    Cleanup verifies the result even if a delete reply is lost. Writes are never
    retried; read-back uses bounded polling for convergence and transient read
    failures. Pre-existing owners and the
    zone apex are not used as write fixtures. Independent protocol/error
    regressions still use the in-memory authority even in live mode. No DNS
    cassettes are generated.
