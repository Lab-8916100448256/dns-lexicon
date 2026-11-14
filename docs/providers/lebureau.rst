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
    Supported types include A, AAAA, CAA, CNAME, MX, NS, SOA, SRV and TXT.

    TXT content can be a plain logical value or DNS quoted character strings.
    Long values are split into strings of at most 255 bytes. Listings return
    concatenated logical content without surrounding quotes where possible;
    binary content and content starting with a quote use DNS quoted syntax.
    Record identifiers are stable across clients and TXT string boundaries.
    Updates and deletes by ID or content preserve other values in the RRset.
    TTL applies to the entire RRset: an update without an explicit TTL preserves
    the selected record's TTL; zero resets it to the default of 3600 seconds.

    The provider implements the protocol independently of ``ddns`` to keep
    existing DDNS consumers unchanged. Its tests run Lexicon's shared V2
    contract and DNS wire exchanges against a disposable in-memory authority.
    DNS signatures, TCP framing and multi-message transfer processing use
    dnspython; no HTTP VCR cassettes or live credentials are needed::

        pytest tests/providers/test_lebureau.py
