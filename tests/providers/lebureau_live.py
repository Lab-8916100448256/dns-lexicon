"""Isolation and cleanup for opt-in Le Bureau DNS integration tests.

This is test infrastructure, not a replacement for the provider: requests still
use the real Provider and its DNS transport. Relative fixture names are placed
under a fresh namespace so the shared contract cannot modify existing owners.
"""

import os
import time
import uuid

import dns.exception
import dns.name

from lexicon._private.providers.lebureau import Provider
from lexicon.config import ConfigResolver
from lexicon.exceptions import LexiconError

READ_ERRORS = (LexiconError, dns.exception.DNSException, OSError, EOFError)


def error_summary(error):
    """Provider errors are sanitized; avoid dumping raw DNS/key objects."""
    detail = str(error) if isinstance(error, (LexiconError, AssertionError)) else ""
    return type(error).__name__ + (": " + detail if detail else "")


def live_config():
    """Require an explicitly selected test zone and use normal credential options."""
    domain = os.environ.get("LEXICON_LEBUREAU_TEST_DOMAIN")
    if not domain:
        raise ValueError("Live tests require LEXICON_LEBUREAU_TEST_DOMAIN")
    config = (
        ConfigResolver()
        .with_dict(
            {
                "provider_name": "lebureau",
                "domain": domain,
                "delegated": domain,
                "ttl": 3600,
            }
        )
        .with_env()
    )
    if not config.resolve("lexicon:lebureau:auth_token"):
        raise ValueError("Live tests require LEXICON_LEBUREAU_AUTH_TOKEN")
    return config


class LiveZone:
    """Own one random namespace for one test, and remember attempted writes."""

    def __init__(self, config, prefix=None):
        self.config = config
        self.origin = dns.name.from_text(
            config.resolve("lexicon:domain")
        ).canonicalize()
        self.namespace = dns.name.from_text(
            prefix or "_lexicon-test-" + uuid.uuid4().hex,
            origin=self.origin,
        )
        self.domain = self.namespace.to_text(omit_final_dot=True)
        self.names = set()

    def owns(self, name):
        return dns.name.from_text(name).is_subdomain(self.namespace)

    def name(self, name):
        if name in ("", "@"):
            return self.domain
        parsed = dns.name.from_text(name, origin=None)
        absolute = parsed.derelativize(dns.name.root)
        if absolute.is_subdomain(self.namespace):
            return absolute.to_text(omit_final_dot=True)
        if parsed.is_absolute() or absolute.is_subdomain(self.origin):
            raise ValueError("Live fixture owner is outside its test namespace")
        return parsed.derelativize(self.namespace).to_text(omit_final_dot=True)

    def provider(self):
        backend = Provider(self.config)
        backend.authenticate()
        return ScopedProvider(self, backend)

    def prepare(self):
        backend = Provider(self.config)
        backend.authenticate()
        if any(self.owns(record["name"]) for record in backend.list_records()):
            raise LexiconError(
                "Live test namespace already exists; no writes performed"
            )

    def cleanup(self):
        # Names are registered BEFORE writes, including ones with a lost reply.
        # Try every owner even if one deletion fails; report failures to pytest.
        failures = []
        for name in sorted(self.names):
            try:
                self._cleanup_name(name)
            except (
                LexiconError,
                dns.exception.DNSException,
                OSError,
                ValueError,
                AssertionError,
                EOFError,
            ) as error:
                failures.append(f"{name} ({error_summary(error)})")
        if failures:
            raise LexiconError(
                "Live fixture cleanup failed for: " + ", ".join(failures)
            )

    def _cleanup_name(self, name):
        backend = Provider(self.config)
        read_with_retry(backend.authenticate)
        # Leave server-generated DNSSEC records to the authoritative server.
        records = read_with_retry(lambda: backend.list_records(name=name))
        types = {r["type"] for r in records if r["type"] in Provider.VALID_TYPES}
        for rtype in types:
            delete_error = None
            try:
                backend.delete_record(rtype=rtype, name=name)
            except READ_ERRORS as error:
                # A reply can be lost after the server applies the deletion.
                # Check the state; never repeat this potentially completed write.
                delete_error = error_summary(error)
            try:
                wait_until(lambda rtype=rtype: not backend.list_records(rtype, name))
            except AssertionError as error:
                detail = f"; delete result: {delete_error}" if delete_error else ""
                raise LexiconError(
                    f"Cleanup verification failed for {rtype}: {error}{detail}"
                ) from None
        wait_until(
            lambda: (
                not [
                    r
                    for r in backend.list_records(name=name)
                    if r["type"] in Provider.VALID_TYPES
                ]
            )
        )


def wait_until(condition, timeout=30):
    """Poll reads only, tolerating transient read failures within the deadline."""
    deadline = time.monotonic() + timeout
    last_error = None
    while True:
        try:
            if condition():
                return
            last_error = None
        except READ_ERRORS as error:
            last_error = error_summary(error)
        if time.monotonic() >= deadline:
            detail = f"; last read error: {last_error}" if last_error else ""
            raise AssertionError(
                "Live DNS fixture did not converge before timeout" + detail
            ) from None
        time.sleep(0.5)


def read_with_retry(operation):
    """Retry a read, treating an empty result as a successful response."""
    result = None

    def read():
        nonlocal result
        result = operation()
        return True

    wait_until(read)
    return result


class ScopedProvider:
    """Adapt shared-test relative names to full owners in the isolated namespace.

    Returned record names, contents and IDs are unmodified provider results.
    Each construction authenticates a fresh real provider, so IDs cross clients.
    """

    def __init__(self, zone, backend):
        self.zone = zone
        self.backend = backend

    @property
    def domain_id(self):
        return self.backend.domain_id

    def list_records(self, rtype=None, name=None, content=None):
        return [
            r
            for r in self.backend.list_records(
                rtype,
                self.zone.name(name) if name is not None else None,
                content,
            )
            if self.zone.owns(r["name"])
        ]

    def create_record(self, rtype, name, content):
        owner = self.zone.name(name)
        self.zone.names.add(owner)
        result = self.backend.create_record(rtype, owner, content)
        wait_until(lambda: self.list_records(rtype, owner, content))
        return result

    def update_record(self, identifier=None, rtype=None, name=None, content=None):
        matches = self.list_records(
            None if identifier else rtype, None if identifier else name
        )
        if identifier:
            matches = [r for r in matches if r["id"] == identifier]
        if len(matches) != 1:
            raise LexiconError("Expected one record in the live test namespace")
        original = matches[0]
        owner = self.zone.name(name) if name is not None else original["name"]
        self.zone.names.add(owner)
        result = self.backend.update_record(identifier, rtype, owner, content)
        target_type = rtype or original["type"]
        target_content = original["content"] if content is None else content
        wait_until(lambda: self.list_records(target_type, owner, target_content))
        updated = self.list_records(target_type, owner, target_content)
        if original["id"] not in {r["id"] for r in updated}:
            wait_until(
                lambda: (
                    not self.list_records(
                        original["type"],
                        original["name"],
                        original["content"],
                    )
                )
            )
        return result

    def delete_record(self, identifier=None, rtype=None, name=None, content=None):
        if not identifier and name is None:
            raise ValueError("Live deletion requires an identifier or fixture name")
        matches = self.list_records(
            None if identifier else rtype,
            None if identifier else name,
            None if identifier else content,
        )
        if identifier:
            matches = [r for r in matches if r["id"] == identifier]
        # Only IDs first resolved inside this namespace reach the real provider.
        for record in matches:
            self.backend.delete_record(record["id"])
        wait_until(
            lambda: (
                not any(
                    r["id"] in {m["id"] for m in matches} for r in self.list_records()
                )
            )
        )
        return True
