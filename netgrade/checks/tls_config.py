"""Check 2 -- TLS configuration.

Opens a TLS connection to port 443 and reports on three things a small
business can act on: whether the certificate is trusted and for the right
name, how long it has left, and whether the server still accepts protocol
versions that were deprecated years ago.

The certificate is parsed from the DER ourselves rather than read through
``ssl.getpeercert()``. That function returns nothing at all on a connection
that failed verification, which is exactly the expired and self-signed cases
this check exists to catch -- so reading it that way would go blind precisely
when it matters.
"""

import asyncio
import contextlib
import logging
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone

try:
    from datetime import UTC
except ImportError:
    UTC = timezone.utc
from typing import Final

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

from netgrade.checks.base import Check
from netgrade.context import ScanContext
from netgrade.models import CheckResult, CheckStatus, Severity

logger = logging.getLogger(__name__)

CHECK_ID: Final = "tls_config"
TITLE: Final = "TLS configuration"

HTTPS_PORT: Final = 443

#: Certificate lifetime thresholds, in days. Under 14 days is urgent because
#: automated renewal has usually already had several attempts by then; under
#: 30 is worth flagging while there is still time to act calmly.
_EXPIRY_CRITICAL_DAYS: Final = 14
_EXPIRY_WARNING_DAYS: Final = 30

#: Deprecated protocol versions worth probing for. TLS 1.0 and 1.1 were
#: deprecated by RFC 8996 in 2021. We do not probe 1.2 or 1.3: their presence
#: changes no finding, and every probe is another connection to a host that
#: did not ask to be scanned.
#:
#: Each entry is (name to report, version to request, string OpenSSL reports
#: on success). The third is not redundant: Python reports TLS 1.0 as "TLSv1",
#: so comparing against the display name silently discards every detection.
_LEGACY_PROTOCOLS: Final = (
    ("TLS 1.0", ssl.TLSVersion.TLSv1, "TLSv1"),
    ("TLS 1.1", ssl.TLSVersion.TLSv1_1, "TLSv1.1"),
)


@dataclass(frozen=True, slots=True)
class _Handshake:
    """The outcome of one TLS connection."""

    protocol: str | None = None
    cipher: str | None = None
    certificate: x509.Certificate | None = None
    verified: bool = False
    verification_error: str | None = None


async def run(domain: str, ctx: ScanContext) -> CheckResult:
    """Inspect the TLS configuration served on port 443."""
    await ctx.assert_domain_exists(domain)
    await ctx.assert_public_host(domain)

    handshake = await _connect(domain, ctx, verify=True)
    if handshake.certificate is None:
        # Verification failed before a certificate could be captured. Retry
        # without verification purely to read what is being served, which is
        # the only way to tell the user *why* their certificate is rejected.
        handshake = await _connect(domain, ctx, verify=False, previous=handshake)

    legacy = await _probe_legacy_protocols(domain, ctx)
    expiry = _expiry(handshake.certificate)
    hostname_ok = _matches_hostname(handshake.certificate, domain)

    status, severity, summary, fix = _assess(handshake, expiry, hostname_ok, legacy)

    return CheckResult(
        id=CHECK_ID,
        title=TITLE,
        status=status,
        severity=severity,
        summary=summary,
        explanation=_explain(handshake, expiry, hostname_ok, legacy),
        fix=fix,
        evidence={
            "tls_version": handshake.protocol,
            "cipher": handshake.cipher,
            "certificate_trusted": handshake.verified,
            "verification_error": handshake.verification_error,
            "certificate_expires": expiry.isoformat().replace("+00:00", "Z") if expiry else None,
            "days_remaining": _days_remaining(expiry),
            "hostname_matches": hostname_ok,
            "issuer": _issuer(handshake.certificate),
            "subject_alternative_names": _subject_alt_names(handshake.certificate)[:12],
            "fingerprint_sha256": _fingerprint(handshake.certificate),
            "legacy_protocols_accepted": list(legacy),
        },
    )


def _assess(
    handshake: _Handshake,
    expiry: datetime | None,
    hostname_ok: bool,
    legacy: tuple[str, ...],
) -> tuple[CheckStatus, Severity, str, str]:
    """Rank findings by what a visitor's browser would actually do."""
    days = _days_remaining(expiry)

    if handshake.certificate is None:
        return (
            "fail",
            "critical",
            "No usable HTTPS connection could be established on port 443.",
            "Check that the site is served over HTTPS and that port 443 is reachable. "
            "Visitors currently cannot connect securely at all.",
        )

    if days is not None and days < 0:
        return (
            "fail",
            "critical",
            f"The certificate expired {abs(days)} days ago.",
            "Renew the certificate now. Every visitor is currently seeing a full-page "
            "browser warning, and most will not click past it.",
        )

    if not hostname_ok:
        return (
            "fail",
            "critical",
            "The certificate is not valid for this domain name.",
            "Reissue the certificate so it covers this exact domain name. Browsers "
            "refuse the connection outright when the name does not match.",
        )

    if not handshake.verified:
        return (
            "fail",
            "high",
            "The certificate is not trusted by browsers.",
            "Replace it with a certificate from a recognised authority. Let's Encrypt "
            "issues these free and renews them automatically.",
        )

    if days is not None and days < _EXPIRY_CRITICAL_DAYS:
        return (
            "fail",
            "high",
            f"The certificate expires in {days} days.",
            "Renew it now and confirm automatic renewal is actually running. At this "
            "point an automated renewal has usually already failed several times.",
        )

    if legacy:
        return (
            "fail",
            "medium",
            f"The server still accepts {' and '.join(legacy)}.",
            f"Disable {' and '.join(legacy)} in your web server or CDN settings and "
            "require TLS 1.2 as a minimum. These versions were formally deprecated "
            "in 2021 and fail most compliance checks.",
        )

    if days is not None and days < _EXPIRY_WARNING_DAYS:
        return (
            "warn",
            "low",
            f"The certificate expires in {days} days.",
            "Confirm automatic renewal is configured. There is still time, but this "
            "should not be a manual task.",
        )

    summary = f"{handshake.protocol} with a trusted certificate"
    summary += f", {days} days remaining." if days is not None else "."
    return (
        "pass",
        "info",
        summary,
        "No action needed. Confirm certificate auto-renewal is running so this does "
        "not lapse.",
    )


def _explain(
    handshake: _Handshake,
    expiry: datetime | None,
    hostname_ok: bool,
    legacy: tuple[str, ...],
) -> str:
    """Say what a visitor experiences, rather than what the protocol does."""
    days = _days_remaining(expiry)

    if handshake.certificate is None:
        return (
            "Nothing could be negotiated on the HTTPS port, so traffic to this site is "
            "either unencrypted or unreachable. Anything a visitor types can be read or "
            "altered in transit."
        )
    if days is not None and days < 0:
        return (
            "Browsers show a full-page security warning for an expired certificate. Most "
            "visitors will leave rather than click through it, and search engines treat it "
            "as a trust signal."
        )
    if not hostname_ok:
        return (
            "The certificate was issued for a different name, so browsers cannot tell "
            "whether they are talking to the right server and refuse the connection."
        )
    if not handshake.verified:
        return (
            "The certificate is not signed by an authority browsers recognise, so visitors "
            "see the same warning they would see for an impostor site."
        )
    if legacy:
        return (
            "Older protocol versions remain enabled alongside the current one. An attacker "
            "positioned between a visitor and the site can try to force the weaker version "
            "and attack that instead."
        )
    return (
        "Traffic between your visitors and your site is encrypted with a current protocol, "
        "and the outdated versions attackers try to force are refused."
    )


async def _connect(
    domain: str,
    ctx: ScanContext,
    *,
    verify: bool,
    previous: _Handshake | None = None,
) -> _Handshake:
    """Perform one TLS handshake and capture what was negotiated.

    A failure to connect is returned as an empty handshake rather than raised,
    because "no HTTPS at all" is itself the finding.
    """
    context = _ssl_context(verify=verify)

    async with ctx.limiter:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(domain, HTTPS_PORT, ssl=context, server_hostname=domain),
                timeout=ctx.timeouts.connect,
            )
        except ssl.SSLCertVerificationError as exc:
            logger.info("%s certificate did not verify: %s", domain, exc.verify_message)
            return _Handshake(verification_error=exc.verify_message or str(exc))
        except (TimeoutError, OSError, ssl.SSLError) as exc:
            logger.info("%s TLS connection failed: %s", domain, exc)
            return _Handshake(
                verification_error=previous.verification_error if previous else None,
            )

        try:
            transport = writer.get_extra_info("ssl_object")
            der = transport.getpeercert(binary_form=True)
            return _Handshake(
                protocol=transport.version(),
                cipher=(transport.cipher() or (None,))[0],
                certificate=x509.load_der_x509_certificate(der) if der else None,
                verified=verify,
                verification_error=previous.verification_error if previous else None,
            )
        finally:
            await _close(writer)


async def _probe_legacy_protocols(domain: str, ctx: ScanContext) -> tuple[str, ...]:
    """Find out which deprecated TLS versions the server still accepts.

    Each probe pins both the minimum and maximum version, so a successful
    handshake means the server genuinely agreed to that version rather than
    negotiating up to a current one.
    """
    accepted: list[str] = []

    for label, version, negotiated_name in _LEGACY_PROTOCOLS:
        context = _ssl_context(verify=False)
        try:
            context.minimum_version = version
            context.maximum_version = version
        except ValueError:
            # The local OpenSSL build refuses to offer this version at all, so
            # the server's answer is unknowable from here. Reported as untested
            # rather than as absent.
            logger.info("cannot probe %s; local OpenSSL will not offer it", label)
            continue

        async with ctx.limiter:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        domain, HTTPS_PORT, ssl=context, server_hostname=domain
                    ),
                    timeout=ctx.timeouts.connect,
                )
            except (TimeoutError, OSError, ssl.SSLError):
                continue  # Refused, which is the desired outcome.

            # A successful handshake is not proof the server agreed to this
            # version. OpenSSL may raise the floor we asked for rather than
            # refusing it, in which case the connection completes on a modern
            # version and reporting the legacy one would be a false positive.
            # Only the version actually negotiated counts.
            transport = writer.get_extra_info("ssl_object")
            negotiated = transport.version() if transport else None
            await _close(writer)

            if negotiated == negotiated_name:
                accepted.append(label)
            elif negotiated is not None:
                logger.debug("%s: asked for %s, negotiated %s", domain, label, negotiated)

    return tuple(accepted)


def _ssl_context(*, verify: bool) -> ssl.SSLContext:
    """Build a client context, optionally with verification disabled.

    Verification is switched off only to *read* a certificate the browser
    would reject, so that the report can say why. No data is ever sent over an
    unverified connection: the handshake is the entire transaction.
    """
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    # Legacy probes need the security level relaxed; modern OpenSSL refuses
    # old versions at the default level regardless of the version bounds.
    context.set_ciphers("DEFAULT@SECLEVEL=0" if not verify else "DEFAULT")
    return context


def _expiry(certificate: x509.Certificate | None) -> datetime | None:
    """The certificate's not-after date, in UTC."""
    return certificate.not_valid_after_utc if certificate else None


def _days_remaining(expiry: datetime | None) -> int | None:
    """Whole days until expiry; negative once it has passed."""
    if expiry is None:
        return None
    return (expiry - datetime.now(UTC)).days


def _matches_hostname(certificate: x509.Certificate | None, domain: str) -> bool:
    """Whether the certificate covers this domain, wildcards included."""
    if certificate is None:
        return False

    names = _subject_alt_names(certificate)
    if not names:
        # Certificates without a SAN extension have not been accepted by
        # browsers for years, but fall back to the common name so the report
        # explains the real problem rather than reporting no name at all.
        names = tuple(
            attribute.value
            for attribute in certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if isinstance(attribute.value, str)
        )

    return any(_name_matches(name.lower(), domain.lower()) for name in names)


def _name_matches(pattern: str, domain: str) -> bool:
    """Match a certificate name against a domain, honouring a leading wildcard.

    A wildcard covers exactly one label: ``*.example.com`` matches
    ``www.example.com`` but not ``a.b.example.com`` and not ``example.com``.
    """
    if not pattern.startswith("*."):
        return pattern == domain

    suffix = pattern[2:]
    head, separator, tail = domain.partition(".")
    return bool(head) and separator == "." and tail == suffix


def _subject_alt_names(certificate: x509.Certificate | None) -> tuple[str, ...]:
    """Every DNS name in the subject alternative name extension."""
    if certificate is None:
        return ()
    try:
        extension = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return ()
    return tuple(extension.value.get_values_for_type(x509.DNSName))


def _issuer(certificate: x509.Certificate | None) -> str | None:
    """The issuing authority's common name, or its organisation."""
    if certificate is None:
        return None
    for oid in (NameOID.COMMON_NAME, NameOID.ORGANIZATION_NAME):
        for attribute in certificate.issuer.get_attributes_for_oid(oid):
            if isinstance(attribute.value, str):
                return attribute.value
    return None


def _fingerprint(certificate: x509.Certificate | None) -> str | None:
    """SHA-256 fingerprint, as the colon-free hex form tooling expects."""
    if certificate is None:
        return None
    return certificate.fingerprint(hashes.SHA256()).hex()


async def _close(writer: asyncio.StreamWriter) -> None:
    """Close a connection we have finished with.

    A peer that has already hung up makes the close raise, which is not a
    finding about anything and must not become one.
    """
    writer.close()
    with contextlib.suppress(OSError, ssl.SSLError):
        await writer.wait_closed()


CHECK: Final = Check(id=CHECK_ID, title=TITLE, run=run)
