"""Domain input handling and outbound destination safety.

Two jobs, both at the boundary between untrusted input and the network.

First, turn whatever the user typed into one canonical name the checks can
agree on. Users paste URLs, trailing slashes, mixed case and internationalised
names; the checks should never have to think about any of that.

Second, decide whether we are willing to send traffic to where that name
resolves. The scanner makes server-side requests to hosts chosen by whoever
is using it, which is the shape of a server-side request forgery primitive.
Refusing to resolve to anything but public addresses is what keeps it from
being one.
"""

import ipaddress
import logging
import re
from typing import Final

import idna
import tldextract

logger = logging.getLogger(__name__)

#: RFC 1035: a fully-qualified name is at most 253 characters, each label 63.
MAX_DOMAIN_LENGTH: Final = 253
MAX_LABEL_LENGTH: Final = 63

#: Offline extractor. suffix_list_urls=() pins it to the snapshot bundled with
#: the installed version, so a scan never depends on fetching the public
#: suffix list at runtime and two runs always agree.
#:
#: The ICANN section only, which is what DMARC's organisational domain
#: algorithm is defined against. Including the private section would treat
#: e.g. github.io as a suffix, which is right for cookie scope and wrong here.
_EXTRACT: Final = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

#: A hostname label: alphanumeric, internal hyphens permitted.
_LABEL_PATTERN: Final = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

#: Stripped from pasted input before parsing.
_SCHEME_PATTERN: Final = re.compile(r"^[a-z][a-z0-9+.-]*://")


class InvalidDomainError(ValueError):
    """The input is not a domain we are willing to scan.

    Carries a message written for the person who typed it, not for a log.
    """


def normalise_domain(raw: str) -> str:
    """Reduce user input to a canonical A-label domain name.

    Accepts what people actually paste -- ``https://Example.COM/pricing?a=1``,
    ``  example.com.  ``, ``bücher.de`` -- and returns ``example.com`` or
    ``xn--bcher-kva.de``.

    The return value is always the A-label (punycode) form, never Unicode.
    A report that rendered the Unicode form would let a homograph domain
    display as the name it is imitating, which is a spoofing surface we would
    be introducing ourselves.

    Raises:
        InvalidDomainError: if the input is empty, malformed, an IP address,
            or not under a recognised public suffix.
    """
    candidate = raw.strip().lower()
    if not candidate:
        raise InvalidDomainError("Enter a domain name, for example example.com.")

    candidate = _SCHEME_PATTERN.sub("", candidate)
    # Reduce to the authority, then drop any userinfo.
    candidate = candidate.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    candidate = candidate.rpartition("@")[2]
    candidate = _strip_port(candidate)
    # A trailing dot is a legal absolute name but breaks suffix matching.
    candidate = candidate.rstrip(".")

    if not candidate:
        raise InvalidDomainError("Enter a domain name, for example example.com.")

    if _is_ip_literal(candidate):
        raise InvalidDomainError(
            "Enter a domain name rather than an IP address. This tool reports on "
            "a domain's public configuration, which an address on its own does not have."
        )

    encoded = _to_ascii(candidate)

    if len(encoded) > MAX_DOMAIN_LENGTH:
        raise InvalidDomainError("That domain name is too long to be valid.")

    labels = encoded.split(".")
    if len(labels) < 2:
        raise InvalidDomainError(
            "Enter a full domain name including its ending, for example example.com."
        )
    for label in labels:
        if not _LABEL_PATTERN.match(label):
            raise InvalidDomainError(f"'{candidate}' is not a valid domain name.")

    if not _EXTRACT(encoded).suffix:
        raise InvalidDomainError(
            f"'{candidate}' does not end in a recognised public domain ending "
            "such as .com or .nl."
        )

    return encoded


def organisational_domain(domain: str) -> str:
    """Return the registrable domain, e.g. ``example.co.uk`` for a subdomain.

    DMARC looks up a policy on the exact name and, failing that, falls back to
    the organisational domain. Getting this wrong on a multi-part suffix like
    ``.co.uk`` is the difference between reporting a real missing policy and
    reporting a false one.
    """
    return _EXTRACT(domain).top_domain_under_public_suffix or domain


def is_public_address(address: str) -> bool:
    """Whether an IP address is one we are willing to send traffic to.

    Excludes loopback, RFC 1918 private space, link-local (which is how
    169.254.169.254 cloud metadata endpoints get reached), carrier-grade NAT,
    multicast and reserved ranges. ``is_global`` is the stdlib's own view of
    what is publicly routable, so this tracks the standards rather than a
    hand-maintained list of prefixes that would drift.
    """
    try:
        return ipaddress.ip_address(address).is_global
    except ValueError:
        logger.warning("could not parse resolved address %r", address)
        return False


def _strip_port(authority: str) -> str:
    """Remove a trailing port, without mangling an IPv6 literal.

    Splitting on the first colon would turn ``[::1]`` into ``[``, which then
    fails validation for the wrong reason and tells the user their domain is
    incomplete rather than that it is an address. Bracketed and bare IPv6 both
    have to survive intact so the IP check downstream can recognise them.
    """
    if authority.startswith("["):
        return authority[1:].partition("]")[0]
    if authority.count(":") > 1:
        return authority  # bare IPv6 literal; a bare form cannot carry a port
    return authority.split(":", 1)[0]


def _is_ip_literal(candidate: str) -> bool:
    """Whether the input is an IP address rather than a name."""
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return True


def _to_ascii(candidate: str) -> str:
    """Convert to A-label form, tolerating names idna's strict mode rejects.

    idna implements IDNA2008, which refuses some names that resolve perfectly
    well in practice -- a leading digit in a label, for one. Falling back to
    the already-ASCII input keeps those scannable, while non-ASCII input that
    fails encoding is genuinely unusable and is rejected.
    """
    try:
        return idna.encode(candidate, uts46=True).decode("ascii")
    except idna.IDNAError:
        if candidate.isascii():
            return candidate
        raise InvalidDomainError(f"'{candidate}' is not a valid domain name.") from None
