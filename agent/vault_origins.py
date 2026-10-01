"""Strict web-origin permissions for local login credentials."""
from collections.abc import Sequence
from functools import lru_cache
import ipaddress
from urllib.parse import urlsplit

import idna

_UNAVAILABLE = "Wildcard origin validation is unavailable; run hermes pm repair."


def normalize_web_origin(value: str) -> str:
    """Canonicalize an exact HTTP(S) credential grant.

    Full URLs are accepted, but only their scheme, host and port define the
    grant. Ambiguous authorities are rejected rather than repaired so Python
    and the browser cannot disagree about where a credential may be sent.
    Wildcard grants are validated separately by ``normalize_wildcard_origin``;
    browser-reported page URLs are handled by ``browser_url_origin``.

    Args:
        value: An explicit HTTP(S) origin or URL. Surrounding whitespace is
            ignored; embedded whitespace, controls, backslashes and wildcards
            are forbidden.

    Returns:
        A ``scheme://host[:port]`` origin with a canonical IP address or lowercase
        ASCII IDNA hostname. Default ports and URL paths, queries and fragments
        are omitted. A trailing DNS dot is retained as a distinct origin.

    Raises:
        ValueError: The value is blank, is not a string, or contains an invalid,
            unsupported or ambiguous scheme, authority, hostname or port.
    """
    # Permit harmless copy/paste padding, but never infer a missing destination.
    if not isinstance(value, str) or not value.strip():
        raise ValueError("origin: expected a nonblank URL")
    value = value.strip()
    # urlsplit can discard controls; browsers also treat backslashes as URL
    # separators. Reject these before parsing rather than silently changing the
    # grant. A wildcard must go through the separate, explicit permission path.
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("origin: whitespace or control characters are forbidden")
    if "\\" in value or "*" in value:
        raise ValueError("origin: backslashes and wildcards are forbidden")
    try:
        parsed = urlsplit(value)
        # Grants must name an explicit web origin: no inferred scheme, relative
        # URL or non-web protocol may become a credential destination.
        if parsed.scheme not in ("http", "https") or not parsed.netloc or not parsed.hostname:
            raise ValueError
        # Userinfo can disguise the destination, and browsers decode escaped
        # host bytes differently from urlsplit. Neither belongs in a grant.
        if "@" in parsed.netloc or "%" in parsed.netloc:
            raise ValueError
        # Reading .port validates its range. A dangling colon must not silently
        # acquire the default port and turn malformed input into a valid grant.
        port = parsed.port
        host = parsed.hostname
        if parsed.netloc.endswith(":"):
            raise ValueError
        if parsed.netloc.startswith("[") or ":" in host:
            # Equivalent IPv6 spellings should compare equally; brackets keep
            # the address's colons distinct from the optional port separator.
            host = f"[{ipaddress.IPv6Address(host).compressed}]"
        else:
            try:
                # Use strict dotted-decimal IPv4, not a browser's permissive
                # shorthand, octal or hexadecimal interpretation.
                host = str(ipaddress.IPv4Address(host))
            except ValueError:
                # Non-transitional UTS #46 preserves distinctions such as ß
                # versus ss while producing the ASCII host used for matching.
                # Do not remove a trailing DNS dot: it remains a separate grant.
                host = idna.encode(host, uts46=True, transitional=False, std3_rules=True).decode("ascii").lower()
                # A numeric final label can make a browser interpret this as
                # IPv4 even though the strict IP parser rejected it. Fail closed
                # instead of treating that alternate IP spelling as a DNS name.
                last_label = host.rstrip(".").split(".")[-1]
                if last_label.isdigit() or (
                    last_label.startswith("0x") and all(c in "0123456789abcdef" for c in last_label[2:])
                ):
                    raise ValueError
        # Only default ports are equivalent to omission. Retain other ports and
        # discard URL suffixes because permissions are scoped to origins.
        default = 443 if parsed.scheme == "https" else 80
        return f"{parsed.scheme}://{host}" + (f":{port}" if port is not None and port != default else "")
    except (ValueError, UnicodeError):
        # Parser errors may echo input (including accidental userinfo); expose
        # one metadata-safe error without the original exception's details.
        raise ValueError("origin: invalid HTTP(S) host, authority or port") from None


def browser_url_origin(value: str) -> str:
    """Extract a concrete origin from a browser-reported HTTP(S) URL.

    Unlike configured grants, a page URL's path, query and fragment do not
    participate in authorization. Validate the raw scheme/authority before
    parsing can discard invalid characters there.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError("origin: expected a nonblank URL")
    scheme, separator, authority = value.strip().partition("://")
    if not separator:
        raise ValueError("origin: expected an absolute HTTP(S) URL")
    for delimiter in ("/", "?", "#"):
        authority = authority.split(delimiter, 1)[0]
    # The slash keeps trailing authority whitespace from being stripped.
    return normalize_web_origin(f"{scheme}://{authority}/")


@lru_cache(maxsize=1)
def _extractor():
    try:
        from tldextract import TLDExtract
        extractor = TLDExtract(
            suffix_list_urls=(), cache_dir=None, fallback_to_snapshot=True,
            include_psl_private_domains=True, cache_fetch_timeout=None,
        )
        if not extractor("example.com").suffix:
            raise ValueError
        return extractor
    except Exception:
        raise ValueError(_UNAVAILABLE) from None


def _registrable(host: str) -> str:
    try:
        result = _extractor()(host)
        return result.top_domain_under_public_suffix if result.suffix and result.domain else ""
    except Exception:
        raise ValueError(_UNAVAILABLE) from None


def normalize_wildcard_origin(value: str) -> str:
    """Validate an HTTPS subdomain grant against the bundled public/private PSL."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("wildcard origin: expected a nonblank URL")
    value = value.strip()
    if not value.lower().startswith("https://*.") or value.count("*") != 1:
        raise ValueError("wildcard origin: expected https://*.base[:port]")
    plain = value[:8] + value[10:]
    base = normalize_web_origin(plain)
    parsed = urlsplit(plain)
    if parsed.path not in ("", "/") or "?" in plain or "#" in plain:
        raise ValueError("wildcard origin: paths, queries and fragments are forbidden")
    host = urlsplit(base).hostname
    if host.endswith("."):
        raise ValueError("wildcard origin: trailing DNS dots are forbidden")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("wildcard origin: IP addresses are forbidden")
    if not _registrable(host):
        raise ValueError("wildcard origin: requires a registrable domain below a recognized suffix")
    return "https://*." + base[8:]


def _rules(values, field: str, normalizer) -> tuple[str, ...]:
    if values is None:
        return ()
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
        raise ValueError(f"{field}: expected an array")
    normalized = []
    for index, value in enumerate(values):
        try:
            rule = normalizer(value)
        except ValueError as exc:
            raise ValueError(f"{field}[{index}]: {exc}") from None
        if rule not in normalized:
            normalized.append(rule)
    return tuple(normalized)


def normalize_login_rules(
    origin: str, allowed_origins: Sequence[str] | None = None,
    wildcard_origins: Sequence[str] | None = None,
) -> tuple[str, tuple[str, ...], tuple[str, ...]]:
    primary = normalize_web_origin(origin)
    exact = _rules(allowed_origins, "allowed_origins", normalize_web_origin)
    wildcards = _rules(wildcard_origins, "wildcard_origins", normalize_wildcard_origin)
    return primary, tuple(dict.fromkeys((primary, *exact))), wildcards


def origin_is_allowed(
    page_origin: str, *, allowed_origins: Sequence[str],
    wildcard_origins: Sequence[str] = (),
) -> bool:
    exact = _rules(allowed_origins, "allowed_origins", normalize_web_origin)
    wildcards = _rules(wildcard_origins, "wildcard_origins", normalize_wildcard_origin)
    page = normalize_web_origin(page_origin)
    if page in exact:
        return True
    candidate = urlsplit(page)
    for rule in wildcards:
        base = urlsplit(rule.replace("*.", "", 1))
        if (candidate.scheme == base.scheme and candidate.port == base.port
                and candidate.hostname.endswith("." + base.hostname)
                and _registrable(candidate.hostname) == _registrable(base.hostname)):
            return True
    return False
