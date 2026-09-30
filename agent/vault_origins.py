"""Strict web-origin permissions for local login credentials."""
from collections.abc import Sequence
from functools import lru_cache
import ipaddress
from urllib.parse import urlsplit

import idna

_UNAVAILABLE = "Wildcard origin validation is unavailable; run hermes pm repair."


def normalize_web_origin(value: str) -> str:
    """Normalize an explicit HTTP(S) URL without broadening its origin."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("origin: expected a nonblank URL")
    value = value.strip()
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("origin: whitespace or control characters are forbidden")
    if "\\" in value or "*" in value:
        raise ValueError("origin: backslashes and wildcards are forbidden")
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in ("http", "https") or not parsed.netloc or not parsed.hostname:
            raise ValueError
        if "@" in parsed.netloc or "%" in parsed.netloc:
            raise ValueError
        port = parsed.port
        host = parsed.hostname
        if parsed.netloc.endswith(":"):
            raise ValueError
        if parsed.netloc.startswith("[") or ":" in host:
            host = f"[{ipaddress.IPv6Address(host).compressed}]"
        else:
            try:
                host = str(ipaddress.IPv4Address(host))
            except ValueError:
                host = idna.encode(host, uts46=True, transitional=False, std3_rules=True).decode("ascii").lower()
                # Numeric-looking noncanonical IPs have different browser URL semantics.
                last_label = host.rstrip(".").split(".")[-1]
                if last_label.isdigit() or (
                    last_label.startswith("0x") and all(c in "0123456789abcdef" for c in last_label[2:])
                ):
                    raise ValueError
        default = 443 if parsed.scheme == "https" else 80
        return f"{parsed.scheme}://{host}" + (f":{port}" if port is not None and port != default else "")
    except (ValueError, UnicodeError):
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
