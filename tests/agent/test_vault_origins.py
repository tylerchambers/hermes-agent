"""Credential grants are explicit, canonical, and offline."""
import socket

import pytest

from agent.vault_origins import (
    _extractor, browser_url_origin, normalize_login_rules, normalize_web_origin,
    normalize_wildcard_origin, origin_is_allowed,
)


@pytest.fixture(autouse=True)
def offline(monkeypatch, tmp_path):
    def forbidden(*args, **kwargs):
        raise AssertionError("Origin policy must not access the network")
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setenv("TLDEXTRACT_CACHE", str(tmp_path / "forbidden-cache"))
    _extractor.cache_clear()
    yield
    assert not (tmp_path / "forbidden-cache").exists()
    _extractor.cache_clear()


@pytest.mark.parametrize("value, expected", [
    (" HTTPS://ExAmPlE.com:443/path?q=1#x ", "https://example.com"),
    ("https://0xcorp.com", "https://0xcorp.com"),
    ("http://localhost:80", "http://localhost"),
    ("https://faß.de", "https://xn--fa-hia.de"),
    ("https://EXAMPLE.com.", "https://example.com."),
    ("https://[2001:0db8::1]:443/x", "https://[2001:db8::1]"),
    ("https://user:password@example.com", None),
    ("https://exa%6dple.com", None),
    ("https://example.com:70000", None),
    ("https://example.com:", None),
    ("https://exam\nple.com", None),
    ("https://example.com /login", None),
    ("https://example.com\\evil", None),
    ("https://*.example.com", None),
    ("example.com", None),
    ("https://127.1", None),
    ("https://[::1]extra", None),
    ("https://[v1.foo]", None),
    ("https://0x7f000001", None),
    ("https://127.0.0.0x1", None),
])
def test_exact_normalization(value, expected):
    if expected is None:
        with pytest.raises(ValueError) as error:
            normalize_web_origin(value)
        assert value not in str(error.value)
        with pytest.raises(ValueError):
            browser_url_origin(value)
    else:
        assert normalize_web_origin(value) == expected
        assert normalize_web_origin(expected) == expected
        assert browser_url_origin(value) == expected


@pytest.mark.parametrize("suffix", [
    "/reports/*",
    "/login?next=/reports/*",
    "/login#reports/*",
    "/reports/*?next=/*#section/*",
    r"/login?next=\reports\*",
])
def test_browser_url_suffix_does_not_change_origin_or_grant_rules(suffix):
    url = "https://LOGIN.example.com:443" + suffix
    origin = browser_url_origin(url)
    assert origin == "https://login.example.com"
    assert origin_is_allowed(origin, allowed_origins=(origin,))
    assert origin_is_allowed(origin, allowed_origins=(), wildcard_origins=("https://*.example.com",))
    assert not origin_is_allowed(origin, allowed_origins=("https://other.example.com",))
    with pytest.raises(ValueError):
        normalize_web_origin(url)
    with pytest.raises(ValueError):
        normalize_login_rules("https://other.example.com", [url])


@pytest.mark.parametrize("rule, page, allowed", [
    ("https://*.example.com", "https://a.example.com", True),
    ("https://*.example.com", "https://b.a.example.com", True),
    ("https://*.example.com", "https://example.com", False),
    ("https://*.example.com", "https://badexample.com", False),
    ("https://*.example.com", "https://example.com.evil.net", False),
    ("https://*.example.com", "http://a.example.com", False),
    ("https://*.example.com:8443", "https://a.example.com", False),
    ("https://*.example.com:8443", "https://a.example.com:8443", True),
    ("https://*.example.com", "https://a.example.com.", False),
    ("https://*.tenant.github.io", "https://a.tenant.github.io", True),
    ("https://*.amazonaws.com", "https://tenant.s3.amazonaws.com", False),
    ("https://*.www.ck", "https://a.www.ck", True),
    ("https://*.tenant.foo.ck", "https://a.tenant.foo.ck", True),
    ("https://*.foo.ck", "https://a.foo.ck", None),
    ("https://*.com", "https://a.com", None),
    ("https://*.co.uk", "https://a.co.uk", None),
    ("https://*.github.io", "https://a.github.io", None),
    ("https://*.blogspot.com", "https://a.blogspot.com", None),
    ("https://*.localhost", "https://a.localhost", None),
    ("https://*.example.internal", "https://a.example.internal", None),
    ("https://*.example.com.", "https://a.example.com.", None),
    ("http://*.example.com", "http://a.example.com", None),
    ("https://*.127.0.0.1", "https://a.127.0.0.1", None),
    ("https://*.example.com/?", "https://a.example.com", None),
])
def test_explicit_permissions(rule, page, allowed):
    if allowed is None:
        with pytest.raises(ValueError):
            normalize_wildcard_origin(rule)
    else:
        assert origin_is_allowed(page, allowed_origins=(), wildcard_origins=(rule,)) is allowed
    assert not origin_is_allowed("https://fass.de", allowed_origins=("https://faß.de",))
    assert not origin_is_allowed("https://example.com.", allowed_origins=("https://example.com",))
    assert normalize_login_rules("https://example.com", ["https://EXAMPLE.com:443", "https://other.net"])[1] == (
        "https://example.com", "https://other.net",
    )
    for malformed in ("https://example.com", {}, [None], [""], [1]):
        with pytest.raises(ValueError):
            normalize_login_rules("https://example.com", malformed)
