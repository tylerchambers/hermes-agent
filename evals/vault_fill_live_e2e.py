"""Live E2E: vault fill through the REAL browser_exec path (Browser Use CLI + Hermes' packaged Chromium).

Proves problem (1) of the #106480 re-review is fixed: on the default browser backend the login page lives in
a tab browser_exec opened, the supervisor is attached by browser_exec itself, browser_vault_fill focuses the
tab on the bound origin and injects the password over the supervisor's CDP WebSocket, and the secret is absent
from every model-facing result. Also exercises a payment fill (confirm gate, card fields, decline = no write).

A separately owned HTTPS Chromium fixture uses mapped example domains and an ephemeral certificate's
SPKI pin (no global TLS bypass). It exercises explicit alternate origins, multi-depth wildcards,
scheme/host/port refusals, URL suffixes containing *, a real-JS allowed-to-allowed navigation race,
and metadata-only revocation.
Only fixture-owned task supervisors, browser processes, servers and temporary directories are removed.

Run: HERMES_E2E_BROWSER=1 <venv>/bin/python evals/vault_fill_live_e2e.py
"""
from __future__ import annotations

import base64
import hashlib
import http.server
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
HOME = Path(tempfile.mkdtemp(prefix="hermes-vault-e2e-"))
os.environ["HERMES_HOME"] = str(HOME)

PAGES = {
    "/login": b"""<!doctype html><title>login</title>
<form><input name=email type=email autocomplete=username><input name=pw type=password autocomplete=current-password>
<input type=submit></form>""",
    "/checkout": b"""<!doctype html><title>checkout</title>
<form><input name=cardnum placeholder="Card number"><input name=exp placeholder="Expiry (MM/YY)">
<input name=cvv placeholder="CVC"><select name=country><option value=DE>Germany<option value=US>United States</select>
<input name=email type=email></form>""",
}
TASK = "vault-e2e"


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = PAGES.get(self.path, b"nope")
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # noqa: ARG002 — quiet
        pass


def _exec(code: str) -> dict:
    from tools import browser_use_cli as bu

    out = json.loads(bu.browser_exec(code, task_id=TASK, timeout_s=90))
    assert out.get("success"), out
    return out


@contextmanager
def _https_browser():
    """Own a TLS fixture and browser; trust only this fixture's ephemeral SPKI."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from tools.browser_supervisor import SUPERVISOR_REGISTRY
    from hermes_cli.browser_runtime import chromium_executable
    from tools.browser_tool_session import _needs_chromium_sandbox_bypass

    hosts = (
        "primary.example.com", "www.example.com", "login.example.com",
        "deep.login.example.com", "other.example.com", "example.com",
        "login.example.com.evil.net", "login.example.net",
    )
    chrome = chromium_executable()
    if chrome is None:
        raise RuntimeError("HTTPS vault eval requires PM-managed Chromium or Chrome/Chromium on PATH")
    task_id = f"vault-https-e2e-{os.getpid()}"
    servers = []
    threads = []
    proc = None
    with tempfile.TemporaryDirectory(prefix="hermes-vault-https-") as directory:
        root = Path(directory)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hosts[0])])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=1))
                .not_valid_after(now + timedelta(hours=1))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(h) for h in hosts]), critical=False)
                .sign(key, hashes.SHA256()))
        cert_path, key_path = root / "cert.pem", root / "key.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                              serialization.PrivateFormat.PKCS8,
                                              serialization.NoEncryption()))
        spki = key.public_key().public_bytes(serialization.Encoding.DER,
                                            serialization.PublicFormat.SubjectPublicKeyInfo)
        pin = base64.b64encode(hashlib.sha256(spki).digest()).decode("ascii")
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert_path, key_path)
        try:
            for secure in (True, True, False):
                server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
                servers.append(server)
                if secure:
                    server.socket = tls.wrap_socket(server.socket, server_side=True)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                threads.append(thread)
            profile = root / "chrome-profile"
            with (root / "chrome.stderr").open("w+b") as stderr:
                proc = subprocess.Popen([
                    chrome, "--remote-debugging-port=0", f"--user-data-dir={profile}",
                    "--no-first-run", "--no-default-browser-check", "--headless=new",
                    "--disable-gpu", "--no-proxy-server",
                    *(["--no-sandbox"] if _needs_chromium_sandbox_bypass() else []),
                    "--host-resolver-rules=" + ",".join(f"MAP {host} 127.0.0.1" for host in hosts),
                    f"--ignore-certificate-errors-spki-list={pin}", "about:blank",
                ], stdout=subprocess.DEVNULL, stderr=stderr)
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                deadline = time.monotonic() + 20
                while time.monotonic() < deadline and proc.poll() is None:
                    try:
                        port = int((profile / "DevToolsActivePort").read_text().splitlines()[0])
                        endpoint = f"http://127.0.0.1:{port}"
                        with opener.open(endpoint + "/json/version", timeout=1) as response:
                            ws = json.load(response)["webSocketDebuggerUrl"]
                        break
                    except (OSError, ValueError, KeyError):
                        time.sleep(0.1)
                else:
                    stderr.seek(0)
                    raise RuntimeError("Fixture Chromium did not expose CDP: " +
                                       stderr.read().decode("utf-8", errors="replace"))
                supervisor = SUPERVISOR_REGISTRY.get_or_start(task_id, ws)

                def request(path, method="GET"):
                    with opener.open(urllib.request.Request(endpoint + path, method=method), timeout=5) as response:
                        return response.read()

                yield task_id, supervisor, request, [s.server_address[1] for s in servers]
        finally:
            SUPERVISOR_REGISTRY.stop(task_id)
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
            for server in servers:
                server.shutdown()
                server.server_close()
            for thread in threads:
                thread.join(timeout=5)


def _https_origin_proof():
    from agent.vault_store import get_vault_store
    from tools import browser_vault_tool as bvt
    from tools.browser_cdp_tool import _redact_cdp_output

    password = "vault-origin-smoke-password"
    otp_seed = "JBSWY3DPEHPK3PXP"
    store = get_vault_store()
    with _https_browser() as (task_id, sup, request, ports):
        port, other_port, http_port = ports
        primary = f"https://primary.example.com:{port}"
        alternate = f"https://www.example.com:{port}"
        wildcard = f"https://*.example.com:{port}"
        login_origin = f"https://login.example.com:{port}"
        login = store.add_item(
            "login", "HTTPS origin smoke",
            {"identifier_type": "email", "identifier": "smoke@example.com",
             "password": password, "otp_secret": otp_seed},
            origin=primary, allowed_origins=[alternate],
        )
        original_secret = store.resolve_secret(login.id)

        def read_dom():
            result = sup.evaluate_runtime(
                "JSON.stringify({origin:location.origin,password:document.querySelector('[name=pw]').value})")
            assert result.get("ok"), "Fixture DOM read failed"
            return json.loads(result["result"])

        def wait_for_form(origin):
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                result = sup.evaluate_runtime(
                    f"location.origin === {json.dumps(origin)} && "
                    "document.readyState === 'complete' && !!document.querySelector('[name=pw]')")
                if result.get("ok") and result.get("result") is True:
                    return
                time.sleep(0.05)
            raise AssertionError(f"Fixture form did not load at {origin}")

        def page(origin, suffix="/login"):
            # Keep one blank tab while closing every previous form. No allowed tab can mask a denial.
            request("/json/new?about:blank", "PUT")
            for target in json.loads(request("/json/list")):
                if target.get("type") == "page" and target.get("url") != "about:blank":
                    request("/json/close/" + target["id"])
            request("/json/new?" + urllib.parse.quote(origin + "/login", safe=""), "PUT")
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if sup.focus_page(origin, accept=bvt._TAB_PROBES["login"]).get("ok"):
                    wait_for_form(origin)
                    assert read_dom()["password"] == "", "Fresh fixture form was not empty"
                    if suffix != "/login":
                        updated = sup.evaluate_runtime(
                            f"history.replaceState(null, '', {json.dumps(suffix)}); location.href")
                        assert updated.get("ok") and updated.get("result") == origin + suffix, updated
                        assert read_dom() == {"origin": origin, "password": ""}, "URL suffix changed the origin"
                    return
                time.sleep(0.05)
            raise AssertionError(f"Fixture tab could not be focused at {origin}")

        def fill():
            raw = bvt.browser_vault_fill(login.id, task_id=task_id)
            assert password not in raw and otp_seed not in raw, "Tool result exposed a secret"
            return json.loads(raw)

        def success(origin, suffix="/login"):
            page(origin, suffix)
            # Make selection observable: start on an unrelated real form, not
            # the eligible tab established while checking the fixture.
            distractor = f"https://login.example.net:{port}"
            request("/json/new?" + urllib.parse.quote(distractor + "/login", safe=""), "PUT")
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if sup.focus_page(distractor, accept=bvt._TAB_PROBES["login"]).get("ok"):
                    wait_for_form(distractor)
                    break
                time.sleep(0.05)
            else:
                raise AssertionError("Could not focus the unrelated fixture form")
            result = fill()
            assert result.get("success") and result.get("origin") == origin, result
            assert result.get("filled_fields") == 1, result
            dom = read_dom()
            assert dom["origin"] == origin and dom["password"] == password, "Password did not land on expected origin"
            redacted = json.dumps(_redact_cdp_output({"result": {"value": dom["password"]}}))
            assert password not in redacted, "Model-facing CDP read exposed the password"
            print("HTTPS allowed:", origin + suffix)

        def denied(origin, suffix="/login"):
            page(origin, suffix)
            result = fill()
            assert result.get("error_type") == "origin_mismatch", result
            assert read_dom()["password"] == "", "Denied origin received a password"
            print("Origin denied without write:", origin + suffix)

        try:
            success(alternate)
            for suffix in ("/reports/*", "/login?next=/reports/*", "/login#reports/*"):
                success(alternate, suffix)
            changed = store.update_origin_rules(login.id, origin=primary,
                                               allowed_origins=[], wildcard_origins=[wildcard])
            assert changed.id == login.id
            success(login_origin)
            success(f"https://deep.login.example.com:{port}")
            success(login_origin, "/reports/*?next=/*#section/*")
            for origin in (
                f"https://example.com:{port}",
                f"https://login.example.com.evil.net:{port}",
                f"https://login.example.net:{port}",
                f"http://login.example.com:{http_port}",
                f"https://login.example.com:{other_port}",
            ):
                denied(origin)
            denied(f"https://login.example.net:{port}",
                   f"/reports/*?next={login_origin}/reports/*#section/*")

            page(login_origin)
            destination = f"https://other.example.com:{port}"
            original_eval = bvt._eval_js_secret
            navigations = []

            def navigate_before_write(write_task, expression):
                # Deterministically pause at the actual write boundary. Do not mock its result:
                # the real production-generated JS runs against the new Chromium document.
                assert write_task == task_id
                navigations.append(destination)
                sup.evaluate_runtime(f"location.href = {json.dumps(destination + '/login')}")
                wait_for_form(destination)
                return original_eval(write_task, expression)

            bvt._eval_js_secret = navigate_before_write
            try:
                result = fill()
            finally:
                bvt._eval_js_secret = original_eval
            assert navigations == [destination]
            assert result.get("error_type") == "origin_changed", result
            assert read_dom() == {"origin": destination, "password": ""}, "Navigation race wrote a password"
            print("TOCTOU: real fill JS refused navigation between two wildcard-allowed origins")

            revoked = store.update_origin_rules(login.id, origin=primary,
                                               allowed_origins=[], wildcard_origins=[])
            assert revoked.id == login.id and revoked.identifier == login.identifier
            assert revoked.created_at == login.created_at and revoked.has_otp
            assert store.resolve_secret(login.id) == original_secret, "Origin edits changed stored secrets"
            denied(login_origin)
            metadata = json.dumps([item.to_dict() for item in store.list_items()])
            metadata += bvt.browser_vault_list()
            assert password not in metadata and otp_seed not in metadata, "Metadata exposed a secret"
            print("Revocation: same handle/password/TOTP preserved; removed wildcard denies previous subdomain")
        finally:
            store.remove_item(login.id)


def main() -> int:
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    origin = f"http://127.0.0.1:{srv.server_address[1]}"

    from tools.browser_supervisor import SUPERVISOR_REGISTRY
    try:
        # browser_exec opens its own tabs; the login page is deliberately NOT the first one.
        _exec("new_tab('about:blank')")
        _exec(f"new_tab({origin + '/login'!r}); wait_for_load()")
        _exec(f"new_tab({origin + '/checkout'!r}); wait_for_load(); print(page_info()['url'])")

        sup = SUPERVISOR_REGISTRY.get(TASK)
        assert sup is not None, "browser_exec did not attach a supervisor for its task (problem 1 regressed)"
        print("supervisor attached by browser_exec; its page before fill:", sup.evaluate_runtime("location.href")["result"])

        from tools import browser_vault_tool as bvt
        from tools.browser_cdp_tool import _redact_cdp_output
        from agent.vault_store import get_vault_store
        from agent import redact
        import tools.approval_prompt as ap

        store = get_vault_store()
        login = store.add_item("login", "site", {"identifier_type": "email", "identifier": "a@b.c", "password": "pw-E2E-8842"}, origin=origin)
        card = store.add_item("payment", "visa", {"card_number": "4111111111111111", "exp_month": "7", "exp_year": "2029", "cvc": "987"}, origin=origin)

        raw = bvt.browser_vault_fill(login.id, task_id=TASK)
        out = json.loads(raw)
        print("login fill:", out)
        assert out["success"] and out["filled_fields"] == 1, out
        assert "pw-E2E-8842" not in raw
        dom = sup.evaluate_runtime("location.pathname + ' ' + document.querySelector('input[name=pw]').value")
        assert dom["result"] == "/login pw-E2E-8842", dom  # raw supervisor read (not a model surface): the write landed in the login tab
        assert "pw-E2E-8842" not in json.dumps(_redact_cdp_output({"result": {"value": dom["result"]}}))
        print("login: password landed in the /login tab; model-facing read is scrubbed")

        ap.request_elicitation_consent = lambda *a, **k: "decline"
        out = json.loads(bvt.browser_vault_fill(card.id, task_id=TASK))
        assert out["error_type"] == "payment_declined", out
        assert sup.focus_page(origin, accept=bvt._TAB_PROBES["payment"])["ok"]
        r = sup.evaluate_runtime("['cardnum','exp','cvv'].map(n => document.querySelector('[name='+n+']').value).join('|')")
        assert r.get("result") == "||", r
        print("payment: declined confirmation wrote nothing")

        ap.request_elicitation_consent = lambda *a, **k: "accept"
        raw = bvt.browser_vault_fill(card.id, task_id=TASK)
        out = json.loads(raw)
        print("payment fill:", out)
        assert out["success"] and out["filled_fields"] == 3 and out["fields"] == ["cc-csc", "cc-exp", "cc-number"], out
        assert "4111" not in raw and "987" not in raw
        r = sup.evaluate_runtime("['cardnum','exp','cvv','country','email'].map(n => document.querySelector('[name='+n+']').value).join('|')")
        assert r.get("result") == "4111111111111111|07/29|987|DE|", r
        print("payment: card/expiry/cvc filled on the /checkout tab, email untouched, select untouched without a value")

        # save-on-page: the supervisor's default page is the blank first tab; the tool must find the login
        # tab itself (Browser Use daemon tabs are how a real session looks) and bind the item to ITS origin.
        from agent.vault_backends import unlock as vault_unlock
        store.remove_item(login.id)
        sup.evaluate_runtime("document.querySelector('input[name=pw]') && (document.querySelector('input[name=pw]').value = '')")
        assert sup.focus_page("about:blank")["ok"] is False  # about: pages are never candidates
        vault_unlock.set_save_login_prompt_callback(lambda o, site: {"identifier": "new@b.c", "password": "pw-SAVE-5150"})
        vault_unlock.set_unlock_prompt_callback(lambda *a: "")  # an interactive surface installs both; can_prompt_here keys off this one
        raw = bvt.browser_vault_save_login(task_id=TASK)
        out = json.loads(raw)
        vault_unlock.set_save_login_prompt_callback(None); vault_unlock.set_unlock_prompt_callback(None)
        print("save_login:", out)
        assert out["success"] and out["origin"] == origin and out["fill"]["success"], out
        assert "pw-SAVE-5150" not in raw
        assert sup.focus_page(origin, accept=bvt._TAB_PROBES["login"])["ok"]
        dom = sup.evaluate_runtime("location.pathname + ' ' + document.querySelector('input[name=pw]').value")
        assert dom["result"] == "/login pw-SAVE-5150", dom
        print("save_login: found the login tab from a blank default page, bound to its origin, filled")

        _https_origin_proof()
        redact.clear_vault_redaction_values()
        print("E2E OK")
        return 0
    finally:
        SUPERVISOR_REGISTRY.stop(TASK)
        try:
            from tools.browser_tool_lifecycle import cleanup_browser
            cleanup_browser(TASK)
        except Exception:
            pass
        srv.shutdown()
        srv.server_close()
        shutil.rmtree(HOME, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
