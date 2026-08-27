"""Tests for the static web dashboard served by the API app."""

from pathlib import Path

from fastapi.testclient import TestClient

from api.app import app

client = TestClient(app)
WEB_HTML = Path("web/index.html").read_text()


def test_dashboard_served():
    r = client.get("/app/")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "Universal Mail Automation" in r.text


def test_root_redirects_to_dashboard():
    r = client.get("/", follow_redirects=False)
    assert r.status_code in (301, 302, 307, 308)
    assert r.headers["location"] == "/app/"


def test_dashboard_does_not_shadow_api():
    # The static mount must not break the JSON API.
    assert client.get("/health").status_code == 200
    r = client.post("/v1/senders/check", json={"sender": "clerk@courts.ca.gov"})
    assert r.status_code == 200 and r.json()["protected"] is True


def test_dashboard_developer_links_resolve():
    assert client.get("/docs").status_code == 200
    assert client.get("/llms.txt").status_code == 200
    assert client.get("/.well-known/agent.json").status_code == 200
    assert client.get("/health").status_code == 200

    r = client.get("/server.json")
    assert r.status_code == 200
    body = r.json()
    assert body["name"] == "io.github.a-organvm/universal-mail-automation"
    assert body["remotes"][0]["url"] == "http://testserver/mcp"


def test_dashboard_interactive_controls_use_real_api_states():
    assert "localSenderCheck" not in WEB_HTML
    assert "localPreviewResult" not in WEB_HTML
    assert "This share link is running in static mode" not in WEB_HTML
    assert 'data-sender=""' in WEB_HTML
    assert "Cannot reach the API" in WEB_HTML
    assert 'href="/server.json">MCP registry' in WEB_HTML


def test_dashboard_defines_status_color_tokens():
    for token in ("--green:", "--green-2:", "--green-soft:"):
        assert token in WEB_HTML


def test_checkout_saves_api_key_to_localstorage_before_redirect():
    # The checkout handler must persist account_api_key to localStorage before
    # navigating to Stripe — otherwise a new subscriber loses their only key.
    assert "uma-pending-key" in WEB_HTML
    assert "localStorage.setItem" in WEB_HTML
    # Must store the key BEFORE the redirect (setItem appears before location.href).
    set_pos = WEB_HTML.index('localStorage.setItem("uma-pending-key"')
    href_pos = WEB_HTML.index("window.location.href = data.url")
    assert set_pos < href_pos, "api key must be saved before the Stripe redirect"


def test_billing_success_copies_raw_api_key_and_shows_header_guidance():
    # On ?billing=success return, the raw key is the copy target while the
    # Authorization header remains separate guidance. This avoids saving a
    # value that becomes "Bearer Authorization: Bearer ..." in API clients.
    assert 'localStorage.getItem("uma-pending-key")' in WEB_HTML
    assert 'localStorage.removeItem("uma-pending-key")' in WEB_HTML
    assert 'id="apiKeyOut"' in WEB_HTML
    assert 'aria-label="Raw API key"' in WEB_HTML
    assert 'value="${escapeHtml(k)}"' in WEB_HTML
    assert "document.getElementById('apiKeyOut').value" in WEB_HTML
    assert "Copy API key" in WEB_HTML
    assert "Authorization: Bearer &lt;your-api-key&gt;" in WEB_HTML
    assert "Authorization: Bearer ${escapeHtml(k)}" not in WEB_HTML


def test_plan_cards_render_features_from_api():
    # renderPlans must use p.features from the API payload, not a hardcoded list.
    assert "p.features" in WEB_HTML
    # The static fallback SAMPLE_PLANS must also carry features so the plan cards
    # are informative even when the API is unreachable.
    assert '"Everything in Free"' in WEB_HTML
    assert '"Everything in Pro"' in WEB_HTML
    assert '"All providers: Gmail, IMAP/iCloud, Outlook, Mail.app"' in WEB_HTML
    assert '"1-year retained signed-receipt history (compliance export)"' in WEB_HTML
    assert '"Scheduled / recurring triage + webhooks"' in WEB_HTML
    assert '"MCP server access + ACP agent-commerce surface"' in WEB_HTML
