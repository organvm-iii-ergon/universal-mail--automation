"""Tests for the receipt-bound, zero-write-by-default mail send lane."""

from __future__ import annotations

import email
import email.policy
import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import mail_send
from mail_send import (
    EXIT_FAIL_CLOSED,
    EXIT_NOT_FOUND,
    EXIT_OK,
    EXIT_UNVERIFIED,
    build_message,
    build_self_test_message,
    run_from_draft,
    send_and_verify,
)
from mail_send_safety import (
    AUTHORIZATION_SIGNATURE_ALGORITHM,
    AuthorizationError,
    CredentialFileError,
    authorization_binding,
    authorization_key_id,
    authorization_signature,
    claim_authorized_attempt,
    parse_credential_env_file,
    resolve_smtp_credentials,
    validate_authorization_receipt,
)

CREDS = ("me@example.com", "app-password")
ATTEMPT = "attempt-20260716-a"
AUTHORIZATION_PRIVATE_KEY = bytes(range(1, 33))
AUTHORIZATION_PUBLIC_KEY = (
    Ed25519PrivateKey.from_private_bytes(AUTHORIZATION_PRIVATE_KEY)
    .public_key()
    .public_bytes(Encoding.Raw, PublicFormat.Raw)
)


class _FakeSMTP:
    """Captures the composed message + envelope instead of opening a connection."""

    captured = None
    envelope = None
    logged_in = None
    refused = {}
    send_calls = 0
    data_calls = 0
    rcpt_calls = []
    rset_calls = 0
    mail_response = (250, b"sender ok")
    data_response = (250, b"queued")

    def __init__(self, host, port, timeout=None):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def login(self, user, pw):
        _FakeSMTP.logged_in = (user, pw)

    def mail(self, from_addr):
        _FakeSMTP.envelope = (from_addr, [])
        return _FakeSMTP.mail_response

    def rcpt(self, address):
        _FakeSMTP.rcpt_calls.append(address)
        _FakeSMTP.envelope[1].append(address)
        return _FakeSMTP.refused.get(address, (250, b"recipient ok"))

    def rset(self):
        _FakeSMTP.rset_calls += 1
        return (250, b"reset")

    def data(self, payload):
        _FakeSMTP.send_calls += 1
        _FakeSMTP.data_calls += 1
        _FakeSMTP.captured = email.message_from_bytes(
            payload, policy=email.policy.default
        )
        return _FakeSMTP.data_response


class _FakeImap:
    def __init__(
        self,
        sent_ok=True,
        draft_raw=None,
        match=None,
        trash_ok=True,
        forbid_mutation=False,
    ):
        self.sent_ok = sent_ok
        self.draft_raw = draft_raw
        self.match = match
        self.trash_ok = trash_ok
        self.forbid_mutation = forbid_mutation
        self.trashed = []
        self.sent_calls = 0

    def newest_matching(self, mailbox, query):
        return self.match

    def fetch_raw(self, mailbox, uid):
        return self.draft_raw

    def sent_has(self, message_id, timeout_s=60, step_s=5):
        self.sent_calls += 1
        return self.sent_ok

    def trash_draft(self, uid):
        if self.forbid_mutation:
            raise AssertionError("dry-run attempted an IMAP mutation")
        self.trashed.append(uid)
        return self.trash_ok

    def close(self):
        pass


class _DraftMoveConnection:
    def __init__(self, *, move_ok=False, uid_expunge_ok=True):
        self.move_ok = move_ok
        self.uid_expunge_ok = uid_expunge_ok
        self.calls = []
        self.global_expunge_calls = 0

    def select(self, mailbox):
        self.calls.append(("SELECT", mailbox))
        return ("OK", [b"1"])

    def uid(self, command, *args):
        self.calls.append((command, *args))
        if command == "MOVE":
            return ("OK" if self.move_ok else "NO", [])
        if command == "EXPUNGE":
            return ("OK" if self.uid_expunge_ok else "NO", [])
        return ("OK", [])

    def expunge(self):
        self.global_expunge_calls += 1
        raise AssertionError("mailbox-wide EXPUNGE must never run")


@pytest.fixture(autouse=True)
def _isolated_effectors(monkeypatch, tmp_path):
    _FakeSMTP.captured = None
    _FakeSMTP.envelope = None
    _FakeSMTP.logged_in = None
    _FakeSMTP.refused = {}
    _FakeSMTP.send_calls = 0
    _FakeSMTP.data_calls = 0
    _FakeSMTP.rcpt_calls = []
    _FakeSMTP.rset_calls = 0
    _FakeSMTP.mail_response = (250, b"sender ok")
    _FakeSMTP.data_response = (250, b"queued")
    monkeypatch.setattr(mail_send.smtplib, "SMTP_SSL", _FakeSMTP)
    monkeypatch.setattr(
        mail_send, "DEFAULT_CREDENTIAL_FILE", str(tmp_path / "absent-credentials.env")
    )
    monkeypatch.setattr(
        mail_send,
        "DEFAULT_AUTHORIZATION_KEY_FILE",
        str(tmp_path / "authorization.pub"),
    )
    monkeypatch.setattr(
        mail_send,
        "DEFAULT_ATTEMPT_STORE",
        str(tmp_path / "attempts"),
    )
    for var in ("GMAIL_USER", "GMAIL_APP_PASSWORD", "IMAP_USER", "IMAP_PASS"):
        monkeypatch.delenv(var, raising=False)


def _authorization_key_file(tmp_path, key=AUTHORIZATION_PUBLIC_KEY):
    path = tmp_path / "authorization.pub"
    if not path.exists():
        path.write_bytes(key)
        path.chmod(0o600)
    return path


def _write_receipt(
    tmp_path,
    msg,
    *,
    action="compose",
    attempt_id=ATTEMPT,
    overrides=None,
    expired=False,
    effect_context=None,
):
    _authorization_key_file(tmp_path)
    binding = authorization_binding(
        msg,
        envelope_sender=CREDS[0],
        action=action,
        attempt_id=attempt_id,
        effect_context=effect_context,
    )
    now = datetime.now(timezone.utc)
    receipt = {
        **binding,
        "authorized": True,
        "authorized_by": "human:test-authority",
        "issued_at": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (
            now + (-timedelta(minutes=1) if expired else timedelta(minutes=10))
        ).isoformat(),
        "signature_algorithm": AUTHORIZATION_SIGNATURE_ALGORITHM,
        "key_id": authorization_key_id(AUTHORIZATION_PUBLIC_KEY),
    }
    receipt.update(overrides or {})
    receipt["signature"] = authorization_signature(
        receipt, AUTHORIZATION_PRIVATE_KEY
    )
    path = (
        tmp_path
        / f"authorization-{len(list(tmp_path.glob('authorization-*.json')))}.json"
    )
    path.write_text(json.dumps(receipt), encoding="utf-8")
    return path, binding


def _validated_grant(tmp_path, msg, *, action="compose", attempt_id=ATTEMPT):
    path, binding = _write_receipt(tmp_path, msg, action=action, attempt_id=attempt_id)
    return validate_authorization_receipt(
        path,
        binding,
        authorization_key_file=_authorization_key_file(tmp_path),
    )


def _set_env_creds(monkeypatch):
    monkeypatch.setenv("GMAIL_USER", CREDS[0])
    monkeypatch.setenv("GMAIL_APP_PASSWORD", CREDS[1])


def test_reply_threading_headers():
    reply_headers = {
        "Message-ID": "<orig-123@mail.example>",
        "References": "<root-1@mail.example>",
        "Subject": "Docket X — request",
        "From": "Clerk <clerk@example.gov>",
    }
    msg = build_message(
        CREDS, ["clerk@example.gov"], "", "body text", reply_headers=reply_headers
    )
    assert msg["In-Reply-To"] == "<orig-123@mail.example>"
    assert msg["References"] == "<root-1@mail.example> <orig-123@mail.example>"
    assert msg["Subject"] == "Re: Docket X — request"
    assert msg["Message-ID"]


def test_reply_subject_not_double_prefixed():
    msg = build_message(
        CREDS,
        ["a@b.c"],
        "",
        "x",
        reply_headers={"Message-ID": "<m@x>", "Subject": "Re: already"},
    )
    assert msg["Subject"] == "Re: already"


def test_send_and_verify_requires_current_exact_grant(tmp_path):
    msg = build_message(CREDS, ["a@b.c"], "s", "b")
    grant = _validated_grant(tmp_path, msg)
    assert (
        send_and_verify(
            msg, CREDS, _FakeImap(sent_ok=True), 1, grant, "compose", ATTEMPT
        )
        == EXIT_OK
    )
    assert _FakeSMTP.send_calls == 1

    changed = build_message(CREDS, ["a@b.c"], "changed", "b")
    assert (
        send_and_verify(changed, CREDS, _FakeImap(), 1, grant, "compose", ATTEMPT)
        == EXIT_FAIL_CLOSED
    )
    assert _FakeSMTP.send_calls == 1


def test_send_and_verify_unverified(tmp_path):
    msg = build_message(CREDS, ["a@b.c"], "s", "b")
    grant = _validated_grant(tmp_path, msg)
    assert (
        send_and_verify(
            msg, CREDS, _FakeImap(sent_ok=False), 1, grant, "compose", ATTEMPT
        )
        == EXIT_UNVERIFIED
    )


def test_bcc_stripped_from_wire_but_delivered(tmp_path):
    msg = build_message(CREDS, ["to@x.y"], "s", "b", bcc=["hidden@x.y"])
    grant = _validated_grant(tmp_path, msg)
    rc = send_and_verify(
        msg,
        CREDS,
        _FakeImap(),
        1,
        grant,
        "compose",
        ATTEMPT,
        to_addrs=["to@x.y", "hidden@x.y"],
    )
    assert rc == EXIT_OK
    assert "Bcc" not in _FakeSMTP.captured
    assert _FakeSMTP.envelope == (CREDS[0], ["hidden@x.y", "to@x.y"])


def test_smtp_envelope_cannot_add_or_drop_bound_recipients(tmp_path):
    msg = build_message(CREDS, ["to@x.y"], "s", "b", cc=["copy@x.y"])
    grant = _validated_grant(tmp_path, msg)
    rc = send_and_verify(
        msg,
        CREDS,
        _FakeImap(),
        1,
        grant,
        "compose",
        ATTEMPT,
        to_addrs=["to@x.y", "attacker@x.y"],
    )
    assert rc == EXIT_FAIL_CLOSED
    assert _FakeSMTP.rcpt_calls == []
    assert _FakeSMTP.data_calls == 0


def test_any_smtp_recipient_refusal_is_failure_and_skips_verification(tmp_path):
    msg = build_message(CREDS, ["ok@example.com", "no@example.com"], "s", "b")
    grant = _validated_grant(tmp_path, msg)
    _FakeSMTP.refused = {"no@example.com": (550, b"refused")}
    imap = _FakeImap()
    rc = send_and_verify(
        msg,
        CREDS,
        imap,
        1,
        grant,
        "compose",
        ATTEMPT,
        to_addrs=["ok@example.com", "no@example.com"],
    )
    assert rc == EXIT_FAIL_CLOSED
    assert _FakeSMTP.data_calls == 0
    assert _FakeSMTP.rset_calls == 1
    assert imap.sent_calls == 0


def test_smtp_envelope_preserves_recipient_local_part_case(tmp_path):
    msg = build_message(CREDS, ["CaseSensitive@Example.COM"], "s", "b")
    grant = _validated_grant(tmp_path, msg)

    assert (
        send_and_verify(
            msg,
            CREDS,
            _FakeImap(),
            1,
            grant,
            "compose",
            ATTEMPT,
            to_addrs=["CaseSensitive@Example.COM"],
        )
        == EXIT_OK
    )
    assert _FakeSMTP.rcpt_calls == ["CaseSensitive@example.com"]


def test_same_authorized_attempt_is_one_shot(tmp_path):
    msg = build_message(CREDS, ["a@b.c"], "s", "b")
    grant = _validated_grant(tmp_path, msg)
    assert (
        send_and_verify(msg, CREDS, _FakeImap(), 1, grant, "compose", ATTEMPT)
        == EXIT_OK
    )
    assert (
        send_and_verify(msg, CREDS, _FakeImap(), 1, grant, "compose", ATTEMPT)
        == EXIT_FAIL_CLOSED
    )
    assert _FakeSMTP.data_calls == 1


def test_attempt_store_environment_cannot_redirect_replay_claim(
    monkeypatch, tmp_path
):
    msg = build_message(CREDS, ["a@b.c"], "s", "b")
    grant = _validated_grant(tmp_path, msg)
    caller_store = tmp_path / "caller-selected-store"
    monkeypatch.setenv("UMA_MAIL_SEND_ATTEMPT_STORE", str(caller_store))

    assert (
        send_and_verify(msg, CREDS, _FakeImap(), 1, grant, "compose", ATTEMPT)
        == EXIT_OK
    )
    assert not caller_store.exists()
    assert (
        send_and_verify(msg, CREDS, _FakeImap(), 1, grant, "compose", ATTEMPT)
        == EXIT_FAIL_CLOSED
    )


def test_receipt_change_after_validation_blocks_before_smtp(tmp_path):
    msg = build_message(CREDS, ["a@b.c"], "s", "b")
    grant = _validated_grant(tmp_path, msg)
    receipt = json.loads(grant.receipt_path.read_text())
    receipt["authorized_by"] = "revoked:changed"
    grant.receipt_path.write_text(json.dumps(receipt))
    assert (
        send_and_verify(msg, CREDS, _FakeImap(), 1, grant, "compose", ATTEMPT)
        == EXIT_FAIL_CLOSED
    )
    assert _FakeSMTP.rcpt_calls == []
    assert _FakeSMTP.data_calls == 0


def test_authorization_key_rotation_after_validation_blocks_before_smtp(tmp_path):
    msg = build_message(CREDS, ["a@b.c"], "s", "b")
    grant = _validated_grant(tmp_path, msg)
    grant.authorization_public_key_path.write_bytes(
        b"rotated-independent-key-material-32-bytes"
    )
    grant.authorization_public_key_path.chmod(0o600)
    assert (
        send_and_verify(msg, CREDS, _FakeImap(), 1, grant, "compose", ATTEMPT)
        == EXIT_FAIL_CLOSED
    )
    assert _FakeSMTP.rcpt_calls == []
    assert _FakeSMTP.data_calls == 0


def test_grant_is_rechecked_after_rcpt_before_data(monkeypatch, tmp_path):
    msg = build_message(CREDS, ["a@b.c"], "s", "b")
    grant = _validated_grant(tmp_path, msg)
    checks = 0

    def recheck(_grant, _binding):
        nonlocal checks
        checks += 1
        if checks == 2:
            raise AuthorizationError("expired at DATA boundary")

    monkeypatch.setattr(mail_send, "assert_grant_current", recheck)
    assert (
        send_and_verify(msg, CREDS, _FakeImap(), 1, grant, "compose", ATTEMPT)
        == EXIT_FAIL_CLOSED
    )
    assert _FakeSMTP.rcpt_calls == ["a@b.c"]
    assert _FakeSMTP.data_calls == 0


def _draft_message():
    draft = email.message.EmailMessage()
    draft["From"] = CREDS[0]
    draft["To"] = "alice@example.com"
    draft["Cc"] = "bob@example.com"
    draft["Bcc"] = "carol@example.com"
    draft["Subject"] = "Re: the thing"
    draft["Message-ID"] = "<draft-1@mail.example>"
    draft.set_content("draft body")
    return draft


def test_from_draft_apply_is_receipt_bound_then_trashes(tmp_path):
    draft = _draft_message()
    parsed = email.message_from_bytes(draft.as_bytes(), policy=email.policy.default)
    effect_context = {
        "source_mailbox": mail_send.DRAFTS,
        "source_uid": "7",
        "source_message_id": "<draft-1@mail.example>",
    }
    receipt, _ = _write_receipt(
        tmp_path,
        parsed,
        action="from_draft",
        effect_context=effect_context,
    )
    imap = _FakeImap(
        match=(b"7", {"Subject": "Re: the thing"}), draft_raw=draft.as_bytes()
    )
    rc = run_from_draft(
        "the thing",
        CREDS,
        imap,
        1,
        apply=True,
        attempt_id=ATTEMPT,
        authorization_receipt=str(receipt),
        authorization_key_file=str(_authorization_key_file(tmp_path)),
    )
    assert rc == EXIT_OK
    assert "Bcc" not in _FakeSMTP.captured
    assert _FakeSMTP.envelope[1] == [
        "alice@example.com",
        "bob@example.com",
        "carol@example.com",
    ]
    assert _FakeSMTP.captured["Message-ID"] == "<draft-1@mail.example>"
    assert imap.trashed == [b"7"]


def test_from_draft_not_found():
    assert (
        run_from_draft(
            "nope",
            CREDS,
            _FakeImap(match=None),
            1,
            apply=False,
            attempt_id=ATTEMPT,
            authorization_receipt=None,
            authorization_key_file=None,
        )
        == EXIT_NOT_FOUND
    )
    assert _FakeSMTP.send_calls == 0


def test_from_draft_default_preview_has_no_smtp_or_imap_mutation():
    draft = _draft_message()
    imap = _FakeImap(
        match=(b"9", {}),
        draft_raw=draft.as_bytes(),
        forbid_mutation=True,
    )
    rc = run_from_draft(
        "thing",
        CREDS,
        imap,
        1,
        apply=False,
        attempt_id=ATTEMPT,
        authorization_receipt=None,
        authorization_key_file=None,
    )
    assert rc == EXIT_OK
    assert _FakeSMTP.send_calls == 0
    assert imap.trashed == []
    assert imap.sent_calls == 0


def test_from_draft_requires_an_exact_authenticated_from_header():
    draft = _draft_message()
    del draft["From"]
    imap = _FakeImap(match=(b"9", {}), draft_raw=draft.as_bytes())
    assert (
        run_from_draft(
            "thing",
            CREDS,
            imap,
            1,
            apply=False,
            attempt_id=ATTEMPT,
            authorization_receipt=None,
            authorization_key_file=None,
        )
        == EXIT_FAIL_CLOSED
    )
    assert _FakeSMTP.data_calls == 0


def test_draft_cleanup_uses_scoped_move_or_uid_expunge_only():
    connection = _DraftMoveConnection(move_ok=False, uid_expunge_ok=True)
    imap = mail_send.GmailImap(CREDS)
    imap._conn = connection
    assert imap.trash_draft(b"7") is True
    assert ("MOVE", b"7", f'"{mail_send.TRASH}"') in connection.calls
    assert ("EXPUNGE", b"7") in connection.calls
    assert connection.global_expunge_calls == 0

    connection = _DraftMoveConnection(move_ok=False, uid_expunge_ok=False)
    imap._conn = connection
    assert imap.trash_draft(b"8") is False
    assert ("STORE", b"8", "-FLAGS", r"(\Deleted)") in connection.calls
    assert connection.global_expunge_calls == 0


def test_missing_creds_fails_closed():
    rc = mail_send.main(["--self-test", "--attempt-id", ATTEMPT])
    assert rc == EXIT_FAIL_CLOSED
    assert _FakeSMTP.send_calls == 0


def test_apply_without_receipt_fails_before_any_effect(monkeypatch):
    _set_env_creds(monkeypatch)
    rc = mail_send.main(["--self-test", "--attempt-id", ATTEMPT, "--apply"])
    assert rc == EXIT_FAIL_CLOSED
    assert _FakeSMTP.send_calls == 0


def test_apply_without_authentication_key_fails_before_any_effect(monkeypatch):
    _set_env_creds(monkeypatch)
    rc = mail_send.main(
        [
            "--self-test",
            "--attempt-id",
            ATTEMPT,
            "--apply",
            "--authorization-receipt",
            "/does/not/matter.json",
        ]
    )
    assert rc == EXIT_FAIL_CLOSED
    assert _FakeSMTP.data_calls == 0


def test_argparse_and_mode_errors_exit_before_effects(monkeypatch):
    _set_env_creds(monkeypatch)
    with pytest.raises(SystemExit) as exc:
        mail_send.main(["--self-test", "--from-draft", "x", "--attempt-id", ATTEMPT])
    assert exc.value.code == 2
    with pytest.raises(SystemExit) as exc:
        mail_send.main(["--attempt-id", ATTEMPT, "--verify-timeout", "not-an-int"])
    assert exc.value.code == 2
    assert _FakeSMTP.data_calls == 0


def test_verify_timeout_and_ignored_compose_options_fail_closed(monkeypatch):
    _set_env_creds(monkeypatch)
    assert (
        mail_send.main(
            ["--self-test", "--attempt-id", ATTEMPT, "--verify-timeout", "0"]
        )
        == EXIT_FAIL_CLOSED
    )
    assert (
        mail_send.main(
            [
                "--self-test",
                "--attempt-id",
                ATTEMPT,
                "--to",
                "ignored@example.com",
            ]
        )
        == EXIT_FAIL_CLOSED
    )
    assert _FakeSMTP.data_calls == 0


def test_invalid_or_missing_attempt_id_fails_closed(monkeypatch):
    _set_env_creds(monkeypatch)
    assert mail_send.main(["--self-test"]) == EXIT_FAIL_CLOSED
    assert mail_send.main(["--self-test", "--attempt-id", "short"]) == EXIT_FAIL_CLOSED
    assert _FakeSMTP.send_calls == 0


def test_recipient_validation_refuses(monkeypatch, tmp_path):
    _set_env_creds(monkeypatch)
    body = tmp_path / "b.txt"
    body.write_text("hello")
    base = ["--attempt-id", ATTEMPT, "--subject", "s", "--body-file", str(body)]
    assert mail_send.main(["--to", "not-an-address", *base]) == EXIT_FAIL_CLOSED
    assert (
        mail_send.main(["--to", "x@privaterelay.appleid.com", *base])
        == EXIT_FAIL_CLOSED
    )
    assert _FakeSMTP.send_calls == 0


def test_compose_is_zero_write_by_default(monkeypatch, tmp_path):
    _set_env_creds(monkeypatch)
    body = tmp_path / "b.txt"
    body.write_text("hello there")
    imap = _FakeImap(forbid_mutation=True)
    monkeypatch.setattr(mail_send, "GmailImap", lambda creds: imap)
    rc = mail_send.main(
        [
            "--attempt-id",
            ATTEMPT,
            "--to",
            "A@B.C",
            "--subject",
            "s",
            "--body-file",
            str(body),
        ]
    )
    assert rc == EXIT_OK
    assert _FakeSMTP.send_calls == 0
    assert imap.sent_calls == 0
    assert imap.trashed == []
    assert not (tmp_path / "attempts").exists()


def test_explicit_dry_run_is_also_zero_write(monkeypatch, tmp_path):
    _set_env_creds(monkeypatch)
    body = tmp_path / "b.txt"
    body.write_text("hello there")
    rc = mail_send.main(
        [
            "--attempt-id",
            ATTEMPT,
            "--to",
            "a@b.c",
            "--subject",
            "s",
            "--body-file",
            str(body),
            "--dry-run",
        ]
    )
    assert rc == EXIT_OK
    assert _FakeSMTP.send_calls == 0


def test_self_test_preview_is_deterministic_and_zero_write(monkeypatch, capsys):
    _set_env_creds(monkeypatch)
    args = ["--self-test", "--attempt-id", ATTEMPT]
    assert mail_send.main(args) == EXIT_OK
    first = capsys.readouterr().out
    assert mail_send.main(args) == EXIT_OK
    second = capsys.readouterr().out
    assert first == second
    expected_suffix = hashlib.sha256(ATTEMPT.encode()).hexdigest()[:32]
    assert f"<uma-self-test-{expected_suffix}@example.com>" in first
    assert '"authorized": false' in first
    assert _FakeSMTP.send_calls == 0


def test_cli_rejects_caller_selected_attempt_store():
    with pytest.raises(SystemExit):
        mail_send.main(
            [
                "--self-test",
                "--attempt-id",
                ATTEMPT,
                "--attempt-store",
                "/tmp/caller-selected-store",
            ]
        )


def test_self_test_exact_authorization_is_one_shot(monkeypatch, tmp_path):
    _set_env_creds(monkeypatch)
    expected = build_self_test_message(CREDS, ATTEMPT)
    receipt, _ = _write_receipt(tmp_path, expected, action="self_test")
    imap = _FakeImap(sent_ok=True)
    monkeypatch.setattr(mail_send, "GmailImap", lambda creds: imap)
    args = [
        "--self-test",
        "--attempt-id",
        ATTEMPT,
        "--apply",
        "--authorization-receipt",
        str(receipt),
    ]
    assert mail_send.main(args) == EXIT_OK
    assert _FakeSMTP.envelope == (CREDS[0], [CREDS[0]])
    assert mail_send.main(args) == EXIT_FAIL_CLOSED
    assert _FakeSMTP.data_calls == 1


def test_compose_apply_with_exact_receipt(monkeypatch, tmp_path):
    _set_env_creds(monkeypatch)
    body = tmp_path / "body.txt"
    body.write_text("authorized body")
    expected = build_message(
        CREDS,
        ["a@b.c"],
        "Exact subject",
        "authorized body",
        attempt_id=ATTEMPT,
    )
    receipt, _ = _write_receipt(tmp_path, expected)
    imap = _FakeImap(sent_ok=True)
    monkeypatch.setattr(mail_send, "GmailImap", lambda creds: imap)
    rc = mail_send.main(
        [
            "--attempt-id",
            ATTEMPT,
            "--to",
            "a@b.c",
            "--subject",
            "Exact subject",
            "--body-file",
            str(body),
            "--apply",
            "--authorization-receipt",
            str(receipt),
        ]
    )
    assert rc == EXIT_OK
    assert _FakeSMTP.send_calls == 1
    assert imap.sent_calls == 1


def test_receipt_subject_mismatch_blocks_before_smtp(monkeypatch, tmp_path):
    _set_env_creds(monkeypatch)
    body = tmp_path / "body.txt"
    body.write_text("authorized body")
    expected = build_message(
        CREDS,
        ["a@b.c"],
        "Different subject",
        "authorized body",
        attempt_id=ATTEMPT,
    )
    receipt, _ = _write_receipt(tmp_path, expected)
    rc = mail_send.main(
        [
            "--attempt-id",
            ATTEMPT,
            "--to",
            "a@b.c",
            "--subject",
            "Actual subject",
            "--body-file",
            str(body),
            "--apply",
            "--authorization-receipt",
            str(receipt),
        ]
    )
    assert rc == EXIT_FAIL_CLOSED
    assert _FakeSMTP.send_calls == 0


def test_missing_body_file_is_a_controlled_fail_closed_exit(monkeypatch, tmp_path):
    _set_env_creds(monkeypatch)
    rc = mail_send.main(
        [
            "--attempt-id",
            ATTEMPT,
            "--to",
            "a@b.c",
            "--subject",
            "s",
            "--body-file",
            str(tmp_path / "missing-body.txt"),
        ]
    )
    assert rc == EXIT_FAIL_CLOSED
    assert _FakeSMTP.data_calls == 0


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("schema", "wrong.schema"),
        ("action", "reply"),
        ("attempt_id", "attempt-20260716-other"),
        ("sender", "other@example.com"),
        ("recipients", {"to": ["other@example.com"], "cc": [], "bcc": []}),
        ("subject", "other"),
        ("message_id", "<other@example.com>"),
        ("thread", {"in_reply_to": "<other@example.com>", "references": ""}),
        ("headers", [["reply-to", "other@example.com"]]),
        ("body_sha256", "0" * 64),
        ("attachments", [{"filename": "x", "size": 1, "sha256": "0" * 64}]),
        ("effect_context", {"source_uid": "other"}),
        ("binding_sha256", "0" * 64),
    ],
)
def test_every_bound_receipt_field_mismatch_is_rejected(tmp_path, field, replacement):
    msg = build_message(CREDS, ["a@b.c"], "s", "body")
    path, binding = _write_receipt(tmp_path, msg, overrides={field: replacement})
    with pytest.raises(AuthorizationError, match=field):
        validate_authorization_receipt(
            path,
            binding,
            authorization_key_file=_authorization_key_file(tmp_path),
        )


def test_expired_or_non_authorizing_receipt_is_rejected(tmp_path):
    msg = build_message(CREDS, ["a@b.c"], "s", "body")
    path, binding = _write_receipt(tmp_path, msg, expired=True)
    with pytest.raises(AuthorizationError, match="expired"):
        validate_authorization_receipt(
            path,
            binding,
            authorization_key_file=_authorization_key_file(tmp_path),
        )
    path, binding = _write_receipt(tmp_path, msg, overrides={"authorized": False})
    with pytest.raises(AuthorizationError, match="authorized=true"):
        validate_authorization_receipt(
            path,
            binding,
            authorization_key_file=_authorization_key_file(tmp_path),
        )


def test_receipt_requires_authentic_signature_and_bounded_lifetime(tmp_path):
    msg = build_message(CREDS, ["a@b.c"], "s", "body")
    path, binding = _write_receipt(tmp_path, msg)
    receipt = json.loads(path.read_text())
    receipt["authorized_by"] = "forged:caller"
    path.write_text(json.dumps(receipt))
    with pytest.raises(AuthorizationError, match="signature verification"):
        validate_authorization_receipt(
            path,
            binding,
            authorization_key_file=_authorization_key_file(tmp_path),
        )


def test_public_verification_key_cannot_authorize_a_forged_receipt(tmp_path):
    msg = build_message(CREDS, ["a@b.c"], "s", "body")
    path, binding = _write_receipt(tmp_path, msg)
    receipt = json.loads(path.read_text())
    receipt["authorized_by"] = "forged:sender"
    receipt["signature"] = authorization_signature(
        receipt, AUTHORIZATION_PUBLIC_KEY
    )
    path.write_text(json.dumps(receipt))

    with pytest.raises(AuthorizationError, match="signature verification"):
        validate_authorization_receipt(
            path,
            binding,
            authorization_key_file=_authorization_key_file(tmp_path),
        )

    now = datetime.now(timezone.utc)
    path, binding = _write_receipt(
        tmp_path,
        msg,
        overrides={
            "issued_at": now.isoformat(),
            "expires_at": (now + timedelta(hours=24)).isoformat(),
        },
    )
    with pytest.raises(AuthorizationError, match="lifetime exceeds"):
        validate_authorization_receipt(
            path,
            binding,
            authorization_key_file=_authorization_key_file(tmp_path),
            now=now,
        )


def test_authorization_control_files_refuse_symlinks_and_open_permissions(tmp_path):
    msg = build_message(CREDS, ["a@b.c"], "s", "body")
    path, binding = _write_receipt(tmp_path, msg)
    receipt_link = tmp_path / "receipt-link.json"
    receipt_link.symlink_to(path)
    with pytest.raises(AuthorizationError, match="not a symlink"):
        validate_authorization_receipt(
            receipt_link,
            binding,
            authorization_key_file=_authorization_key_file(tmp_path),
        )

    key_path = _authorization_key_file(tmp_path)
    key_path.chmod(0o666)
    with pytest.raises(AuthorizationError, match="group/world writable"):
        validate_authorization_receipt(
            path,
            binding,
            authorization_key_file=key_path,
        )


def test_attempt_store_refuses_symlink_without_touching_target(tmp_path):
    msg = build_message(CREDS, ["a@b.c"], "s", "body")
    grant = _validated_grant(tmp_path, msg)
    binding = authorization_binding(
        msg, envelope_sender=CREDS[0], action="compose", attempt_id=ATTEMPT
    )
    target = tmp_path / "outside"
    target.mkdir()
    link = tmp_path / "attempt-link"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(AuthorizationError, match="attempt store"):
        claim_authorized_attempt(grant, binding, link)
    assert list(target.iterdir()) == []

    with pytest.raises(AuthorizationError, match="attempt store"):
        claim_authorized_attempt(grant, binding, link / "nested")
    assert list(target.iterdir()) == []


def test_binding_normalizes_recipient_roles_and_hashes_attachments(tmp_path):
    attachment = tmp_path / "proof.bin"
    attachment.write_bytes(b"proof bytes")
    msg = build_message(
        CREDS,
        ["Alpha@Example.COM", "alpha@example.com"],
        "s",
        "body",
        cc=["BETA@example.com"],
        bcc=["Hidden@Example.com"],
        attachments=[attachment],
    )
    binding = authorization_binding(
        msg, envelope_sender="ME@EXAMPLE.COM", action="compose", attempt_id=ATTEMPT
    )
    assert binding["sender"] == "ME@example.com"
    assert binding["recipients"] == {
        "to": ["Alpha@example.com", "alpha@example.com"],
        "cc": ["BETA@example.com"],
        "bcc": ["Hidden@example.com"],
    }
    assert len(binding["attachments"]) == 1
    assert binding["attachments"][0]["filename"] == "proof.bin"
    assert binding["attachments"][0]["size"] == len(b"proof bytes")
    assert binding["attachments"][0]["sha256"] == hashlib.sha256(
        b"proof bytes"
    ).hexdigest()
    assert binding["attachments"][0]["content_type"] == "application/octet-stream"


def test_binding_covers_thread_and_selected_remote_source():
    first = build_message(
        CREDS,
        ["a@b.c"],
        "",
        "body",
        reply_headers={"Message-ID": "<first@x>", "Subject": "same"},
    )
    second = build_message(
        CREDS,
        ["a@b.c"],
        "",
        "body",
        reply_headers={"Message-ID": "<second@x>", "Subject": "same"},
    )
    first_binding = authorization_binding(
        first,
        envelope_sender=CREDS[0],
        action="reply",
        attempt_id=ATTEMPT,
        effect_context={"source_mailbox": "all", "source_uid": "1"},
    )
    second_binding = authorization_binding(
        second,
        envelope_sender=CREDS[0],
        action="reply",
        attempt_id=ATTEMPT,
        effect_context={"source_mailbox": "all", "source_uid": "2"},
    )
    assert first_binding["thread"]["in_reply_to"] == "<first@x>"
    assert first_binding["effect_context"]["source_uid"] == "1"
    assert first_binding["binding_sha256"] != second_binding["binding_sha256"]


def test_binding_covers_mime_rendering_metadata_and_structure():
    plain = email.message.EmailMessage()
    plain["From"] = CREDS[0]
    plain["To"] = "a@b.c"
    plain["Subject"] = "same"
    plain.set_content("same body")

    flowed = email.message.EmailMessage()
    flowed["From"] = CREDS[0]
    flowed["To"] = "a@b.c"
    flowed["Subject"] = "same"
    flowed.set_content("same body")
    flowed.set_param("format", "flowed", header="Content-Type")

    alternative = email.message.EmailMessage()
    alternative["From"] = CREDS[0]
    alternative["To"] = "a@b.c"
    alternative["Subject"] = "same"
    alternative.set_content("same body")
    alternative.add_alternative("<p>same body</p>", subtype="html")

    bindings = [
        authorization_binding(
            message,
            envelope_sender=CREDS[0],
            action="from_draft",
            attempt_id=ATTEMPT,
        )
        for message in (plain, flowed, alternative)
    ]

    assert len({binding["binding_sha256"] for binding in bindings}) == 3
    assert len({binding["mime_structure_sha256"] for binding in bindings}) == 2


def test_missing_attachment_fails_closed(monkeypatch, tmp_path):
    _set_env_creds(monkeypatch)
    body = tmp_path / "b.txt"
    body.write_text("hello")
    rc = mail_send.main(
        [
            "--attempt-id",
            ATTEMPT,
            "--to",
            "a@b.c",
            "--subject",
            "s",
            "--body-file",
            str(body),
            "--attach",
            "/nonexistent.pdf",
        ]
    )
    assert rc == EXIT_FAIL_CLOSED
    assert _FakeSMTP.send_calls == 0


def test_credential_file_is_parsed_as_data_and_never_executes(tmp_path):
    marker = tmp_path / "must-not-exist"
    credentials = tmp_path / "credentials.env"
    credentials.write_text(
        "\n".join(
            [
                "# literal credential file",
                "export GMAIL_USER='Me@Example.com'",
                f"export GMAIL_APP_PASSWORD=$(touch {marker})",
                f"touch {marker}",
                "UNRELATED=$HOME",
            ]
        )
    )
    values = parse_credential_env_file(credentials)
    assert values == {
        "GMAIL_USER": "Me@Example.com",
        "GMAIL_APP_PASSWORD": f"$(touch {marker})",
    }
    assert resolve_smtp_credentials([credentials], {}) == (
        "Me@Example.com",
        f"$(touch {marker})",
    )
    assert not marker.exists()


def test_credential_file_rejects_unmatched_allowed_value_quote(tmp_path):
    credentials = tmp_path / "credentials.env"
    credentials.write_text("GMAIL_USER='unterminated\n")
    with pytest.raises(CredentialFileError, match="unmatched"):
        parse_credential_env_file(credentials)


def test_credential_file_refuses_symlink_and_writable_control_file(tmp_path):
    credentials = tmp_path / "credentials.env"
    credentials.write_text("GMAIL_USER=me@example.com\nGMAIL_APP_PASSWORD=secret\n")
    link = tmp_path / "credentials-link.env"
    link.symlink_to(credentials)
    with pytest.raises(CredentialFileError, match="symlink"):
        parse_credential_env_file(link)

    credentials.chmod(0o666)
    with pytest.raises(CredentialFileError, match="group/world writable"):
        parse_credential_env_file(credentials)


def test_complete_process_environment_pair_outranks_other_file_alias(tmp_path):
    credentials = tmp_path / "credentials.env"
    credentials.write_text("IMAP_USER=file@example.com\nIMAP_PASS=file-secret\n")
    assert resolve_smtp_credentials(
        [credentials],
        {
            "GMAIL_USER": "env@example.com",
            "GMAIL_APP_PASSWORD": "env-secret",
        },
    ) == ("env@example.com", "env-secret")


def test_complete_environment_pair_skips_malformed_credential_file(tmp_path):
    credentials = tmp_path / "credentials.env"
    credentials.write_text("GMAIL_USER='unterminated\n")

    assert resolve_smtp_credentials(
        [credentials],
        {
            "GMAIL_USER": "env@example.com",
            "GMAIL_APP_PASSWORD": "env-secret",
        },
    ) == ("env@example.com", "env-secret")


def test_cli_discovers_explicit_credential_file_without_sourcing(monkeypatch, tmp_path):
    credentials = tmp_path / "credentials.env"
    credentials.write_text(
        "GMAIL_USER=me@example.com\nGMAIL_APP_PASSWORD=literal-secret\n"
    )
    body = tmp_path / "b.txt"
    body.write_text("hello")
    rc = mail_send.main(
        [
            "--credentials-file",
            str(credentials),
            "--attempt-id",
            ATTEMPT,
            "--to",
            "a@b.c",
            "--subject",
            "s",
            "--body-file",
            str(body),
        ]
    )
    assert rc == EXIT_OK
    assert _FakeSMTP.send_calls == 0
