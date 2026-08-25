"""Tests for providers.base.EmailProvider — the shared provider contract.

The base class supplies behavior every concrete provider inherits: capability
gating for star/unstar/category, the default archive/batch/health-check
implementations, the context-manager lifecycle, and the apply_actions orchestrator
(its protected-sender gate is exercised in test_protected_enforcement.py; here we
cover the star/category dispatch, error accounting, and label stats).

All tests use lightweight fakes — no network, no real accounts.
"""

import pytest

from core.models import EmailMessage, LabelAction, FlagColor
from providers.base import (
    EmailProvider,
    ProviderCapabilities,
    ListMessagesResult,
)


class FakeProvider(EmailProvider):
    """Minimal label-style provider that records every mutating call.

    Capabilities are injectable so the gating branches can be probed both ways.
    """

    name = "fake"

    def __init__(self, capabilities=ProviderCapabilities.STAR | ProviderCapabilities.ARCHIVE):
        self.capabilities = capabilities
        self.connected = False
        self.disconnected = False
        self.store = {}            # id -> EmailMessage
        self.applied = []          # (message_id, label)
        self.removed = []          # (message_id, label)
        self.list_calls = []       # (query, limit, page_token)
        self.ensured = []          # labels passed to ensure_label_exists
        self.health_should_fail = False

    def connect(self):
        self.connected = True

    def disconnect(self):
        self.disconnected = True

    def list_messages(self, query="", limit=100, page_token=None):
        self.list_calls.append((query, limit, page_token))
        if self.health_should_fail:
            raise RuntimeError("connection refused")
        msgs = list(self.store.values())[:limit]
        return ListMessagesResult(messages=msgs)

    def get_message_details(self, message_id):
        return self.store.get(message_id)

    def apply_label(self, message_id, label):
        self.applied.append((message_id, label))
        return True

    def remove_label(self, message_id, label):
        self.removed.append((message_id, label))
        return True

    def ensure_label_exists(self, label):
        self.ensured.append(label)
        return label


class CategoryProvider(FakeProvider):
    """Folder provider that supports color categories (models Outlook)."""

    name = "category"

    def __init__(self):
        super().__init__(
            capabilities=ProviderCapabilities.FOLDERS
            | ProviderCapabilities.CATEGORIES
            | ProviderCapabilities.STAR
            | ProviderCapabilities.ARCHIVE
        )
        self.categories = []  # (message_id, category, color)

    def apply_category(self, message_id, category, color="blue"):
        if not (self.capabilities & ProviderCapabilities.CATEGORIES):
            return False
        self.categories.append((message_id, category, color))
        return True


class TestContextManager:
    def test_enter_connects_and_exit_disconnects(self):
        p = FakeProvider()
        with p as ctx:
            assert ctx is p
            assert p.connected is True
            assert p.disconnected is False
        assert p.disconnected is True


class TestStarGating:
    def test_star_applies_when_capable(self):
        p = FakeProvider(capabilities=ProviderCapabilities.STAR)
        assert p.star("m1") is True
        assert ("m1", "STARRED") in p.applied

    def test_star_noop_without_capability(self):
        p = FakeProvider(capabilities=ProviderCapabilities.ARCHIVE)
        assert p.star("m1") is False
        assert p.applied == []

    def test_unstar_removes_when_capable(self):
        p = FakeProvider(capabilities=ProviderCapabilities.STAR)
        assert p.unstar("m1") is True
        assert ("m1", "STARRED") in p.removed

    def test_unstar_noop_without_capability(self):
        p = FakeProvider(capabilities=ProviderCapabilities.ARCHIVE)
        assert p.unstar("m1") is False
        assert p.removed == []


class TestCategoryGating:
    def test_base_apply_category_false_without_capability(self):
        p = FakeProvider(capabilities=ProviderCapabilities.STAR)
        assert p.apply_category("m1", "Work", "red") is False

    def test_base_apply_category_false_even_with_capability(self):
        # Base implementation always returns False — subclasses must override.
        p = FakeProvider(capabilities=ProviderCapabilities.CATEGORIES)
        assert p.apply_category("m1", "Work") is False

    def test_subclass_override_applies_category(self):
        p = CategoryProvider()
        assert p.apply_category("m1", "Work", "purple") is True
        assert ("m1", "Work", "purple") in p.categories


class TestDefaultArchiveAndCache:
    def test_archive_removes_inbox_label(self):
        p = FakeProvider()
        assert p.archive("m1") is True
        assert ("m1", "INBOX") in p.removed

    def test_get_label_cache_defaults_empty(self):
        assert FakeProvider().get_label_cache() == {}


class TestBatchGetDetails:
    def test_returns_found_and_omits_missing(self):
        p = FakeProvider()
        p.store = {
            "a": EmailMessage(id="a", sender="x@y.com", subject="A"),
            "b": EmailMessage(id="b", sender="x@y.com", subject="B"),
        }
        out = p.batch_get_details(["a", "missing", "b"])
        assert set(out) == {"a", "b"}
        assert out["a"].subject == "A"

    def test_empty_request_returns_empty(self):
        assert FakeProvider().batch_get_details([]) == {}


class TestHealthCheck:
    def test_healthy_provider_reports_ok(self):
        p = FakeProvider()
        ok, msg = p.health_check()
        assert ok is True
        assert msg == "OK"
        # Health check probes with a single-message list.
        assert p.list_calls[-1][1] == 1

    def test_unhealthy_provider_reports_error(self):
        p = FakeProvider()
        p.health_should_fail = True
        ok, msg = p.health_check()
        assert ok is False
        assert "connection refused" in msg


class TestApplyActionsDispatch:
    def test_star_and_category_dispatched(self):
        p = CategoryProvider()
        p.apply_actions([
            LabelAction(
                message_id="m1",
                sender="promo@some-shop.example",
                add_labels=["Work"],
                star=True,
                category="Work",
                category_color="yellow",
            )
        ])
        # FOLDERS provider star routes through apply_label("STARRED").
        assert ("m1", "STARRED") in p.applied
        assert ("m1", "Work", "yellow") in p.categories

    def test_label_stats_counted_for_applied_labels(self):
        p = FakeProvider(capabilities=ProviderCapabilities.TRUE_LABELS)
        result = p.apply_actions([
            LabelAction(message_id="m1", sender="a@b.com", add_labels=["Finance/Banking"]),
            LabelAction(message_id="m2", sender="c@d.com", add_labels=["Finance/Banking"]),
        ])
        assert result.success_count == 2
        assert result.processed_count == 2
        assert result.label_counts["Finance/Banking"] == 2
        assert result.error_count == 0

    def test_default_category_color_blue_when_unspecified(self):
        p = CategoryProvider()
        p.apply_actions([
            LabelAction(message_id="m1", sender="a@b.com", category="Reference"),
        ])
        assert ("m1", "Reference", "blue") in p.categories

    def test_exception_during_apply_is_counted_not_raised(self):
        class ExplodingProvider(FakeProvider):
            def apply_label(self, message_id, label):
                raise RuntimeError("API 500")

        p = ExplodingProvider(capabilities=ProviderCapabilities.TRUE_LABELS)
        result = p.apply_actions([
            LabelAction(message_id="boom", sender="a@b.com", add_labels=["X"]),
        ])
        assert result.error_count == 1
        assert result.success_count == 0
        assert result.processed_count == 1
        assert any("boom" in e and "API 500" in e for e in result.errors)

    def test_star_fails_without_capability(self):
        # A star action on a non-star provider now fails (returns False) and
        # is counted as an error, not silently skipped.
        p = FakeProvider(capabilities=ProviderCapabilities.TRUE_LABELS)
        result = p.apply_actions([
            LabelAction(message_id="m1", sender="a@b.com", star=True),
        ])
        assert result.error_count == 1
        assert result.success_count == 0
        assert ("m1", "STARRED") not in p.applied


class TestFlagOperationsOnUnsupportedProvider:
    """Providers without COLORED_FLAGS must reject flag operations."""

    def test_get_flag_color_raises_on_unsupported(self):
        p = FakeProvider(capabilities=ProviderCapabilities.STAR | ProviderCapabilities.ARCHIVE)
        with pytest.raises(NotImplementedError, match="does not support COLORED_FLAGS"):
            p.get_flag_color("m1")

    def test_set_flag_color_raises_on_unsupported(self):
        p = FakeProvider(capabilities=ProviderCapabilities.STAR | ProviderCapabilities.ARCHIVE)
        with pytest.raises(NotImplementedError, match="does not support COLORED_FLAGS"):
            p.set_flag_color("m1", FlagColor.RED)

    def test_clear_flag_raises_on_unsupported(self):
        p = FakeProvider(capabilities=ProviderCapabilities.STAR | ProviderCapabilities.ARCHIVE)
        with pytest.raises(NotImplementedError, match="does not support COLORED_FLAGS"):
            p.clear_flag("m1")


class TestFlagOperationFailuresCounted:
    """Failed flag operations must increment error_count, not success_count."""

    def test_set_flag_color_false_is_error(self):
        class FailingProvider(FakeProvider):
            def set_flag_color(self, message_id, color):
                return False

        p = FailingProvider(capabilities=ProviderCapabilities.COLORED_FLAGS)
        result = p.apply_actions([
            LabelAction(message_id="m1", sender="a@b.com", flag_color=FlagColor.RED),
        ])
        assert result.error_count == 1
        assert result.success_count == 0

    def test_clear_flag_false_is_error(self):
        class FailingProvider(FakeProvider):
            def clear_flag(self, message_id):
                return False

        p = FailingProvider(capabilities=ProviderCapabilities.COLORED_FLAGS)
        result = p.apply_actions([
            LabelAction(message_id="m1", sender="a@b.com", clear_flag=True),
        ])
        assert result.error_count == 1
        assert result.success_count == 0

    def test_star_false_is_error(self):
        class FailingProvider(FakeProvider):
            def star(self, message_id, due_date=None):
                return False

        p = FailingProvider(capabilities=ProviderCapabilities.STAR)
        result = p.apply_actions([
            LabelAction(message_id="m1", sender="a@b.com", star=True),
        ])
        assert result.error_count == 1
        assert result.success_count == 0


class TestProviderCapabilitiesFlag:
    def test_flags_compose_and_test_membership(self):
        caps = ProviderCapabilities.STAR | ProviderCapabilities.ARCHIVE
        assert caps & ProviderCapabilities.STAR
        assert caps & ProviderCapabilities.ARCHIVE
        assert not (caps & ProviderCapabilities.CATEGORIES)
