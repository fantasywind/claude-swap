"""Tests for pure-HTTPS cross-account Claude Artifact sharing & auto-acceptance.

Exercises URL/slug parsing, SessionVault persistence (plus read-only fallback
to chrome_web_sessions.json), add_session_key verification, ArtifactSyncState
caching, settings.json persistence, owner/target streaming orchestration with
progress callbacks, and ArtifactSyncRunner switch/periodic hooks without
touching any real network.
"""

from __future__ import annotations

import json
import stat
import sys
import time
from pathlib import Path

import pytest

from claude_swap import artifact_sync as art
from claude_swap.settings import (
    load_artifact_settings,
    set_artifact_sync_enabled,
    unrecognized_keys,
)


def _seed_store(root: Path, accounts: list[tuple[str, str, str, float | None]]) -> None:
    seq = {"activeAccountNumber": 1, "accounts": {}}
    vault = art.SessionVault(root)
    for slot, email, org, exp in accounts:
        seq["accounts"][slot] = {"email": email, "organizationUuid": org}
        if exp is not None:
            vault.put(
                slot,
                session_key=f"sk-ant-sid01-{slot}",
                email=email,
                account_uuid=f"acc-{slot}",
                org_uuid=org,
                expires_at=exp,
            )
    (root / "sequence.json").write_text(json.dumps(seq), encoding="utf-8")


@pytest.mark.parametrize(
    ("slug", "expected_uuid"),
    [
        ("1RQPLGDWF3VJSxMwK89UJe", "03684313-ca04-4bc1-bc47-d8460e51013b"),
        ("91nkgPmS6ZkD4QfTRcFfkW", "40e54e3d-4fee-4776-b915-b5744ac73a13"),
    ],
)
def test_base58_slug_roundtrip(slug: str, expected_uuid: str):
    assert art.decode_artifact_slug(slug) == expected_uuid
    assert art.encode_artifact_slug(expected_uuid) == slug


def test_parse_artifact_ref_variants():
    fid, org = art.parse_artifact_ref(
        "https://claude.ai/artifact/1RQPLGDWF3VJSxMwK89UJe#page-5634c5cea0db"
    )
    assert fid == "03684313-ca04-4bc1-bc47-d8460e51013b"
    assert org == ""

    fid2, org2 = art.parse_artifact_ref(
        "https://claude.ai/artifact/91nkgPmS6ZkD4QfTRcFfkW?org=16bc9f86-430b-4278-893c-24f382255e58"
    )
    assert fid2 == "40e54e3d-4fee-4776-b915-b5744ac73a13"
    assert org2 == "16bc9f86-430b-4278-893c-24f382255e58"

    fid3, org3 = art.parse_artifact_ref(
        "https://claude.ai/chat/e829334a-12e1-4cf6-a3c4-8aa2bfcc30fd"
        "?artifact=03684313-ca04-4bc1-bc47-d8460e51013b&frame_layout=expanded"
    )
    assert fid3 == "03684313-ca04-4bc1-bc47-d8460e51013b"
    assert org3 == ""

    fid4, _ = art.parse_artifact_ref("03684313-CA04-4BC1-BC47-D8460E51013B")
    assert fid4 == "03684313-ca04-4bc1-bc47-d8460e51013b"

    fid5, _ = art.parse_artifact_ref("1RQPLGDWF3VJSxMwK89UJe")
    assert fid5 == "03684313-ca04-4bc1-bc47-d8460e51013b"


@pytest.mark.parametrize("bad", ["", "   ", "https://claude.ai/artifacts", "not-base58-0OIl"])
def test_parse_artifact_ref_rejects_invalid(bad: str):
    with pytest.raises(ValueError):
        art.parse_artifact_ref(bad)


def test_session_vault_roundtrip_and_mode(tmp_path: Path):
    vault = art.SessionVault(tmp_path)
    assert vault.get("1") is None
    vault.put("1", session_key="sk-1", email="a@example.com", account_uuid="acc-1", org_uuid="org-1")
    entry = vault.get("1")
    assert entry is not None and entry["email"] == "a@example.com"
    assert vault.slot_numbers() == {"1"}
    if sys.platform != "win32":
        mode = stat.S_IMODE((tmp_path / art.SESSIONS_FILENAME).stat().st_mode)
        assert mode == 0o600
    assert vault.delete("1") is True
    assert vault.delete("1") is False
    assert vault.get("1") is None


def test_load_artifact_accounts_reads_legacy_web_vault_fallback(tmp_path: Path):
    future = time.time() + 10 * 86400
    (tmp_path / "sequence.json").write_text(
        json.dumps({"accounts": {"1": {"email": "a@example.com", "organizationUuid": "11111111-1111-1111-1111-111111111111"}}}),
        encoding="utf-8",
    )
    (tmp_path / art.LEGACY_WEB_VAULT_FILENAME).write_text(
        json.dumps({
            "1": {
                "email": "a@example.com",
                "accountUuid": "acc-1",
                "cookies": [
                    {"name": "sessionKey", "value": "sk-from-web", "expires": future},
                    {"name": "lastActiveOrg", "value": "11111111-1111-1111-1111-111111111111"},
                ],
            }
        }),
        encoding="utf-8",
    )
    accounts = art.load_artifact_accounts(tmp_path)
    assert len(accounts) == 1
    assert accounts[0].has_session() is True
    assert accounts[0].session_key == "sk-from-web"
    assert 9.0 < (accounts[0].days_until_expiry() or 0) <= 10.1


def test_add_session_key_verifies_and_matches_slot(tmp_path: Path):
    (tmp_path / "sequence.json").write_text(
        json.dumps({"accounts": {"2": {"email": "b@example.com", "organizationUuid": "22222222-2222-2222-2222-222222222222"}}}),
        encoding="utf-8",
    )

    def fake_req(method, url, sk, **kw):
        assert method == "GET" and url.endswith("/api/account")
        if sk == "sk-good":
            return 200, {"uuid": "acc-2", "email_address": "b@example.com"}
        return 401, {"error": "unauthorized"}

    slot, email = art.add_session_key(tmp_path, "sessionKey=sk-good", requester=fake_req)
    assert (slot, email) == ("2", "b@example.com")
    stored = art.SessionVault(tmp_path).get("2")
    assert stored is not None and stored["sessionKey"] == "sk-good"

    bad_slot, reason = art.add_session_key(tmp_path, "sk-bad", requester=fake_req)
    assert bad_slot is None and "rejected" in reason


def test_artifact_sync_state_roundtrip_and_new_account_invalidation(tmp_path: Path):
    st = art.ArtifactSyncState(tmp_path)
    fid = "03684313-ca04-4bc1-bc47-d8460e51013b"
    assert not st.is_covered(fid, ["b@example.com"])

    st.record(fid, owner_slot="1", title="Demo", accepted_emails={"b@example.com"})
    if sys.platform != "win32":
        mode = stat.S_IMODE((tmp_path / art.STATE_FILENAME).stat().st_mode)
        assert mode == 0o600

    assert st.is_covered(fid, ["B@EXAMPLE.COM"])
    assert not st.is_covered(fid, ["b@example.com", "c@example.com"])

    st.record(fid, owner_slot="1", title="Demo", accepted_emails={"c@example.com"})
    assert st.is_covered(fid, ["b@example.com", "c@example.com"])
    assert st.summary()["count"] == 1


def test_artifact_sync_state_tolerates_corrupt_json(tmp_path: Path):
    (tmp_path / art.STATE_FILENAME).write_text("{corrupt", encoding="utf-8")
    st = art.ArtifactSyncState(tmp_path)
    assert st.summary() == {"count": 0, "lastUpdatedAt": 0}
    assert st.synced_emails("03684313-ca04-4bc1-bc47-d8460e51013b") == set()


def test_artifact_settings_roundtrip_and_recognized_by_config(tmp_path: Path):
    assert load_artifact_settings(tmp_path).enabled is False
    set_artifact_sync_enabled(tmp_path, True)
    assert load_artifact_settings(tmp_path).enabled is True
    assert unrecognized_keys(tmp_path) == []

    set_artifact_sync_enabled(tmp_path, False)
    assert load_artifact_settings(tmp_path).enabled is False


def test_share_artifact_invites_and_accepts_with_progress(tmp_path: Path):
    future = time.time() + 20 * 86400
    _seed_store(
        tmp_path,
        [
            ("1", "a@example.com", "11111111-1111-1111-1111-111111111111", future),
            ("2", "b@example.com", "22222222-2222-2222-2222-222222222222", future),
            ("3", "c@example.com", "33333333-3333-3333-3333-333333333333", future),
        ],
    )
    events: list[art.ProgressEvent] = []
    calls: list[tuple[str, str, str]] = []

    def fake_req(method, url, sk, *, body=None, timeout=15.0):
        calls.append((method, sk, url))
        if method == "GET" and "/api/frame/invites/" in url:
            assert sk == "sk-ant-sid01-1"
            return 200, {
                "invites": [
                    {"id": "inv-c", "email": "c@example.com", "status": "accepted", "role": "editor"},
                ]
            }
        if method == "POST" and "/api/frame/invite/" in url:
            assert sk == "sk-ant-sid01-1"
            assert body == {"email": "b@example.com", "role": "editor"}
            return 200, {
                "created": True,
                "invite": {"id": "inv-b-1", "email": "b@example.com", "status": "pending", "role": "editor"},
            }
        if method == "POST" and "/api/frame/invitation/inv-b-1/accept" in url:
            assert sk == "sk-ant-sid01-2"
            assert "org=22222222-2222-2222-2222-222222222222" in url
            return 200, {"slug": "03684313-ca04-4bc1-bc47-d8460e51013b", "role": "editor"}
        pytest.fail(f"unexpected request: {method} {url}")

    rep = art.share_artifact(
        tmp_path,
        "https://claude.ai/artifact/1RQPLGDWF3VJSxMwK89UJe#page-5634c5cea0db",
        owner_ref="1",
        on_progress=events.append,
        requester=fake_req,
    )
    assert rep.ok
    assert rep.invited == 1
    assert rep.accepted == 1
    assert rep.already_synced == 1
    assert [(e.phase, e.account, e.current, e.total) for e in events] == [
        ("invite", "a@example.com", 0, 1),
        ("invite", "a@example.com", 1, 1),
        ("accept", "b@example.com", 0, 1),
        ("accept", "b@example.com", 1, 1),
    ]
    st = art.ArtifactSyncState(tmp_path)
    assert st.is_covered("03684313-ca04-4bc1-bc47-d8460e51013b", ["b@example.com", "c@example.com"])


def test_sync_artifacts_streams_progress_and_skips_cached_on_second_pass(tmp_path: Path):
    future = time.time() + 20 * 86400
    _seed_store(
        tmp_path,
        [
            ("1", "a@example.com", "11111111-1111-1111-1111-111111111111", future),
            ("2", "b@example.com", "22222222-2222-2222-2222-222222222222", future),
        ],
    )
    events: list[art.ProgressEvent] = []
    invite_gets = 0

    def fake_req(method, url, sk, *, body=None, timeout=15.0):
        nonlocal invite_gets
        if method == "GET" and "/api/frame/artifacts?" in url:
            return 200, {
                "artifacts": [
                    {"id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "title": "A1", "rel": "mine"},
                    {"id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "title": "A2", "rel": "mine"},
                    {"id": "cccccccc-cccc-cccc-cccc-cccccccccccc", "title": "Other", "rel": "shared"},
                ]
            }
        if method == "GET" and "/api/frame/invites/" in url:
            invite_gets += 1
            return 200, {"invites": []}
        if method == "POST" and "/api/frame/invite/" in url:
            fid = url.split("/invite/")[1].split("?")[0]
            return 200, {"created": True, "invite": {"id": f"inv-{fid[:4]}", "email": body["email"], "status": "pending", "role": "editor"}}
        if method == "POST" and "/accept?" in url:
            return 200, {"role": "editor"}
        pytest.fail(f"unexpected request: {method} {url}")

    rep1 = art.sync_artifacts(tmp_path, owner_ref="1", on_progress=events.append, requester=fake_req)
    assert rep1.ok
    assert rep1.accepted == 2
    assert invite_gets == 2
    assert [(e.phase, e.current, e.total, e.label) for e in events] == [
        ("list", 0, 0, "fetching artifacts"),
        ("invite", 0, 2, ""),
        ("invite", 1, 2, "A1"),
        ("invite", 2, 2, "A2"),
        ("accept", 0, 2, ""),
        ("accept", 1, 2, "A1"),
        ("accept", 2, 2, "A2"),
    ]

    rep2 = art.sync_artifacts(tmp_path, owner_ref="1", requester=fake_req)
    assert rep2.ok
    assert rep2.artifacts_checked == 0
    assert invite_gets == 2  # No redundant /invites calls for cached artifacts!


def test_sync_artifacts_reports_expired_session_without_crashing(tmp_path: Path):
    future = time.time() + 20 * 86400
    _seed_store(
        tmp_path,
        [
            ("1", "a@example.com", "11111111-1111-1111-1111-111111111111", future),
            ("2", "b@example.com", "22222222-2222-2222-2222-222222222222", future),
        ],
    )

    def fake_req(method, url, sk, *, body=None, timeout=15.0):
        if sk == "sk-ant-sid01-2":
            return 401, {"error": "expired"}
        if "/api/frame/artifacts?" in url:
            return 200, {"artifacts": [{"id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "title": "A1", "rel": "mine"}]}
        if "/api/frame/invites/" in url:
            return 200, {"invites": []}
        if "/api/frame/invite/" in url:
            return 200, {"created": True, "invite": {"id": "inv-1", "email": body["email"], "status": "pending", "role": "editor"}}
        pytest.fail(f"unexpected request: {method} {url}")

    rep = art.sync_artifacts(tmp_path, owner_ref="1", requester=fake_req)
    assert not rep.ok
    assert rep.expired_accounts == ["b@example.com"]
    assert rep.accepted == 0


def test_share_artifact_auto_detects_owner(tmp_path: Path):
    future = time.time() + 20 * 86400
    _seed_store(
        tmp_path,
        [
            ("1", "a@example.com", "11111111-1111-1111-1111-111111111111", future),
            ("2", "b@example.com", "22222222-2222-2222-2222-222222222222", future),
        ],
    )

    def fake_req(method, url, sk, *, body=None, timeout=15.0):
        if method == "GET" and "/api/frame/invites/" in url:
            return (200, {"invites": []}) if sk == "sk-ant-sid01-1" else (403, {})
        if method == "POST" and "/api/frame/invite/" in url:
            return 200, {"created": True, "invite": {"id": "inv-1", "email": "b@example.com", "status": "pending", "role": "editor"}}
        if method == "POST" and "/accept?" in url:
            return 200, {"role": "editor"}
        pytest.fail(f"unexpected request: {method} {url}")

    rep = art.share_artifact(tmp_path, "1RQPLGDWF3VJSxMwK89UJe", active_slot="2", requester=fake_req)
    assert rep.ok
    assert rep.accepted == 1


def test_artifact_runner_switch_and_periodic_hooks(tmp_path: Path, monkeypatch):
    called: list[str] = []
    monkeypatch.setattr(art, "sync_after_switch", lambda root, settings, slot, **kw: called.append(slot))
    # Simulate a freshly booted machine (monotonic < PERIODIC_SYNC_INTERVAL_S).
    monkeypatch.setattr(art.time, "monotonic", lambda: 10.0)

    runner = art.ArtifactSyncRunner(art.ArtifactSyncSettings(enabled=True), tmp_path)
    runner.follow_switch(outgoing_account="1", target_account="2")
    assert called == ["1"]

    called.clear()
    runner.follow_switch(outgoing_account="2", target_account="2")
    assert called == []

    runner.background = True
    runner.maybe_sync_artifacts("3")
    assert runner.wait_idle(timeout=5.0)
    assert called == ["3"]

    called.clear()
    runner.maybe_sync_artifacts("3")
    assert runner.wait_idle(timeout=5.0)
    assert called == []

    disabled = art.ArtifactSyncRunner(art.ArtifactSyncSettings(enabled=False), tmp_path)
    disabled.follow_switch(outgoing_account="1", target_account="2")
    assert called == []
