"""Cross-account Claude Artifact sharing & auto-acceptance (opt-in, pure HTTPS).

Artifacts on claude.ai default to private for the account that created them.
When claude-swap rotates between accounts mid-session, the incoming account
cannot edit artifacts created by the outgoing account unless invited as an
editor.

How it works (verified live against api.anthropic.com)
------------------------------------------------------
``https://api.anthropic.com/api/frame/*`` serves the artifact sharing endpoints
over plain HTTPS using each account's ``sessionKey`` cookie (plus
``X-Frame-CP: go`` and ``Origin: https://claude.ai`` for write requests):

1. ``GET /api/account`` verifies a registered ``sessionKey`` and returns the
   account's ``email_address`` and ``uuid``.
2. ``GET /api/frame/artifacts?rel=all&empty=exclude&limit=N&org=<org>&sort=last_viewed``
   lists recent artifacts; filtering ``rel == "mine"`` selects owned ones.
3. ``GET /api/frame/invites/<uuid>?org=<org>`` inspects existing collaborators
   (returning 403/404 when the caller is not the owner).
4. ``POST /api/frame/invite/<uuid>?org=<org>`` (``{"email", "role": "editor"}``;
   ``notify: false`` is rejected with HTTP 409 ``invite_notify_required``)
   creates an invitation and returns ``invite.id`` directly — no email polling
   is needed. Existing accepted non-editor collaborators are upgraded via
   ``PATCH /api/frame/invite/<uuid>/<inviteId>?org=<org>``.
5. ``POST /api/frame/invitation/<inviteId>/accept?org=<targetOrg>`` accepts the
   invitation under the target account's ``sessionKey``, binding the artifact
   explicitly to that slot's ``organizationUuid`` (including multi-org
   accounts).

Session keys live in ``<backup_root>/artifact_sessions.json`` (chmod 0600),
registered with ``cswap artifact add-session``. If an account has no entry
there yet, ``SessionVault`` also checks ``chrome_web_sessions.json`` if present
on disk. Cross-platform (macOS, Linux, Windows); zero browser dependencies;
never imports ``switcher.py``; never prints or logs session keys.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from claude_swap.fsutil import atomic_write_text

_logger = logging.getLogger("claude-swap")

API_BASE = "https://api.anthropic.com"
CLAUDE_ORIGIN = "https://claude.ai"

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE58_INDEX = {ch: idx for idx, ch in enumerate(BASE58_ALPHABET)}
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_ARTIFACT_PATH_RE = re.compile(r"/artifact/([1-9A-HJ-NP-Za-km-z]{16,32})")

FRAME_HEADERS = {
    "X-Frame-CP": "go",
    "X-Frame-Platform": "web",
    "X-Frame-Surface": "standalone",
    "Origin": CLAUDE_ORIGIN,
    "Referer": f"{CLAUDE_ORIGIN}/",
}
VALID_ROLES = ("editor", "commenter", "reader")
DEFAULT_ROLE = "editor"
DEFAULT_SYNC_LIMIT = 48
SWITCH_SYNC_LIMIT = 10
PERIODIC_SYNC_INTERVAL_S = 180.0
SESSIONS_FILENAME = "artifact_sessions.json"
LEGACY_WEB_VAULT_FILENAME = "chrome_web_sessions.json"
STATE_FILENAME = "artifact_sync_state.json"


# --------------------------------------------------------------------------- #
# Settings & progress value objects
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ArtifactSyncSettings:
    """The ``artifacts`` section of ``settings.json``."""

    enabled: bool = False


@dataclass(frozen=True)
class ProgressEvent:
    """One incremental progress update emitted during ``sync`` or ``share``."""

    phase: str        # "list" | "invite" | "accept" | "probe"
    account: str      # email currently being operated on
    current: int      # completed items in this phase
    total: int        # total items in this phase (0 = indeterminate)
    label: str = ""   # artifact title or short UUID
    detail: str = ""  # short outcome hint (e.g. "invited", "accepted", "synced")


ProgressCallback = Callable[[ProgressEvent], None]
Requester = Callable[..., tuple[int, dict | None]]


def _emit(cb: ProgressCallback | None, event: ProgressEvent) -> None:
    if cb is None:
        return
    try:
        cb(event)
    except Exception:  # noqa: BLE001
        pass


# --------------------------------------------------------------------------- #
# Pure HTTPS transport (stdlib urllib.request)
# --------------------------------------------------------------------------- #
def _http_request(
    method: str,
    url: str,
    session_key: str,
    *,
    body: dict | None = None,
    timeout: float = 15.0,
) -> tuple[int, dict | None]:
    """Perform one JSON HTTPS request authenticated by ``Cookie: sessionKey=...``."""
    headers = {
        **FRAME_HEADERS,
        "Cookie": f"sessionKey={session_key}",
        "Accept": "application/json",
    }
    data: bytes | None = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode("utf-8")

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            try:
                parsed = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                parsed = None
            return resp.status, parsed if isinstance(parsed, dict) else None
    except urllib.error.HTTPError as exc:
        raw = ""
        try:
            raw = exc.read().decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass
        try:
            parsed = json.loads(raw) if raw else None
        except json.JSONDecodeError:
            parsed = {"error": raw.strip()[:200]} if raw.strip() else None
        return exc.code, parsed if isinstance(parsed, dict) else None
    except Exception as exc:  # noqa: BLE001
        return 0, {"error": str(exc)}


# --------------------------------------------------------------------------- #
# Slug / URL parsing
# --------------------------------------------------------------------------- #
def decode_artifact_slug(slug: str) -> str:
    """Decode a claude.ai ``/artifact/<base58>`` slug into its 128-bit UUID."""
    s = slug.strip()
    if not s:
        raise ValueError("empty artifact slug")
    n = 0
    for ch in s:
        digit = _BASE58_INDEX.get(ch)
        if digit is None:
            raise ValueError(f"invalid Base58 character {ch!r} in artifact slug")
        n = n * 58 + digit
    if n < 0 or n >= (1 << 128):
        raise ValueError(f"artifact slug out of 128-bit UUID range: {slug!r}")
    return str(uuid.UUID(int=n))


def encode_artifact_slug(frame_uuid: str) -> str:
    """Encode a 128-bit UUID into the 22-char Base58 slug used in ``/artifact/<slug>``."""
    n = uuid.UUID(frame_uuid).int
    if n == 0:
        return BASE58_ALPHABET[0] * 22
    chars: list[str] = []
    while n > 0:
        n, rem = divmod(n, 58)
        chars.append(BASE58_ALPHABET[rem])
    return "".join(reversed(chars)).rjust(22, BASE58_ALPHABET[0])


def parse_artifact_ref(raw: str) -> tuple[str, str]:
    """Parse an artifact URL, UUID, or Base58 slug into ``(frame_uuid, org_hint)``."""
    text = (raw or "").strip()
    if not text:
        raise ValueError("artifact reference is empty")

    if _UUID_RE.match(text):
        return text.lower(), ""

    if "://" in text or text.startswith("/"):
        parsed = urllib.parse.urlparse(text)
        qs = urllib.parse.parse_qs(parsed.query)
        org_hint = (qs.get("org") or [""])[0].strip().lower()
        if org_hint and not _UUID_RE.match(org_hint):
            org_hint = ""
        art_param = (qs.get("artifact") or [""])[0].strip()
        if art_param and _UUID_RE.match(art_param):
            return art_param.lower(), org_hint
        m = _ARTIFACT_PATH_RE.search(parsed.path)
        if m:
            return decode_artifact_slug(m.group(1)), org_hint
        raise ValueError(f"could not find an artifact ID in URL: {raw!r}")

    return decode_artifact_slug(text), ""


# --------------------------------------------------------------------------- #
# SessionVault: per-slot claude.ai sessionKey storage (chmod 0600)
# --------------------------------------------------------------------------- #
class SessionVault:
    """Stores each slot's ``sessionKey`` cookie at chmod 0600.

    Primary store: ``<backup_root>/artifact_sessions.json``.
    Schema: ``{"<slot>": {"sessionKey", "email", "accountUuid", "orgUuid",
    "capturedAt", "expiresAt"}}``.
    """

    def __init__(self, backup_root: Path):
        self._root = Path(backup_root)
        self._path = self._root / SESSIONS_FILENAME

    def _read(self) -> dict:
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def _write(self, data: dict) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(self._path, json.dumps(data, indent=2) + "\n")
        if sys.platform != "win32":
            try:
                os.chmod(self._path, 0o600)
            except OSError:
                pass

    def get(self, slot: str) -> dict | None:
        entry = self._read().get(str(slot))
        if isinstance(entry, dict) and entry.get("sessionKey"):
            return entry
        return None

    def put(
        self,
        slot: str,
        *,
        session_key: str,
        email: str,
        account_uuid: str = "",
        org_uuid: str = "",
        expires_at: float = 0.0,
    ) -> None:
        data = self._read()
        data[str(slot)] = {
            "sessionKey": session_key,
            "email": email,
            "accountUuid": account_uuid,
            "orgUuid": org_uuid,
            "capturedAt": int(time.time() * 1000),
            "expiresAt": float(expires_at or 0.0),
        }
        self._write(data)

    def delete(self, slot: str) -> bool:
        data = self._read()
        if data.pop(str(slot), None) is not None:
            self._write(data)
            return True
        return False

    def slot_numbers(self) -> set[str]:
        return {k for k, v in self._read().items() if isinstance(v, dict) and v.get("sessionKey")}


def _read_optional_web_vault(backup_root: Path) -> dict:
    """Read-only fallback for users who already have ``chrome_web_sessions.json``."""
    try:
        data = json.loads((Path(backup_root) / LEGACY_WEB_VAULT_FILENAME).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


@dataclass(frozen=True)
class ArtifactAccount:
    """One managed cswap slot paired with any stored ``sessionKey``."""

    slot: str
    email: str
    org_uuid: str
    account_uuid: str = ""
    session_key: str = ""
    captured_at: int = 0
    session_expires_at: float = 0.0  # epoch seconds (0 = unknown)

    def has_session(self) -> bool:
        return bool(self.email and self.org_uuid and self.session_key)

    def days_until_expiry(self, now: float | None = None) -> float | None:
        if self.session_expires_at <= 0:
            return None
        cur = time.time() if now is None else now
        return (self.session_expires_at - cur) / 86400.0


def load_artifact_accounts(backup_root: Path) -> list[ArtifactAccount]:
    """All managed slots paired with their stored claude.ai session key."""
    root = Path(backup_root)
    seq_accounts: dict = {}
    try:
        seq = json.loads((root / "sequence.json").read_text(encoding="utf-8"))
        if isinstance(seq.get("accounts"), dict):
            seq_accounts = seq["accounts"]
    except (OSError, json.JSONDecodeError):
        pass

    vault = SessionVault(root)
    fallback = _read_optional_web_vault(root)
    slots = sorted(
        set(seq_accounts.keys()) | vault.slot_numbers() | set(fallback.keys()),
        key=lambda n: (0, int(n)) if str(n).isdigit() else (1, str(n)),
    )

    out: list[ArtifactAccount] = []
    for num in slots:
        s_entry = seq_accounts.get(num) or {}
        v_entry = vault.get(num)
        if v_entry is not None:
            session_key = str(v_entry.get("sessionKey", "")).strip()
            email = str(v_entry.get("email") or s_entry.get("email") or "").strip()
            org_uuid = str(v_entry.get("orgUuid") or s_entry.get("organizationUuid") or "").strip().lower()
            account_uuid = str(v_entry.get("accountUuid") or s_entry.get("accountUuid") or "").strip()
            captured_at = int(v_entry.get("capturedAt", 0) or 0)
            expires_at = float(v_entry.get("expiresAt", 0) or 0)
        else:
            f_entry = fallback.get(num) if isinstance(fallback.get(num), dict) else {}
            cookies = f_entry.get("cookies") or []
            session_key = next(
                (str(c.get("value", "")).strip() for c in cookies if isinstance(c, dict) and c.get("name") == "sessionKey"),
                "",
            )
            last_org = next(
                (str(c.get("value", "")).strip() for c in cookies if isinstance(c, dict) and c.get("name") == "lastActiveOrg"),
                "",
            )
            expires_at = next(
                (float(c.get("expires", 0) or 0) for c in cookies if isinstance(c, dict) and c.get("name") == "sessionKey"),
                0.0,
            )
            email = str(f_entry.get("email") or s_entry.get("email") or "").strip()
            org_uuid = str(last_org or s_entry.get("organizationUuid") or "").strip().lower()
            account_uuid = str(f_entry.get("accountUuid") or s_entry.get("accountUuid") or "").strip()
            captured_at = int(f_entry.get("capturedAt", 0) or 0)

        out.append(
            ArtifactAccount(
                slot=str(num),
                email=email,
                org_uuid=org_uuid,
                account_uuid=account_uuid,
                session_key=session_key,
                captured_at=captured_at,
                session_expires_at=expires_at,
            )
        )
    return out


def resolve_artifact_account(accounts: list[ArtifactAccount], ref: str) -> ArtifactAccount | None:
    """Match a slot number, email (case-insensitive), or org UUID."""
    key = (ref or "").strip()
    if not key:
        return None
    low = key.lower()
    for acc in accounts:
        if acc.slot == key or acc.email.lower() == low or acc.org_uuid.lower() == low:
            return acc
    return None


def add_session_key(
    backup_root: Path,
    session_key: str,
    *,
    slot_ref: str | None = None,
    requester: Requester = _http_request,
) -> tuple[str | None, str]:
    """Verify a ``sessionKey`` via ``GET /api/account`` and store it for its slot.

    Returns ``(slot, email)`` on success, or ``(None, reason)`` on failure.
    """
    sk = (session_key or "").strip()
    if sk.lower().startswith("sessionkey="):
        sk = sk.split("=", 1)[1].strip()
    if not sk:
        return None, "sessionKey is empty"

    status, data = requester("GET", f"{API_BASE}/api/account", sk)
    if status == 401 or status == 403:
        return None, "sessionKey was rejected (expired or invalid)"
    if status != 200 or not isinstance(data, dict) or not data.get("email_address"):
        return None, f"could not verify sessionKey (HTTP {status})"

    email = str(data["email_address"]).strip()
    acc_uuid = str(data.get("uuid", "")).strip()
    accounts = load_artifact_accounts(backup_root)

    if slot_ref:
        target = resolve_artifact_account(accounts, slot_ref)
        if target is None:
            return None, f"no managed account matches {slot_ref!r} (see `cswap list`)"
        if target.email and target.email.lower() != email.lower():
            return None, f"sessionKey belongs to {email}, not {target.email}"
        slot = target.slot
        org_uuid = target.org_uuid
    else:
        hits = [a for a in accounts if a.email.lower() == email.lower()]
        if len(hits) != 1:
            return None, f"no single managed account matches {email} (pass --account <slot>)"
        slot = hits[0].slot
        org_uuid = hits[0].org_uuid

    SessionVault(backup_root).put(
        slot,
        session_key=sk,
        email=email,
        account_uuid=acc_uuid,
        org_uuid=org_uuid,
    )
    return slot, email


# --------------------------------------------------------------------------- #
# Persistent sync state (idempotency cache; chmod 0600)
# --------------------------------------------------------------------------- #
class ArtifactSyncState:
    """Tracks which ``frame_uuid``s have already been shared with which emails."""

    def __init__(self, backup_root: Path):
        self._path = Path(backup_root) / STATE_FILENAME

    def _read(self) -> dict:
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def _write(self, data: dict) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(self._path, json.dumps(data, indent=2) + "\n")
        if sys.platform != "win32":
            try:
                os.chmod(self._path, 0o600)
            except OSError:
                pass

    def synced_emails(self, frame_uuid: str, role: str = DEFAULT_ROLE) -> set[str]:
        entry = (self._read().get("synced") or {}).get(frame_uuid.lower())
        if not isinstance(entry, dict):
            return set()
        if role == DEFAULT_ROLE:
            raw = entry.get("editors") or []
        else:
            raw = (entry.get("roles") or {}).get(role) or []
        return {str(e).lower() for e in raw if isinstance(e, str)}

    def is_covered(self, frame_uuid: str, target_emails: list[str], role: str = DEFAULT_ROLE) -> bool:
        if not target_emails:
            return True
        known = self.synced_emails(frame_uuid, role=role)
        return all(e.lower() in known for e in target_emails)

    def record(
        self,
        frame_uuid: str,
        *,
        owner_slot: str,
        title: str,
        accepted_emails: set[str],
        role: str = DEFAULT_ROLE,
    ) -> None:
        data = self._read()
        synced = data.setdefault("synced", {})
        fid = frame_uuid.lower()
        prev = synced.get(fid) if isinstance(synced.get(fid), dict) else {}
        if role == DEFAULT_ROLE:
            merged = sorted({*(e.lower() for e in prev.get("editors") or []), *(e.lower() for e in accepted_emails)})
            prev["editors"] = merged
        else:
            roles_map = prev.get("roles") if isinstance(prev.get("roles"), dict) else {}
            prev_r = roles_map.get(role) or []
            roles_map[role] = sorted({*(e.lower() for e in prev_r), *(e.lower() for e in accepted_emails)})
            prev["roles"] = roles_map
        prev["ownerSlot"] = str(owner_slot)
        if title:
            prev["title"] = title
        prev["updatedAt"] = int(time.time() * 1000)
        synced[fid] = prev
        self._write(data)

    def summary(self) -> dict:
        synced = self._read().get("synced")
        if not isinstance(synced, dict):
            return {"count": 0, "lastUpdatedAt": 0}
        last = max((int(v.get("updatedAt", 0) or 0) for v in synced.values() if isinstance(v, dict)), default=0)
        return {"count": len(synced), "lastUpdatedAt": last}


# --------------------------------------------------------------------------- #
# Result objects & high-level orchestrators
# --------------------------------------------------------------------------- #
@dataclass
class SyncReport:
    """Summary of one artifact sync or share pass."""

    artifacts_checked: int = 0
    invited: int = 0
    accepted: int = 0
    upgraded: int = 0
    already_synced: int = 0
    expired_accounts: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    details: list[dict] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors and not self.expired_accounts


def _short_label(title: str, artifact_id: str) -> str:
    return title.strip() if title and title.strip() else artifact_id[:8]


def _sync_owner_pass(
    owner: ArtifactAccount,
    targets: list[ArtifactAccount],
    state: ArtifactSyncState,
    *,
    role: str = DEFAULT_ROLE,
    limit: int = DEFAULT_SYNC_LIMIT,
    force: bool = False,
    only_ids: list[str] | None = None,
    on_progress: ProgressCallback | None = None,
    requester: Requester = _http_request,
) -> SyncReport:
    """Run one owner → targets invite-and-accept pass over pure HTTPS."""
    report = SyncReport()
    usable_targets = [
        t for t in targets
        if t.has_session() and t.email.lower() != owner.email.lower()
    ]
    if not owner.has_session() or not usable_targets:
        return report

    target_emails = [t.email.lower() for t in usable_targets]
    target_by_email = {t.email.lower(): t for t in usable_targets}
    org_q = urllib.parse.quote(owner.org_uuid)

    skip_ids: set[str] = set()
    if not force and not only_ids:
        raw_synced = state._read().get("synced") or {}
        for fid, entry in raw_synced.items():
            if not isinstance(entry, dict):
                continue
            if str(entry.get("ownerSlot", "")) == owner.slot and state.is_covered(fid, target_emails, role=role):
                skip_ids.add(fid.lower())

    if only_ids:
        candidates = [{"id": fid.lower(), "title": ""} for fid in only_ids]
    else:
        _emit(on_progress, ProgressEvent("list", owner.email, 0, 0, label="fetching artifacts"))
        list_url = (
            f"{API_BASE}/api/frame/artifacts?rel=all&empty=exclude"
            f"&limit={int(limit)}&org={org_q}&sort=last_viewed"
        )
        status, data = requester("GET", list_url, owner.session_key)
        if status == 401:
            report.expired_accounts.append(owner.email)
            return report
        if status != 200 or not isinstance(data, dict):
            report.errors.append(f"owner {owner.email}: list failed (HTTP {status})")
            return report
        raw_items = data.get("artifacts") or data.get("items") or []
        candidates = [
            {"id": str(it["id"]).lower(), "title": str(it.get("title") or "")}
            for it in raw_items
            if isinstance(it, dict)
            and it.get("rel") == "mine"
            and isinstance(it.get("id"), str)
            and str(it["id"]).lower() not in skip_ids
        ]

    pending_by_email: dict[str, list[dict]] = {}
    total_arts = len(candidates)
    if total_arts > 0:
        _emit(on_progress, ProgressEvent("invite", owner.email, 0, total_arts))

    for idx, art in enumerate(candidates, start=1):
        fid = art["id"]
        title = art["title"]
        label = _short_label(title, fid)
        report.artifacts_checked += 1

        inv_url = f"{API_BASE}/api/frame/invites/{urllib.parse.quote(fid)}?org={org_q}"
        s0, d0 = requester("GET", inv_url, owner.session_key)
        if s0 == 401:
            report.expired_accounts.append(owner.email)
            return report
        if s0 in (403, 404):
            _emit(on_progress, ProgressEvent("invite", owner.email, idx, total_arts, label=label, detail="not owner"))
            continue
        if s0 != 200 or not isinstance(d0, dict):
            report.errors.append(f"{fid} → {owner.email} [list_invites HTTP {s0}]")
            _emit(on_progress, ProgressEvent("invite", owner.email, idx, total_arts, label=label, detail="error"))
            continue

        by_email: dict[str, dict] = {}
        for inv in d0.get("invites") or []:
            if isinstance(inv, dict) and isinstance(inv.get("email"), str):
                by_email[inv["email"].lower()] = inv

        covered_here: set[str] = set()
        invited_here = False
        for email in target_emails:
            prev = by_email.get(email)
            if prev and prev.get("status") == "accepted":
                if prev.get("role") == role or prev.get("effectiveRole") == role:
                    covered_here.add(email)
                    continue
                patch_url = (
                    f"{API_BASE}/api/frame/invite/{urllib.parse.quote(fid)}/"
                    f"{urllib.parse.quote(str(prev.get('id', '')))}?org={org_q}"
                )
                sp, _ = requester("PATCH", patch_url, owner.session_key, body={"role": role})
                if 200 <= sp < 300:
                    report.upgraded += 1
                    covered_here.add(email)
                    report.details.append({
                        "artifactId": fid,
                        "title": title,
                        "from": owner.email,
                        "to": email,
                        "action": "upgraded",
                        "role": role,
                    })
                else:
                    report.errors.append(f"{fid} → {email} [patch_role HTTP {sp}]")
                continue

            if prev and prev.get("status") == "pending" and prev.get("id"):
                if prev.get("role") != role:
                    patch_url = (
                        f"{API_BASE}/api/frame/invite/{urllib.parse.quote(fid)}/"
                        f"{urllib.parse.quote(str(prev['id']))}?org={org_q}"
                    )
                    requester("PATCH", patch_url, owner.session_key, body={"role": role})
                pending_by_email.setdefault(email, []).append({
                    "artifactId": fid,
                    "title": title,
                    "inviteId": str(prev["id"]),
                })
                invited_here = True
                continue

            post_url = f"{API_BASE}/api/frame/invite/{urllib.parse.quote(fid)}?org={org_q}"
            s1, d1 = requester("POST", post_url, owner.session_key, body={"email": email, "role": role})
            if s1 == 401:
                report.expired_accounts.append(owner.email)
                return report
            if not (200 <= s1 < 300) or not isinstance(d1, dict):
                reason = d1.get("reason", "") if isinstance(d1, dict) else ""
                report.errors.append(f"{fid} → {email} [create_invite HTTP {s1} {reason}]".strip())
                continue
            if d1.get("shared_with_member"):
                covered_here.add(email)
                continue
            inv_obj = d1.get("invite") if isinstance(d1.get("invite"), dict) else None
            if inv_obj and inv_obj.get("status") == "accepted":
                covered_here.add(email)
            elif inv_obj and inv_obj.get("id"):
                if d1.get("created"):
                    report.invited += 1
                pending_by_email.setdefault(email, []).append({
                    "artifactId": fid,
                    "title": title,
                    "inviteId": str(inv_obj["id"]),
                })
                invited_here = True
            else:
                report.errors.append(f"{fid} → {email} [create_invite unexpected response]")

        if covered_here:
            state.record(fid, owner_slot=owner.slot, title=title, accepted_emails=covered_here, role=role)
            report.already_synced += len(covered_here)

        detail = "invited" if invited_here else "synced"
        _emit(on_progress, ProgressEvent("invite", owner.email, idx, total_arts, label=label, detail=detail))

    for email, items in pending_by_email.items():
        target = target_by_email[email]
        t_org_q = urllib.parse.quote(target.org_uuid)
        total_acc = len(items)
        _emit(on_progress, ProgressEvent("accept", target.email, 0, total_acc))

        for idx, item in enumerate(items, start=1):
            fid = item["artifactId"]
            title = item["title"]
            label = _short_label(title, fid)
            acc_url = (
                f"{API_BASE}/api/frame/invitation/"
                f"{urllib.parse.quote(item['inviteId'])}/accept?org={t_org_q}"
            )
            sa, da = requester("POST", acc_url, target.session_key)
            if sa == 401:
                report.expired_accounts.append(target.email)
                break
            if 200 <= sa < 300:
                state.record(fid, owner_slot=owner.slot, title=title, accepted_emails={email}, role=role)
                report.accepted += 1
                report.details.append({
                    "artifactId": fid,
                    "title": title,
                    "from": owner.email,
                    "to": target.email,
                    "action": "accepted",
                    "role": (da.get("role") if isinstance(da, dict) else None) or role,
                })
                _emit(on_progress, ProgressEvent("accept", target.email, idx, total_acc, label=label, detail="accepted"))
            else:
                reason = da.get("reason", "") if isinstance(da, dict) else ""
                report.errors.append(f"accept {fid} as {target.email} [HTTP {sa} {reason}]".strip())
                _emit(on_progress, ProgressEvent("accept", target.email, idx, total_acc, label=label, detail="error"))

    return report


def _merge_reports(reports: list[SyncReport]) -> SyncReport:
    merged = SyncReport()
    for r in reports:
        merged.artifacts_checked += r.artifacts_checked
        merged.invited += r.invited
        merged.accepted += r.accepted
        merged.upgraded += r.upgraded
        merged.already_synced += r.already_synced
        for em in r.expired_accounts:
            if em not in merged.expired_accounts:
                merged.expired_accounts.append(em)
        merged.errors.extend(r.errors)
        merged.details.extend(r.details)
    return merged


def share_artifact(
    backup_root: Path,
    artifact_ref: str,
    *,
    owner_ref: str | None = None,
    target_refs: list[str] | None = None,
    role: str = DEFAULT_ROLE,
    active_slot: str | None = None,
    on_progress: ProgressCallback | None = None,
    requester: Requester = _http_request,
) -> SyncReport:
    """Share one artifact (URL, UUID, or Base58 slug) and accept on target accounts."""
    if role not in VALID_ROLES:
        raise ValueError(f"invalid role {role!r}; choose from {', '.join(VALID_ROLES)}")
    frame_uuid, org_hint = parse_artifact_ref(artifact_ref)

    accounts = load_artifact_accounts(backup_root)
    usable = [a for a in accounts if a.has_session()]
    if len(usable) < 2:
        return SyncReport(errors=["need at least 2 accounts with stored session keys (`cswap artifact add-session`)"])

    owner: ArtifactAccount | None = None
    if owner_ref:
        owner = resolve_artifact_account(usable, owner_ref)
        if owner is None:
            return SyncReport(errors=[f"owner account {owner_ref!r} has no stored session key"])
    elif org_hint:
        owner = resolve_artifact_account(usable, org_hint)

    if target_refs:
        targets: list[ArtifactAccount] = []
        for tref in target_refs:
            t = resolve_artifact_account(usable, tref)
            if t is None:
                return SyncReport(errors=[f"target account {tref!r} has no stored session key"])
            targets.append(t)
    else:
        targets = list(usable)

    state = ArtifactSyncState(backup_root)

    if owner is not None:
        return _sync_owner_pass(
            owner,
            [t for t in targets if t.slot != owner.slot],
            state,
            role=role,
            force=True,
            only_ids=[frame_uuid],
            on_progress=on_progress,
            requester=requester,
        )

    ordered = sorted(usable, key=lambda a: (0 if active_slot and a.slot == str(active_slot) else 1, a.slot))
    expired: list[str] = []
    for idx, candidate in enumerate(ordered, start=1):
        _emit(on_progress, ProgressEvent("probe", candidate.email, idx, len(ordered), label=frame_uuid[:8]))
        probe_url = (
            f"{API_BASE}/api/frame/invites/{urllib.parse.quote(frame_uuid)}"
            f"?org={urllib.parse.quote(candidate.org_uuid)}"
        )
        st, _ = requester("GET", probe_url, candidate.session_key)
        if st == 401:
            expired.append(candidate.email)
            continue
        if st == 200:
            rep = _sync_owner_pass(
                candidate,
                [t for t in targets if t.slot != candidate.slot],
                state,
                role=role,
                force=True,
                only_ids=[frame_uuid],
                on_progress=on_progress,
                requester=requester,
            )
            for em in expired:
                if em not in rep.expired_accounts:
                    rep.expired_accounts.append(em)
            return rep

    return SyncReport(
        expired_accounts=expired,
        errors=[f"could not find an owner account with invite permission for artifact {frame_uuid}"],
    )


def sync_artifacts(
    backup_root: Path,
    *,
    owner_ref: str | None = None,
    target_refs: list[str] | None = None,
    role: str = DEFAULT_ROLE,
    limit: int = DEFAULT_SYNC_LIMIT,
    force: bool = False,
    on_progress: ProgressCallback | None = None,
    requester: Requester = _http_request,
) -> SyncReport:
    """Sync owned artifacts across managed accounts with stored session keys."""
    if role not in VALID_ROLES:
        raise ValueError(f"invalid role {role!r}; choose from {', '.join(VALID_ROLES)}")

    accounts = load_artifact_accounts(backup_root)
    usable = [a for a in accounts if a.has_session()]
    if len(usable) < 2:
        return SyncReport(errors=["need at least 2 accounts with stored session keys (`cswap artifact add-session`)"])

    if owner_ref:
        owner = resolve_artifact_account(usable, owner_ref)
        if owner is None:
            return SyncReport(errors=[f"account {owner_ref!r} has no stored session key"])
        owners = [owner]
    else:
        owners = list(usable)

    if target_refs:
        targets: list[ArtifactAccount] = []
        for tref in target_refs:
            t = resolve_artifact_account(usable, tref)
            if t is None:
                return SyncReport(errors=[f"target account {tref!r} has no stored session key"])
            targets.append(t)
    else:
        targets = list(usable)

    state = ArtifactSyncState(backup_root)
    reports: list[SyncReport] = []
    for owner in owners:
        peer_targets = [t for t in targets if t.slot != owner.slot]
        if not peer_targets:
            continue
        reports.append(
            _sync_owner_pass(
                owner,
                peer_targets,
                state,
                role=role,
                limit=limit,
                force=force,
                on_progress=on_progress,
                requester=requester,
            )
        )
    return _merge_reports(reports)


def sync_after_switch(
    backup_root: Path,
    settings: ArtifactSyncSettings,
    outgoing_slot: str,
    *,
    limit: int = SWITCH_SYNC_LIMIT,
    requester: Requester = _http_request,
) -> SyncReport | None:
    """Best-effort incremental sync of an account's recent artifacts."""
    if not settings.enabled:
        return None
    try:
        rep = sync_artifacts(
            backup_root,
            owner_ref=str(outgoing_slot),
            limit=limit,
            force=False,
            requester=requester,
        )
        if rep.accepted or rep.upgraded:
            _logger.info(
                "artifact-sync: shared %d accepted / %d upgraded from account %s",
                rep.accepted,
                rep.upgraded,
                outgoing_slot,
            )
        if rep.expired_accounts:
            _logger.warning(
                "artifact-sync: claude.ai session expired for %s (re-add with `cswap artifact add-session`)",
                ", ".join(rep.expired_accounts),
            )
        if rep.errors:
            _logger.warning("artifact-sync: %s", "; ".join(rep.errors[:3]))
        return rep
    except Exception as exc:  # noqa: BLE001
        _logger.warning("artifact-sync: sync failed: %s", exc)
        return None


# --------------------------------------------------------------------------- #
# Facade owned by switcher.py & menubar.py
# --------------------------------------------------------------------------- #
class ArtifactSyncRunner:
    """Best-effort companion to account switches and periodic menubar ticks.

    No-op unless ``artifacts.enabled`` is true.
    """

    def __init__(self, settings: ArtifactSyncSettings, backup_root: Path):
        self._s = settings
        self._backup_root = Path(backup_root)
        self.background = False
        self._lock = threading.Lock()
        self._pending_slot: str | None = None
        self._thread: threading.Thread | None = None
        self._last_periodic: float | None = None

    @property
    def active(self) -> bool:
        return bool(self._s.enabled)

    def reload_settings(self) -> ArtifactSyncSettings:
        from claude_swap.settings import load_artifact_settings

        self._s = load_artifact_settings(self._backup_root)
        return self._s

    def follow_switch(
        self,
        *,
        outgoing_account: str | None,
        target_account: str | None,
    ) -> None:
        if not self.active or not outgoing_account:
            return
        if target_account is not None and str(outgoing_account) == str(target_account):
            return
        self._schedule(str(outgoing_account))

    def maybe_sync_artifacts(self, active_account: str | None = None) -> None:
        if not self.active or not active_account:
            return
        now = time.monotonic()
        with self._lock:
            if self._last_periodic is not None and now - self._last_periodic < PERIODIC_SYNC_INTERVAL_S:
                return
            self._last_periodic = now
        self._schedule(str(active_account))

    def _schedule(self, owner_slot: str) -> None:
        if not self.background:
            sync_after_switch(self._backup_root, self._s, owner_slot)
            return
        with self._lock:
            self._pending_slot = owner_slot
            if self._thread is None or not self._thread.is_alive():
                self._thread = threading.Thread(target=self._worker, name="artifact-sync", daemon=True)
                self._thread.start()

    def _worker(self) -> None:
        while True:
            with self._lock:
                slot, self._pending_slot = self._pending_slot, None
                if slot is None:
                    self._thread = None
                    return
            sync_after_switch(self._backup_root, self._s, slot)

    def wait_idle(self, timeout: float | None = None) -> bool:
        with self._lock:
            t = self._thread
        if t is not None:
            t.join(timeout)
        with self._lock:
            return self._thread is None or not self._thread.is_alive()
