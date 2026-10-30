# -*- coding: utf-8 -*-
"""waf_extras.py: レスポンス検査、自動BAN、Slowloris対策、Webhook、GeoIP、
信頼する逆プロキシ、管理画面の認証、追加設定の表示/更新をまとめたモジュール。
依存は標準ライブラリのみ(maxminddb は任意)
"""

import gzip
import hashlib
import hmac
import html
import ipaddress
import json
import os
import queue
import re
import secrets
import ssl
import threading
import time
import urllib.request
import zlib
from collections import deque

# ---------------------------------------------------------------------------
# 既定値(waf.DEFAULT_CONFIG に取り込まれる)
# ---------------------------------------------------------------------------
EXTRA_DEFAULTS = {
    "ip_allowlist": [],            # 指定時は、このIP/CIDR以外を全て拒否(空=無効)
    "exempt_ips": [],              # BAN・レート制限・自動BANの対象外にするIP/CIDR(監視サーバ等)
    "trusted_proxies": [],         # 信頼する逆プロキシ。ここからの接続は X-Forwarded-For で送信元を判定
    "country_allowlist": [],       # 指定時は、この国以外を全て拒否(国コード)
    "country_block_unknown": False,  # 国が判定できないIP(プライベート等)も拒否
    "geoip": {
        "mmdb": "",                # GeoLite2-City.mmdb / GeoLite2-Country.mmdb のパス(空=自動検出)
        "online": True,            # オフラインDBが無いとき外部API(ipinfo.io / ip-api.com)で判定
    },
    "autoban": {                   # 攻撃(BLOCK/DETECT)を繰り返す送信元を自動BAN
        "enabled": True,
        "threshold": 10,           # window_seconds 内の攻撃回数
        "window_seconds": 60,
        "ban_seconds": 300,
    },
    "slow_ban": {                  # 低速接続(ヘッダ/ボディの締め切り超過)の繰り返しでBAN
        "enabled": True,
        "threshold": 10,
        "window_seconds": 60,
    },
    "connlimit_ban": {             # IPごとの同時接続上限の超過が続いたらBAN
        "enabled": True,
        "threshold": 5,
        "window_seconds": 60,
    },
    "header_timeout_seconds": 10,  # 1バイト目からヘッダ受信完了までの締め切り(Slowloris対策。0=無効)
    "body_timeout_seconds": 30,    # ボディ受信の締め切り(Slow POST対策。0=無効)
    "max_body_bytes": 10485760,    # リクエストボディの上限(超えたら 413。0=無制限)
    "response_inspection": {       # バックエンド応答(HTML)の Stored XSS 検査
        "action": "sanitize",      # sanitize(無害化) / block(403) / monitor(記録のみ) / off
        "max_bytes": 2097152,      # これより大きい応答は検査しない
    },
    "webhook": {
        "url": "",                 # 検知イベントを JSON で POST する先(空=無効)
        "send_pass": False,        # 通過(PASS)も送る
        "timeout_seconds": 3,
    },
}

RESPONSE_ACTIONS = ("sanitize", "block", "monitor", "off")


# ---------------------------------------------------------------------------
# IP/CIDR ユーティリティ
# ---------------------------------------------------------------------------
def parse_nets(items):
    nets = []
    for s in items or []:
        s = str(s).strip()
        if not s:
            continue
        try:
            nets.append(ipaddress.ip_network(s, strict=False))
        except ValueError:
            continue
    return nets


def ip_in_nets(ip, nets):
    if not nets or not ip:
        return False
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in nets if n.version == a.version)


class NetCache:
    """cfg の文字列リストを ip_network に変換してキャッシュする。設定の変更にも追従する"""
    def __init__(self):
        self._c = {}

    def get(self, items):
        key = tuple(str(x) for x in (items or []))
        hit = self._c.get(key)
        if hit is None:
            if len(self._c) > 32:
                self._c.clear()
            hit = self._c[key] = parse_nets(items)
        return hit

    def contains(self, items, ip):
        return ip_in_nets(ip, self.get(items))


_NETS = NetCache()


def in_list(items, ip):
    return _NETS.contains(items, ip)


def validate_ip_or_cidr(s):
    s = str(s).strip()
    try:
        if "/" in s:
            ipaddress.ip_network(s, strict=False)
        else:
            ipaddress.ip_address(s)
    except ValueError:
        raise RuntimeError("無効なIP/CIDRです: " + s)
    return s


def effective_client_ip(remote_ip, xff, trusted):
    """接続元が信頼する逆プロキシのときだけ X-Forwarded-For を右からたどり、
    信頼プロキシでない最初のIPを返す。左側はクライアントが偽装できるので使わない
    """
    if not xff or not trusted or not in_list(trusted, remote_ip):
        return remote_ip
    for part in reversed([p.strip() for p in str(xff).split(",")]):
        try:
            ipaddress.ip_address(part)
        except ValueError:
            return remote_ip
        if not in_list(trusted, part):
            return part
    return remote_ip


# ---------------------------------------------------------------------------
# レスポンス検査(Stored XSS 対策)
# ---------------------------------------------------------------------------
# リクエスト検査だけでは、WAFを通らずDBに書かれたスクリプトや、WAF導入前から保存されていたスクリプトは止められない。
# バックエンドが返すHTMLをブラウザに渡す前に検査し、ページを開くだけで実行されるスクリプトを無害化/遮断する。
# アプリ自身の正規スクリプトを壊さないよう、攻撃で典型的な処理を含むものだけを対象にする。
_RESP_SINK = re.compile(
    r"\b(?:alert|prompt|confirm|eval|atob)\s*\(|String\s*\.\s*fromCharCode|"
    r"document\s*\.\s*(?:cookie|write|domain)\b|\.constructor\s*\(", re.I)
_RESP_HANDLER_SINK = re.compile(
    _RESP_SINK.pattern + r"|\bfetch\s*\(|XMLHttpRequest|\bimport\s*\(|new\s+Image\b|\bsendBeacon\b", re.I)
_AUTO_EVENTS = (r"on(?:error|load|toggle|focus|focusin|blur|pageshow|begin|end|"
                r"animation\w+|transition\w+|mouseover|mouseenter|pointer\w+|wheel|scroll|start|beforeprint|hashchange)")
_RE_SCRIPT = re.compile(r"<script\b[^>]*>(.*?)</script\s*>", re.I | re.S)
_RE_HANDLER = re.compile(
    r"(<[a-zA-Z][^<>]*?\s)(on[a-zA-Z]+)(\s*=\s*)(\"[^\"]*\"|'[^']*'|[^\s>]+)", re.S)
_RE_AUTO_EVENT = re.compile(r"^" + _AUTO_EVENTS + r"$", re.I)
_RE_JS_URI = re.compile(
    r"((?:href|src|action|formaction|data|xlink:href)\s*=\s*[\"']?\s*)(javascript\s*:)([^\"'>]*)", re.I)
_RE_EMBED = re.compile(
    r"<(iframe|object|embed|frame)\b(?=[^>]*(?:\bsrcdoc\s*=|=\s*[\"']?\s*(?:javascript\s*:|data\s*:\s*text/html)))",
    re.I)


def _rule_script(text):
    found = []

    def sub(m):
        if _RESP_SINK.search(m.group(1)):
            found.append(m.group(0))
            return "<code class=waf-neutralized>" + html.escape(m.group(0), quote=False) + "</code>"
        return m.group(0)
    return _RE_SCRIPT.sub(sub, text), found


def _rule_handler(text):
    found = []

    def sub(m):
        name, value = m.group(2), m.group(4)
        if (_RE_AUTO_EVENT.match(name) and _RESP_HANDLER_SINK.search(value)) or \
                re.search(r"document\s*\.\s*cookie|\beval\s*\(|fromCharCode|\batob\s*\(", value, re.I):
            found.append(name + m.group(3) + value)
            return m.group(1) + "data-waf-removed-" + name + m.group(3) + value
        return m.group(0)
    return _RE_HANDLER.sub(sub, text), found


def _rule_js_uri(text):
    found = []

    def sub(m):
        body = m.group(3).strip()
        if re.fullmatch(r"(?:void\s*\(\s*0\s*\)\s*;?|;?)", body):
            return m.group(0)
        found.append(m.group(2) + m.group(3))
        return m.group(1) + "#waf-blocked"
    return _RE_JS_URI.sub(sub, text), found


def _rule_embed(text):
    found = []

    def sub(m):
        found.append(m.group(0))
        return "&lt;" + m.group(1)
    return _RE_EMBED.sub(sub, text), found


# (id, 深刻度, 説明, 関数)。ID は waf_rules.RESPONSE_META と一致させる
RESPONSE_RULES = [
    ("RESP-001", "critical", "応答の<script>内に alert/eval/document.cookie 等", _rule_script),
    ("RESP-002", "high", "応答の自動発火イベント属性(onerror= 等)に危険な処理", _rule_handler),
    ("RESP-003", "high", "応答の href/src 等の javascript: URL", _rule_js_uri),
    ("RESP-004", "high", "応答の iframe/object/embed の srcdoc・javascript:・data:text/html", _rule_embed),
]


def _decode_body(body, headers):
    enc = (headers.get("content-encoding") or "").lower().strip()
    decompressed = False
    if enc in ("gzip", "x-gzip", "deflate"):
        try:
            if "gzip" in enc:
                body = gzip.decompress(body)
            else:
                try:
                    body = zlib.decompress(body)
                except zlib.error:
                    body = zlib.decompress(body, -zlib.MAX_WBITS)
            decompressed = True
        except (OSError, zlib.error, EOFError):
            return None, None, False
    elif enc not in ("", "identity"):
        return None, None, False
    m = re.search(r"charset=([\w\-]+)", headers.get("content-type", ""), re.I)
    charset = (m.group(1) if m else "utf-8").lower()
    try:
        return body.decode(charset, errors="surrogateescape"), charset, decompressed
    except LookupError:
        return body.decode("utf-8", errors="surrogateescape"), "utf-8", decompressed


def inspect_response(cfg, body, headers, mode, prof=None, path="/"):
    """HTMLレスポンスを検査する。
    headers: {小文字のヘッダ名: 値}
    prof / path: 接続先のプロファイルとリクエストのパス。あればバックエンド別の設定(無効ルール、検知のみ、パス別の指定)を反映する
    戻り値: (action, new_body or None, hits, decompressed)
      action: None(検知なし) / "sanitized" / "blocked" / "monitor"
    """
    ri = cfg.get("response_inspection") or {}
    action = ri.get("action", "sanitize")
    if action not in RESPONSE_ACTIONS or action == "off" or not body:
        return None, None, [], False
    if not cfg.get("rules", {}).get("response", True):
        return None, None, [], False
    ctype = (headers.get("content-type") or "").lower()
    try:
        mx = int(ri.get("max_bytes", 2097152))
    except (TypeError, ValueError):
        mx = 2097152
    if "html" not in ctype or (mx > 0 and len(body) > mx):
        return None, None, [], False
    text, charset, decompressed = _decode_body(body, headers)
    if text is None:
        return None, None, [], False
    disabled = set(cfg.get("disabled_rules", []))
    detect_only = set(cfg.get("detect_only_rules") or ())
    if prof:
        # このバックエンド・このパスで「使わない」ルールは検査しない。「検知のみ」のルールは見つけても書き換えない
        import waf_backend as _wb
        probe = [{"id": rid} for rid, _s, _d, _f in RESPONSE_RULES]
        kept, _n, pdet = _wb.apply_rule_overrides_ex(prof, probe, path or "/")
        keep_ids = {h["id"] for h in kept}
        disabled |= {h["id"] for h in probe if h["id"] not in keep_ids}
        detect_only |= _wb.detect_ids(prof) | pdet
    hits = []
    for rid, sev, desc, fn in RESPONSE_RULES:
        if rid in disabled:
            continue
        if rid in detect_only:
            _unused, found = fn(text)            # 見つけるだけ(本文は書き換えない)
        else:
            text, found = fn(text)
        for f in found[:5]:
            hits.append({"id": rid, "category": "response", "severity": sev, "description": desc,
                         "matched": f[:120] + ("..." if len(f) > 120 else ""), "field": "response:body"})
    if not hits:
        return None, None, [], False
    if mode == "detect" or action == "monitor" or all(h["id"] in detect_only for h in hits):
        return "monitor", None, hits, False
    if action == "block":
        return "blocked", None, hits, False
    try:
        new_body = text.encode(charset, errors="surrogateescape")
    except (LookupError, UnicodeEncodeError):
        new_body = text.encode("utf-8", errors="replace")
    return "sanitized", new_body, hits, decompressed


# ---------------------------------------------------------------------------
# 繰り返し違反のカウンター(攻撃/低速接続/同時接続上限の自動BAN用)
# ---------------------------------------------------------------------------
class StrikeCounter:
    LABELS = {"attack": "攻撃", "slow": "低速接続", "connlimit": "同時接続上限の超過"}
    CFG_KEY = {"attack": "autoban", "slow": "slow_ban", "connlimit": "connlimit_ban"}

    def __init__(self, cfg):
        self.cfg = cfg
        self.lock = threading.Lock()
        self.times = {}      # (kind, ip) をキーにした deque
        self._gc_at = 0.0

    def note(self, kind, ip):
        """1件数えて、しきい値に達したら True を返す。カウンターはリセットする"""
        c = self.cfg.get(self.CFG_KEY[kind]) or {}
        if not c.get("enabled", True) or not ip:
            return False
        if in_list(self.cfg.get("exempt_ips", []), ip) or in_list(self.cfg.get("trusted_proxies", []), ip):
            return False
        try:
            th = max(1, int(c.get("threshold", 10)))
            win = max(1, int(c.get("window_seconds", 60)))
        except (TypeError, ValueError):
            return False
        now = time.time()
        with self.lock:
            dq = self.times.get((kind, ip))
            if dq is None:
                dq = self.times[(kind, ip)] = deque()
            dq.append(now)
            while dq and dq[0] < now - win:
                dq.popleft()
            if len(dq) >= th:
                dq.clear()
                return True
            if len(self.times) > 20000 and now - self._gc_at > 10:
                self._gc_at = now
                for k in [k for k, q in self.times.items() if not q or q[-1] < now - 600]:
                    self.times.pop(k, None)
        return False

    def reset(self, ip):
        with self.lock:
            for k in [k for k in self.times if k[1] == ip]:
                self.times.pop(k, None)

    def ban_seconds(self):
        try:
            return max(1, int((self.cfg.get("autoban") or {}).get("ban_seconds", 300)))
        except (TypeError, ValueError):
            return 300


# ---------------------------------------------------------------------------
# 締め切り監視(Slowloris / Slow POST)。1本のスレッドでまとめて見張る
# ---------------------------------------------------------------------------
class DeadlineWatcher:
    def __init__(self):
        self._lock = threading.Lock()
        self._items = {}
        self._seq = 0
        self._started = False

    def add(self, seconds, callback):
        with self._lock:
            if not self._started:
                self._started = True
                threading.Thread(target=self._run, name="waf-deadline", daemon=True).start()
            self._seq += 1
            self._items[self._seq] = (time.time() + seconds, callback)
            return self._seq

    def cancel(self, token):
        """締め切り前に終わったら True。発火済みなら False"""
        with self._lock:
            return self._items.pop(token, None) is not None

    def _run(self):
        while True:
            time.sleep(0.25)
            now = time.time()
            with self._lock:
                due = [k for k, (t, _) in self._items.items() if t <= now]
                fired = [self._items.pop(k)[1] for k in due]
            for cb in fired:
                try:
                    cb()
                except Exception:
                    pass


DEADLINES = DeadlineWatcher()


# ---------------------------------------------------------------------------
# Webhook
# ---------------------------------------------------------------------------
class Webhook:
    def __init__(self, cfg):
        self.cfg = cfg
        self.q = queue.Queue(maxsize=5000)
        self.sent = 0
        self.failed = 0
        self.dropped = 0
        self.last_error = ""
        threading.Thread(target=self._worker, daemon=True, name="waf-webhook").start()

    def submit(self, record):
        wh = self.cfg.get("webhook") or {}
        url = str(wh.get("url") or "").strip()
        if not url:
            return
        if record.get("action") == "PASS" and not wh.get("send_pass"):
            return
        ev = {k: v for k, v in record.items() if k != "resp"}
        try:
            self.q.put_nowait((url, ev))
        except queue.Full:
            self.dropped += 1

    def _worker(self):
        while True:
            url, ev = self.q.get()
            self._send(url, ev)

    def _send(self, url, ev):
        wh = self.cfg.get("webhook") or {}
        try:
            data = json.dumps(ev, ensure_ascii=False).encode("utf-8")
            req = urllib.request.Request(url, data=data, method="POST",
                                         headers={"Content-Type": "application/json",
                                                  "User-Agent": "WAF-webhook"})
            ctx = ssl._create_unverified_context() if url.startswith("https") else None
            with urllib.request.urlopen(req, timeout=float(wh.get("timeout_seconds", 3)), context=ctx) as r:
                r.read(1)
            self.sent += 1
        except Exception as e:
            self.failed += 1
            self.last_error = f"{type(e).__name__}: {e}"[:200]

    def status(self):
        return {"sent": self.sent, "failed": self.failed, "dropped": self.dropped,
                "last_error": self.last_error, "queued": self.q.qsize()}


# ---------------------------------------------------------------------------
# オフライン GeoIP(任意)
# ---------------------------------------------------------------------------
class OfflineGeo:
    """GeoLite2 の mmdb があれば国コード・国名・緯度経度を返す。無ければ ready=False"""
    def __init__(self, path_hint="", base_dir="."):
        self.reader = None
        self.path = None
        try:
            import maxminddb  # noqa: F401
        except Exception:
            return
        path = self._find(path_hint, base_dir)
        if not path:
            return
        try:
            import maxminddb
            self.reader = maxminddb.open_database(path)
            self.path = path
        except Exception:
            self.reader = None

    @staticmethod
    def _find(hint, base_dir):
        if hint:
            p = hint if os.path.isabs(hint) else os.path.join(base_dir, hint)
            if os.path.exists(p):
                return p
        try:
            import _geoip_geolite2
            cand = os.path.join(os.path.dirname(_geoip_geolite2.__file__), "GeoLite2-City.mmdb")
            if os.path.exists(cand):
                return cand
        except Exception:
            pass
        for name in ("GeoLite2-City.mmdb", "GeoLite2-Country.mmdb"):
            p = os.path.join(base_dir, name)
            if os.path.exists(p):
                return p
        return None

    @property
    def ready(self):
        return self.reader is not None

    def lookup(self, ip):
        if self.reader is None:
            return None
        try:
            rec = self.reader.get(ip)
        except (ValueError, KeyError):
            rec = None
        if not rec:
            return None
        country = rec.get("country") or rec.get("registered_country") or {}
        cc = country.get("iso_code") or ""
        if not cc:
            return None
        names = country.get("names", {}) or {}
        loc = rec.get("location") or {}
        return {"cc": cc.upper(), "country": names.get("en") or names.get("ja") or cc,
                "lat": loc.get("latitude"), "lon": loc.get("longitude")}


# ---------------------------------------------------------------------------
# 国名データ(ダッシュボードの国選択用)
# ---------------------------------------------------------------------------
def country_list():
    try:
        import waf_countries
        return sorted(({"code": k, "ja": v.get("ja", k), "en": v.get("en", k)}
                       for k, v in waf_countries.COUNTRIES.items()), key=lambda x: x["code"])
    except Exception:
        return []


# ---------------------------------------------------------------------------
# 管理画面の認証
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# ユーザー(固定のユーザー名・パスワード)。設定ファイルの dashboard.users に保存する。
#   {"username": "user1", "display": "ユーザー1", "role": "user"|"admin", "password_hash": "pbkdf2_sha256$..."}
# パスワードは平文で保存せず、変更するまで固定(起動のたびに変わらない)。
# ---------------------------------------------------------------------------
_PBKDF2_ITERS = 120000
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{2,32}$")


def hash_password(pw, iters=_PBKDF2_ITERS):
    salt = secrets.token_hex(8)
    dk = hashlib.pbkdf2_hmac("sha256", str(pw).encode("utf-8"), bytes.fromhex(salt), iters)
    return f"pbkdf2_sha256${iters}${salt}${dk.hex()}"


def verify_password(pw, stored):
    try:
        algo, iters, salt, hx = str(stored).split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", str(pw).encode("utf-8"), bytes.fromhex(salt), int(iters))
        return hmac.compare_digest(dk.hex(), hx)
    except Exception:
        return False


def users_of(cfg):
    u = (cfg.get("dashboard") or {}).get("users")
    return [x for x in u if isinstance(x, dict) and x.get("username")] if isinstance(u, list) else []


def users_view(cfg):
    return [{"username": u["username"], "display": u.get("display") or u["username"],
             "role": norm_role(u.get("role")), "org": str(u.get("org") or ""),
             "scope": [str(x) for x in (u.get("scope") or []) if x],
             "provider": (bool(u.get("provider")) or str(u.get("org") or "") == "vendor") and norm_role(u.get("role")) in ("analyst", "key_officer")} for u in users_of(cfg)]


_ALERT_LIM = {"threshold": (1, 100000), "window": (1, 300), "critical": (0, 1000000), "hold": (1, 3600)}


def clean_user_alert(a):
    """ユーザー個人の警報バナー設定。全体の既定より優先する。不正な項目は捨てる"""
    out = {}
    if not isinstance(a, dict):
        return out
    for k in ("enabled", "sound", "bg"):
        if k in a:
            out[k] = bool(a[k])
    if a.get("immediate") in ("critical", "high", "medium", "off"):
        out["immediate"] = a["immediate"]
    if a.get("position") in ("top", "both"):
        out["position"] = a["position"]
    for k, (lo, hi) in _ALERT_LIM.items():
        if k in a:
            try:
                out[k] = max(lo, min(hi, int(a[k])))
            except (TypeError, ValueError):
                pass
    return out


def norm_role(r):
    """ロールを正規化する。
    admin(提供側の運用)、analyst(提供側の監視)、user(提供先企業)、
    key_officer(設定は触れず、暗号化ログの復号だけ担当)
    """
    r = str(r or "")
    return r if r in ("admin", "analyst", "key_officer") else "user"


def _clean_org_fields(cfg, up):
    """ユーザーの所属組織(org)と担当範囲(scope)を検証して (org, scope) を返す。指定が無い項目は None"""
    ids = {o.get("id") for o in (cfg.get("orgs") or []) if isinstance(o, dict)} | {"vendor"}
    org = scope = None
    if "org" in up:
        org = str(up.get("org") or "").strip()
        if org and org not in ids:
            raise ValueError("所属の組織が見つかりません")
    if "scope" in up:
        sc = up.get("scope") or []
        if not isinstance(sc, list):
            raise ValueError("担当範囲の指定が正しくありません")
        scope = []
        for x in sc:
            x = str(x).strip()
            if x and x not in ids:
                raise ValueError(f"担当範囲の組織が見つかりません: {x}")
            if x and x not in scope:
                scope.append(x)
    return org, scope


def users_apply(cfg, up, actor):
    """ユーザー管理の1操作を cfg に適用する。保存は呼び出し側で行う
    actor: 操作者 {"username","role"}。不正なら ValueError
    action: add / delete / set_password / update
    """
    action = str((up or {}).get("action", ""))
    users = cfg.setdefault("dashboard", {}).setdefault("users", [])
    by = {u["username"]: u for u in users if isinstance(u, dict) and u.get("username")}
    is_admin = actor.get("role") == "admin"
    admins = [n for n, u in by.items() if u.get("role") == "admin"]
    name = str(up.get("username", "")).strip()

    def need_admin():
        if not is_admin:
            raise ValueError("この操作は管理者だけができます")

    def check_pw(pw):
        if len(str(pw)) < 6:
            raise ValueError("パスワードは6文字以上にしてください")
        if len(str(pw)) > 128:
            raise ValueError("パスワードが長すぎます")

    if action == "add":
        need_admin()
        if not _USERNAME_RE.match(name):
            raise ValueError("ユーザー名は英数字と _ . - の2〜32文字にしてください")
        if name in by:
            raise ValueError("そのユーザー名はすでに使われています")
        if len(users) >= 20:
            raise ValueError("ユーザーは20人まで登録できます")
        check_pw(up.get("password", ""))
        org, scope = _clean_org_fields(cfg, up)
        users.append({"username": name, "display": str(up.get("display") or name).strip()[:40] or name,
                      "role": norm_role(up.get("role")), "org": org or "", "scope": scope or [],
                      "provider": False,
                      "password_hash": hash_password(up["password"])})
    elif action == "delete":
        need_admin()
        if name not in by:
            raise ValueError("ユーザーが見つかりません")
        if name == actor.get("username"):
            raise ValueError("自分自身は削除できません")
        if by[name].get("role") == "admin" and len(admins) <= 1:
            raise ValueError("最後の管理者は削除できません")
        users[:] = [u for u in users if u.get("username") != name]
        # そのユーザーのバックエンドは操作した管理者のものにする(ログを見失わないため)
        for p in cfg.get("backends", []) or []:
            if p.get("owner") == name:
                p["owner"] = actor.get("username", "")
        for r in cfg.get("removed_backends", []) or []:
            if r.get("owner") == name:
                r["owner"] = actor.get("username", "")
    elif action == "set_password":
        target = name or actor.get("username")
        if target not in by:
            raise ValueError("ユーザーが見つかりません")
        if target != actor.get("username"):
            need_admin()
        else:
            if not verify_password(up.get("old_password", ""), by[target].get("password_hash", "")) and not (
                    is_admin and up.get("force")):
                time.sleep(1.0)
                raise ValueError("現在のパスワードが違います")
        check_pw(up.get("password", ""))
        by[target]["password_hash"] = hash_password(up["password"])
    elif action == "set_alert":
        # 自分の警報バナー設定。全員が自分の分だけ変更でき、reset=true で全体の既定に戻す
        me = actor.get("username")
        if me not in by:
            raise ValueError("ユーザーが見つかりません")
        if up.get("reset"):
            by[me].pop("alert", None)
        else:
            by[me]["alert"] = clean_user_alert(up.get("alert"))
    elif action == "update":
        need_admin()
        if name not in by:
            raise ValueError("ユーザーが見つかりません")
        if "display" in up:
            by[name]["display"] = str(up["display"]).strip()[:40] or name
        if "role" in up:
            role = norm_role(up["role"])
            if by[name].get("role") == "admin" and role != "admin" and len(admins) <= 1:
                raise ValueError("最後の管理者は一般ユーザーにできません")
            by[name]["role"] = role
        org, scope = _clean_org_fields(cfg, up)
        if org is not None:
            by[name]["org"] = org
        if scope is not None:
            by[name]["scope"] = scope
        by[name]["provider"] = False                      # 古い形式のフラグ。ベンダー側かどうかは所属(vendor 組織)で決める
    else:
        raise ValueError("不明な操作です")


class AdminAuth:
    """管理画面の認証。users_fn があり1人以上登録されていればユーザー名+パスワード、
    なければ単一パスワード(password)、どちらも無ければ認証なし
    """
    COOKIE = "waf_session"

    def __init__(self, password="", hours=12, users_fn=None):
        self.password = password or ""
        self.hours = hours
        self.users_fn = users_fn
        self.sessions = {}          # token: (期限, ユーザー名)
        self.lock = threading.Lock()

    def users(self):
        try:
            return [u for u in (self.users_fn() or []) if isinstance(u, dict) and u.get("username")] if self.users_fn else []
        except Exception:
            return []

    @property
    def user_mode(self):
        return bool(self.users())

    @property
    def enabled(self):
        return bool(self.password) or self.user_mode

    def token_from(self, cookie_header):
        for part in (cookie_header or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == self.COOKIE:
                return v
        return ""

    def user(self, cookie_header):
        """ログイン中のユーザー {"username","display","role"}。認証なし/単一パスワードなら管理者扱い。未ログインは None"""
        if not self.enabled:
            return {"username": "", "display": "管理者", "role": "admin"}
        tok = self.token_from(cookie_header)
        if not tok:
            return None
        now = time.time()
        with self.lock:
            ent = self.sessions.get(tok)
            if not ent or ent[0] <= now:
                self.sessions.pop(tok, None)
                return None
        if not self.user_mode:
            return {"username": "", "display": "管理者", "role": "admin"}
        for u in self.users():
            if u["username"] == ent[1]:
                return {"username": u["username"], "display": u.get("display") or u["username"],
                        "role": norm_role(u.get("role")), "org": str(u.get("org") or ""),
                        "scope": [str(x) for x in (u.get("scope") or []) if x],
                        "provider": (bool(u.get("provider")) or str(u.get("org") or "") == "vendor") and norm_role(u.get("role")) in ("analyst", "key_officer"),
                        "alert": clean_user_alert(u.get("alert"))}
        return None            # 削除されたユーザーのセッションは無効

    def authed(self, cookie_header):
        return self.user(cookie_header) is not None

    def login(self, pw, username=None):
        """正しければ Set-Cookie の値を返す。違えば None。総当たり対策で1秒待つ"""
        who = None
        if self.user_mode:
            for u in self.users():
                if u["username"] == str(username or "").strip():
                    if verify_password(pw, u.get("password_hash", "")):
                        who = u["username"]
                    break
        elif self.password and hmac.compare_digest(str(pw).encode(), self.password.encode()):
            who = ""
        if who is not None:
            tok = secrets.token_urlsafe(32)
            with self.lock:
                if len(self.sessions) > 1000:
                    self.sessions.clear()
                self.sessions[tok] = (time.time() + self.hours * 3600, who)
            return (f"{self.COOKIE}={tok}; HttpOnly; SameSite=Strict; Path=/; "
                    f"Max-Age={self.hours * 3600}")
        time.sleep(1.0)
        return None

    def logout(self, cookie_header):
        with self.lock:
            self.sessions.pop(self.token_from(cookie_header), None)

    def active_users(self):
        """期限内のセッションを持つユーザー名の集合。期限切れは削除する"""
        now = time.time()
        with self.lock:
            for t in [t for t, e in self.sessions.items() if e[0] <= now]:
                self.sessions.pop(t, None)
            return {e[1] for e in self.sessions.values() if e[1]}


LOGIN_PAGE = """<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8"><title>WAF ダッシュボード ログイン</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0b1220;color:#e6edf6;
font-family:system-ui,-apple-system,"Segoe UI","Hiragino Sans","Noto Sans JP",sans-serif}
form{background:#121a2b;border:1px solid #23314a;border-radius:14px;padding:28px;width:min(340px,90vw)}
h1{font-size:17px;margin:0 0 16px}input{width:100%;box-sizing:border-box;padding:10px;border-radius:9px;margin-bottom:10px;
border:1px solid #33465f;background:#0e1726;color:#e6edf6;font-size:14px}button{margin-top:6px;width:100%;
padding:10px;border:0;border-radius:9px;background:#4f8cff;color:#fff;font-weight:700;cursor:pointer}
.err{color:#ff7a8a;font-size:13px;margin-top:10px}</style></head><body>
<form method="post" action="/login"><h1>&#128737; WAF ダッシュボード</h1>
__USERFIELD__<input type="password" name="password" placeholder="パスワード" __PWFOCUS__autocomplete="current-password">
<button type="submit">ログイン</button>__ERR__</form></body></html>"""


def login_page(user_mode, err=""):
    uf = ('<input type="text" name="username" placeholder="ユーザー名" autofocus autocomplete="username">'
          if user_mode else "")
    return (LOGIN_PAGE.replace("__USERFIELD__", uf).replace("__PWFOCUS__", "" if user_mode else "autofocus ")
            .replace("__ERR__", err))


def is_loopback_host(host):
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host in ("localhost",)


# ---------------------------------------------------------------------------
# 追加設定の表示/更新(設定の「追加の防御」グループ)
# ---------------------------------------------------------------------------
def _int(v, lo, hi, cur):
    try:
        return max(lo, min(hi, int(v)))
    except (TypeError, ValueError):
        return cur


def extra_view(cfg):
    def sub(k):
        d = dict(EXTRA_DEFAULTS[k])
        d.update(cfg.get(k) or {})
        return d
    return {
        "autoban": sub("autoban"),
        "slow_ban": sub("slow_ban"),
        "connlimit_ban": sub("connlimit_ban"),
        "header_timeout_seconds": cfg.get("header_timeout_seconds", 10),
        "body_timeout_seconds": cfg.get("body_timeout_seconds", 30),
        "max_body_bytes": cfg.get("max_body_bytes", 10485760),
        "response_inspection": sub("response_inspection"),
        "webhook": sub("webhook"),
        "country_block_unknown": bool(cfg.get("country_block_unknown", False)),
        "trusted_proxies": list(cfg.get("trusted_proxies", [])),
    }


def extra_update(cfg, up):
    """up は extra_view と同じ形(一部だけでも可)。不正値は無視するか丸める"""
    if not isinstance(up, dict):
        return
    for k in ("autoban", "slow_ban", "connlimit_ban"):
        u = up.get(k)
        if not isinstance(u, dict):
            continue
        d = cfg.setdefault(k, dict(EXTRA_DEFAULTS[k]))
        if "enabled" in u:
            d["enabled"] = bool(u["enabled"])
        if "threshold" in u:
            d["threshold"] = _int(u["threshold"], 1, 100000, d.get("threshold", 10))
        if "window_seconds" in u:
            d["window_seconds"] = _int(u["window_seconds"], 1, 86400, d.get("window_seconds", 60))
        if k == "autoban" and "ban_seconds" in u:
            d["ban_seconds"] = _int(u["ban_seconds"], 1, 30 * 86400, d.get("ban_seconds", 300))
    if "header_timeout_seconds" in up:
        cfg["header_timeout_seconds"] = _int(up["header_timeout_seconds"], 0, 600, 10)
    if "body_timeout_seconds" in up:
        cfg["body_timeout_seconds"] = _int(up["body_timeout_seconds"], 0, 3600, 30)
    if "max_body_bytes" in up:
        cfg["max_body_bytes"] = _int(up["max_body_bytes"], 0, 1 << 34, 10485760)
    ri = up.get("response_inspection")
    if isinstance(ri, dict):
        d = cfg.setdefault("response_inspection", dict(EXTRA_DEFAULTS["response_inspection"]))
        if ri.get("action") in RESPONSE_ACTIONS:
            d["action"] = ri["action"]
        if "max_bytes" in ri:
            d["max_bytes"] = _int(ri["max_bytes"], 0, 1 << 30, d.get("max_bytes", 2097152))
    wh = up.get("webhook")
    if isinstance(wh, dict):
        d = cfg.setdefault("webhook", dict(EXTRA_DEFAULTS["webhook"]))
        if "url" in wh:
            url = str(wh["url"] or "").strip()
            if url and not re.match(r"^https?://", url, re.I):
                raise ValueError("Webhook の URL は http:// か https:// で始めてください")
            d["url"] = url
        if "send_pass" in wh:
            d["send_pass"] = bool(wh["send_pass"])
        if "timeout_seconds" in wh:
            d["timeout_seconds"] = _int(wh["timeout_seconds"], 1, 60, 3)
    if "country_block_unknown" in up:
        cfg["country_block_unknown"] = bool(up["country_block_unknown"])
    if "trusted_proxies" in up:
        v = up["trusted_proxies"]
        if isinstance(v, str):
            v = re.split(r"[,\s]+", v)
        cfg["trusted_proxies"] = [validate_ip_or_cidr(x) for x in (v or []) if str(x).strip()]


# ---------------------------------------------------------------------------
# IP 許可リスト / 除外IP / 国の許可リスト(IP管理の操作)。Runtime と FileConfigControl で共用
# ---------------------------------------------------------------------------
LIST_KEYS = {"allow": "ip_allowlist", "exempt": "exempt_ips"}


def list_add(cfg, kind, ip):
    key = LIST_KEYS[kind]
    ip = validate_ip_or_cidr(ip)
    lst = cfg.setdefault(key, [])
    if ip not in lst:
        lst.append(ip)


def list_remove(cfg, kind, ip):
    key = LIST_KEYS[kind]
    lst = cfg.setdefault(key, [])
    ip = str(ip).strip()
    if ip in lst:
        lst.remove(ip)


def country_add(cfg, mode, cc):
    cc = str(cc).strip().upper()
    if not re.fullmatch(r"[A-Z]{2}", cc):
        raise RuntimeError("国コード(ISO 3166-1 alpha-2、例: JP)を指定してください")
    key = "country_allowlist" if mode == "allow" else "country_blocklist"
    lst = cfg.setdefault(key, [])
    if cc not in lst:
        lst.append(cc)


def country_remove(cfg, mode, cc):
    key = "country_allowlist" if mode == "allow" else "country_blocklist"
    lst = cfg.setdefault(key, [])
    c = str(cc).strip()
    for x in list(lst):
        if x.upper() == c.upper():
            lst.remove(x)


def policy_op(policy, kind, op, value):
    """バックエンド別のIP/国の制限(policy dict)に1項目を追加/削除する。不正なら RuntimeError"""
    if kind not in ("blocklist", "ip_allowlist", "country_blocklist", "country_allowlist"):
        raise RuntimeError("不明なリストです")
    if kind.startswith("country"):
        v = str(value).strip().upper()
        if op == "add" and not re.fullmatch(r"[A-Z]{2}", v):
            raise RuntimeError("国コード(ISO 3166-1 alpha-2、例: JP)を指定してください")
    else:
        v = str(value).strip()
        if op == "add":
            v = validate_ip_or_cidr(v)
    lst = policy.setdefault(kind, [])
    if op == "add":
        if len(lst) >= 500:
            raise RuntimeError("登録できるのは500件までです")
        if v not in lst:
            lst.append(v)
    elif op == "remove":
        policy[kind] = [i for i in lst if i != v]
    else:
        raise RuntimeError("不明な操作です")
