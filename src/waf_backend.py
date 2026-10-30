"""防御するバックエンド(転送先)の定義・検証・選択・リンク書き換え・接続テスト。標準ライブラリのみ。
プロファイルを複数保存し、1つを「使用中」にする(再起動不要で切替)。
「ホスト名で振り分け」をONにすると、Host ヘッダごとに別のバックエンドへ転送する。
ローカル・LAN内・インターネット上のサイトに対応。別ドメインを経由させるため、Location・Cookie の Domain・ページ内の絶対URLを WAF のアドレスに書き換える。
"""
import http.client
import ipaddress
import json
import re
import socket
import ssl
import time
import zlib
from urllib.parse import urlparse

DEFAULT_PORTS = {"http": 80, "https": 443}
MAX_PROFILES = 30
MAX_REWRITE_BYTES = 8 * 1024 * 1024         # これを超える本文は書き換えない
# 書き換え対象のContent-Type(本文を文字列として扱えるもの)
_TEXT_CT = ("text/", "javascript", "json", "xml", "svg", "x-www-form-urlencoded")

_LABEL_RE = re.compile(r"^[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$")


# ---------------------------------------------------------------------------
# 検証・正規化
# ---------------------------------------------------------------------------
def _clean_host(h):
    h = str(h or "").strip().strip("[]").lower().rstrip(".")
    if not h:
        raise ValueError("ホスト名(またはIP)が空です")
    try:
        ipaddress.ip_address(h)
        return h
    except ValueError:
        pass
    if len(h) > 253 or not all(_LABEL_RE.match(p) for p in h.split(".")):
        raise ValueError(f"ホスト名が正しくありません: {h[:60]}")
    return h


def parse_url(text):
    """'https://example.com:8443/health' / '192.168.1.10:8080' / 'example.com' などを dict(scheme, host, port, path) に分解する"""
    s = str(text or "").strip()
    if not s:
        raise ValueError("URLが空です")
    scheme = "http"
    m = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*)://(.*)$", s)
    if m:
        scheme = m.group(1).lower()
        s = m.group(2)
    if scheme not in ("http", "https"):
        raise ValueError("http:// か https:// のURLだけ指定できます")
    if any(ch in s for ch in " \t\r\n\\@") or "\x00" in s:
        raise ValueError("URLに使えない文字が含まれています(ユーザー名@は指定できません)")
    hostport, _, rest = s.partition("/")
    path = "/" + rest if rest else "/"
    path = path.split("#")[0]
    if hostport.startswith("["):                                # IPv6
        end = hostport.find("]")
        if end < 0:
            raise ValueError("IPv6アドレスの括弧が閉じていません")
        host, tail = hostport[1:end], hostport[end + 1:]
        port_s = tail[1:] if tail.startswith(":") else ""
    elif hostport.count(":") == 1:
        host, _, port_s = hostport.partition(":")
    else:
        host, port_s = hostport, ""
    host = _clean_host(host)
    if port_s:
        if not port_s.isdigit() or not (1 <= int(port_s) <= 65535):
            raise ValueError("ポート番号は 1〜65535 で指定してください")
        port = int(port_s)
    else:
        port = DEFAULT_PORTS[scheme]
    return {"scheme": scheme, "host": host, "port": port, "path": path[:200]}


def _slug(name):
    s = re.sub(r"[^a-z0-9]+", "-", str(name).lower()).strip("-")
    return s[:32]


def normalize_profile(d, used_ids=None):
    """画面や設定ファイルからの1件を検証して正規形にする。不正なら ValueError"""
    if not isinstance(d, dict):
        raise ValueError("バックエンドの設定が正しくありません")
    d = dict(d)
    if d.get("url"):                                   # URL1本での指定は分解して使う
        u = parse_url(d["url"])
        d.update(scheme=u["scheme"], host=u["host"], port=u["port"])
        if not d.get("health_path") and u["path"] != "/":
            d["health_path"] = u["path"]
    scheme = str(d.get("scheme", "http")).lower()
    if scheme not in ("http", "https"):
        raise ValueError("スキームは http か https です")
    host = _clean_host(d.get("host"))
    try:
        port = int(d.get("port") or DEFAULT_PORTS[scheme])
    except (TypeError, ValueError):
        raise ValueError("ポート番号が正しくありません")
    if not (1 <= port <= 65535):
        raise ValueError("ポート番号は 1〜65535 で指定してください")
    name = str(d.get("name") or "").strip()[:40] or f"{host}:{port}"
    rid = str(d.get("id") or "")
    pid = _slug(name if (not rid or rid.startswith("tmp-")) else rid) or "backend"
    used = used_ids if used_ids is not None else set()
    base, n = pid, 2
    while pid in used:
        pid = f"{base}-{n}"
        n += 1
    used.add(pid)
    hp = str(d.get("health_path") or "/").strip()
    if not hp.startswith("/") or any(ch in hp for ch in " \r\n\x00"):
        raise ValueError("稼働チェックのパスは / から始めて指定してください")
    mh = d.get("match_hosts") or []
    if isinstance(mh, str):
        mh = [x for x in re.split(r"[,\s]+", mh) if x]
    hosts = []
    for x in mh[:20]:
        x = str(x).strip().lower().split(":")[0].rstrip(".")
        if x:
            hosts.append(_clean_host(x))
    hh = d.get("host_header", "target")
    lp_raw = d.get("listen_port", 0)
    try:
        lp = int(lp_raw) if str(lp_raw).strip() not in ("", "None") else 0
    except (TypeError, ValueError):
        raise ValueError("専用の待受ポートは数字で指定してください")
    if lp and not (1 <= lp <= 65535):
        raise ValueError("専用の待受ポートは 1〜65535 で指定してください(0か空欄で専用ポートなし)")
    pp = normalize_path_prefix(d.get("path_prefix", ""))
    return {
        "id": pid, "name": name, "scheme": scheme, "host": host, "port": port,
        "verify_tls": bool(d.get("verify_tls", scheme == "https" and not _is_private_host(host))),
        "health_path": hp[:200],
        "match_hosts": hosts,
        "host_header": hh if hh in ("target", "client") else "target",
        "listen_port": lp,          # 0=専用ポートなし(メインの待受ポートで受ける) / 1〜65535=専用の待受ポート
        "path_prefix": pp,          # ""=パス振り分けなし / "/shop" 等=そのパス配下を受け持つ(共有ポート)
        "strip_prefix": bool(d.get("strip_prefix", True)),   # 転送時にプレフィックスを外すか
        "color": (str(d.get("color") or "").strip() if re.match(r"^#[0-9a-fA-F]{6}$", str(d.get("color") or "").strip()) else ""),   # ログ等で使う表示色
        "ip_policy": clean_ip_policy(d.get("ip_policy")),   # このバックエンドだけに効くIP/国の制限
        "owner": str(d.get("owner") or "").strip()[:32],     # このバックエンドを登録したユーザー(その人だけがログを見られる)
        "stopped": bool(d.get("stopped", False)),            # True=稼働停止中(転送せず 503 メンテナンスを返す)
        # 転送時に付ける X-Forwarded-* ヘッダ。外部サイトでリダイレクトを繰り返すことがあるので、個別にOFFにできる
        "xf_host": bool(d.get("xf_host", True)),
        "xf_proto": bool(d.get("xf_proto", True)),
        "xf_for": bool(d.get("xf_for", True)),
        # このバックエンドの防御モード上書き。""=全体設定に従う / "block"=遮断 / "detect"=検知のみ(攻撃を通す)
        "mode_override": (str(d.get("mode_override") or "").strip()
                          if str(d.get("mode_override") or "").strip() in ("block", "detect") else ""),
        # 上書きの自動解除時刻(エポック秒)。0=期限なし。過ぎたら全体設定に戻る
        "mode_until": _clean_epoch(d.get("mode_until")),
        # True=管理者がモードをロックし、一般ユーザーは変更できない
        "mode_lock": bool(d.get("mode_lock", False)),
        # このバックエンドだけのルール設定(管理者が設定。設定画面の保存では変えない)
        "rule_disabled": _clean_ids(d.get("rule_disabled")),      # このバックエンドでは使わないルールID
        "rule_detect": _clean_ids(d.get("rule_detect")),          # このバックエンドでは検知のみにするルールID
        "rule_block": _clean_ids(d.get("rule_block")),            # プリセットでは検知のみのルールを、このバックエンドでは遮断に上げるID
        "rule_preset": clean_preset(d.get("rule_preset")),        # ルールのモードプリセット("" = 全ルール遮断)
        "preset_allowed": clean_preset_allowed(d.get("preset_allowed")),   # アナリストが選べるプリセット(空=すべて。管理者が接続先ごとに決める)
        "exclusions": clean_exclusions(d.get("exclusions")),      # 場所を絞った除外(期限つき)
        # 所属組織と保存期間(提供元の管理者が割り当てる。設定画面の保存では変えない)
        "org": (str(d.get("org") or "").strip() if re.match(r"^[a-z0-9][a-z0-9_-]{0,31}$", str(d.get("org") or "").strip()) else ""),
        "retention_days": _clean_days(d.get("retention_days")),
    }


def _clean_epoch(v):
    try:
        f = float(v)
    except (TypeError, ValueError):
        return 0
    return f if f > 0 else 0


_RULE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,40}$")


def _clean_ids(v):
    out = []
    for x in (v or [])[:500]:
        x = str(x).strip()
        if _RULE_ID_RE.match(x) and x not in out:
            out.append(x)
    return out


def _clean_days(v):
    try:
        n = int(v or 0)
    except (TypeError, ValueError):
        return 0
    return n if 1 <= n <= 3650 else 0


# ---------------------------------------------------------------------------
# ルールのモードプリセット(接続先ごとに選ぶ。保存するのはプリセット名と個別の上書きだけ)
#   rule_preset="" は全ルール遮断。新規の接続先は "standard"。
#   遮断/検知のみは、プリセットの基準と rule_block(遮断に上げる) / rule_detect(検知のみに下げる)で決まる。
#   critical の6件はプリセットでは常に遮断。検知のみ・使わないにできるのは管理者だけ(アナリスト・一般は不可)。
# ---------------------------------------------------------------------------
CRITICAL_IDS = ("XSS-001", "XSS-002", "XXE-001", "PROTO-001", "PROTO-002", "RESP-001")
DEFAULT_NEW_PRESET = "standard"
PRESETS = {
    "standard": {"name": "標準", "base": "standard", "block_add": [], "detect_add": [],
                 "desc": "critical・highは遮断、mediumは検知のみ。迷ったらこれ。"},
    "strict": {"name": "厳格", "base": "strict", "block_add": [], "detect_add": [],
               "desc": "LOGIC-006(エントロピー検出)以外はすべて遮断。誤検知より防御を優先する接続先向け。"},
    "post": {"name": "投稿・入力型", "base": "standard",
             "desc": "ブログ・掲示板・CMS・問い合わせフォーム向け。本文に出やすい表記(iframe/svg・{{ }}・シェル記号など)は検知のみに下げ、保存型XSSの典型(document.cookie・eval・alert 等)は遮断に上げる。",
             "detect_add": ["XSS-007", "XSS-008", "XSS-010", "XSS-020", "XSS-021", "SSTI-001", "SSTI-002", "SSTI-003", "CMDI-001"],
             "block_add": ["XSS-011", "XSS-012", "XSS-013", "XSS-014", "XSS-023"]},
    "api": {"name": "API型", "base": "standard",
            "desc": "JSON/REST/GraphQL向け。GraphQLのintrospection・{{ }}・Base64は検知のみに下げ、画面のないAPIでは攻撃以外にほぼ出ないSQLi系・NoSQL・プロトタイプ汚染・SSRF・デシリアライズ等は遮断に上げる。",
            "detect_add": ["PROTO-006", "XSS-021", "SSTI-002", "LOGIC-003"],
            "block_add": ["SQLI-006", "SQLI-009", "SQLI-013", "NOSQL-003", "PROTO-005", "PROTO-007", "SSRF-003", "DES-003", "XXE-004"]},
    "upload": {"name": "ファイル受付型", "base": "standard",
               "desc": "アップロード・画像/文書の共有向け。ファイルの中身が難読化に見えて起きる誤検知(LOGIC-001〜003)は検知のみに下げ、多重拡張子・Webshell・ファイルラッパー・NULLバイト・XML/デシリアライズ攻撃は遮断に上げる。",
               "detect_add": ["LOGIC-001", "LOGIC-002", "LOGIC-003"],
               "block_add": ["UP-002", "UP-003", "LFI-004", "LFI-005", "XXE-004", "DES-003"]},
}
PRESET_ORDER = ("standard", "strict", "post", "api", "upload")
_RULE_SEV = {}


def _rule_sev():
    """ルールID別の深刻度(組み込みの103ルール)"""
    if not _RULE_SEV:
        import waf_rules
        for r in waf_rules.list_rules():
            _RULE_SEV[r["id"]] = r["severity"]
    return _RULE_SEV


def preset_modes(preset):
    """プリセットの基準 {ルールID: "block"|"detect"}。preset が "" なら全ルール遮断"""
    sev = _rule_sev()
    if preset not in PRESETS:
        return {r: "block" for r in sev}
    p = PRESETS[preset]
    if p["base"] == "strict":
        m = {r: ("detect" if r == "LOGIC-006" else "block") for r in sev}
    else:
        m = {r: ("detect" if v == "medium" else "block") for r, v in sev.items()}
    for r in p.get("detect_add") or ():
        if r in m:
            m[r] = "detect"
    for r in p.get("block_add") or ():
        if r in m:
            m[r] = "block"
    for r in CRITICAL_IDS:
        m[r] = "block"
    return m


def preset_counts(preset):
    m = preset_modes(preset)
    return {"block": sum(1 for v in m.values() if v == "block"), "detect": sum(1 for v in m.values() if v == "detect"), "total": len(m)}


def effective_modes(prof):
    """バックエンドごとのルール別モード {ルールID: "block"|"detect"|"off"}。
    critical の6件も管理者の上書き(検知のみ・使わない)は反映する。アナリスト・一般は設定できない
    """
    m = preset_modes((prof or {}).get("rule_preset") or "")
    for r in (prof or {}).get("rule_detect") or ():
        if r in m:
            m[r] = "detect"
    for r in (prof or {}).get("rule_block") or ():
        if r in m:
            m[r] = "block"
    for r in (prof or {}).get("rule_disabled") or ():
        if r in m:
            m[r] = "off"
    return m


def detect_ids(prof):
    """このバックエンドで検知のみにするルールID(プリセット + 上書き)。カスタムルールなど組み込み外のIDは rule_detect に従う"""
    ids = {r for r, v in effective_modes(prof).items() if v == "detect"}
    ids |= {r for r in ((prof or {}).get("rule_detect") or ()) if r not in _rule_sev() and r not in CRITICAL_IDS}
    return ids


def preset_overrides(prof):
    """プリセットの基準と違うルールの数と一覧。「標準(+3件変更)」の表示用"""
    base = preset_modes((prof or {}).get("rule_preset") or "")
    eff = effective_modes(prof)
    diff = sorted(r for r in eff if eff[r] != base.get(r))
    return diff


def clean_preset(v):
    v = str(v or "").strip()
    return v if v in PRESETS else ""


def clean_preset_allowed(v):
    out = []
    for x in (v or []):
        x = str(x).strip()
        if x in PRESETS and x not in out:
            out.append(x)
    return out


def preset_snapshot(prof):
    """元に戻す用の控え。プリセット名と上書きだけ"""
    return {"rule_preset": (prof or {}).get("rule_preset") or "",
            "rule_disabled": list((prof or {}).get("rule_disabled") or []),
            "rule_detect": list((prof or {}).get("rule_detect") or []),
            "rule_block": list((prof or {}).get("rule_block") or []),
            "exclusions": [dict(e) for e in ((prof or {}).get("exclusions") or [])]}


def clean_exclusions(v):
    """場所を絞った除外の一覧を検証して返す。不正な項目は捨てる
    {id, rule(ルールID。"*"=全ルール), path_prefix("/editor" など。""=全パス), until(エポック秒。0=期限なし),
     mode("off"=そのパスではルールを使わない / "detect"=そのパスでは検知のみ), reason, by, at, ticket}
    """
    out = []
    for e in (v or [])[:200]:
        if not isinstance(e, dict):
            continue
        rule = str(e.get("rule") or "").strip()
        if rule != "*" and not _RULE_ID_RE.match(rule):
            continue
        pp = str(e.get("path_prefix") or "").strip()
        if pp and (not pp.startswith("/") or any(ch in pp for ch in " ?#\r\n\x00\\")):
            continue
        out.append({"id": str(e.get("id") or "")[:20], "rule": rule, "path_prefix": pp[:200],
                    "until": _clean_epoch(e.get("until")), "mode": ("detect" if e.get("mode") == "detect" else "off"),
                    "reason": str(e.get("reason") or "")[:200],
                    "by": str(e.get("by") or "")[:40], "at": str(e.get("at") or "")[:25],
                    "by_role": ("analyst" if e.get("by_role") == "analyst" else ""),   # アナリストが作った除外は、全ルール(*)でもcriticalには効かない
                    "ticket": str(e.get("ticket") or "")[:20]})
    return out


def _exclusion_match(e, rule_id, path, now):
    if e["rule"] != "*" and e["rule"] != rule_id:
        return False
    if e["rule"] == "*" and rule_id in CRITICAL_IDS and e.get("by_role") == "analyst":
        return False
    if e["until"] and now >= e["until"]:
        return False
    pp = e["path_prefix"]
    return (not pp) or match_path(pp.rstrip("/") or "/", path) or (pp == "/")


def apply_rule_overrides_ex(prof, hits, path):
    """バックエンド別の設定を一致結果に適用する。(残す一致, 除外した件数, このパスで検知のみにするルールID) を返す。
    rule_disabled と「使わない」の除外(ルール × パス)に当たる一致は取り除く。「検知のみ」の除外に当たる一致は残し、遮断の対象から外す(ログには DETECT)
    """
    if not prof or not hits:
        return hits, 0, set()
    dis = set(prof.get("rule_disabled") or ())       # critical も、管理者が「使わない」にしたものは外す
    exs = prof.get("exclusions") or ()
    if not dis and not exs:
        return hits, 0, set()
    now = time.time()
    kept, det = [], set()
    for h in hits:
        rid = h.get("id")
        if rid in dis:
            continue
        ms = [e for e in exs if _exclusion_match(e, rid, path or "/", now)]
        if any(e.get("mode") != "detect" for e in ms):
            continue
        if ms:
            det.add(rid)
        kept.append(h)
    return kept, len(hits) - len(kept), det


def apply_rule_overrides(prof, hits, path):
    """apply_rule_overrides_ex の旧形式。(残す一致, 除外した件数) を返す"""
    kept, n, _det = apply_rule_overrides_ex(prof, hits, path)
    return kept, n


def effective_mode(cfg, prof):
    """このバックエンドに適用される防御モード。期限内のバックエンド上書きがあればそれ、なければ全体設定(cfg['mode'])。
    期限切れの上書きは全体設定として扱う
    """
    glob = cfg.get("mode", "block")
    if not prof:
        return glob
    ov = prof.get("mode_override") or ""
    if ov not in ("block", "detect"):
        return glob
    until = prof.get("mode_until") or 0
    try:
        if until and time.time() >= float(until):
            return glob
    except (TypeError, ValueError):
        return glob
    return ov


def append_mode_history(cfg, entry):
    """防御モードの変更履歴を1行追記する(誰が・いつ・何を)。失敗は無視"""
    path = cfg.get("mode_history_file", "mode_history.jsonl")
    if not path:
        return
    try:
        rec = dict(entry)
        rec.setdefault("time", time.strftime("%Y-%m-%dT%H:%M:%S"))
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError:
        pass


def read_mode_history(path, limit=100):
    """防御モードの変更履歴を新しい順に返す"""
    if not path:
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except OSError:
        return []
    out = []
    for line in lines[-max(1, int(limit)) * 2:]:
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    out.reverse()
    return out[:limit]


POLICY_KEYS = ("blocklist", "ip_allowlist", "country_blocklist", "country_allowlist")


def clean_ip_policy(p):
    """バックエンド別のIP/国の制限を検証して返す。不正な項目は捨てる"""
    out = {k: [] for k in POLICY_KEYS}
    if not isinstance(p, dict):
        return out
    for k in ("blocklist", "ip_allowlist"):
        for v in (p.get(k) or [])[:500]:
            v = str(v).strip()
            try:
                if "/" in v:
                    ipaddress.ip_network(v, strict=False)
                else:
                    ipaddress.ip_address(v)
            except ValueError:
                continue
            if v not in out[k]:
                out[k].append(v)
    for k in ("country_blocklist", "country_allowlist"):
        for v in (p.get(k) or [])[:300]:
            v = str(v).strip().upper()
            if re.fullmatch(r"[A-Z]{2}", v) and v not in out[k]:
                out[k].append(v)
    return out


def normalize_path_prefix(v):
    """パス振り分けのプレフィックスを正規化する("/shop/" を "/shop" に)。空なら ""、不正なら ValueError"""
    v = str(v or "").strip()
    if not v or v == "/":
        return ""
    if not v.startswith("/") or any(ch in v for ch in " ?#\r\n\x00\\"):
        raise ValueError("パス振り分けのプレフィックスは / から始めて指定してください(例: /shop)")
    v = "/" + "/".join(x for x in v.split("/") if x)
    if len(v) > 100:
        raise ValueError("パス振り分けのプレフィックスが長すぎます")
    return v


def normalize_backend_settings(up, current=None, reserved_ports=()):
    """画面からの {active, host_routing, rewrite_links, profiles:[...]} を検証して返す"""
    if not isinstance(up, dict):
        raise ValueError("バックエンド設定が正しくありません")
    cur = current or {}
    profiles = up.get("profiles", cur.get("profiles"))
    if not isinstance(profiles, list) or not profiles:
        raise ValueError("バックエンドを1つ以上登録してください")
    if len(profiles) > MAX_PROFILES:
        raise ValueError(f"登録できるのは{MAX_PROFILES}件までです")
    used, out = set(), []
    for p in profiles:
        out.append(normalize_profile(p, used))
    # 防御モードの上書き(mode_override/mode_until/mode_lock)は設定画面では変更させない。
    # 既存バックエンドは現在の値を引き継ぎ、新規は上書きなし。変更は be_mode だけが行う。
    cur_by_id = {str(p.get("id")): p for p in (cur.get("profiles") or [])}
    for i, p in enumerate(out if current is not None else []):    # current なし(起動時の読み込み)は保存済みの値をそのまま使う
        src = cur_by_id.get(str(profiles[i].get("id") or ""))
        ov = str((src or {}).get("mode_override") or "")
        p["mode_override"] = ov if ov in ("block", "detect") else ""
        p["mode_until"] = _clean_epoch((src or {}).get("mode_until"))
        p["mode_lock"] = bool((src or {}).get("mode_lock"))
        p["rule_disabled"] = _clean_ids((src or {}).get("rule_disabled"))
        p["rule_detect"] = _clean_ids((src or {}).get("rule_detect"))
        p["rule_block"] = _clean_ids((src or {}).get("rule_block"))
        p["rule_preset"] = clean_preset((src or {}).get("rule_preset")) if src is not None else DEFAULT_NEW_PRESET    # 新規の接続先は「標準」、既存は変えない
        p["preset_allowed"] = clean_preset_allowed((src or {}).get("preset_allowed"))
        p["exclusions"] = clean_exclusions((src or {}).get("exclusions"))
        so = str((src if src is not None else p).get("org") or "")      # 既存は現在値を維持(変更は組織タブ)、新規は指定値
        p["org"] = so if re.match(r"^[a-z0-9][a-z0-9_-]{0,31}$", so) else ""
        p["retention_days"] = _clean_days((src or {}).get("retention_days"))
    ids = [p["id"] for p in out]
    # 振り分け用ホスト名は、バックエンド間で重複させない
    seen = {}
    for p in out:
        for h in p["match_hosts"]:
            if h in seen and seen[h] != p["id"]:
                raise ValueError(f"振り分けホスト名「{h}」が複数のバックエンドに指定されています")
            seen[h] = p["id"]
    # パス振り分け: 重複なし
    seen_pp = {}
    for p in out:
        pp = p.get("path_prefix") or ""
        if not pp:
            continue
        if pp in seen_pp:
            raise ValueError(f"パス振り分け {pp} が「{seen_pp[pp]}」と「{p['name']}」で重複しています")
        seen_pp[pp] = p["name"]
    # 専用の待受ポート: 重複なし。メインの待受ポートやダッシュボードのポートとも重複なし
    reserved = {int(x) for x in (reserved_ports or ()) if x}
    seen_lp = {}
    for p in out:
        lp = int(p.get("listen_port") or 0)
        if not lp:
            continue
        if lp in reserved:
            raise ValueError(f"「{p['name']}」の待受ポート {lp} は、WAF本体かダッシュボードが使っています")
        if lp in seen_lp:
            raise ValueError(f"待受ポート {lp} が「{seen_lp[lp]}」と「{p['name']}」で重複しています")
        seen_lp[lp] = p["name"]
    active = up.get("active", cur.get("active"))
    # 画面は元のidで送ってくるので、名前から作ったidと食い違わないよう元のidも許す
    orig_ids = [str(p.get("id") or "") for p in profiles]
    if active in ids:
        pass
    elif active in orig_ids:
        active = ids[orig_ids.index(active)]
    else:
        active = ids[0]
    return {
        "profiles": out, "active": active,
        "host_routing": bool(up.get("host_routing", cur.get("host_routing", False))),
        "rewrite_links": bool(up.get("rewrite_links", cur.get("rewrite_links", True))),
    }


def check_not_loop(profile, listen_host, listen_port, extra_ports=()):
    """WAF自身を転送先にすると無限ループになる。同じ端末のWAF待受ポート(メイン+各バックエンド専用)を指していたら ValueError"""
    own_ports = {int(listen_port)} | {int(x) for x in (extra_ports or ()) if x}
    if int(profile["port"]) not in own_ports:
        return
    port = int(profile["port"])
    h = profile["host"]
    own = {"localhost", "127.0.0.1", "::1", "0.0.0.0", str(listen_host or "").lower(),
           socket.gethostname().lower()}
    if h in own:
        raise ValueError(f"「{profile['name']}」はWAF自身({h}:{port})を指しています。ループするので指定できません")
    try:
        ip = ipaddress.ip_address(h)
        local_ips = {ai[4][0] for ai in socket.getaddrinfo(socket.gethostname(), None)}
        if ip.is_loopback or str(ip) in local_ips:
            raise ValueError(f"「{profile['name']}」はこの端末のWAF待受ポート({h}:{port})を指しています。ループするので指定できません")
    except ValueError as e:
        if "ループ" in str(e):
            raise
    except OSError:
        pass


def _is_private_host(h):
    try:
        ip = ipaddress.ip_address(h)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return h == "localhost" or h.endswith((".local", ".lan", ".internal", ".home.arpa"))


# ---------------------------------------------------------------------------
# 設定からの取得・選択
# ---------------------------------------------------------------------------
def legacy_profile(cfg):
    host = cfg.get("backend_host", "127.0.0.1")
    scheme = cfg.get("backend_scheme", "https")
    return {"id": "default", "name": "既定のバックエンド", "scheme": scheme, "host": host,
            "port": int(cfg.get("backend_port", 5000)),
            "verify_tls": bool(cfg.get("backend_verify_tls", False)),
            "health_path": cfg.get("health_check", {}).get("backend_path", "/") if isinstance(cfg.get("health_check"), dict) else "/",
            "match_hosts": [], "host_header": "target", "listen_port": 0}


def get_profiles(cfg):
    ps = cfg.get("backends")
    if isinstance(ps, list) and ps:
        return ps
    return [legacy_profile(cfg)]


def raw_profiles(cfg):
    """休止中(持ち主が未ログイン)も含む、保存済みの全バックエンド"""
    ps = cfg.get("backends")
    return ps if isinstance(ps, list) else []


def active_profile(cfg):
    ps = get_profiles(cfg)
    aid = cfg.get("active_backend")
    for p in ps:
        if p.get("id") == aid:
            return p
    return ps[0]


def listen_ports(cfg):
    """専用の待受ポートを持つバックエンド {ポート: プロファイル}"""
    out = {}
    for p in get_profiles(cfg):
        lp = int(p.get("listen_port") or 0)
        if lp:
            out[lp] = p
    return out


def pick_for_port(cfg, port):
    """接続を受けたポートだけで転送先が決まるとき(専用ポート、またはホスト名振り分けOFF)はそのプロファイル。
    ホスト名振り分けの共有ポートで Host が未確定なら None
    """
    if port:
        p = listen_ports(cfg).get(int(port))
        if p is not None:
            return p
    if cfg.get("host_routing") or path_routes(cfg):
        return None
    return active_profile(cfg)


def path_routes(cfg):
    """パス振り分けを持つバックエンド。長いプレフィックス順 [(prefix, profile)]"""
    out = [(p.get("path_prefix"), p) for p in get_profiles(cfg)
           if p.get("path_prefix") and not int(p.get("listen_port") or 0)]
    out.sort(key=lambda x: -len(x[0]))
    return out


def match_path(prefix, path):
    path = path or "/"
    return path == prefix or path.startswith(prefix + "/")


def forward_path(p, path):
    """転送先へ渡すパス。strip_prefix ならプレフィックスを外す"""
    pp = p.get("path_prefix") or ""
    if pp and p.get("strip_prefix", True) and match_path(pp, path):
        return path[len(pp):] or "/"
    return path


def prefix_location(p, value):
    """プレフィックスを外して転送したとき、バックエンドが返した / 始まりのリダイレクト先にプレフィックスを戻す"""
    pp = p.get("path_prefix") or ""
    if not pp or not p.get("strip_prefix", True) or not value:
        return value
    if value.startswith("/") and not value.startswith("//") and not match_path(pp, value.split("?")[0]):
        return pp + value
    return value


def pick(cfg, req_host=None, port=None, path=None):
    """このリクエストの転送先。優先順は (1)専用の待受ポート (2)パス振り分け(最長一致) (3)ホスト名振り分けON かつ一致 (4)「使用中」"""
    if port:
        p = listen_ports(cfg).get(int(port))
        if p is not None:
            return p
    if path is not None:
        for pp, p in path_routes(cfg):
            if match_path(pp, path):
                return p
    if cfg.get("host_routing") and req_host:
        h = str(req_host).strip().lower()
        h = h[1:h.find("]")] if h.startswith("[") and "]" in h else h.split(":")[0]
        h = h.rstrip(".")
        for p in get_profiles(cfg):
            if h and h in (p.get("match_hosts") or ()):
                return p
    return active_profile(cfg)


def tag(p):
    """ログに付けるバックエンドの印(idと表示名)"""
    return {"backend": p["id"], "backend_name": p["name"]}


def sync_legacy(cfg):
    """旧キー(backend_host など)を「使用中」に合わせる。古い読み方をする箇所のため"""
    p = active_profile(cfg)
    cfg["backend_host"], cfg["backend_port"] = p["host"], p["port"]
    cfg["backend_scheme"], cfg["backend_verify_tls"] = p["scheme"], p["verify_tls"]


def public_view(cfg):
    """画面に出す形"""
    return {"profiles": [dict(p) for p in get_profiles(cfg)],
            "active": active_profile(cfg)["id"],
            "host_routing": bool(cfg.get("host_routing", False)),
            "rewrite_links": bool(cfg.get("backend_rewrite_links", True))}


def apply_to_cfg(cfg, settings):
    cfg["backends"] = settings["profiles"]
    cfg["active_backend"] = settings["active"]
    cfg["host_routing"] = settings["host_routing"]
    cfg["backend_rewrite_links"] = settings["rewrite_links"]
    sync_legacy(cfg)


def origin(p):
    h = p["host"]
    if ":" in h:
        h = f"[{h}]"
    port = int(p["port"])
    return f"{p['scheme']}://{h}" + ("" if port == DEFAULT_PORTS[p["scheme"]] else f":{port}")


def host_header(p):
    h = p["host"]
    if ":" in h:
        h = f"[{h}]"
    port = int(p["port"])
    return h if port == DEFAULT_PORTS[p["scheme"]] else f"{h}:{port}"


def make_conn(p, timeout=30):
    if p["scheme"] == "https":
        ctx = ssl.create_default_context()
        if not p.get("verify_tls"):
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return http.client.HTTPSConnection(p["host"], p["port"], context=ctx, timeout=timeout)
    return http.client.HTTPConnection(p["host"], p["port"], timeout=timeout)


# ---------------------------------------------------------------------------
# 書き換え(別ドメインのサイトを WAF 経由で使えるようにする)
# ---------------------------------------------------------------------------
def _origin_variants(p):
    """バックエンドの絶対URLの書き方(http/https、既定ポートの有無)を全部集める"""
    h = p["host"]
    hh = f"[{h}]" if ":" in h else h
    port = int(p["port"])
    out = []
    for sch in ("https", "http"):
        out.append(f"{sch}://{hh}:{port}")
        if port == DEFAULT_PORTS[p["scheme"]]:
            out.append(f"{sch}://{hh}")
    return sorted(set(out), key=len, reverse=True)       # 長い順(部分一致で壊さないため)


def client_origin(scheme, req_host, fallback):
    return f"{scheme}://{(req_host or fallback)}"


def strip_xf(headers, p):
    """転送ヘッダから、この接続先で「付けない」設定の X-Forwarded-* を取り除く(クライアントが付けた分も)"""
    off = {k for k, key in (("x-forwarded-host", "xf_host"), ("x-forwarded-proto", "xf_proto"),
                            ("x-forwarded-for", "xf_for")) if p.get(key, True) is False}
    return {k: v for k, v in headers.items() if k.lower() not in off}


def is_self_redirect(location, req_host, req_path):
    """Location が今のリクエストURL自身を指しているか(スキームと既定ポートの違いは無視)。
    WAF が Location を自分のアドレスに書き換えるので、これが続くとブラウザが無限にリダイレクトする
    """
    if not location:
        return False
    try:
        u = urlparse(location)
    except ValueError:
        return False
    path = (u.path or "/") + (("?" + u.query) if u.query else "")
    want = req_path if req_path.startswith("/") else "/" + req_path
    if not u.netloc:                          # 相対(/ や ./ から始まる)
        return path == want
    def norm(h):
        h = h.lower()
        return h[:-3] if h.endswith(":80") or h.endswith(":443") else h
    return norm(u.netloc) == norm(req_host) and path == want


def rewrite_location(value, p, c_origin):
    for v in _origin_variants(p):
        if value.lower().startswith(v.lower()) and (len(value) == len(v) or value[len(v)] in "/?#"):
            return c_origin + value[len(v):]
    return value


def rewrite_set_cookie(value):
    """Domain=元サイト は WAF のホストでは無効なので外す(ホスト限定の Cookie にする)"""
    parts = [x for x in value.split(";")]
    keep = [parts[0]] + [x for x in parts[1:] if not x.strip().lower().startswith("domain=")]
    return ";".join(keep)


def is_text_ct(content_type):
    ct = (content_type or "").lower()
    return any(t in ct for t in _TEXT_CT)


def accept_encoding_for_rewrite(value):
    """書き換えのため、標準ライブラリで展開できる gzip/deflate だけを要求する。br/zstd は外す"""
    toks = [t.strip() for t in str(value or "").split(",") if t.strip()]
    keep = [t for t in toks if t.split(";")[0].strip().lower() in ("gzip", "x-gzip", "deflate", "identity")]
    return ", ".join(keep) if keep else "identity"


def decompress(body, encoding):
    """gzip/deflate を展開する。展開後が上限超え、または壊れていれば None"""
    enc = (encoding or "").lower()
    try:
        d = zlib.decompressobj(16 + zlib.MAX_WBITS if "gzip" in enc else zlib.MAX_WBITS)
        out = d.decompress(body, MAX_REWRITE_BYTES + 1)
        if len(out) > MAX_REWRITE_BYTES or d.unconsumed_tail:
            return None
        return out
    except zlib.error:
        if "deflate" in enc:                     # 生のdeflate(zlibヘッダなし)
            try:
                d = zlib.decompressobj(-zlib.MAX_WBITS)
                out = d.decompress(body, MAX_REWRITE_BYTES + 1)
                return out if len(out) <= MAX_REWRITE_BYTES and not d.unconsumed_tail else None
            except zlib.error:
                return None
        return None


def can_rewrite_body(content_type, content_encoding, length):
    ct = (content_type or "").lower()
    return (not content_encoding and length and length <= MAX_REWRITE_BYTES
            and any(t in ct for t in _TEXT_CT))


def rewrite_body(body, p, c_origin):
    """本文中の元サイトの絶対URLを WAF のアドレスに書き換える。バイト列のまま扱い、文字コードは壊さない"""
    c_host = c_origin.split("://", 1)[1]
    for v in _origin_variants(p):
        vb = v.encode()
        if vb in body:
            body = body.replace(vb, c_origin.encode())
        esc = v.replace("/", "\\/").encode()                     # JSON内の https:\/\/host
        if esc in body:
            body = body.replace(esc, c_origin.replace("/", "\\/").encode())
    # プロトコル相対(//host/path)
    h = p["host"]
    hh = f"[{h}]" if ":" in h else h
    port = int(p["port"])
    for hp in {f"{hh}:{port}", hh} if port == DEFAULT_PORTS[p["scheme"]] else {f"{hh}:{port}"}:
        pat = re.compile(rb"(?<=[\"'(=\s])//" + re.escape(hp.encode()) + rb"(?![\w.\-])", re.I)
        body = pat.sub(b"//" + c_host.encode(), body)
    return body


def rewrite_request_header_value(value, c_origin, p):
    """Origin / Referer 内の WAF のアドレスを、元サイトのアドレスに戻す"""
    return value.replace(c_origin, origin(p)) if value else value


# ---------------------------------------------------------------------------
# 接続テスト(設定画面の「接続テスト」ボタン)
# ---------------------------------------------------------------------------
_HINTS = (
    ("CERTIFICATE_VERIFY_FAILED", "証明書を検証できません。自己署名や社内CAの場合は「TLS証明書を検証する」をOFFにしてください"),
    ("self-signed", "自己署名証明書です。「TLS証明書を検証する」をOFFにすると接続できます"),
    ("Hostname mismatch", "証明書のホスト名が一致しません。IPで接続している場合は「TLS証明書を検証する」をOFFにしてください"),
    ("WRONG_VERSION_NUMBER", "相手がHTTPSではないようです。http:// を試してください"),
    ("record layer failure", "相手がHTTPSではないようです。http:// を試してください"),
    ("Connection refused", "接続を拒否されました。ホスト/ポートと、相手のアプリが起動しているかを確認してください"),
    ("actively refused", "接続を拒否されました。ホスト/ポートと、相手のアプリが起動しているかを確認してください"),
    ("timed out", "時間内に応答がありません。ホスト/ポート、ファイアウォール、ネットワークを確認してください"),
    ("getaddrinfo failed", "ホスト名を解決できません。名前の綴りとDNSを確認してください"),
    ("Name or service not known", "ホスト名を解決できません。名前の綴りとDNSを確認してください"),
    ("Network is unreachable", "ネットワークに届きません。経路(VPN/ゲートウェイ)を確認してください"),
    ("No route to host", "ネットワークに届きません。経路(VPN/ゲートウェイ)を確認してください"),
)


def _hint(msg):
    for key, text in _HINTS:
        if key.lower() in msg.lower():
            return text
    return ""


def test_profile(p, timeout=6.0):
    """DNS、TCP、(TLS)、HTTP の順に確認して、失敗した段階を返す"""
    res = {"ok": False, "stage": "dns", "url": origin(p) + p.get("health_path", "/"), "ms": None,
           "ip": None, "tls": None, "status": None, "location": None, "error": "", "hint": ""}
    t0 = time.perf_counter()
    try:
        infos = socket.getaddrinfo(p["host"], p["port"], type=socket.SOCK_STREAM)
        res["ip"] = infos[0][4][0]
        res["stage"] = "tcp"
        s = socket.create_connection(infos[0][4][:2], timeout=timeout)
        s.close()
        if p["scheme"] == "https":
            res["stage"] = "tls"
            tls = {"verified": None, "subject": "", "issuer": "", "not_after": "", "error": ""}
            # 1) 検証つきで試して、証明書として正しいか調べる(結果は表示するだけ)
            try:
                ctx = ssl.create_default_context()
                with socket.create_connection((p["host"], p["port"]), timeout=timeout) as raw:
                    with ctx.wrap_socket(raw, server_hostname=p["host"]) as ss:
                        cert = ss.getpeercert()
                tls["verified"] = True
                tls["subject"] = _dn(cert.get("subject"))
                tls["issuer"] = _dn(cert.get("issuer"))
                tls["not_after"] = cert.get("notAfter", "")
            except ssl.SSLError as e:
                tls["verified"] = False
                tls["error"] = (getattr(e, "verify_message", "") or str(e))[:160]
            except OSError as e:
                tls["error"] = str(e)[:160]
            res["tls"] = tls
            if p.get("verify_tls") and tls["verified"] is False:
                raise ssl.SSLError(tls["error"] or "CERTIFICATE_VERIFY_FAILED")
        res["stage"] = "http"
        conn = make_conn(p, timeout)
        try:
            conn.request("GET", p.get("health_path", "/"),
                         headers={"Host": host_header(p), "User-Agent": "waf-backend-test/1.0",
                                  "Accept": "*/*", "Connection": "close"})
            r = conn.getresponse()
            r.read(2048)
            res["status"] = r.status
            res["location"] = r.getheader("Location")
        finally:
            conn.close()
        res["ok"] = True
        res["stage"] = "done"
        try:
            res["loop"] = probe_redirect_loop(p, timeout)
        except Exception as e:                     # 追加の診断が失敗しても、接続テストの結果は変えない
            res["loop"] = {"error": f"{type(e).__name__}: {e}"[:160]}
    except Exception as e:
        res["error"] = f"{type(e).__name__}: {e}"[:200]
        res["hint"] = _hint(res["error"])
    res["ms"] = round((time.perf_counter() - t0) * 1000.0, 1)
    return res


_XF_SAMPLE = {"X-Forwarded-Host": "waf.example:8080", "X-Forwarded-Proto": "https", "X-Forwarded-For": "203.0.113.10"}
_XF_KEYS = {"X-Forwarded-Host": "xf_host", "X-Forwarded-Proto": "xf_proto", "X-Forwarded-For": "xf_for"}


def _probe_once(p, path, extra, timeout):
    conn = make_conn(p, timeout)
    try:
        hdr = {"Host": host_header(p), "User-Agent": "Mozilla/5.0 (waf-backend-test)", "Accept": "*/*", "Connection": "close"}
        hdr.update(extra)
        conn.request("GET", path, headers=hdr)
        r = conn.getresponse()
        r.read(1024)
        loc = r.getheader("Location") or ""
        return {"status": r.status, "location": loc,
                "self": 300 <= r.status < 400 and is_self_redirect(loc, host_header(p), path)}
    finally:
        conn.close()


def probe_redirect_loop(p, timeout=6.0, path="/"):
    """WAF が付ける転送ヘッダ付きで「/」を取得し、自分自身へのリダイレクト(WAF経由でループ)になるか調べる。
    ループなら、転送ヘッダなし/1つずつ付けた場合も試して、原因のヘッダを特定する
    """
    cur = {k: v for k, v in _XF_SAMPLE.items() if p.get(_XF_KEYS[k], True)}
    out = {"path": path, "with_headers": _probe_once(p, path, cur, timeout), "culprits": [], "ok_without": None, "hint": ""}
    w = out["with_headers"]
    if not w["self"]:
        return out
    base = _probe_once(p, path, {}, timeout)
    out["ok_without"] = not base["self"]
    if not base["self"]:
        for k in cur:
            if _probe_once(p, path, {k: cur[k]}, timeout)["self"]:
                out["culprits"].append(k)
        if not out["culprits"]:
            out["culprits"] = list(cur)             # 単独では再現しない。組み合わせが原因なので、付けている全部を疑う
        offs = " / ".join({"X-Forwarded-Host": "X-Forwarded-Host", "X-Forwarded-Proto": "X-Forwarded-Proto",
                           "X-Forwarded-For": "X-Forwarded-For"}[k] for k in out["culprits"])
        out["hint"] = (f"WAF 経由だとリダイレクトを繰り返します。原因は転送ヘッダ({offs})です。"
                       "この接続先の「編集」で、該当する転送ヘッダを OFF にしてください。")
    else:
        out["hint"] = ("転送ヘッダを付けなくても、このサイトは「/」を自分自身へリダイレクトしています。"
                       "Hostヘッダ(「アクセスされたホスト名のまま渡す」)や接続先のスキーム/ポートの指定を見直してください。")
    return out


def _dn(seq):
    try:
        return ", ".join(f"{k}={v}" for rdn in seq for (k, v) in rdn)[:160]
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# バックエンド別のルール設定(無効化 / 検知のみ / 場所を絞った除外)の操作
# ---------------------------------------------------------------------------
def get_be_rules(cfg):
    """管理者の画面用。バックエンドごとのルール設定の一覧"""
    out = []
    now = time.time()
    for p in get_profiles(cfg):
        out.append({"id": p["id"], "name": p["name"], "owner": p.get("owner") or "", "org": p.get("org") or "",
                    "rule_disabled": list(p.get("rule_disabled") or []),
                    "rule_detect": list(p.get("rule_detect") or []),
                    "rule_block": list(p.get("rule_block") or []),
                    "rule_preset": p.get("rule_preset") or "",
                    "preset_allowed": list(p.get("preset_allowed") or []),
                    "preset_diff": preset_overrides(p),
                    "modes": effective_counts(p),
                    "eff_detect": sorted(r for r, v in effective_modes(p).items() if v == "detect"),
                    "eff_off": sorted(r for r, v in effective_modes(p).items() if v == "off"),
                    "exclusions": [dict(e, expired=bool(e["until"] and now >= e["until"])) for e in (p.get("exclusions") or [])]})
    return out


def effective_counts(prof):
    m = effective_modes(prof)
    return {"block": sum(1 for v in m.values() if v == "block"), "detect": sum(1 for v in m.values() if v == "detect"),
            "off": sum(1 for v in m.values() if v == "off"), "total": len(m)}


def presets_view():
    """プリセットの一覧(画面用)。名前・説明・遮断/検知のみの数・標準との差分"""
    out = []
    std = preset_modes("standard")
    for k in PRESET_ORDER:
        p = PRESETS[k]
        c = preset_counts(k)
        m = preset_modes(k)
        out.append({"id": k, "name": p["name"], "desc": p["desc"], "block": c["block"], "detect": c["detect"], "total": c["total"],
                    "to_detect": sorted(r for r in m if m[r] == "detect" and std[r] == "block"),
                    "to_block": sorted(r for r in m if m[r] == "block" and std[r] == "detect")})
    return {"presets": out, "critical": list(CRITICAL_IDS),
            "legacy": {"id": "", "name": "従来(全ルール遮断)", **{k: v for k, v in preset_counts("").items()}}}


def impact_items(items, prof, preset, global_detect=(), cap=20000):
    """items: (パス, 一致の一覧) のイテレータ。今の設定と、preset を当てた状態(個別の上書きは含めない)を比べる。
    戻り値: {scanned, to_block(今は遮断されず、遮断になる件数), to_pass(今は遮断で、遮断されなくなる件数), top}
    """
    cur = effective_modes(prof)
    alt_prof = dict(prof or {})
    alt_prof["rule_preset"] = preset
    alt_prof["rule_detect"], alt_prof["rule_block"] = [], []
    alt = effective_modes(alt_prof)
    gd = set(global_detect or ())
    scanned = to_block = to_pass = 0
    ex = {}
    for path, hits in items:
        if not hits:
            continue
        scanned += 1
        if scanned > cap:
            scanned = cap
            break
        kept, _n, pdet = apply_rule_overrides_ex(prof, hits, path or "/")
        if not kept:
            continue
        def blocks(modes):
            return any(modes.get(h.get("id"), "block") == "block" and h.get("id") not in pdet and h.get("id") not in gd for h in kept)
        a_, b_ = blocks(cur), blocks(alt)
        if b_ and not a_:
            to_block += 1
            for h in kept:
                if alt.get(h.get("id")) == "block" and cur.get(h.get("id")) != "block":
                    ex[h["id"]] = ex.get(h["id"], 0) + 1
        elif a_ and not b_:
            to_pass += 1
            for h in kept:
                if cur.get(h.get("id")) == "block" and alt.get(h.get("id")) != "block":
                    ex[h["id"]] = ex.get(h["id"], 0) + 1
    top = sorted(ex.items(), key=lambda kv: -kv[1])[:5]
    return {"scanned": scanned, "to_block": to_block, "to_pass": to_pass, "top": [{"rule": k, "n": v} for k, v in top]}


def impact_of(events, prof, preset, cap=20000):
    """記録済みのヒットだけから影響を数える(再検査しない)。events: 辞書のイテレータ({path, hits:[{id}]})"""
    return impact_items(((e.get("path") or "/", e.get("hits") or []) for e in events), prof, preset, cap=cap)


def be_rules_op(cfg, up, by=""):
    """cfg(raw)のバックエンドにルール設定の変更を1件適用し、変更内容(履歴用の dict)を返す。不正なら ValueError
    up = {backend, op: disable|enable|detect|block|add_exclusion|remove_exclusion, rule, path_prefix, minutes, mode(detect|off。add_exclusion のみ), reason, ticket, exclusion}
    """
    bid = str(up.get("backend") or "")
    prof = next((p for p in (cfg.get("backends") or []) if p.get("id") == bid), None)
    if prof is None:
        raise ValueError("バックエンドが見つかりません")
    op = str(up.get("op") or "")
    rule = str(up.get("rule") or "").strip()
    role = str(up.get("_role") or "admin")           # 呼び出し側(ダッシュボード)が操作者の権限を渡す。内部呼び出しは管理者扱い
    ent = {"backend": bid, "backend_name": prof.get("name") or bid, "by": by, "op": op, "rule": rule,
           "before": preset_snapshot(prof)}           # 「1つ前に戻す」用に、変更前のプリセット名と上書きを保存
    if op in ("disable", "enable", "detect", "block"):
        if not _RULE_ID_RE.match(rule):
            raise ValueError("ルールIDを指定してください")
        if op in ("disable", "detect") and rule in CRITICAL_IDS and role != "admin":
            raise ValueError(f"{rule} は critical のため、検知のみ・使わないにできるのは管理者だけです(管理者に申請してください)")
        if op in ("disable", "enable"):
            cur = _clean_ids(prof.get("rule_disabled"))
            cur = ([*cur, rule] if rule not in cur else cur) if op == "disable" else [x for x in cur if x != rule]
            prof["rule_disabled"] = cur
        else:
            # 遮断/検知のみはプリセット基準との差分だけ持つ。基準と同じなら上書きを消す
            base = preset_modes(prof.get("rule_preset") or "").get(rule, "block")
            det = [x for x in _clean_ids(prof.get("rule_detect")) if x != rule]
            blk = [x for x in _clean_ids(prof.get("rule_block")) if x != rule]
            if op == "detect" and base != "detect":
                det.append(rule)
            if op == "block" and base != "block":
                blk.append(rule)
            prof["rule_detect"], prof["rule_block"] = det, blk
    elif op == "set_preset":
        pid = str(up.get("preset") or "")
        if pid not in PRESETS:
            raise ValueError("プリセットの指定が正しくありません")
        allowed = clean_preset_allowed(prof.get("preset_allowed"))
        if role != "admin" and allowed and pid not in allowed:
            raise ValueError("このバックエンドで選べるプリセットは管理者が決めています(選べる範囲外です)")
        keep = bool(up.get("keep_overrides", True))
        prof["rule_preset"] = pid
        if not keep:
            prof["rule_detect"], prof["rule_block"], prof["rule_disabled"] = [], [], []
        ent.update(preset=pid, keep_overrides=keep, rule=PRESETS[pid]["name"])
    elif op == "set_preset_allowed":
        if role != "admin":
            raise ValueError("選べるプリセットの範囲は管理者だけが決められます")
        prof["preset_allowed"] = clean_preset_allowed(up.get("allowed"))
        ent.update(allowed=list(prof["preset_allowed"]), rule="選べる範囲")
    elif op == "undo":
        tg = up.get("_target")
        if not isinstance(tg, dict) or not isinstance(tg.get("before"), dict):
            raise ValueError("戻せる変更がありません")
        b = tg["before"]
        prof["rule_preset"] = clean_preset(b.get("rule_preset"))
        prof["rule_disabled"] = _clean_ids(b.get("rule_disabled"))
        prof["rule_detect"] = _clean_ids(b.get("rule_detect"))
        prof["rule_block"] = _clean_ids(b.get("rule_block"))
        prof["exclusions"] = clean_exclusions(b.get("exclusions"))
        ent.update(rule=str(tg.get("op") or "")[:30], undone_time=str(tg.get("time") or ""), undone_op=str(tg.get("op") or ""),
                   undone_rule=str(tg.get("rule") or "")[:40])
    elif op == "add_exclusion":
        if role != "admin" and rule in CRITICAL_IDS:
            raise ValueError(f"{rule} は critical のため、アナリストはパス別の除外にもできません(管理者に申請してください)")
        if rule != "*" and not _RULE_ID_RE.match(rule):
            raise ValueError("除外するルールIDを指定してください(* で全ルール)")
        until = 0
        mins = up.get("minutes")
        if mins not in (None, "", 0, "0"):
            try:
                until = time.time() + max(1, min(60 * 24 * 365, int(mins))) * 60
            except (TypeError, ValueError):
                raise ValueError("期限(分)は数字で指定してください")
        exs = clean_exclusions(prof.get("exclusions"))
        eid = "EX-" + str(int(time.time() * 1000))[-8:]
        e = {"id": eid, "rule": rule, "path_prefix": str(up.get("path_prefix") or "").strip(), "until": until,
             "mode": ("detect" if up.get("mode") == "detect" else "off"),
             "reason": str(up.get("reason") or "")[:200], "by": by, "at": time.strftime("%Y-%m-%dT%H:%M:%S"),
             "by_role": ("analyst" if role == "analyst" else ""),
             "ticket": str(up.get("ticket") or "")[:20]}
        if clean_exclusions([e]) == []:
            raise ValueError("除外のパスは / から始めて指定してください(例: /editor)")
        exs.append(e)
        prof["exclusions"] = exs
        ent.update(exclusion=eid, path_prefix=e["path_prefix"], until=until, reason=e["reason"], ticket=e["ticket"], mode=e["mode"])
    elif op == "remove_exclusion":
        eid = str(up.get("exclusion") or "")
        exs = clean_exclusions(prof.get("exclusions"))
        n = len(exs)
        prof["exclusions"] = [e for e in exs if e["id"] != eid]
        if len(prof["exclusions"]) == n:
            raise ValueError("その除外は見つかりません")
        ent["exclusion"] = eid
    else:
        raise ValueError("操作の指定が不正です")
    return ent
