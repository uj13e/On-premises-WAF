# -*- coding: utf-8 -*-
"""waf_org.py: 組織の木と、誰がどのバックエンドを見られるかの判定

  ベンダー(提供元): 最初から1つだけ登録済み。削除・種類変更・親の指定はできない
   ├ 直接契約(direct)        自社のWEBだけを持つ(SOC在中でもよい)
   └ 中間企業(intermediary)   他社のWEBを預かる
        └ エンドユーザー企業(enduser) 中間企業の配下にだけ存在する

  ・cfg["orgs"] に組織の一覧、バックエンド(プロファイル)に "org"、ユーザーに "org" / "scope" を持たせる
  ・見える範囲は自分の組織とその下。アナリストは scope(担当する組織IDの一覧)とその下
  ・割り当てが無いアナリストには何も見せない
  ・保存期間は組織、バックエンドの順に決める。組織が未割り当てのバックエンドは自動削除しない(既存ログを守る)
"""
import json
import os
import re
import time

VENDOR_ID = "vendor"
ORG_TYPES = {"vendor": "ベンダー(提供元)", "direct": "直接契約", "intermediary": "中間企業", "enduser": "エンドユーザー企業"}
ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
DEFAULT_RETENTION_DAYS = 30          # 通過を含む個別ログ
DEFAULT_ATTACK_RETENTION_DAYS = 180   # 攻撃のまとめログ
MAX_RETENTION_DAYS = 3650
MAX_ORGS = 500


def _clip(v, n):
    return str(v or "").strip()[:n]


def clean_retention(v):
    """保存期間(日)。0/空 = 指定なし(上位の設定に従う)。範囲外は ValueError"""
    if v in (None, "", 0, "0"):
        return 0
    try:
        n = int(v)
    except (TypeError, ValueError):
        raise ValueError("保存期間は日数(数字)で指定してください")
    if n < 1 or n > MAX_RETENTION_DAYS:
        raise ValueError(f"保存期間は 1〜{MAX_RETENTION_DAYS} 日で指定してください")
    return n


def ensure_vendor(orgs):
    """組織の一覧の先頭にベンダー(提供元)の組織を必ず1つ置く(無ければ補う)。元の一覧は変更しない"""
    orgs = [o for o in (orgs or []) if isinstance(o, dict)]
    if any(o.get("id") == VENDOR_ID for o in orgs):
        return orgs
    return [{"id": VENDOR_ID, "name": "ベンダー(自社)", "type": "vendor", "parent": "", "retention_days": 0,
             "retention_attack_days": 0, "mask_analyst": True}] + orgs


def is_vendor_user(user):
    """ベンダー(提供元)側のユーザーか。所属がベンダー組織、または古い形式の provider フラグ"""
    return bool(user) and (str(user.get("org") or "") == VENDOR_ID or bool(user.get("provider")))


def normalize_orgs(orgs):
    """組織の一覧を検証して正規形にする。不正なら ValueError。ベンダー組織は必ず先頭に1つ含む"""
    if orgs in (None, ""):
        orgs = []
    if not isinstance(orgs, list):
        raise ValueError("組織の一覧が正しくありません")
    orgs = ensure_vendor(orgs)
    if len(orgs) > MAX_ORGS:
        raise ValueError(f"組織は {MAX_ORGS} 件までです")
    out, by = [], {}
    for d in orgs:
        if not isinstance(d, dict):
            raise ValueError("組織の形式が正しくありません")
        oid = _clip(d.get("id"), 40)
        if not ID_RE.match(oid):
            raise ValueError("組織IDは英小文字・数字・_・- の1〜32文字で、先頭は英数字にしてください(フォルダ名に使います)")
        if oid in by:
            raise ValueError(f"{oid}: 組織IDが重複しています")
        typ = _clip(d.get("type"), 20)
        if typ not in ORG_TYPES:
            raise ValueError(f"{oid}: 種類は direct / intermediary / enduser のどれかです")
        if (typ == "vendor") != (oid == VENDOR_ID):
            raise ValueError("ベンダー(提供元)の組織は、ID「vendor」の1つだけです(種類の変更・追加はできません)")
        o = {"id": oid, "name": _clip(d.get("name"), 60) or oid, "type": typ, "parent": _clip(d.get("parent"), 40),
             "retention_days": clean_retention(d.get("retention_days")),
             "retention_attack_days": clean_retention(d.get("retention_attack_days")),
             # アナリストに見せるログの機微情報(Cookie・認証・パスワード等)を伏せるか。既定は伏せる
             "mask_analyst": True}                 # 常に伏せる(選べない)
        out.append(o)
        by[oid] = o
    for o in out:
        p = o["parent"]
        if o["type"] == "enduser":
            if p not in by or by[p]["type"] != "intermediary":
                raise ValueError(f"{o['id']}: エンドユーザー企業は中間企業の配下に置いてください")
        elif p:
            raise ValueError(f"{o['id']}: ベンダー・直接契約・中間企業は最上位に置きます(親は指定できません)")
    return out


def by_id(orgs):
    return {o["id"]: o for o in (orgs or []) if isinstance(o, dict) and o.get("id")}


def closure(orgs, ids):
    """ids の組織と、その配下すべての組織ID"""
    ids = {i for i in (ids or ()) if i}
    out = set(ids)
    changed = True
    while changed:
        changed = False
        for o in orgs or ():
            if o.get("parent") in out and o["id"] not in out:
                out.add(o["id"])
                changed = True
    return out


def org_path(orgs, org_id):
    """フォルダ用のパス。エンドユーザーは '中間企業/自社'、それ以外は '自社'。未割り当ては '_unassigned'"""
    b = by_id(orgs)
    o = b.get(org_id)
    if not o:
        return "_unassigned"
    return f"{o['parent']}/{o['id']}" if o.get("parent") in b else o["id"]


def user_org(user, users=()):
    return str((user or {}).get("org") or "")


def backend_org(prof, users=()):
    """バックエンドの所属組織。未設定の古いデータだけ、登録した人(owner)の所属組織を移行用に使う"""
    o = str((prof or {}).get("org") or "")
    if o:
        return o
    owner = (prof or {}).get("owner")
    if owner:
        for u in users or ():
            if u.get("username") == owner and u.get("org"):
                return str(u["org"])
    return ""


def uncovered_orgs(orgs, users):
    """担当アナリスト(提供元アナリスト以外)がいない組織のID。
    提供元アナリスト(provider=true)がこれらを自動で担当する(直接契約でSOCなしの組織の一次対応)
    """
    covered = set()
    for u in users or ():
        if isinstance(u, dict) and u.get("role") == "analyst" and not is_vendor_user(u):
            covered |= closure(orgs, u.get("scope") or [])
    return {o.get("id") for o in orgs or () if o.get("id") and o.get("id") not in covered}


def scope_orgs(orgs, user, users=None):
    """そのユーザーが見られる組織ID。管理者(または認証なし)は None=すべて
    提供元アナリスト(provider)は、明示した担当範囲に加えて担当アナリストがいない組織も担当する(users を渡したとき)
    """
    if user is None or user.get("role") == "admin":
        return None
    role = user.get("role")
    if role == "key_officer":
        if is_vendor_user(user):                            # ベンダー側のキー・オフィサー: 全組織(今後増える分も)を担当する
            return {o.get("id") for o in orgs if isinstance(o, dict) and o.get("id")}
        return closure(orgs, user.get("scope") or [])       # 担当する組織(と配下)だけ。担当なしなら何も見えない
    if role == "analyst":
        base = user.get("scope") or []
        if is_vendor_user(user) and users is not None:
            return closure(orgs, base) | uncovered_orgs(orgs, users)
    else:
        base = [user.get("org")] if user.get("org") else []
    return closure(orgs, base)


def scope_backends(orgs, profiles, user, users=(), removed=()):
    """見られるバックエンドID。None=すべて(管理者)
    接続先は組織に紐づく。一般ユーザーは所属組織(と配下)、アナリストは担当範囲の組織のものだけ。
    登録した人(owner)は見える範囲に影響しない
    """
    so = scope_orgs(orgs, user, users)
    if so is None:
        return None
    ids = set()
    for p in list(profiles or ()) + list(removed or ()):
        if backend_org(p, users) in so:
            ids.add(p.get("id"))
    ids.discard(None)
    ids.discard("")
    return frozenset(ids)


def retention_for(orgs, prof, users=()):
    """このバックエンドのログを何日残すか。None=自動削除しない(組織未割り当て・無期限)
    優先順はバックエンド個別の設定、組織の設定、既定(90日)。組織に属さないものは自動削除しない
    """
    oid = backend_org(prof, users)
    o = by_id(orgs).get(oid)
    if not o:
        return None
    n = int((prof or {}).get("retention_days") or 0) or int(o.get("retention_days") or 0) or DEFAULT_RETENTION_DAYS
    return n


def attack_retention_for(orgs, org_id):
    """その組織の攻撃のまとめログを何日残すか(組織の設定、なければ既定180日)"""
    o = by_id(orgs).get(org_id) or {}
    return int(o.get("retention_attack_days") or 0) or DEFAULT_ATTACK_RETENTION_DAYS


def mask_for_analyst(orgs, prof, users=()):
    """このバックエンドのログをアナリストに見せるとき、機微情報を伏せるか。組織未割り当ては伏せる"""
    o = by_id(orgs).get(backend_org(prof, users))
    return True                                  # アナリストには常に伏せる(組織ごとの設定は廃止)


# ---------------------------------------------------------------------------
# 保存期間(古い行の削除)と書き出し
# ---------------------------------------------------------------------------
def _ts_epoch(ts):
    try:
        return time.mktime(time.strptime(str(ts)[:19].replace("T", " "), "%Y-%m-%d %H:%M:%S"))
    except (ValueError, TypeError):
        return None


def prune_log(path, limits, lock=None, now=None):
    """waf.log から、保存期間(日)を過ぎた行を取り除く。limits = {バックエンドID: 日数}(載っていないものは残す)
    WAFの書き込みと衝突しないよう lock を共有し、同じファイルをその場で書き直す。削除した行数を返す
    """
    import contextlib
    if not limits or not path or not os.path.exists(path):
        return 0
    now = now if now is not None else time.time()
    # limits の値は日数、または (通過の日数, 攻撃の日数)。攻撃の行は攻撃の日数で判定する
    def _cut(d):
        a, k = (d if isinstance(d, (tuple, list)) else (d, d))
        return (now - int(a) * 86400 if a else None, now - int(k) * 86400 if k else None)
    cutoff = {b: _cut(d) for b, d in limits.items() if d}
    _ATK = ("BLOCK", "DETECT", "RATELIMIT", "BAN")
    removed = 0
    with (lock if lock is not None else contextlib.nullcontext()):
        keep = []
        with open(path, "rb") as f:
            for raw in f:
                drop = False
                try:
                    e = json.loads(raw)
                    if isinstance(e, dict):
                        c = cutoff.get(e.get("backend") or "")
                        if c is not None:
                            c = c[1] if str(e.get("action") or "").upper() in _ATK else c[0]
                            t = _ts_epoch(e.get("ts"))
                            drop = c is not None and t is not None and t < c
                except ValueError:
                    pass
                if drop:
                    removed += 1
                else:
                    keep.append(raw)
        if removed:
            with open(path, "r+b") as f:
                f.seek(0)
                f.write(b"".join(keep))
                f.truncate()
    return removed


def export_org_logs(log_path, orgs, profiles, org_id, out_root, users=()):
    """組織(と配下)のログを out_root/<組織パス>/<バックエンドID>/waf.log に書き出す(解約・データ返却用)
    {バックエンドID: 行数} を返す
    """
    so = closure(orgs, [org_id])
    if org_id not in by_id(orgs):
        raise ValueError("組織が見つかりません")
    targets = {p["id"]: org_path(orgs, backend_org(p, users)) for p in profiles if backend_org(p, users) in so}
    files, counts = {}, {}
    try:
        with open(log_path, "rb") as f:
            for raw in f:
                try:
                    e = json.loads(raw)
                    b = (e.get("backend") or "") if isinstance(e, dict) else ""
                except ValueError:
                    continue
                if b in targets:
                    if b not in files:
                        d = os.path.join(out_root, targets[b], b)
                        os.makedirs(d, exist_ok=True)
                        files[b] = open(os.path.join(d, "waf.log"), "wb")
                    files[b].write(raw if raw.endswith(b"\n") else raw + b"\n")
                    counts[b] = counts.get(b, 0) + 1
    except FileNotFoundError:
        pass                                     # ログが無ければ書き出す行も無い
    finally:
        for fh in files.values():
            fh.close()
    return counts


# ---------------------------------------------------------------------------
# 設定への適用(Runtime / FileConfigControl 共通)
# ---------------------------------------------------------------------------
def orgs_view(cfg):
    """画面用: 組織の一覧、バックエンドの所属と保存期間、ユーザーの所属"""
    orgs = ensure_vendor(cfg.get("orgs"))
    users = (cfg.get("dashboard") or {}).get("users") or []
    profs = cfg.get("backends") or []
    return {"orgs": [dict(o) for o in orgs], "types": ORG_TYPES, "default_retention_days": DEFAULT_RETENTION_DAYS,
            "default_attack_retention_days": DEFAULT_ATTACK_RETENTION_DAYS,
            "backends": [{"id": p.get("id"), "name": p.get("name") or p.get("id"), "owner": p.get("owner") or "",
                          "org": p.get("org") or "", "org_effective": backend_org(p, users),
                          "retention_days": int(p.get("retention_days") or 0),
                          "retention_effective": retention_for(orgs, p, users),
                          "attack_retention_effective": attack_retention_for(orgs, backend_org(p, users)) if backend_org(p, users) in by_id(orgs) else None}
                         for p in profs],
            "users": [{"username": u.get("username"), "role": u.get("role"), "org": u.get("org") or "",
                       "scope": u.get("scope") or []} for u in users if isinstance(u, dict)]}


def orgs_op(cfg, up):
    """組織まわりの1操作を cfg に適用する。保存は呼び出し側で行う。変更内容(履歴用)を返す。不正なら ValueError
    op: add_org / update_org / delete_org / assign_backend / set_backend_retention
    """
    op = str((up or {}).get("op") or "")
    orgs = [dict(o) for o in ensure_vendor(cfg.get("orgs"))]
    b = by_id(orgs)
    profs = cfg.get("backends") or []
    ent = {"op": op}
    if op == "add_org":
        o = {"id": _clip(up.get("id"), 40), "name": up.get("name"), "type": up.get("type"), "parent": up.get("parent"),
             "retention_days": up.get("retention_days"), "retention_attack_days": up.get("retention_attack_days"),
             "mask_analyst": True}
        orgs.append(o)
        cfg["orgs"] = normalize_orgs(orgs)
        ent["org"] = o["id"]
    elif op == "update_org":
        oid = _clip(up.get("id"), 40)
        if oid not in b:
            raise ValueError("組織が見つかりません")
        if oid == VENDOR_ID and (up.get("type", "vendor") != "vendor" or up.get("parent")):
            raise ValueError("ベンダー(提供元)の種類と親は変更できません")
        for k in ("name", "type", "parent", "retention_days", "retention_attack_days"):
            if k in up:
                b[oid][k] = up[k]
        cfg["orgs"] = normalize_orgs(orgs)
        ent["org"] = oid
    elif op == "delete_org":
        oid = _clip(up.get("id"), 40)
        if oid not in b:
            raise ValueError("組織が見つかりません")
        if oid == VENDOR_ID:
            raise ValueError("ベンダー(提供元)の組織は削除できません")
        if any(o.get("parent") == oid for o in orgs):
            raise ValueError("配下に組織があるため削除できません")
        users = (cfg.get("dashboard") or {}).get("users") or []
        if any(p.get("org") == oid for p in profs) or any(u.get("org") == oid or oid in (u.get("scope") or []) for u in users):
            raise ValueError("この組織に割り当てられたバックエンドまたはユーザーがあるため削除できません")
        cfg["orgs"] = [o for o in orgs if o["id"] != oid]
        ent["org"] = oid
    elif op == "assign_backend":
        bid = _clip(up.get("backend"), 40)
        oid = _clip(up.get("org"), 40)
        p = next((x for x in profs if x.get("id") == bid), None)
        if p is None:
            raise ValueError("バックエンドが見つかりません")
        if oid and oid not in b:
            raise ValueError("組織が見つかりません")
        ent.update(backend=bid, org=oid, before=p.get("org") or "")
        p["org"] = oid
    elif op == "set_backend_retention":
        bid = _clip(up.get("backend"), 40)
        p = next((x for x in profs if x.get("id") == bid), None)
        if p is None:
            raise ValueError("バックエンドが見つかりません")
        n = clean_retention(up.get("retention_days"))
        ent.update(backend=bid, retention_days=n, before=int(p.get("retention_days") or 0))
        p["retention_days"] = n
    else:
        raise ValueError("操作の指定が不正です")
    return ent
