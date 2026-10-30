# -*- coding: utf-8 -*-
"""waf_logstore.py: ログの保存先を決めて、書く・消す・読む窓口。logs/ のファイルはここ以外から直接開かない

  logs/
   ├ _all/YYYY-MM-DD.log          提供元(管理者)用。全社のログすべて(通過を含む)
   ├ _system/YYYY-MM-DD.log       WEBに属さない記録(握手失敗・不正リクエスト等)
   ├ _unassigned/<WEB>/...        組織に属さないWEBの全ログ(自動削除しない)
   ├ x/                           中間企業X
   │   ├ _all/YYYY-MM-DD.log      Xと配下のログすべて(SOC担当用)
   │   └ b/                       エンドユーザー企業B
   │       ├ _all/YYYY-MM-DD.log  B社のログすべて
   │       └ b1/YYYY-MM-DD.log    WEBの全ログ(通過を含む。元の記録)
   └ a/ ...                       直接契約企業A(同じ構成)

  書き込みは、そのWEBの日次ログ(元の記録)、所属組織と上位組織の _all、提供元の _all の順(1件あたり2〜4か所)。
  まとめがずれても rebuild_rollups() で元の記録から作り直せる。
  保存期間は日付ごとのファイルを古い順に消す。まとめ(_all)は通過の期限を過ぎたら攻撃の行だけに絞り、攻撃の期限で消す。
  ロックはファイル(=WEB)ごと。開くファイル数には上限があり、使い回す。
  フォルダ名 _all は ROLLUP で変えられる(WEBのIDには使えない)
"""
import collections
import csv
import datetime
import heapq
import shutil
import io
import json
import os
import re
import threading
import time

import waf_org

ATTACK_ACTIONS = ("BLOCK", "DETECT", "RATELIMIT", "BAN")
ROLLUP = "_all"                 # 上位組織ごとの「ログすべて」まとめのフォルダ名
DEFAULT_ACCESS_DAYS = 30        # 通過を含む個別ログ
DEFAULT_ATTACK_DAYS = 180       # 攻撃のまとめログ
SYSTEM_DAYS = 30
MAX_HANDLES = 256
EXPORT_ROW_CAP = 100000
_DATE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})\.log$")
_SAFE = re.compile(r"[^A-Za-z0-9_.-]")


def is_attack(rec):
    return str((rec or {}).get("action") or "").upper() in ATTACK_ACTIONS


def _safe(name):
    s = _SAFE.sub("_", str(name or ""))[:64].lstrip(".")
    return s or "_"


def _date_of(rec):
    ts = str((rec or {}).get("ts") or "")
    if re.match(r"^\d{4}-\d{2}-\d{2}", ts):
        return ts[:10]
    return datetime.date.today().isoformat()


class LogStore:
    def __init__(self, root, resolver=None, ttl=2.0):
        """resolver() -> (orgs, profiles, users)。None なら組織なし(すべて _unassigned)"""
        self.root = root
        self.resolver = resolver
        self.ttl = ttl
        self._snap = None
        self._snap_at = 0.0
        self._glock = threading.Lock()
        self._locks = {}
        self._fh = collections.OrderedDict()
        self.errors = 0

    # 組織の解決
    def snapshot(self):
        now = time.monotonic()
        if self._snap is None or now - self._snap_at > self.ttl:
            try:
                orgs, profs, users = self.resolver() if self.resolver else ([], [], [])
            except Exception:
                orgs, profs, users = ([], [], [])
            self._snap = (list(orgs or []), list(profs or []), list(users or []))
            self._snap_at = now
        return self._snap

    def invalidate(self):
        self._snap = None

    def place(self, backend, snap=None):
        """WEBの置き場所 (個別ログのフォルダ, [まとめのフォルダ...])。組織に属さないWEBは _unassigned で、まとめは _all のみ"""
        orgs, profs, users = snap or self.snapshot()
        if not backend:
            return os.path.join(self.root, "_system"), []
        prof = next((p for p in profs if p.get("id") == backend), None)
        oid = waf_org.backend_org(prof, users) if prof else ""
        by = waf_org.by_id(orgs)
        if oid not in by:
            return os.path.join(self.root, "_unassigned", _safe(backend)), [os.path.join(self.root, ROLLUP)]
        parts = waf_org.org_path(orgs, oid).split("/")
        roll = [os.path.join(self.root, *[_safe(x) for x in parts[:i + 1]], ROLLUP) for i in range(len(parts))]
        roll.reverse()                                    # 自分の組織から上位の順
        roll.append(os.path.join(self.root, ROLLUP))
        return os.path.join(self.root, *[_safe(x) for x in parts], _safe(backend)), roll

    # 書き込み
    def _lock(self, path):
        with self._glock:
            lk = self._locks.get(path)
            if lk is None:
                lk = self._locks[path] = threading.Lock()
            return lk

    def _append(self, path, line):
        lk = self._lock(path)
        with lk:
            with self._glock:
                fh = self._fh.get(path)
                if fh is not None:
                    self._fh.move_to_end(path)
            if fh is None or fh.closed or not os.path.exists(path):
                if fh is not None and not fh.closed:
                    try:
                        fh.close()
                    except OSError:
                        pass
                os.makedirs(os.path.dirname(path), exist_ok=True)
                fh = open(path, "a", encoding="utf-8")
                with self._glock:
                    self._fh[path] = fh
                    while len(self._fh) > MAX_HANDLES:
                        _, old = self._fh.popitem(last=False)
                        try:
                            old.close()
                        except OSError:
                            pass
            fh.write(line + "\n")
            fh.flush()

    def write(self, rec, line=None):
        """1件の記録を書く。失敗してもWAFの処理は止めず、False を返す"""
        try:
            line = line or json.dumps(rec, ensure_ascii=False)
            day = _date_of(rec) + ".log"
            folder, rolls = self.place(rec.get("backend") or "")
            self._append(os.path.join(folder, day), line)
            for r in rolls:                                   # まとめにはログすべてを書く(通過を含む)
                self._append(os.path.join(r, day), line)
            return True
        except Exception:
            self.errors += 1
            return False

    def close_all(self):
        with self._glock:
            for fh in self._fh.values():
                try:
                    fh.close()
                except OSError:
                    pass
            self._fh.clear()

    def _drop_handle(self, path):
        with self._glock:
            fh = self._fh.pop(path, None)
        if fh is not None:
            try:
                fh.close()
            except OSError:
                pass

    # 一覧・読み込み
    @staticmethod
    def _day_files(folder, lo=None, hi=None):
        """フォルダ内の日次ログを (日付, パス) の古い順で返す。lo/hi は 'YYYY-MM-DD'(両端を含む)"""
        out = []
        try:
            for n in os.listdir(folder):
                m = _DATE_RE.match(n)
                if m and (lo is None or m.group(1) >= lo) and (hi is None or m.group(1) <= hi):
                    out.append((m.group(1), os.path.join(folder, n)))
        except OSError:
            return []
        return sorted(out)

    # WEBの置き場所の探索。組織を移しても過去ログは元の組織に残るので、全体から探す
    def web_dirs(self):
        """{WEBのフォルダ名: [フォルダ...]}。'' は _system。まとめ(_all)は含まない"""
        out = {}
        for dirpath, dirnames, files in os.walk(self.root):
            base = os.path.basename(dirpath)
            if base == ROLLUP:
                dirnames[:] = []
                continue
            if any(_DATE_RE.match(n) for n in files):
                key = "" if dirpath == os.path.join(self.root, "_system") else base
                out.setdefault(key, []).append(dirpath)
        return out

    def find_dirs(self, backend):
        """このWEBの個別ログのフォルダすべて。現在の置き場所と、過去に別の組織にあった分"""
        want = _safe(backend) if backend else ""
        dirs = list(self.web_dirs().get(want, []))
        cur, _ = self.place(backend)
        if os.path.isdir(cur) and cur not in dirs:
            dirs.append(cur)
        return dirs

    def read_backend(self, backend, lo=None, hi=None, attacks_only=False):
        """WEBの個別ログを日付順に1行ずつ(辞書)返す。組織を移した場合は元の組織の過去分も含む"""
        files = []
        for folder in self.find_dirs(backend):
            files.extend(self._day_files(folder, lo, hi))
        for _day, path in sorted(files):
            try:
                with open(path, "rb") as f:
                    for raw in f:
                        try:
                            e = json.loads(raw)
                        except ValueError:
                            continue
                        if isinstance(e, dict) and (not attacks_only or is_attack(e)):
                            yield e
            except OSError:
                continue

    def reader(self, webs=None, pos=None):
        """ダッシュボード用の読み取り係。webs: 見てよいWEBのid(None=すべて、_systemも)。pos: 続きから読む位置"""
        return Reader(self, webs, pos)

    def total_size(self):
        n = 0
        for _k, folders in self.web_dirs().items():
            for f in folders:
                for _d, p in self._day_files(f):
                    try:
                        n += os.path.getsize(p)
                    except OSError:
                        pass
        return n

    # まとめ(_all)フォルダの一覧と書き換え
    def rollup_folders(self):
        out = []
        for dirpath, dirnames, _files in os.walk(self.root):
            if os.path.basename(dirpath) == ROLLUP:
                out.append(dirpath)
                dirnames[:] = []
        return out

    def _rewrite(self, path, keep):
        """日次ファイルを、keep(行の辞書)が真の行だけに書き直す。行が残らなければ消す。(残った行数, 消した行数)を返す"""
        kept, dropped = [], 0
        try:
            with open(path, "rb") as f:
                for raw in f:
                    try:
                        e = json.loads(raw)
                    except ValueError:
                        kept.append(raw if raw.endswith(b"\n") else raw + b"\n")
                        continue
                    if isinstance(e, dict) and keep(e):
                        kept.append(raw if raw.endswith(b"\n") else raw + b"\n")
                    else:
                        dropped += 1
        except OSError:
            return 0, 0
        if not dropped:
            return len(kept), 0
        lk = self._lock(path)
        with lk:
            self._drop_handle(path)
            try:
                if kept:
                    tmp = path + ".tmp"
                    with open(tmp, "wb") as f:
                        f.write(b"".join(kept))
                    os.replace(tmp, path)
                else:
                    os.remove(path)
            except OSError:
                pass
        return len(kept), dropped

    # 削除(ダッシュボードの「ログ削除」)
    def delete_events(self, backend):
        """backend: WEBのid / '__none'(WEBに属さない記録) / '__all'(すべて)
        個別ログのファイルを消し、まとめ(_all)からもそのWEBの行を取り除く。消した行数(個別ログ分)を返す
        """
        removed = 0
        wd = self.web_dirs()
        if backend == "__all":
            targets = [f for fs in wd.values() for f in fs]
        elif backend == "__none":
            targets = list(wd.get("", []))
        else:
            targets = self.find_dirs(backend)
        for folder in targets:
            for _d, p in self._day_files(folder):
                try:
                    with open(p, "rb") as f:
                        removed += sum(1 for _ in f)
                except OSError:
                    pass
                self._drop_handle(p)
                try:
                    os.remove(p)
                except OSError:
                    pass
        if backend != "__none":
            for folder in self.rollup_folders():
                for _d, p in self._day_files(folder):
                    if backend == "__all":
                        self._drop_handle(p)
                        try:
                            os.remove(p)
                        except OSError:
                            pass
                    else:
                        self._rewrite(p, lambda e, b=backend: (e.get("backend") or "") != b)
        return removed

    # 再構築(元の記録からまとめを作る)
    def rebuild_rollups(self):
        """まとめ(各組織の _all/ と提供元の _all/)をWEBの個別ログから作り直し、行数を返す。
        個別ログがもう無い古い日のまとめ(攻撃の履歴)は触らない
        """
        snap = self.snapshot()
        buckets = {}                                         # まとめ先のフォルダ -> [(ts, 行, 日付)]
        days = set()
        for key, folders in self.web_dirs().items():
            if key == "":
                continue                                     # _system はまとめに入れない
            for folder in folders:
                for day, path in self._day_files(folder):
                    days.add(day)
                    try:
                        with open(path, "rb") as f:
                            for raw in f:
                                try:
                                    e = json.loads(raw)
                                except ValueError:
                                    continue
                                if isinstance(e, dict):
                                    _f, rolls = self.place(e.get("backend") or key, snap)
                                    ln = raw.decode("utf-8", "replace").rstrip("\n")
                                    for r in rolls:
                                        buckets.setdefault(r, []).append((str(e.get("ts") or ""), ln, _date_of(e)))
                    except OSError:
                        continue
        for folder in self.rollup_folders():                 # 個別ログが残っている日のまとめだけ消して作り直す
            for day, p in self._day_files(folder):
                if day in days:
                    self._drop_handle(p)
                    try:
                        os.remove(p)
                    except OSError:
                        pass
        n = 0
        for r, rows in buckets.items():
            rows.sort(key=lambda x: x[0])
            for _ts, ln, day in rows:
                self._append(os.path.join(r, day + ".log"), ln)
                n += 1
        return n

    # 既存 waf.log の一度きりの変換
    def migrate_legacy(self, legacy_path):
        """旧形式の waf.log(1ファイル)を新しい構成へ書き写す。logs/.migrated があれば何もしない。
        成功したら waf.log を waf.log.migrated に改名する(以後 waf.log には書かない)。変換した行数を返す
        """
        mark = os.path.join(self.root, ".migrated")
        if os.path.exists(mark) or not legacy_path or not os.path.exists(legacy_path):
            return 0
        n = 0
        with open(legacy_path, "rb") as f:
            for raw in f:
                try:
                    e = json.loads(raw)
                except ValueError:
                    continue
                if isinstance(e, dict):
                    if self.write(e, raw.decode("utf-8", "replace").rstrip("\n")):
                        n += 1
        os.makedirs(self.root, exist_ok=True)
        with open(mark, "w", encoding="utf-8") as f:
            f.write(json.dumps({"at": datetime.datetime.now().isoformat(timespec="seconds"), "rows": n, "from": os.path.basename(legacy_path)}))
        try:
            os.replace(legacy_path, legacy_path + ".migrated")
        except OSError:
            pass
        return n

    # 旧構成(攻撃だけの attacks/ フォルダ)からの移行
    def upgrade_layout(self):
        """旧構成の攻撃だけのまとめ(attacks/ フォルダ)を消し、_all を個別ログから作り直す。
        WEBのIDが attacks のものがあれば、そのフォルダは消さない。作り直した行数を返す(旧フォルダが無ければ 0)
        """
        _o, profs, _u = self.snapshot()
        ids = {p.get("id") for p in profs}
        olds = []
        for dirpath, dirnames, files in os.walk(self.root):
            if "attacks" in dirnames and "attacks" not in ids:
                olds.append(os.path.join(dirpath, "attacks"))
                dirnames.remove("attacks")
            if os.path.basename(dirpath) == ROLLUP:
                dirnames[:] = []
        if not olds:
            return 0
        for d in olds:
            for _day, p in self._day_files(d):
                self._drop_handle(p)
            shutil.rmtree(d, ignore_errors=True)
        return self.rebuild_rollups()

    # 保存期間(古い日付のファイルを消す)
    def prune(self, today=None):
        """期限を過ぎた日次ファイルを整理する。戻り値は消した/絞ったファイルの数
        個別ログは、組織(のWEB)の保存期間(既定30日)を使い、WEB個別の設定を優先する。組織に属さないWEB(_unassigned)は消さない
        まとめ(_all)は、通過の期限(既定30日)を過ぎたら攻撃の行だけに絞り、攻撃の期限(既定180日)で消す
        提供元の _all は全組織で最長の期限に合わせる。_system は30日
        """
        today = today or datetime.date.today()
        orgs, profs, users = self.snapshot()
        done = 0

        def cut(days):
            return (today - datetime.timedelta(days=int(days))).isoformat()

        def sweep(folder, days):
            nonlocal done
            c = cut(days)
            for day, path in self._day_files(folder, None, None):
                if day < c:
                    self._drop_handle(path)
                    try:
                        os.remove(path)
                        done += 1
                    except OSError:
                        pass

        def thin(folder, access_days, attack_days):
            """通過の期限を過ぎ、攻撃の期限は過ぎていない日は攻撃の行だけ残す。それ以前は消す"""
            nonlocal done
            c_acc, c_atk = cut(access_days), cut(attack_days)
            for day, path in self._day_files(folder, None, None):
                if day < c_atk:
                    self._drop_handle(path)
                    try:
                        os.remove(path)
                        done += 1
                    except OSError:
                        pass
                elif day < c_acc:
                    _kept, dropped = self._rewrite(path, is_attack)
                    if dropped:
                        done += 1
        acc_all, atk_all = DEFAULT_ACCESS_DAYS, DEFAULT_ATTACK_DAYS
        for p in profs:
            bid = p.get("id")
            if not bid or waf_org.backend_org(p, users) not in waf_org.by_id(orgs):
                continue
            folder, _ = self.place(bid, (orgs, profs, users))
            d = waf_org.retention_for(orgs, p, users) or DEFAULT_ACCESS_DAYS
            acc_all = max(acc_all, d)
            sweep(folder, d)
        for o in orgs:
            a_days = waf_org.retention_for(orgs, {"org": o["id"]}, users) or DEFAULT_ACCESS_DAYS
            k_days = waf_org.attack_retention_for(orgs, o["id"])
            atk_all = max(atk_all, k_days)
            acc_all = max(acc_all, a_days)
            thin(self.rollup_dir(o["id"]), a_days, max(k_days, a_days))
        thin(self.rollup_dir(None), acc_all, max(atk_all, acc_all))
        sweep(os.path.join(self.root, "_system"), SYSTEM_DAYS)
        return done

    # 書き出し(管理者・アナリスト)
    def rollup_dir(self, org_id=None):
        """まとめ(_all)のフォルダ。org_id=None は提供元(logs/_all)"""
        if not org_id:
            return os.path.join(self.root, ROLLUP)
        orgs, _p, _u = self.snapshot()
        return os.path.join(self.root, *[_safe(x) for x in waf_org.org_path(orgs, org_id).split("/")], ROLLUP)

    def _read_rollup(self, folders, backends, lo, hi, attacks_only=True):
        want = set(backends)
        for folder in folders:
            for _day, path in self._day_files(folder, lo, hi):
                try:
                    with open(path, "rb") as f:
                        for raw in f:
                            try:
                                e = json.loads(raw)
                            except ValueError:
                                continue
                            if isinstance(e, dict) and (e.get("backend") or "") in want and (not attacks_only or is_attack(e)):
                                yield e
                except OSError:
                    continue

    def export(self, backends, lo=None, hi=None, attacks_only=False, fmt="jsonl", mask=None, cap=EXPORT_ROW_CAP, rollup_dirs=None):
        """指定したWEB(呼び出し側が範囲を絞って渡す)の記録を、期間・種類で絞って書き出す。
        攻撃のみで rollup_dirs(担当範囲の _all フォルダ)が渡されたら、保存期間の長いまとめから攻撃の行を読む。
        mask(e) -> e で伏せる。行数が cap を超えたら打ち切って truncated=True を返す。
        戻り値: (本文bytes, 行数, 打ち切りか, 形式)
        """
        rows, truncated = [], False
        if attacks_only and rollup_dirs is not None:
            sources = [self._read_rollup(rollup_dirs, backends, lo, hi)]
        else:
            sources = [self.read_backend(b, lo, hi, attacks_only) for b in backends]
        for src in sources:
            for e in src:
                if len(rows) >= cap:
                    truncated = True
                    break
                rows.append(mask(e) if mask else e)
            if truncated:
                break
        rows.sort(key=lambda e: str(e.get("ts") or ""))
        if fmt == "csv":
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["ts", "action", "backend", "client_ip", "method", "path", "query", "status", "rules", "disposition", "count"])
            for e in rows:
                req = e.get("req") or {}
                w.writerow([e.get("ts", ""), e.get("action", ""), e.get("backend", ""), e.get("client_ip", ""), e.get("method", ""),
                            e.get("path", ""), req.get("query", e.get("query", "")), e.get("status", ""),
                            ",".join(sorted({h.get("id", "") for h in (e.get("hits") or []) if isinstance(h, dict)})),
                            e.get("disposition", ""), e.get("count", 1)])
            body = ("﻿" + buf.getvalue()).encode("utf-8")            # Excel で文字化けしないよう BOM をつける
        else:
            fmt = "jsonl"
            body = ("\n".join(json.dumps(e, ensure_ascii=False) for e in rows) + ("\n" if rows else "")).encode("utf-8")
        return body, len(rows), truncated, fmt


    # 組織まるごとの書き出し(解約・データ返却用。管理者のみ、マスクなし)
    def export_org_tree(self, org_id, out_root):
        """組織(と配下)のフォルダを out_root/<org>-<日時>/ にそのままコピーする。戻り値: ({WEB: 行数}, 出力先)"""
        orgs, profs, users = self.snapshot()
        if org_id not in waf_org.by_id(orgs):
            raise ValueError("組織が見つかりません")
        dst = os.path.join(out_root, f"{_safe(org_id)}-{time.strftime('%Y%m%d-%H%M%S')}")
        src = os.path.join(self.root, *[_safe(x) for x in waf_org.org_path(orgs, org_id).split("/")])
        counts = {}
        for dirpath, _dn, files in os.walk(src):      # 中間企業のフォルダには配下のエンドユーザーのフォルダも入る
            sub = os.path.relpath(dirpath, self.root)
            for n in files:
                if not _DATE_RE.match(n):
                    continue
                os.makedirs(os.path.join(dst, sub), exist_ok=True)
                shutil.copy2(os.path.join(dirpath, n), os.path.join(dst, sub, n))
                if os.path.basename(dirpath) != ROLLUP:
                    with open(os.path.join(dirpath, n), "rb") as f:
                        k = os.path.basename(dirpath)
                        counts[k] = counts.get(k, 0) + sum(1 for _ in f)
        return counts, dst


class Reader:
    """ログの読み取り位置を持つ係(ダッシュボードの集計・リアルタイム配信ごとに1つ)。
    増えた行だけを時刻順に返す。ファイルが消えた/小さくなったら reset=True を返し、呼び出し側が最初から読み直す
    """
    RESCAN = 2.0

    def __init__(self, store, webs=None, pos=None):
        self.store = store
        self.webs = None if webs is None else {_safe(w) for w in webs}
        self.pos = dict(pos or {})
        self._files = []
        self._scanned = 0.0

    def _allowed(self, key):
        if self.webs is None:
            return True
        return key != "" and key in self.webs

    def _scan(self, force=False):
        now = time.monotonic()
        if not force and self._files and now - self._scanned < self.RESCAN:
            return self._files
        files = []
        for key, folders in self.store.web_dirs().items():
            if self._allowed(key):
                for f in folders:
                    files.extend(self.store._day_files(f))
        self._files = sorted(files)
        self._scanned = now
        return self._files

    def _gen(self, path, end):
        pos = self.pos.get(path, 0)
        try:
            with open(path, "rb") as f:
                f.seek(pos)
                while pos < end:
                    raw = f.readline()
                    if not raw or not raw.endswith(b"\n"):
                        break
                    pos += len(raw)
                    self.pos[path] = pos
                    try:
                        e = json.loads(raw)
                    except ValueError:
                        continue
                    if isinstance(e, dict):
                        yield (str(e.get("ts") or ""), e)
        except OSError:
            return

    def seek_end(self):
        for _d, p in self._scan(True):
            try:
                self.pos[p] = os.path.getsize(p)
            except OSError:
                pass

    def poll(self):
        """(新しいイベントのイテレータ, reset)。reset=True のときは読み直しが必要で、イテレータは空"""
        files = self._scan()
        have = {p for _d, p in files}
        for p in list(self.pos):
            if p not in have:
                if not os.path.exists(p):
                    return iter(()), True          # 保存期間や削除でファイルが消えた
                self.pos.pop(p, None)
        gens = []
        for _d, p in files:
            try:
                size = os.path.getsize(p)
            except OSError:
                continue
            pos = self.pos.get(p, 0)
            if size < pos:
                return iter(()), True              # ファイルが小さくなった
            if size > pos:
                gens.append(self._gen(p, size))
        if not gens:
            return iter(()), False
        return (e for _ts, e in heapq.merge(*gens, key=lambda x: x[0])), False
