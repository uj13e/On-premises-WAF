# -*- coding: utf-8 -*-
"""waf_custom.py: 追加ルール(custom_rules.json)の検証・読み込み・保存・過去ログ検証
標準ルール(waf_rules.py)とは別に、新しい脆弱性への対応などのルールをJSONに置き、WAFを再起動せずに入れ替える。
検証はツールとWAFで同じものを使う。読み込みは全ルールが検証を通ったときだけ一括で入れ替える。保存は一時ファイル経由で、旧版を残す。
新規ルールは既定で検知のみ(detect)。誤検知がないと確認してから block にする。
"""
import datetime
import json
import os
import re
import subprocess
import sys
import threading
import time
from urllib.parse import parse_qsl

import waf_rules

CUSTOM_ID_RE = re.compile(r"^CUS-[A-Za-z0-9_-]{1,32}$")
SEVERITIES = ("critical", "high", "medium", "low")
TARGETS = ("all", "path", "query", "body", "header")
MAX_PATTERN = 500
MAX_RULES = 500

# 入れ子の量指定子(ReDoS の典型)。例: (a+)+  (.*)*  (\w+\s*)+
_NESTED_Q = re.compile(r"\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)\s*(?:[+*]|\{\d+,\d*\})")
_BACKREF = re.compile(r"\\[1-9]|\(\?P=")


def _now():
    return datetime.datetime.now().isoformat(timespec="seconds")


def check_pattern_safety(pattern, timeout=3.0):
    """危険な正規表現を弾く。問題なければ None、あれば理由の文字列"""
    if _NESTED_Q.search(pattern):
        return "入れ子の繰り返し(例: (a+)+)は、処理が極端に重くなるため使えません"
    if _BACKREF.search(pattern):
        return "後方参照は使えません(処理が重くなるため)"
    # 実測: 別プロセスで悪意ある入力に当てて時間を測る。固まっても本体は巻き込まない
    code = (
        "import re,sys,time\n"
        "p=re.compile(sys.argv[1],re.I|re.S)\n"
        "t=time.perf_counter()\n"
        "for s in ('a'*3000,'a'*2999+'!','<'*3000,' '*3000+'x','1'*1500+\"' OR \"+'1'*1500,'%41'*1000,'/'*3000+'..'):\n"
        "    p.search(s)\n"
        "print(time.perf_counter()-t)\n"
    )
    try:
        r = subprocess.run([sys.executable, "-I", "-c", code, pattern], capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return "この正規表現は長い入力で処理が終わりません(重すぎます)"
    except OSError:
        return None            # 実測できない環境では構文・形の検査だけで通す
    if r.returncode != 0:
        return "正規表現の確認に失敗しました"
    try:
        if float(r.stdout.strip() or 0) > 0.5:
            return "この正規表現は長い入力で処理が重すぎます"
    except ValueError:
        pass
    return None


def validate_rule(d, check_safety=True):
    """1件を検証して正規形にする。不正なら ValueError(理由は画面に出せる文)"""
    if not isinstance(d, dict):
        raise ValueError("ルールの形式が正しくありません")
    rid = str(d.get("id") or "").strip()
    if not CUSTOM_ID_RE.match(rid):
        raise ValueError("ルールIDは CUS- で始め、英数字・_・- で指定してください(例: CUS-2026-001)")
    pattern = str(d.get("pattern") or "")
    if not pattern:
        raise ValueError(f"{rid}: 正規表現を入力してください")
    if len(pattern) > MAX_PATTERN:
        raise ValueError(f"{rid}: 正規表現が長すぎます({MAX_PATTERN}文字まで)")
    try:
        re.compile(pattern, re.I | re.S)
    except re.error as e:
        raise ValueError(f"{rid}: 正規表現の構文エラー: {e}")
    if check_safety:
        why = check_pattern_safety(pattern)
        if why:
            raise ValueError(f"{rid}: {why}")
    sev = str(d.get("severity") or "medium").lower()
    if sev not in SEVERITIES:
        raise ValueError(f"{rid}: 重大度は critical/high/medium/low のどれかです")
    target = str(d.get("target") or "all").lower()
    if target not in TARGETS:
        raise ValueError(f"{rid}: 検査対象は all/path/query/body/header のどれかです")
    mode = str(d.get("mode") or "detect").lower()
    if mode not in ("detect", "block"):
        raise ValueError(f"{rid}: モードは detect(検知のみ) か block(遮断) です")
    return {
        "id": rid,
        "name": str(d.get("name") or rid).strip()[:80],
        "pattern": pattern,
        "target": target,
        "severity": sev,
        "mode": mode,
        "enabled": bool(d.get("enabled", True)),
        "description": str(d.get("description") or d.get("name") or rid).strip()[:200],
        "cve": str(d.get("cve") or "").strip()[:40],
        "added_by": str(d.get("added_by") or "")[:40],
        "added_at": str(d.get("added_at") or _now())[:25],
    }


def validate_all(rules, check_safety=True):
    """全体を検証する。ID重複・件数上限も見る。正規化済みの一覧を返し、不正なら ValueError"""
    if not isinstance(rules, list):
        raise ValueError("rules は一覧で指定してください")
    if len(rules) > MAX_RULES:
        raise ValueError(f"追加ルールは {MAX_RULES} 件までです")
    out, seen = [], set()
    for r in rules:
        n = validate_rule(r, check_safety)
        if n["id"] in seen:
            raise ValueError(f"{n['id']}: IDが重複しています")
        seen.add(n["id"])
        out.append(n)
    return out


# ---------------------------------------------------------------------------
# ファイルの読み書き(原子的に書き込み、旧版を保存)
# ---------------------------------------------------------------------------
def read_file(path):
    """ファイルを読んで (rules(未検証のdictの一覧), version) を返す。無い/壊れていれば ValueError"""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return [], 0
    except (OSError, ValueError) as e:
        raise ValueError(f"追加ルールのファイルを読めません: {e}")
    if isinstance(data, list):
        return data, 0
    if not isinstance(data, dict) or not isinstance(data.get("rules", []), list):
        raise ValueError("追加ルールのファイルの形式が正しくありません")
    return data.get("rules", []), int(data.get("version") or 0)


def history_dir_of(path):
    return os.path.join(os.path.dirname(os.path.abspath(path)), "custom_rules_history")


def save_file(path, rules, by="", note="", check_safety=True):
    """検証してから保存する。保存前に、いまのファイルを旧版として残す。保存した版番号を返す"""
    norm = validate_all(rules, check_safety)
    cur_rules, ver = [], 0
    try:
        cur_rules, ver = read_file(path)
    except ValueError:
        pass
    hd = history_dir_of(path)
    if os.path.exists(path):
        try:
            os.makedirs(hd, exist_ok=True)
            snap = os.path.join(hd, time.strftime("%Y%m%d-%H%M%S") + f"-v{ver}.json")
            n = 1
            while os.path.exists(snap):
                n += 1
                snap = os.path.join(hd, time.strftime("%Y%m%d-%H%M%S") + f"-v{ver}-{n}.json")
            with open(path, "rb") as src, open(snap, "wb") as dst:
                dst.write(src.read())
        except OSError:
            pass
    newv = ver + 1
    payload = {"version": newv, "saved_at": _now(), "saved_by": by, "note": str(note)[:200], "rules": norm}
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)
    return newv


def list_snapshots(path):
    hd = history_dir_of(path)
    try:
        names = sorted(os.listdir(hd), reverse=True)
    except OSError:
        return []
    out = []
    for n in names:
        if not n.endswith(".json"):
            continue
        try:
            with open(os.path.join(hd, n), "r", encoding="utf-8") as f:
                d = json.load(f)
            out.append({"name": n, "version": d.get("version", 0), "saved_at": d.get("saved_at", ""),
                        "saved_by": d.get("saved_by", ""), "note": d.get("note", ""),
                        "count": len(d.get("rules", []) if isinstance(d, dict) else d)})
        except (OSError, ValueError):
            continue
    return out


def restore_snapshot(path, name, by=""):
    """旧版へ戻す。戻す直前の状態も旧版として残る"""
    if not re.fullmatch(r"[0-9A-Za-z_.-]+\.json", name or ""):
        raise ValueError("版の指定が正しくありません")
    snap = os.path.join(history_dir_of(path), name)
    rules, _ = read_file(snap)
    return save_file(path, rules, by=by, note=f"{name} へ戻しました")


# ---------------------------------------------------------------------------
# 稼働中のWAFが使う追加ルール。ホットリロードできる
# ---------------------------------------------------------------------------
class CustomRules:
    def __init__(self, path, log=print):
        self.path = path
        self.log = log
        self._lock = threading.Lock()
        self._compiled = ()          # ((rule(dict), compiled regex), ...)
        self._mtime = None
        self.version = 0
        self.loaded_at = ""
        self.error = ""
        self.count = 0

    def _load(self):
        rules, ver = read_file(self.path)
        norm = validate_all(rules)          # 1件でも不正なら全体を採用しない
        comp = tuple((r, re.compile(r["pattern"], re.I | re.S)) for r in norm if r["enabled"])
        return comp, ver, len(norm)

    def reload(self, force=False):
        """ファイルが更新されていたら読み直す。変更があれば True。失敗しても今のルールを維持する"""
        try:
            mt = os.path.getmtime(self.path)
        except OSError:
            mt = None
        if not force and mt == self._mtime:
            return False
        try:
            comp, ver, n = self._load()
        except ValueError as e:
            with self._lock:
                self._mtime = mt                 # 同じ壊れたファイルを何度も検査しない
                self.error = str(e)
            self.log(f"[追加ルール] 読み込みに失敗(今のルールのまま稼働): {e}")
            return False
        with self._lock:
            self._compiled = comp
            self._mtime = mt
            self.version = ver
            self.count = n
            self.error = ""
            self.loaded_at = _now()
        self.log(f"[追加ルール] 反映しました: v{ver} / {n}件(有効 {len(comp)}件)")
        return True

    def start(self, interval=3.0):
        self.reload(force=True)

        def loop():
            while True:
                time.sleep(interval)
                try:
                    self.reload()
                except Exception:
                    pass
        threading.Thread(target=loop, daemon=True, name="custom-rules").start()

    def status(self):
        return {"path": os.path.basename(self.path), "version": self.version, "count": self.count,
                "active": len(self._compiled), "loaded_at": self.loaded_at, "error": self.error}

    def rules_view(self):
        with self._lock:
            return [dict(r) for r, _ in self._compiled]

    def detect_ids(self):
        """検知のみ(mode=detect)の追加ルールID。遮断の判定から外す"""
        return {r["id"] for r, _ in self._compiled if r["mode"] == "detect"}

    @staticmethod
    def _target_ok(target, label):
        if target == "all":
            return True
        if target == "path":
            return label == "path"
        if target == "query":
            return label.startswith("query:")
        if target == "header":
            return label.startswith("header:")
        if target == "body":
            return label == "body" or label.startswith(("json:", "form:"))
        return True

    def scan(self, label, value, normalized=None):
        comp = self._compiled
        if not comp:
            return []
        norm = normalized if normalized is not None else waf_rules.normalize(value)
        hits = []
        for r, rx in comp:
            if not self._target_ok(r["target"], label):
                continue
            m = rx.search(norm)
            if m:
                s = m.group(0)
                hits.append({"id": r["id"], "category": "custom", "severity": r["severity"],
                             "description": r["description"], "matched": s[:120] + ("..." if len(s) > 120 else "")})
        return hits


# ---------------------------------------------------------------------------
# 過去ログへの当てはめ。新ルールを本番に出す前の検証
# ---------------------------------------------------------------------------
def _event_fields(ev):
    out = []
    p = ev.get("path")
    if p:
        out.append(("path", str(p)))
    for k, v in parse_qsl(str(ev.get("query") or ""), keep_blank_values=True):
        out.append((f"query:{k}", v))
    req = ev.get("req") or {}
    b = req.get("body")
    if b:
        out.append(("body", str(b)))
    for k, v in (req.get("headers") or {}).items():
        kl = k.lower()
        if kl in ("host", "accept", "accept-encoding", "accept-language", "connection", "content-length", "content-type", "cookie"):
            continue
        out.append((f"header:{kl}", str(v)))
    return out


def replay(rules, log_path, limit=20000, sample=5):
    """検証済みの rules(dict の一覧)を、直近のログ最大 limit 件に当てて、一致件数と例を返す。
    PASS(通した通信)への一致は、本番で遮断すると誤検知になりうる
    """
    comp = []
    for r in rules:
        n = validate_rule(r, check_safety=False)
        comp.append((n, re.compile(n["pattern"], re.I | re.S), CustomRules._target_ok))
    try:
        with open(log_path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - 64 * 1024 * 1024))
            lines = f.read().decode("utf-8", "replace").splitlines()
    except OSError:
        lines = []
    lines = lines[-int(limit):]
    result = {r["id"]: {"id": r["id"], "matched_total": 0, "on_pass": 0, "on_detect_block": 0, "samples": []} for r, _, _ in comp}
    scanned = 0
    for line in lines:
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        act = ev.get("action")
        if act not in ("PASS", "DETECT", "BLOCK"):
            continue
        scanned += 1
        fields = [(lb, waf_rules.normalize(v)) for lb, v in _event_fields(ev)]
        for r, rx, tok in comp:
            res = result[r["id"]]
            for lb, nv in fields:
                if not tok(r["target"], lb):
                    continue
                if rx.search(nv):
                    res["matched_total"] += 1
                    res["on_pass" if act == "PASS" else "on_detect_block"] += 1
                    if len(res["samples"]) < sample:
                        res["samples"].append({"ts": ev.get("ts", ""), "action": act, "path": ev.get("path", ""),
                                               "field": lb, "backend": ev.get("backend", "")})
                    break
    return {"scanned": scanned, "results": list(result.values())}


# ---------------------------------------------------------------------------
# ルール変更の履歴(誰が・いつ・何を)
# ---------------------------------------------------------------------------
def append_history(path, entry):
    if not path:
        return
    try:
        rec = dict(entry)
        rec.setdefault("time", _now())
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError:
        pass


def read_history(path, limit=200):
    if not path:
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except OSError:
        return []
    out = []
    for line in lines[-int(limit) * 2:]:
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    out.reverse()
    return out[:limit]
