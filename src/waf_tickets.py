# -*- coding: utf-8 -*-
"""waf_tickets.py: 例外申請(誤検知の除外依頼)・問い合わせ・ルール変更提案のチケット

  - 保存: tickets.json に全チケットを入れ、原子的に書き換える
  - 通知: SMTP の設定があるときだけメールを送る(別スレッド。失敗してもWAFには影響しない)
"""
import datetime
import json
import os
import smtplib
import threading
from email.message import EmailMessage

KINDS = {"false_positive": "誤検知の除外申請", "inquiry": "問い合わせ", "rule_proposal": "ルール変更の提案", "mode_unlock": "防御モードの変更依頼", "decrypt": "暗号化ログの復号の申請", "log_review": "ログの確認依頼(キー・オフィサーへ)"}
STATUSES = {"open": "受付中", "in_progress": "対応中", "escalated": "管理者対応中", "done": "完了", "rejected": "却下"}


def _now():
    return datetime.datetime.now().isoformat(timespec="seconds")


def _clip(v, n):
    return str(v or "").strip()[:n]


def _clean_proposal(pr):
    """ルール変更の提案。承認時に管理者がそのまま適用できる形で残す。
    {op:"disable", rule} はこのバックエンドでルールを使わない、{op:"exclude", rule, path_prefix, minutes} はこのパスでだけ使わない
    """
    if not isinstance(pr, dict):
        return {}
    rule = _clip(pr.get("rule"), 40)
    if not rule:
        return {}
    if pr.get("op") == "disable":
        return {"op": "disable", "rule": rule}
    if pr.get("op") == "exclude":
        pp = _clip(pr.get("path_prefix"), 200)
        if not pp.startswith("/"):
            return {}
        try:
            mins = max(0, min(525600, int(pr.get("minutes") or 0)))
        except (TypeError, ValueError):
            mins = 0
        return {"op": "exclude", "rule": rule, "path_prefix": pp, "minutes": mins}
    return {}


def _clean_grant(g):
    """復号申請の対象期間 {"from","to"}(ISO形式の日時)。不正なら ValueError"""
    if not isinstance(g, dict):
        raise ValueError("復号する期間を指定してください")
    out = {}
    for k in ("from", "to"):
        v = str(g.get(k) or "").strip()[:19].replace(" ", "T")
        try:
            minute_only = len(v) == 16                       # 画面の入力は分まで。終了はその分の :59 まで含める
            v = datetime.datetime.fromisoformat(v + (":59" if (minute_only and k == "to") else "")).isoformat(timespec="seconds")      # 秒まで揃える(期間を文字列比較で判定するため)
        except ValueError:
            raise ValueError("復号する期間の日時が正しくありません")
        out[k] = v
    if out["from"] > out["to"]:
        raise ValueError("復号する期間の開始が終了より後になっています")
    if (datetime.datetime.fromisoformat(out["to"]) - datetime.datetime.fromisoformat(out["from"])).days > 93:
        raise ValueError("復号する期間は93日以内にしてください")
    return out


def _clean_evidence(ev):
    """ログの該当リクエストの要点だけ残す。ヘッダー・本文など機微情報は入れない"""
    if not isinstance(ev, dict):
        return {}
    hits = []
    for h in (ev.get("hits") or [])[:20]:
        if isinstance(h, dict):
            hits.append({"id": _clip(h.get("id"), 40), "severity": _clip(h.get("severity"), 10),
                         "field": _clip(h.get("field"), 80), "description": _clip(h.get("description"), 120),
                         "matched": _clip(h.get("matched"), 120)})
    return {"ts": _clip(ev.get("ts"), 30), "method": _clip(ev.get("method"), 10), "path": _clip(ev.get("path"), 300),
            "query": _clip(ev.get("query"), 400), "backend": _clip(ev.get("backend"), 40),
            "client_ip": _clip(ev.get("client_ip"), 60), "action": _clip(ev.get("action"), 10), "hits": hits}


class TicketStore:
    def __init__(self, path, mailer=None):
        self.path = path
        self.lock = threading.Lock()
        self.mailer = mailer             # callable(subject, body) または None

    def _load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                d = json.load(f)
            return d if isinstance(d, dict) and isinstance(d.get("tickets"), list) else {"seq": 0, "tickets": []}
        except (OSError, ValueError):
            return {"seq": 0, "tickets": []}

    def _save(self, d):
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(d, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self.path)

    def _notify(self, subject, body):
        if self.mailer is not None:
            try:
                threading.Thread(target=self.mailer, args=(subject, body), daemon=True, name="ticket-mail").start()
            except Exception:
                pass

    @staticmethod
    def view(t, full=True):
        out = dict(t)
        if not full:
            out.pop("comments", None)
            out.pop("evidence", None)
        return out

    def list(self, owner=None, backends=None):
        """owner を指定すると、その人が出したものだけ返す。新しい順"""
        with self.lock:
            ts = list(self._load()["tickets"])
        if owner is not None:
            ts = [t for t in ts if t.get("by") == owner]
        ts.sort(key=lambda t: t.get("id", ""), reverse=True)
        return ts

    def get(self, tid):
        with self.lock:
            return next((t for t in self._load()["tickets"] if t.get("id") == tid), None)

    def create(self, by, kind, backend, subject, body="", evidence=None, role="user", org="", proposal=None, stage="admin", grant=None):
        """stage: "analyst"=担当アナリストが一次対応、"admin"=管理者が対応(担当アナリストなし・アナリスト自身の申請・エスカレーション後)"""
        if kind not in KINDS:
            raise ValueError("申請の種類が正しくありません")
        subject = _clip(subject, 120)
        if not subject:
            raise ValueError("件名を入力してください")
        grant = _clean_grant(grant) if kind == "decrypt" else None
        with self.lock:
            d = self._load()
            d["seq"] = int(d.get("seq") or 0) + 1
            t = {"id": "T-%04d" % d["seq"], "kind": kind, "status": "open", "by": _clip(by, 40), "role": role,
                 "backend": _clip(backend, 40), "org": _clip(org, 40), "subject": subject, "body": _clip(body, 2000),
                 "evidence": _clean_evidence(evidence), "proposal": _clean_proposal(proposal), "comments": [], "resolution": "",
                 "stage": stage if stage in ("analyst", "ko") else "admin", "handler": "", "escalated_by": "",
                 "created": _now(), "updated": _now()}
            if grant:
                t["grant"] = grant            # 承認までは申請の状態。承認で approved_by / until が入り、その間だけ復号できる
            d["tickets"].append(t)
            self._save(d)
        if t["stage"] == "admin":          # 担当アナリストが一次対応するものは管理者に通知しない(エスカレーション時に通知)
            self._notify(f"[WAF] 新しい申請 {t['id']}: {subject}",
                         f"{KINDS[kind]}\n申請者: {t['by']}\n接続先: {t['backend']}\n\n{t['body']}\n")
        return t

    def decide_grant(self, tid, by, approve, hours=24, comment="", role="user"):
        """復号の申請を承認(期限つき)または却下する。承認者(組織側)の確認は呼び出し側で行う"""
        hours = max(1, min(168, int(hours or 24)))
        with self.lock:
            d = self._load()
            t = next((x for x in d["tickets"] if x.get("id") == tid), None)
            if t is None or t.get("kind") != "decrypt":
                raise ValueError("復号の申請が見つかりません")
            if t.get("status") not in ("open", "in_progress", "escalated"):
                raise ValueError("この申請はすでに完了しています")
            if approve:
                until = (datetime.datetime.now() + datetime.timedelta(hours=hours)).isoformat(timespec="seconds")
                t["grant"] = dict(t.get("grant") or {}, approved_by=_clip(by, 40), approved_at=_now(), until=until)
                t["status"] = "done"
                t["resolution"] = "承認(%d時間)" % hours
            else:
                t["status"] = "rejected"
                t["resolution"] = "却下"
            t["comments"].append({"by": _clip(by, 40), "role": role if role in ("user", "analyst") else "user", "at": _now(),
                                  "text": ("復号を承認しました(%d時間)" % hours if approve else "復号を却下しました") + (": " + _clip(comment, 300) if comment else "")})
            t["updated"] = _now()
            self._note_review(d, t, "復号の申請 %s が%sされました" % (tid, "承認" if approve else "却下") + ("(%d時間)" % hours if approve else ""), by)
            self._save(d)
        self._notify(f"[WAF] 復号の申請 {tid} が{'承認' if approve else '却下'}されました", f"{t['subject']}\n承認者: {by}\n")
        return t

    def escalate(self, tid, by, reason):
        """一次対応のアナリストが管理者に依頼する。理由は必須"""
        reason = _clip(reason, 1000)
        if not reason:
            raise ValueError("管理者へ依頼する理由を入力してください")
        with self.lock:
            d = self._load()
            t = next((x for x in d["tickets"] if x.get("id") == tid), None)
            if t is None:
                raise ValueError("申請が見つかりません")
            if t.get("status") in ("done", "rejected"):
                raise ValueError("完了・却下した申請は管理者へ依頼できません")
            if t.get("stage") == "admin" and t.get("status") == "escalated":
                raise ValueError("すでに管理者へ依頼しています")
            t["stage"] = "admin"
            t["status"] = "escalated"
            t["escalated_by"] = _clip(by, 40)
            if not t.get("handler"):
                t["handler"] = _clip(by, 40)
            t["comments"].append({"by": _clip(by, 40), "role": "analyst", "at": _now(), "text": "管理者へ依頼しました: " + reason})
            t["updated"] = _now()
            self._save(d)
        self._notify(f"[WAF] 申請 {tid} が管理者へ依頼されました", f"{t['subject']}\n依頼者: {by}\n理由: {reason}\n")
        return t

    def link_review(self, did, rid, by):
        """復号申請 did を、ログ確認依頼 rid に結びつける。依頼が「受付中」なら「対応中」にして、経過をコメントに残す"""
        with self.lock:
            d = self._load()
            t = next((x for x in d["tickets"] if x.get("id") == did and x.get("kind") == "decrypt"), None)
            r = next((x for x in d["tickets"] if x.get("id") == rid and x.get("kind") == "log_review"), None)
            if t is None or r is None:
                return None
            t["review"] = rid
            if r.get("status") == "open":
                r["status"] = "in_progress"
            r["comments"].append({"by": _clip(by, 40), "role": "key_officer", "at": _now(),
                                  "text": "復号を申請しました(%s)。対応中にしました" % did})
            r["updated"] = _now()
            self._save(d)
        return r

    def _note_review(self, d, t, text, by):
        rid = t.get("review")
        r = next((x for x in d["tickets"] if x.get("id") == rid and x.get("kind") == "log_review"), None) if rid else None
        if r is not None:
            r["comments"].append({"by": _clip(by, 40), "role": "user", "at": _now(), "text": text})
            r["updated"] = _now()

    def comment(self, tid, by, text, role="user"):
        text = _clip(text, 2000)
        if not text:
            raise ValueError("コメントを入力してください")
        with self.lock:
            d = self._load()
            t = next((x for x in d["tickets"] if x.get("id") == tid), None)
            if t is None:
                raise ValueError("申請が見つかりません")
            t["comments"].append({"by": _clip(by, 40), "role": role, "at": _now(), "text": text})
            t["updated"] = _now()
            self._save(d)
        if role == "user":
            self._notify(f"[WAF] 申請 {tid} にコメント", f"{by}: {text}\n")
        return t

    def set_status(self, tid, status, by, resolution="", role="admin"):
        if status not in STATUSES:
            raise ValueError("状態の指定が正しくありません")
        with self.lock:
            d = self._load()
            t = next((x for x in d["tickets"] if x.get("id") == tid), None)
            if t is None:
                raise ValueError("申請が見つかりません")
            t["status"] = status
            if role == "admin":
                t["stage"] = "admin"            # 管理者が触ったら管理者側の対応にする
            elif not t.get("handler"):
                t["handler"] = _clip(by, 40)    # 一次対応したアナリスト(二重対応を防ぐ表示用)
            if resolution:
                t["resolution"] = _clip(resolution, 500)
            t["comments"].append({"by": _clip(by, 40), "role": role if role in ("admin", "analyst", "key_officer") else "admin", "at": _now(),
                                  "text": f"状態を「{STATUSES[status]}」にしました" + (f"({_clip(resolution, 200)})" if resolution else "")})
            t["updated"] = _now()
            self._save(d)
        self._notify(f"[WAF] 申請 {tid} が「{STATUSES[status]}」になりました", f"{t['subject']}\n{t.get('resolution','')}\n")
        return t


def make_mailer(cfg_fn):
    """SMTP送信関数を作る。cfg_fn() は設定の notify_email(dict) を返す。無効・未設定なら何もしない"""
    def send(subject, body):
        c = cfg_fn() or {}
        if not c.get("enabled") or not c.get("smtp_host") or not c.get("to"):
            return False
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = c.get("from") or c.get("username") or "waf@localhost"
        msg["To"] = ", ".join(c["to"]) if isinstance(c["to"], list) else str(c["to"])
        msg.set_content(body)
        port = int(c.get("smtp_port") or 25)
        try:
            if c.get("smtp_ssl"):
                s = smtplib.SMTP_SSL(c["smtp_host"], port, timeout=10)
            else:
                s = smtplib.SMTP(c["smtp_host"], port, timeout=10)
                if c.get("smtp_tls"):
                    s.starttls()
            try:
                if c.get("username"):
                    s.login(c["username"], c.get("password") or "")
                s.send_message(msg)
            finally:
                s.quit()
            return True
        except Exception as e:           # 通知が失敗してもWAFは止めない
            print(f"[通知] メール送信に失敗: {e}", flush=True)
            return False
    return send
