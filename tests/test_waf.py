#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_waf.py: WAF の動作確認テスト

ダミーのバックエンド(常に 200 OK)の手前に WAF を立てて、次を確認する。
  * 正常リクエストは通る (200)
  * XSS / SQLi / traversal / cmdi は block モードで遮断される (403)
  * detect モードでは遮断せず通す (200) が、ログには残る
  * セキュリティヘッダが付く
  * レート制限が効く (429)
WAF本体・ルールには手を入れない。

    python3 test_waf.py
"""
import os as _os, sys as _sys
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
for _p in (_ROOT, _os.path.join(_ROOT, "src")):
    if _p not in _sys.path:
        _sys.path.insert(0, _p)
import json
import os
import threading
import time
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import waf
import waf_rules


# ダミーバックエンド
class Echo(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass
    def _ok(self):
        body = b"OK from backend"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
    def _html(self, body, ctype):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        # WAF がバックエンドへ送った Accept-Encoding をそのまま返す(確認用)
        self.send_header("X-Seen-AE", self.headers.get("Accept-Encoding", "(none)"))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
    def do_GET(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n: self.rfile.read(n)
        if self.path == "/page":
            return self._html(b"<html><head><title>t</title></head><body>hi</body></html>",
                              "text/html; charset=utf-8")
        if self.path == "/sjis":
            return self._html(("<html><head></head><body>こんにちは</body></html>").encode("shift_jis"),
                              "text/html; charset=Shift_JIS")
        self._ok()
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n: self.rfile.read(n)
        self._ok()


def start_server(httpd):
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return t


def req(url, data=None, headers=None, method=None):
    r = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        resp = urllib.request.urlopen(r, timeout=10)
        return resp.status, resp.read(), dict(resp.getheaders())
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)


PASS, FAIL = 0, 0
def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"  ✓ {name}")
    else:
        FAIL += 1; print(f"  ✗ {name}  <<< FAILED")


def build_waf(mode, port, backend_port, rate=None, log_path="/tmp/waf_test.log",
              cip=None, blocklist=None, conn_burst=0, tls=False):
    cfg = waf.load_config(None)
    if cip:
        cfg["client_ip_report"].update(cip)
    if blocklist:
        cfg["blocklist"] = list(blocklist)
    cfg["mode"] = mode
    cfg["listen_port"] = port
    cfg["listen_tls"] = False
    cfg["backend_host"] = "127.0.0.1"
    cfg["backend_port"] = backend_port
    cfg["backend_scheme"] = "http"   # テストでは平文バックエンド
    if rate:
        cfg["rate_limit"] = rate
    else:
        cfg["rate_limit"] = {"enabled": False, "max_requests": 1000, "window_seconds": 60}
    inspector = waf.Inspector(cfg)
    limiter = waf.RateLimiter(cfg["rate_limit"]["max_requests"],
                              cfg["rate_limit"]["window_seconds"],
                              conn_burst_max=conn_burst, conn_burst_seconds=5)
    logger = waf.WafLogger(log_path)
    # オフラインで完結させるため、グローバルIP解決は無効にする
    ipresolver = waf.GlobalIPResolver(enabled=False)
    handler, accept_gate, _conn_limiter = waf.make_handler(cfg, inspector, limiter, logger, ipresolver)
    httpd = waf.GatedHTTPServer(("127.0.0.1", port), handler)
    httpd.gate = accept_gate
    httpd.conn_limiter = _conn_limiter
    httpd.limiter = limiter
    if tls:
        import ssl
        cert, key = "/tmp/waf_test_cert.pem", "/tmp/waf_test_key.pem"
        if not os.path.exists(cert):
            assert waf.ensure_tls_cert(cert, key)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        httpd.ssl_context = ctx      # main() と同じ: ゲート通過後にワーカー側でTLS化
    return httpd


def main():
    # 単体: ルール検出
    print("[1] ルールエンジン単体")
    cats = ["xss", "sqli", "traversal", "cmdi"]
    check("通常テキストは検知しない",
          waf_rules.scan_value("こんにちは、良い掲示板ですね", cats) == [])
    check("<script> を検知", any(h["id"] == "XSS-001"
          for h in waf_rules.scan_value("<script>alert(1)</script>", cats)))
    check("二重URLエンコードされた <script> を検知",
          waf_rules.scan_value("%253Cscript%253E", cats) != [])
    check("HTMLエンティティ難読化を検知",
          waf_rules.scan_value("&lt;script&gt;x&lt;/script&gt;", cats) != [])
    check("onerror イベントハンドラを検知",
          any(h["id"] == "XSS-006" or h["id"] == "XSS-009"
              for h in waf_rules.scan_value('<img src=x onerror=alert(1)>', cats)))
    check("UNION SELECT を検知",
          any(h["category"] == "sqli"
              for h in waf_rules.scan_value("1 UNION SELECT user,pass FROM users", cats)))
    check("../ トラバーサルを検知",
          any(h["category"] == "traversal"
              for h in waf_rules.scan_value("../../../../etc/passwd", cats)))
    check("コマンド連結を検知",
          any(h["category"] == "cmdi"
              for h in waf_rules.scan_value("x; cat /etc/passwd", cats)))

    # バックエンド起動
    backend = ThreadingHTTPServer(("127.0.0.1", 15000), Echo)
    start_server(backend)

    # block モード
    print("[2] block モード (エンドツーエンド)")
    waf_block = build_waf("block", 18080, 15000)
    start_server(waf_block)
    time.sleep(0.3)
    base = "http://127.0.0.1:18080"

    s, b, h = req(base + "/board")
    check("正常GETは200で通過", s == 200 and b == b"OK from backend")

    s, b, h = req(base + "/board",
                  data=b"body=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
                  headers={"Content-Type": "application/x-www-form-urlencoded"},
                  method="POST")
    check("XSSのPOSTフォームを403遮断", s == 403)
    check("遮断ページにルールIDヘッダ", "XSS" in (h.get("X-WAF-Block", "")))

    s, b, h = req(base + "/search?q=1%20UNION%20SELECT%20pass%20FROM%20users")
    check("SQLiのクエリを403遮断", s == 403)

    s, b, h = req(base + "/..%2f..%2f..%2fetc%2fpasswd")
    check("traversalのパスを403遮断", s == 403)

    s, b, h = req(base + "/board",
                  data=json.dumps({"body": "<svg onload=alert(1)>"}).encode(),
                  headers={"Content-Type": "application/json"}, method="POST")
    check("JSONボディ内のXSSを403遮断", s == 403)

    s, b, h = req(base + "/board", headers={"User-Agent": "<script>evil</script>"})
    check("User-Agentヘッダ内のXSSを403遮断", s == 403)

    s, b, h = req(base + "/board")
    check("正常応答にCSPヘッダ付与", "Content-Security-Policy" in h)
    check("正常応答にX-Frame-Options付与", h.get("X-Frame-Options") == "DENY")

    s, b, h = req(base + "/board", data=b"body=%E6%99%AE%E9%80%9A%E3%81%AE%E6%8A%95%E7%A8%BF",
                  headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST")
    check("正常な日本語投稿は通過(誤検知なし)", s == 200)

    # detect モード
    print("[3] detect モード")
    waf_detect = build_waf("detect", 18081, 15000)
    start_server(waf_detect)
    time.sleep(0.3)
    d = "http://127.0.0.1:18081"
    s, b, h = req(d + "/board",
                  data=b"body=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
                  headers={"Content-Type": "application/x-www-form-urlencoded"},
                  method="POST")
    check("detectではXSSを遮断せず素通し(200)", s == 200 and b == b"OK from backend")

    # レート制限
    print("[4] レート制限")
    waf_rl = build_waf("block", 18082, 15000,
                       rate={"enabled": True, "max_requests": 5, "window_seconds": 60})
    start_server(waf_rl)
    time.sleep(0.3)
    rl = "http://127.0.0.1:18082"
    codes = [req(rl + "/")[0] for _ in range(8)]
    check("5req/分制限で6回目以降は429", codes.count(429) >= 1 and codes[:5] == [200]*5)

    # クライアント申告方式
    print("[5] クライアント申告方式(ブラウザが申告した公開IP)")
    import os
    clog = "/tmp/waf_test_cip.log"
    try:
        os.remove(clog)
    except OSError:
        pass
    waf_cip = build_waf("block", 18083, 15000, log_path=clog)
    start_server(waf_cip)
    time.sleep(0.3)
    c = "http://127.0.0.1:18083"

    def last_rec():
        time.sleep(0.25)     # ログは応答の後に書かれるので少し待つ
        with open(clog, encoding="utf-8") as f:
            return json.loads(f.read().strip().splitlines()[-1])

    s, b, h = req(c + "/__waf/cip.js")
    check("収集スクリプト(/__waf/cip.js)をJSとして配信",
          s == 200 and "javascript" in h.get("Content-Type", "") and b"waf_cip" in b)
    check("ページを開くたびに必ず取り直す(Cookieがあっても省略しない)", b"run();" in b and b"has()" not in b)
    check("タブ復帰・フォーカス・bfcache・ネットワーク変化でも取り直す",
          all(x in b for x in (b"'focus'", b"'pageshow'", b"'online'", b"visibilitychange", b"connection")))
    check("Cookieは長寿命(期限切れで出口IPへ戻らない)", b"max-age='+M" in b and b"M=3600" in b)
    s, b, h = req(c + "/page", headers={"Accept-Encoding": "gzip"})
    check("HTML応答へスクリプトを差し込む(</head>の直前)",
          s == 200 and b'<script src="/__waf/cip.js" defer></script></head>' in b)
    check("差し込み後の Content-Length が本文と一致", int(h.get("Content-Length", -1)) == len(b))
    check("バックエンドへは圧縮なし(identity)で問い合わせる", h.get("X-Seen-AE") == "identity")
    csp = h.get("Content-Security-Policy", "")
    check("CSPの connect-src にだけプロバイダを追加(script-src 'self' は維持)",
          "connect-src 'self' https://api.ipify.org https://ipinfo.io" in csp and "script-src 'self';" in csp)
    s, b, h = req(c + "/")
    check("HTML以外(text/plain)には差し込まない", b == b"OK from backend")
    s, b, h = req(c + "/sjis")
    check("Shift_JISのページも文字化けさせずに差し込む",
          "こんにちは".encode("shift_jis") in b and b"/__waf/cip.js" in b)

    req(c + "/board", headers={"X-Client-IP": "8.8.8.8"})
    r = last_rec()
    check("ヘッダ申告の公開IPを送信元に採用(ip_src=reported)",
          r.get("client_ip") == "8.8.8.8" and r.get("ip_src") == "reported")
    check("実際の接続元(プライベート/ループバック)は conn_ip に残る", r.get("conn_ip") == "127.0.0.1")
    req(c + "/board", headers={"Cookie": "waf_cip=1.1.1.1"})
    r = last_rec()
    check("Cookie申告の公開IPを採用", r.get("client_ip") == "1.1.1.1" and r.get("ip_src") == "reported")
    req(c + "/board", headers={"Cookie": "waf_cip=2606%3A4700%3A4700%3A%3A1111"})
    r = last_rec()
    check("IPv6の申告(URLエンコード)も採用", r.get("client_ip") == "2606:4700:4700::1111")
    for bad in ("10.0.0.5", "192.168.1.1", "not-an-ip", "999.1.1.1", "127.0.0.1"):
        req(c + "/board", headers={"X-Client-IP": bad})
        r = last_rec()
        check(f"不正/非公開な申告は無視: {bad}", r.get("ip_src") != "reported")
    req(c + "/board")
    r = last_rec()
    check("申告が無いリクエストは従来どおり(reportedにならない)", r.get("ip_src") != "reported")

    cfg_t = waf.load_config(None)
    pub, priv = "1.1.1.1", "192.168.1.5"
    check("公開IPからの接続の申告は無視(インターネット側からの偽装防止)",
          waf.read_reported_ip(cfg_t, {"X-Client-IP": "8.8.8.8"}, pub) is None)
    check("プライベートIPからの接続の申告は採用",
          waf.read_reported_ip(cfg_t, {"X-Client-IP": "8.8.8.8"}, priv) == "8.8.8.8")
    cfg_t["client_ip_report"]["private_only"] = False
    check("private_only=false なら公開IPからの申告も採用",
          waf.read_reported_ip(cfg_t, {"X-Client-IP": "8.8.8.8"}, pub) == "8.8.8.8")
    cfg_t["client_ip_report"]["enabled"] = False
    check("機能OFFなら申告は読まない",
          waf.read_reported_ip(cfg_t, {"X-Client-IP": "8.8.8.8"}, priv) is None)

    # 申告を偽装しても手動ブロックは逃れられない。画面に出るIPでもブロックできる
    waf_bl = build_waf("block", 18084, 15000, log_path=clog, blocklist=["8.8.8.8"])
    start_server(waf_bl)
    time.sleep(0.3)
    def dropped(url, headers):
        try:
            req(url, headers=headers)
            return False
        except Exception:
            return True
    check("ブロックリストの申告IP(画面に出るIP)の端末はdrop",
          dropped("http://127.0.0.1:18084/board", {"X-Client-IP": "8.8.8.8"}))
    check("別のIPを申告した端末は通る(ブロックは申告IP/実接続IPで照合)",
          not dropped("http://127.0.0.1:18084/board", {"X-Client-IP": "9.9.9.9"}))

    # OFF のとき: 配信なし・差し込みなし・申告無視
    waf_off = build_waf("block", 18085, 15000, log_path=clog, cip={"enabled": False})
    start_server(waf_off)
    time.sleep(0.3)
    o = "http://127.0.0.1:18085"
    s, b, h = req(o + "/__waf/cip.js")
    check("OFFのときは /__waf/cip.js が404", s == 404)
    s, b, h = req(o + "/page", headers={"Accept-Encoding": "gzip"})
    check("OFFのときはHTMLに差し込まず、Accept-Encodingもそのまま",
          b"cip.js" not in b and h.get("X-Seen-AE") == "gzip"
          and "connect-src" not in h.get("Content-Security-Policy", ""))
    req(o + "/board", headers={"X-Client-IP": "8.8.8.8"})
    check("OFFのときは申告を採用しない", last_rec().get("ip_src") != "reported")

    # [6] 接続レベルの対策
    print("[6] 接続レベルの対策(握手タイムアウト/接続頻度BAN/接続カウンター)")
    import socket, ssl
    # 単体: conn_burst_max=0 なら無効、>0 なら閾値超過で True(BAN)
    rl0 = waf.RateLimiter(1000, 60)
    check("conn_burst_max=0 のとき note_conn は常に False(無効)",
          not any(rl0.note_conn("9.9.9.9") for _ in range(500)))
    rl1 = waf.RateLimiter(1000, 60, conn_burst_max=5, conn_burst_seconds=5)
    res = [rl1.note_conn("9.9.9.9") for _ in range(8)]
    check("conn_burst_max=5: 閾値を超えた接続でBAN発動(以降はBAN扱い)",
          (not any(res[:5])) and any(res) and rl1.is_banned("9.9.9.9") and not rl1.is_banned("9.9.9.10"))

    # HTTP: カウンターの動き
    c6 = build_waf("block", 18086, 15000, log_path="/tmp/waf_test6.log")
    start_server(c6)
    time.sleep(0.3)
    st6 = c6.conn_limiter.stats
    req("http://127.0.0.1:18086/board")
    s0 = socket.create_connection(("127.0.0.1", 18086)); s0.close()                 # 接続だけ
    s1 = socket.create_connection(("127.0.0.1", 18086)); s1.sendall(b"\x00garbage\r\n\r\n")
    try: s1.recv(100)
    except Exception: pass
    s1.close()
    time.sleep(0.6)
    snap = st6.snapshot()
    check("ConnStats: 接続・リクエストが数えられる(accepted>=3, requests>=1)",
          snap["accepted"] >= 3 and snap["requests"] >= 1)
    check("ConnStats: 接続だけ/ゴミ送信は no_request に数えられる(waf.logには出ない)",
          snap["no_request"] >= 2)
    check("ConnStats: 不正なHTTPは bad_request に数えられる", snap["bad_request"] >= 1)
    check("ConnStats: 解放漏れなし(同時接続スロットが全て返る)",
          c6.conn_limiter.snapshot()["total"] == 0)

    # HTTPS: 無言の接続があっても他のクライアントは通る(握手タイムアウト+ワーカースレッド化)
    t6 = build_waf("block", 18087, 15000, log_path="/tmp/waf_test6t.log", tls=True)
    start_server(t6)
    time.sleep(0.3)
    silent = socket.create_connection(("127.0.0.1", 18087))         # 握手を始めない
    cctx = ssl.create_default_context(); cctx.check_hostname = False; cctx.verify_mode = ssl.CERT_NONE
    t0 = time.time()
    try:
        with socket.create_connection(("127.0.0.1", 18087), timeout=4) as raw:
            with cctx.wrap_socket(raw, server_hostname="x") as ss:
                ss.sendall(b"GET /board HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\n")
                data = ss.recv(200)
        ok_tls = data.startswith(b"HTTP/1.")
    except Exception as e:
        ok_tls = False
    check("無言のTCP接続が1本あってもHTTPSの正規リクエストが通る(待たされない)",
          ok_tls and time.time() - t0 < 2.0)
    silent.close()

    # 接続頻度BAN: 握手だけ繰り返すフラッド(HTTPは送らない)を検知して、以後ゲートで遮断
    f6 = build_waf("block", 18088, 15000, log_path="/tmp/waf_test6f.log", tls=True,
                   rate={"enabled": True, "max_requests": 1000, "window_seconds": 60,
                         "ban_threshold": 3, "ban_seconds": 60, "burst_max": 1000,
                         "burst_seconds": 5, "global_max_rps": 0, "ban_escalate": False},
                   conn_burst=15)
    # ゲート自体の挙動を見るテスト(/health 用の通路は[10]で検証)
    f6.conn_limiter.health.cfg.setdefault("health_check", {})["allow_when_blocked"] = False
    start_server(f6)
    time.sleep(0.3)
    for _ in range(40):
        try:
            with socket.create_connection(("127.0.0.1", 18088), timeout=2) as raw:
                with cctx.wrap_socket(raw, server_hostname="x"):
                    pass
        except Exception:
            pass
    time.sleep(0.5)
    fs = f6.conn_limiter.stats.snapshot()
    check("握手だけのフラッドで conn_flood BAN が発動する", fs["gate_conn_flood"] >= 1)
    check("BAN後はTLS握手前にゲートで遮断される(gate_ban が増え、握手回数は頭打ち)",
          fs["gate_ban"] >= 10 and fs["tls_ok"] < 30)
    check("握手完了だがリクエスト無しの接続は no_request に数えられる", fs["no_request"] >= 5)
    check("握手フラッド後もスロットが解放されている(total==0)",
          f6.conn_limiter.snapshot()["total"] == 0 and t6.conn_limiter.snapshot()["total"] == 0)

    # [7] ダッシュボードの差分読み込み(EventStore)
    print("[7] ダッシュボードの差分読み込み(EventStore)")
    import tempfile
    import dashboard
    d7 = tempfile.mkdtemp()
    lp = os.path.join(d7, "w.log")
    def wl(f, act, ip="1.2.3.4", n=1, ts="2026-10-16T10:00:00", **kw):
        r = {"ts": ts, "action": act, "client_ip": ip, "count": n}
        r.update(kw)
        f.write(json.dumps(r, ensure_ascii=False) + "\n")
    with open(lp, "w", encoding="utf-8") as f:
        wl(f, "PASS"); wl(f, "BLOCK", path="/x", hits=[{"id": "XSS-001", "category": "xss", "severity": "high", "field": "q"}])
        wl(f, "RATELIMIT", n=5, disposition="ban")
    st7 = dashboard.EventStore(lp)
    s7, _ = st7.stats(None, "all")
    check("EventStore: 既存ログを読み込み、count を合算(PASS1/BLOCK1/RATELIMIT5)",
          s7["actions"]["PASS"] == 1 and s7["actions"]["BLOCK"] == 1 and s7["actions"]["RATELIMIT"] == 5 and s7["total"] == 7)
    same = dashboard.aggregate(dashboard.read_events(lp), None)
    for dct in (s7, same):
        dct.pop("generated_at", None)
    check("EventStore の集計は従来の全件集計(aggregate)と完全に一致", s7 == same)

    off0 = st7.offset
    st7.refresh(force=True)
    check("追記がなければ何も読み直さない(読み終わり位置が不変)", st7.offset == off0)
    with open(lp, "a", encoding="utf-8") as f:
        f.write('{"ts": "2026-10-16T10:00:01", "action": "PASS", "client_ip": "1.2.3.4"')   # 書きかけ(改行なし)
    st7.refresh(force=True)
    check("書きかけの行は数えない", st7.agg.action_counts["PASS"] == 1)
    with open(lp, "a", encoding="utf-8") as f:
        f.write(', "count": 3}\n')
    st7.refresh(force=True)
    check("書き終わったら次の更新で数える(増分だけ読む)", st7.agg.action_counts["PASS"] == 4)
    with open(lp, "w", encoding="utf-8") as f:
        wl(f, "BLOCK")
    st7.refresh(force=True)
    check("ログが切り詰められたら最初から読み直す",
          st7.agg.action_counts["BLOCK"] == 1 and st7.agg.action_counts["PASS"] == 0)

    big = os.path.join(d7, "big.log")
    NB = 230000
    with open(big, "w", encoding="utf-8") as f:
        for i in range(NB):
            wl(f, "PASS", ip="10.0.%d.%d" % (i % 200, i % 250))
    stb = dashboard.EventStore(big, recent_max=1000)
    sb, _ = stb.stats(None, "all")
    check("20万行を超えるログでも合計が欠けない(旧実装は末尾20万行まで)", sb["total"] == NB)
    check("直近イベントのメモリ保持は recent_max まで", len(stb.recent) == 1000)
    t0 = time.time()
    for _ in range(20):
        stb.stats(None, "all")
        stb.refresh(force=True)
    check("追記なしの再集計はログ全体の大きさに依存せず高速(20回で1秒未満)", time.time() - t0 < 1.0)

    # [8] 稼働モニター(掲示板アプリ / WAF待受 / 外部確認用 /health)
    print("[8] 稼働モニター(掲示板アプリ / WAF待受 / 外部確認用 /health)")
    from http.server import BaseHTTPRequestHandler as _BH, ThreadingHTTPServer as _TS
    class _B500(_BH):
        def log_message(self, *a): pass
        def do_GET(self):
            self.send_response(500); self.send_header("Content-Length", "1"); self.end_headers(); self.wfile.write(b"x")
    b500 = _TS(("127.0.0.1", 15011), _B500)
    threading.Thread(target=b500.serve_forever, daemon=True).start()

    lg8 = "/tmp/waf_test8.log"
    open(lg8, "w").close()
    h8 = build_waf("block", 18090, 15000, log_path=lg8,
                   rate={"enabled": True, "max_requests": 1000, "window_seconds": 60,
                         "ban_threshold": 3, "ban_seconds": 60, "burst_max": 1000,
                         "burst_seconds": 5, "global_max_rps": 0, "ban_escalate": False})
    start_server(h8)
    time.sleep(0.3)
    mon = h8.conn_limiter.health
    cfg8 = mon.cfg
    mon.check_once()
    snap = mon.snapshot()["targets"]
    check("掲示板アプリが生きていれば up(応答時間つき)",
          snap["backend"]["state"] == "up" and snap["backend"]["latency_ms"] is not None)
    check("WAF自身の待受への確認も up", snap["waf"]["state"] == "up")

    s_, b_, hd_ = req("http://127.0.0.1:18090/health")
    check("外部確認用 /health は200で {waf: ok, backend: up}",
          s_ == 200 and json.loads(b_) == {"waf": "ok", "backend": "up"})
    nlines = len(open(lg8).read().splitlines())
    for _ in range(3):
        req("http://127.0.0.1:18090/health")
    mon.check_once()
    check("稼働チェックのアクセスは waf.log に残らない(定期確認でログが埋まらない)",
          len(open(lg8).read().splitlines()) == nlines)

    # 127.0.0.1 がBANされていても、WAF自身の確認は通る(確認用の接続はゲートの対象外)
    h8.limiter._do_ban("127.0.0.1", time.time(), reason="test")
    try:
        req("http://127.0.0.1:18090/board")
        banned_ok = False
    except Exception:
        banned_ok = True
    mon.check_once()
    check("BAN中のIPからの通常アクセスは切られるが、WAF待受の稼働チェックは up のまま",
          banned_ok and mon.snapshot()["targets"]["waf"]["state"] == "up")
    h8.limiter.clear_bans() if hasattr(h8.limiter, "clear_bans") else None

    # 一時的な失敗では揺れない。連続失敗でdown、復旧は即時
    cfg8["backend_port"] = 15999            # 誰も待ち受けていないポート
    mon.check_once()
    st1 = mon.snapshot()["targets"]["backend"]["state"]
    mon.check_once()
    st2 = mon.snapshot()["targets"]["backend"]["state"]
    check("1回の失敗では up のまま、連続2回失敗で down(fail_threshold=2)", st1 == "up" and st2 == "down")
    code503, body503, _h = req("http://127.0.0.1:18090/health")
    check("掲示板アプリがダウンなら /health は503(WAFは ok のまま)",
          code503 == 503 and json.loads(body503) == {"waf": "ok", "backend": "down"})
    check("ダウンの履歴が記録される(up→down)",
          any(x["target"] == "backend" and x["from"] == "up" and x["to"] == "down"
              for x in mon.snapshot()["history"]))
    cfg8["backend_port"] = 15000
    mon.check_once()
    check("復旧したら即 up に戻る", mon.snapshot()["targets"]["backend"]["state"] == "up")

    cfg8["backend_port"] = 15011
    mon.check_once(); mon.check_once()
    check("5xx を返し続けると error(異常応答)", mon.snapshot()["targets"]["backend"]["state"] == "error")
    cfg8["backend_port"] = 15000
    cfg8["health_check"]["slow_ms"] = 0
    mon.check_once()
    check("応答が slow_ms を超えたら slow(遅い)", mon.snapshot()["targets"]["backend"]["state"] == "slow")
    cfg8["health_check"]["slow_ms"] = 1000

    # HTTPS待受でも確認できる
    t8 = build_waf("block", 18091, 15000, log_path="/tmp/waf_test8t.log", tls=True)
    t8.conn_limiter.health.cfg["listen_tls"] = True
    start_server(t8)
    time.sleep(0.3)
    t8.conn_limiter.health.check_once()
    check("HTTPS待受(TLS握手つき)のWAF自身の稼働チェックも up",
          t8.conn_limiter.health.snapshot()["targets"]["waf"]["state"] == "up")
    check("確認用の接続が同時接続スロットを漏らさない(total==0)",
          h8.conn_limiter.snapshot()["total"] == 0 and t8.conn_limiter.snapshot()["total"] == 0)

    # [9] 受付スレッドの並列化(accept_threads)
    print("\n[9] 並列 accept")
    p9 = build_waf("block", 18092, 15000, log_path="/tmp/waf_test9.log", tls=True)
    start_server(p9)
    n9 = p9.start_extra_acceptors(4)
    time.sleep(0.3)
    check("受付スレッドが指定本数で動く", n9 == 4 and sum(t.name.startswith("acceptor-") for t in threading.enumerate()) == 3)
    import ssl as _ssl, concurrent.futures as _cf
    _ctx = _ssl.create_default_context(); _ctx.check_hostname = False; _ctx.verify_mode = _ssl.CERT_NONE
    def _one(_):
        try:
            with urllib.request.urlopen("https://127.0.0.1:18092/health", timeout=10, context=_ctx) as r:
                return r.status
        except Exception:
            return -1
    with _cf.ThreadPoolExecutor(16) as ex:
        res = list(ex.map(_one, range(300)))
    check("並列acceptでも300件すべて取りこぼしなく応答(200)", res.count(200) == 300)
    time.sleep(0.5)
    check("並列acceptでも同時接続スロットを漏らさない(total==0)", p9.conn_limiter.snapshot()["total"] == 0)
    p9.stop_acceptors()

    # [10] BAN中でも /health だけ見える通路
    print("\n[10] 遮断中でも /health だけ見える通路")
    import socket as _sk, ssl as _ssl2
    r10 = {"enabled": True, "max_requests": 1000, "window_seconds": 60, "burst_max": 0,
           "ban_threshold": 5, "ban_seconds": 300}
    l10 = build_waf("block", 18093, 15000, rate=r10, log_path="/tmp/waf_test10.log", tls=True)
    start_server(l10)
    time.sleep(0.3)
    l10.limiter.ban("127.0.0.1", 60)
    _c10 = _ssl2.create_default_context(); _c10.check_hostname = False; _c10.verify_mode = _ssl2.CERT_NONE
    def _raw(path, method="GET"):
        try:
            s_ = _sk.create_connection(("127.0.0.1", 18093), timeout=4)
            s_ = _c10.wrap_socket(s_, server_hostname="x")
            s_.sendall(f"{method} {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".encode())
            d = b""
            while True:
                c = s_.recv(4096)
                if not c: break
                d += c
            s_.close()
            return d
        except Exception as e:
            return b""
    out = _raw("/health")
    check("BAN中でも /health は 200/503 で応答する", out.startswith(b"HTTP/1.1 200") or out.startswith(b"HTTP/1.1 503"))
    check("応答本文に waf:ok が入る", b'"waf": "ok"' in out)
    check("BAN中は /health 以外には何も返さず切る(プロキシしない)", _raw("/board") == b"" and _raw("/health?x=1".replace("/health", "/other")) == b"")
    time.sleep(0.3)
    check("通路の接続は同時接続スロットを使わない/漏らさない(total==0, lane.active==0)",
          l10.conn_limiter.snapshot()["total"] == 0)
    # 予算: 短時間に大量に来たら、予算超過分は即切断(応答なし)
    served = 0
    with _cf.ThreadPoolExecutor(8) as ex:
        res10 = list(ex.map(lambda _: _raw("/health"), range(200)))
    served = sum(1 for r_ in res10 if r_.startswith(b"HTTP/1.1"))
    check(f"フラッド時は予算内だけ通る(200回中 {served} 回のみ応答。全部は通らない)", 0 < served < 120)
    snap10 = l10.conn_limiter.stats.snapshot()
    check("統計: 通路で答えた回数 / /health 以外を切った回数が数えられる", snap10["lane_ok"] >= 1 and snap10["lane_other"] >= 1)
    # 無効化すると BAN は /health も切る
    l10.conn_limiter.health.cfg.setdefault("health_check", {})["allow_when_blocked"] = False
    time.sleep(1.2)
    check("allow_when_blocked=false なら BAN中は /health も見えない", _raw("/health") == b"")

    # [11] BAN履歴の永続化
    print("\n[11] BAN履歴は再起動しても残る")
    import tempfile as _tf
    d11 = _tf.mkdtemp(); hp = os.path.join(d11, "ban_history.jsonl")
    a11 = waf.RateLimiter(100, 60, ban_threshold=3, ban_seconds=60, conn_burst_max=3, history_path=hp)
    for _ in range(4): a11.note_conn("10.1.1.1")
    a11.unban("10.1.1.1")
    for _ in range(4): a11.note_conn("10.1.1.1")     # 2回目のBAN(offense=2)
    for _ in range(4): a11.note_conn("10.2.2.2")
    a11.flush_history()
    b11 = waf.RateLimiter(100, 60, ban_threshold=3, ban_seconds=60, conn_burst_max=3, history_path=hp)
    h11 = b11.ban_history()
    check("再起動(新しいインスタンス)後も履歴が読み込まれる(3件・新しい順)",
          len(h11) == 3 and h11[0]["ip"] == "10.2.2.2" and h11[2]["ip"] == "10.1.1.1" and h11[1]["offense"] == 2)
    for _ in range(4): b11.note_conn("10.3.3.3")
    b11.flush_history()
    c11 = waf.RateLimiter(100, 60, history_path=hp)
    check("再起動後に増えたBANも続けて保存される(4件)", len(c11.ban_history()) == 4 and c11.ban_history()[0]["ip"] == "10.3.3.3")
    with open(hp, "a", encoding="utf-8") as f_:
        f_.write("これは壊れた行\n")
    check("壊れた行があっても読み込める", len(waf.RateLimiter(100, 60, history_path=hp).ban_history()) == 4)
    import dashboard as _dash
    rt11 = _dash.FileConfigControl.__new__(_dash.FileConfigControl)
    if rt11 is not None:
        check("ダッシュボード単体起動でも履歴ファイルを読んで表示できる",
              len(rt11._read_ban_history(hp)) == 4 and rt11._read_ban_history(hp)[0]["ip"] == "10.3.3.3")

    # [12] 状態ログ(永続化・稼働率計算・ページ)
    print("\n[12] 状態ログ")
    import datetime as _dt, tempfile as _tf2
    import dashboard as _d12
    d12 = _tf2.mkdtemp(); hp12 = os.path.join(d12, "h.jsonl"); bp12 = os.path.join(d12, "b.txt")
    open(bp12, "w").write((_dt.datetime.now() - _dt.timedelta(minutes=10)).isoformat(timespec="seconds"))
    cfg12 = waf.load_config(None); cfg12["backend_port"] = 15000
    m12 = waf.HealthMonitor(cfg12)
    m12.enable_persistence(hp12, bp12)
    ev12 = _d12.read_health_events(hp12)
    check("起動時: 前回の生存確認が古ければ『停止していた』と『起動』が記録される",
          [(e["target"], e["to"]) for e in ev12] == [("process", "down"), ("process", "up")])
    m12._apply("backend", True, 5, "HTTP 200", 200)
    m12._apply("backend", False, 0, "refused", None); m12._apply("backend", False, 0, "refused", None)
    m12.flush_history()
    ev12 = _d12.read_health_events(hp12)
    check("状態が変わると保存される(backend: 未確認→稼働中→ダウン)",
          [(e["to"]) for e in ev12 if e["target"] == "backend"] == ["up", "down"])
    open(hp12, "a", encoding="utf-8").write("壊れた行\n")
    check("壊れた行があっても読み込める", len(_d12.read_health_events(hp12)) == len(ev12))
    now12 = _dt.datetime(2026, 10, 16, 15, 0, 0)
    evs = [
        {"ts": "2026-10-16T10:00:00", "target": "process", "from": "unknown", "to": "up", "detail": ""},
        {"ts": "2026-10-16T10:00:00", "target": "waf", "from": "unknown", "to": "up", "detail": ""},
        {"ts": "2026-10-16T12:00:00", "target": "waf", "from": "up", "to": "down", "detail": ""},
        {"ts": "2026-10-16T13:00:00", "target": "waf", "from": "down", "to": "up", "detail": ""},
        {"ts": "2026-10-16T13:30:00", "target": "process", "from": "up", "to": "down", "detail": ""},
        {"ts": "2026-10-16T14:00:00", "target": "process", "from": "down", "to": "up", "detail": ""},
    ]
    r12 = _d12.build_status_log(evs, now12)
    check("稼働率: WAFプロセス = 4.5/5時間 = 90%", r12["summary"]["process"]["uptime_24h"] == 90.0)
    check("稼働率: WAF待受(ダウン1時間+停止30分を除く) = 3.5/5時間 = 70%", r12["summary"]["waf"]["uptime_24h"] == 70.0)
    check("変化の一覧は新しい順で、継続時間が入る",
          r12["events"][0]["ts"] >= r12["events"][-1]["ts"] and any(e["duration_sec"] == 3600 for e in r12["events"]))
    check("ダッシュボードのナビに「状態ログ」タブがあり、API(/api/health-log)から読み込む",
          'data-p="status"' in _d12.PAGE and 'id="page-status"' in _d12.PAGE and "/api/health-log" in _d12.PAGE)

    # [13] イベントログの全件読み込みと深刻度の数え方
    print("\n[13] 全件読み込み・深刻度")
    import dashboard as _d13, tempfile as _tf3
    lp13 = os.path.join(_tf3.mkdtemp(), "w.log")
    with open(lp13, "w", encoding="utf-8") as f_:
        for i_ in range(300):
            f_.write(json.dumps({"ts": "2026-10-16T10:%02d:%02d" % (i_ // 60, i_ % 60), "action": "RATELIMIT",
                                 "disposition": "ban", "client_ip": "9.9.9.9", "conn_ip": "10.0.0.1", "count": 1000}) + "\n")
        f_.write(json.dumps({"ts": "2026-10-16T11:00:00", "action": "PASS", "client_ip": "1.1.1.1", "method": "GET", "path": "/"}) + "\n")
    evs13, nread13, nfile13, tr13 = _d13.read_events_all(lp13, None)
    check("全行読み(limit=None)は上限内なら全行を返す", len(evs13) == 301 and nfile13 == 301 and not tr13)
    check("merge=True だと連続する同一IPの遮断は1行にまとまる(従来の表示)", len(_d13._recent(evs13, None)) == 2)
    check("merge=False なら、ログの1行=1行で全件返る(全件読み込み用)", len(_d13._recent(evs13, None, merge=False)) == 301)
    _, _, nf2, tr2 = _d13.read_events_all(lp13, 100)
    check("末尾 limit 行だけ読んだときは、切り捨てたことが分かる", nf2 == 301 and tr2)
    ag13 = _d13.Aggregates() if hasattr(_d13, "Aggregates") else None
    if ag13 is not None:
        ag13.add({"ts": "2026-10-16T10:00:00", "action": "BLOCK", "client_ip": "2.2.2.2", "path": "/x", "count": 1,
                  "hits": [{"id": "A", "category": "xss", "severity": "medium", "field": "q"},
                           {"id": "B", "category": "sqli", "severity": "critical", "field": "q"}]})
        ag13.add({"ts": "2026-10-16T10:00:01", "action": "DETECT", "client_ip": "2.2.2.2", "path": "/x", "count": 1,
                  "hits": [{"id": "A", "category": "xss", "severity": "low", "field": "q"}]})
        check("深刻度は『1件の攻撃=一番重いルール』で数える(合計=攻撃件数)",
              dict(ag13.severity_counts) == {"critical": 1, "low": 1})

    # [14] 攻撃アラート(警報バナー)の設定
    print("\n[14] 攻撃アラート")
    import dashboard as _d14, tempfile as _tf4
    cp14 = os.path.join(_tf4.mkdtemp(), "c.json")
    json.dump({"mode": "block"}, open(cp14, "w"))
    ctl14 = _d14.FileConfigControl(cp14)
    a14 = ctl14.get()["editable"]["alert"]
    check("既定: アラートON・警報音OFF・警戒5件/10秒・緊急100件・2秒で自動消去",
          a14 == {"enabled": True, "sound": False, "immediate": "critical", "threshold": 5, "window": 10, "critical": 100, "hold": 2, "position": "top", "bg": True})
    a14 = ctl14.set({"alert": {"enabled": False, "sound": True, "threshold": 9999999, "window": 0, "critical": -5, "hold": 1}})["editable"]["alert"]
    check("OFF/音ONを保存でき、数値は範囲内に丸められる",
          a14["enabled"] is False and a14["sound"] is True and a14["threshold"] == 100000
          and a14["window"] == 1 and a14["critical"] == 0 and a14["hold"] == 1)
    a14b = ctl14.set({"alert": {"immediate": "medium"}})["editable"]["alert"]
    check("「1件でも表示する深刻度」を保存でき、変な値は無視する(既定はcritical)",
          a14b["immediate"] == "medium" and ctl14.set({"alert": {"immediate": "xx"}})["editable"]["alert"]["immediate"] == "medium"
          and _d14.alert_view({})["immediate"] == "critical")
    _insp14 = waf.Inspector(waf.DEFAULT_CONFIG)
    _sev14 = lambda q_: {h["severity"] for h in _insp14.inspect_request("GET", "/board", q_, {}, b"", "")}
    check("既定(critical)では、XSSのscriptタグ(critical)は1件で表示対象、UNION SELECT(high)は件数が溜まったとき(設定でhighにすれば1件)",
          "critical" in _sev14("q=<script>alert(1)</script>")
          and "critical" not in _sev14("id=1' UNION SELECT username,password FROM users--")
          and "high" in _sev14("id=1' UNION SELECT username,password FROM users--"))
    check("設定ファイルの dashboard.alert に保存される", json.load(open(cp14))["dashboard"]["alert"]["enabled"] is False)
    check("WAF本体(ホットリロード側)にも同じ設定項目があり、既定値が揃っている",
          waf.DEFAULT_CONFIG["dashboard"]["alert"] == {"enabled": True, "sound": False, "immediate": "critical",
                                                     "threshold": 5, "window": 10, "critical": 100, "hold": 2, "position": "top", "bg": True}
          and waf._alert_view({}) == waf.DEFAULT_CONFIG["dashboard"]["alert"])
    check("バナーに攻撃方法と攻撃元の国(日本語名・内部IPの印)を出す",
          'id="abCty"' in _d14.PAGE and "Intl.DisplayNames" in _d14.PAGE and "(内部IP)" in _d14.PAGE
          and "攻撃元の国" in _d14.PAGE and "攻撃方法" in _d14.PAGE)
    check("攻撃マップ(リアルタイム/集計)に全画面ボタンがあり、Escで戻り、アラートの下に収まる",
          _d14.PAGE.count('class="mapfs"') == 3 and "function mapFsSet" in _d14.PAGE   # マップ2つ + イベントログ
          and "top:var(--ab-h,0px)" in _d14.PAGE and "ev.key==='Escape' && mapFsCard" in _d14.PAGE)
    check("アラートは攻撃の性質で文言が変わる(不正アクセス/大量アクセス/DoS)。XSS以外・レート制限系の理由も日本語で出す",
          all(s in _d14.PAGE for s in ("Flood Detected", "DoS Attack in Progress", "Intrusion Detected",
                                       "BAN発動(レート超過)", "接続フラッド", "同時接続数の超過", "AL_SEV", "data-alt=\"crit|flood\"")))
    check("画面にバナーと設定(ON/OFF・テスト表示)がある",
          'id="alertBar"' in _d14.PAGE and "function alertOnEvent" in _d14.PAGE
          and "sw('s-alon'" in _d14.PAGE and "function alPreview" in _d14.PAGE)

    # [15] 防御するバックエンドの切替(複数登録・ホスト名振り分け・リンク書き換え)
    print("\n[15] バックエンド切替")
    import waf_backend as _wb
    pr15 = _wb.normalize_backend_settings({"profiles": [
        {"id": "tmp-1", "name": "ローカル掲示板", "url": "http://127.0.0.1:5000"},
        {"id": "tmp-2", "name": "社内 サーバ", "url": "https://192.168.1.10:8443/health", "match_hosts": "Board.Example.test, x.test"},
        {"id": "tmp-3", "name": "外部サイト", "url": "https://www.example.com"}], "active": "tmp-2", "host_routing": True})
    check("URL指定で複数登録でき、使用中のid・ホスト名(小文字化)が正規化される",
          len(pr15["profiles"]) == 3 and pr15["active"] == pr15["profiles"][1]["id"]
          and pr15["profiles"][1]["match_hosts"] == ["board.example.test", "x.test"]
          and pr15["profiles"][1]["port"] == 8443 and pr15["profiles"][1]["health_path"] == "/health")
    check("https は公開サイトなら証明書検証ON・LAN/IPなら検証OFFが既定",
          pr15["profiles"][2]["verify_tls"] is True and pr15["profiles"][1]["verify_tls"] is False)
    cfg15 = {"backend_host": "127.0.0.1", "backend_port": 5000, "backend_scheme": "http"}
    check("backendsが空なら旧設定(backend_host/port)を1件として使う",
          _wb.active_profile(cfg15)["host"] == "127.0.0.1" and _wb.pick(cfg15, "any")["port"] == 5000)
    _wb.apply_to_cfg(cfg15, pr15)
    check("使用中=社内サーバ。ホスト名振り分けON: Host が一致すればそのバックエンド、無ければ使用中",
          _wb.pick(cfg15, "board.example.test:8080")["host"] == "192.168.1.10"
          and _wb.pick(cfg15, "unknown.test")["host"] == "192.168.1.10" and cfg15["backend_host"] == "192.168.1.10")
    cfg15["host_routing"] = False
    check("ホスト名振り分けOFFなら、Host に関係なく使用中", _wb.pick(cfg15, "board.example.test")["host"] == "192.168.1.10")
    bad15 = 0
    for b_ in ({"url": "ftp://a.b"}, {"url": "http://u@evil.com/"}, {"host": "a b", "scheme": "http"},
               {"host": "example.com", "scheme": "http", "port": 70000}, {"url": ""}):
        try:
            _wb.normalize_profile(dict(b_, name="x"))
        except ValueError:
            bad15 += 1
    check("不正な入力(ftp/ユーザー名@/空白入りホスト/範囲外ポート/空URL)は拒否する", bad15 == 5)
    try:
        _wb.check_not_loop(_wb.normalize_profile({"name": "w", "url": "http://127.0.0.1:8080"}), "0.0.0.0", 8080)
        loop15 = False
    except ValueError:
        loop15 = True
    check("WAF自身(待受ポート)を転送先にするとループするので拒否する", loop15)
    p15 = _wb.normalize_profile({"name": "o", "url": "http://10.0.0.5:5000"})
    c15 = "https://waf.local:8080"
    body15 = ('<a href="http://10.0.0.5:5000/x"> <img src="//10.0.0.5:5000/i.png"> "https:\\/\\/10.0.0.5:5000\\/j"').encode()
    out15 = _wb.rewrite_body(body15, p15, c15).decode()
    check("本文の元サイトURL(絶対/プロトコル相対/JSONエスケープ)をWAFのアドレスへ書き換える",
          "10.0.0.5" not in out15 and 'href="https://waf.local:8080/x"' in out15 and "//waf.local:8080/i.png" in out15)
    check("Location は書き換え、無関係なURL・相対パスはそのまま",
          _wb.rewrite_location("http://10.0.0.5:5000/a?b=1", p15, c15) == c15 + "/a?b=1"
          and _wb.rewrite_location("http://other.example/a", p15, c15) == "http://other.example/a"
          and _wb.rewrite_location("/rel", p15, c15) == "/rel")
    check("Set-Cookie は Domain だけ外し、他の属性は残す",
          _wb.rewrite_set_cookie("sid=1; Domain=10.0.0.5; Path=/; HttpOnly") == "sid=1; Path=/; HttpOnly")
    check("画面: 登録・使用中の切替・接続テスト・ホスト名振り分け・書き換えの設定がある",
          all(s in _d14.PAGE for s in ("id=\"beList\"", "function beTest", "/api/backend-test", "s-berout", "s-berw", "function beAdd")))


    # [16] 複数バックエンドの同時防御(専用の待受ポート)とバックエンド別のログ
    print("\n[16] 複数同時防御 / バックエンド別ログ")
    import socket as _s16
    pf16 = _wb.normalize_profile({"name": "x", "url": "http://10.0.0.5:80", "listen_port": "8081"})
    check("専用の待受ポート(listen_port)を数字で受け取る。空欄/未指定は0(専用なし)",
          pf16["listen_port"] == 8081 and _wb.normalize_profile({"name": "y", "url": "http://10.0.0.6"})["listen_port"] == 0
          and _wb.normalize_profile({"name": "y", "url": "http://10.0.0.6", "listen_port": ""})["listen_port"] == 0)
    bad16 = 0
    for lp_ in (70000, "abc", -5):
        try:
            _wb.normalize_profile({"name": "z", "url": "http://10.0.0.7", "listen_port": lp_})
        except ValueError:
            bad16 += 1
    check("範囲外/数字でない待受ポートは拒否する", bad16 == 3)
    def _st16(a_, b_, reserved=()):
        return _wb.normalize_backend_settings({"profiles": [
            {"id": "a", "name": "A", "url": "http://10.0.0.1", "listen_port": a_},
            {"id": "b", "name": "B", "url": "http://10.0.0.2", "listen_port": b_}], "active": "a"}, reserved_ports=reserved)
    n16 = 0
    for args_ in ((9001, 9001, ()), (9001, 0, (9001,)), (0, 8080, (8080, 8090))):
        try:
            _st16(*args_)
        except ValueError:
            n16 += 1
    check("待受ポートの重複、WAF本体/ダッシュボードのポートとの重複は拒否する", n16 == 3)
    cfg16 = {"host_routing": True}
    _wb.apply_to_cfg(cfg16, _st16(0, 9001))
    cfg16["host_routing"] = True
    check("専用ポートで受けたら、Host や使用中に関係なくそのバックエンドへ",
          _wb.pick(cfg16, "whatever.test", 9001)["id"] == "b" and _wb.pick(cfg16, "whatever.test", 8080)["id"] == "a"
          and _wb.pick(cfg16, None, 9001)["id"] == "b")
    check("接続の入口(Host不明)では、専用ポートなら宛先が決まる/ホスト名振り分けの共有ポートは未定(None)",
          _wb.pick_for_port(cfg16, 9001)["id"] == "b" and _wb.pick_for_port(cfg16, 8080) is None)
    cfg16["host_routing"] = False
    check("ホスト名振り分けOFFなら、共有ポートの宛先は使用中", _wb.pick_for_port(cfg16, 8080)["id"] == "a")
    check("ログに付ける印は id と表示名", _wb.tag(_wb.pick(cfg16, None, 9001)) == {"backend": "b", "backend_name": "B"})
    loop16 = False
    try:
        _wb.check_not_loop(_wb.normalize_profile({"name": "w", "url": "http://127.0.0.1:9001"}), "0.0.0.0", 8080, extra_ports=[9001])
    except ValueError:
        loop16 = True
    check("別のバックエンドの専用ポート(=WAF自身)を転送先にしてもループとして拒否する", loop16)
    class _Lg16:
        def __init__(self): self.rows = []
        def write(self, r): self.rows.append(dict(r))
    lg16 = _Lg16()
    agg16 = waf.DropAggregator(lg16, interval=999)
    for bid_ in ("a", "b", "a"):
        agg16.add({"action": "RATELIMIT", "disposition": "ban", "client_ip": "1.1.1.1", "conn_ip": "1.1.1.1", "backend": bid_})
    agg16.flush()
    check("dropの集約はバックエンドごとに別の行(a×2, b×1)になる",
          sorted((r["backend"], r["count"]) for r in lg16.rows) == [("a", 2), ("b", 1)])
    # 専用ポートの待受を実際に開閉する
    class _H16(__import__("http.server").server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"ok")
        def log_message(self, *a): pass
    def _free16():
        so = _s16.socket(); so.bind(("127.0.0.1", 0)); p_ = so.getsockname()[1]; so.close(); return p_
    def _up16(p_):
        try:
            c_ = __import__("http.client").client.HTTPConnection("127.0.0.1", p_, timeout=2); c_.request("GET", "/"); ok_ = c_.getresponse().read() == b"ok"; c_.close(); return ok_
        except OSError:
            return False
    cfg16b = {"listen_host": "127.0.0.1"}
    lm16 = waf.ListenerManager(cfg16b, type("M", (), {"ssl_context": None})(), _H16, None, None)
    p1_, p2_ = _free16(), _free16()
    lm16.prepare({p1_, p2_})
    check("専用ポートを開く", _up16(p1_) and _up16(p2_))
    lm16.commit({p1_})
    check("設定から外れたポートだけ閉じる", _up16(p1_) and not _up16(p2_))
    busy16 = _s16.socket(); busy16.bind(("127.0.0.1", 0)); busy16.listen(1); pb_ = busy16.getsockname()[1]
    try:
        lm16.prepare({p1_, p2_, pb_}); busy_ok16 = False
    except ValueError:
        busy_ok16 = True
    busy16.close()
    check("使用中のポートが混ざると全体を拒否し、今回開いた分は残さない", busy_ok16 and not _up16(p2_) and _up16(p1_))
    lm16.stop()
    check("停止で全部閉じる", not _up16(p1_))
    rows16 = _d14._recent([{"action": "PASS", "client_ip": "1.1.1.1", "ts": "2026-01-01T00:00:00", "backend": "b", "backend_name": "社内B"}], None)
    ag16 = _d14.Aggregates(); ag16.add({"action": "BLOCK", "backend": "b", "backend_name": "社内B", "count": 3}); ag16.add({"action": "PASS", "backend": "a"})
    bk16 = {x["id"]: x for x in ag16.snapshot_data("all", __import__("datetime").datetime.now())["backends"]}
    check("ダッシュボード: イベント行にバックエンド名が付き、バックエンド別に件数を集計する",
          rows16[0]["backend"] == "b" and rows16[0]["backend_name"] == "社内B" and bk16["b"]["counts"]["BLOCK"] == 3
          and bk16["b"]["name"] == "社内B" and bk16["a"]["total"] == 1)
    check("画面: イベントログの全画面ボタン・バックエンド絞り込み・件数チップ・専用ポート入力・稼働の複数表示がある",
          all(x in _d14.PAGE for x in ('id="logfs"', 'id="lf-backend"', "be-e-lp", "listen_port", 'id="slLive"',
                                      "全${bl.length}件", "function beChipsRender")))

    print(f"\n結果: PASS={PASS}  FAIL={FAIL}")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
