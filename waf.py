#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""waf.py: stored-XSS PoC アプリの手前に置くリバースプロキシ型 WAF

クライアント -> [ WAF (このプロセス) ] -> バックエンド (Flask アプリ :5000)

URL・クエリ・フォーム・JSON・ヘッダ・Cookie を検査し、XSS / SQLi / パストラバーサル / コマンドインジェクションの署名に当たったら
block モードは 403 で遮断、detect モードは通してログだけ残す。
応答にはセキュリティヘッダ(CSP 等)を付ける。同一 IP の過剰アクセスは 429 でレート制限。
検知はすべて waf.log(JSON Lines)に記録する。依存は標準ライブラリのみ。

使い方:
    python3 waf.py                      # waf_config.json を読み込んで起動
    python3 waf.py --config other.json
"""

import argparse
import datetime
import html
import http.client
import ipaddress
import json
import os
import re
import selectors
import socket
import ssl
import struct
import sys
import threading
import time
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qsl, unquote

# フォルダ構成: 一番上は waf.py と start_rules_tool.bat だけ。部品は src/、設定は config/、実行時に増えるデータは data/
ROOT = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(ROOT, "src")
CONFIG_DIR = os.path.join(ROOT, "config")
DATA_DIR = os.path.join(ROOT, "data")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(CONFIG_DIR, exist_ok=True)

import waf_backend as wb
import waf_extras as wx
import waf_rules
import waf_custom
import waf_org
import waf_logstore
import waf_crypt
import waf_tickets

BASE_DIR = ROOT


def _abs_path(p):
    """相対パスの置き場所を決める。「config/」「data/」で始まるものは waf.py のあるフォルダ基準、それ以外は data/ の中。空/None は None"""
    if not p:
        return None
    if os.path.isabs(p):
        return p
    if p.replace("\\", "/").startswith(("config/", "data/")):
        return os.path.join(ROOT, p)
    return os.path.join(DATA_DIR, p)


class QuietThreadingHTTPServer(ThreadingHTTPServer):
    """クライアント切断(接続リセット/中断/タイムアウト)でトレースバックを出さない ThreadingHTTPServer。
    正常系として静かに無視する。
    """
    daemon_threads = True
    # accept キューを深くして、フラッド時の取りこぼしと RST を減らす
    request_queue_size = 512

    def handle_error(self, request, client_address):
        et = sys.exc_info()[0]
        if et is not None and issubclass(
                et, (ConnectionError, BrokenPipeError, TimeoutError,
                     socket.timeout, ssl.SSLError)):
            return   # 接続断は想定内。黙って終了
        super().handle_error(request, client_address)


class GatedHTTPServer(QuietThreadingHTTPServer):
    """accept 直後、ワーカースレッドを作る前に accept_gate で接続可否を判定するサーバ。
    BAN/ブロック/同時接続過多は verify_request=False で即クローズし、スレッドを作らない。

    TLS は待受ソケットではなく ssl_context として持ち、ゲートを通った接続だけをワーカー側でTLS化する(WafHandler.setup)。
    弾く接続は握手もSSLオブジェクト生成もしないので、フラッド時にさばける接続数が増える。
    """
    gate = None            # make_handler が返す accept_gate を main で代入
    ssl_context = None     # TLS 待受のときだけ main が代入
    stats = None           # ConnStats(受付エラーの計数用。任意)
    last_accept_error = ""
    t_acc = None           # {client_address: accept時刻}。受付から処理開始までの遅れを測る

    def verify_request(self, request, client_address):
        g = self.gate
        if g is None:
            return True
        try:
            try:
                lport = request.getsockname()[1]     # 受けた待受ポート(バックエンド別ログ用)
            except Exception:
                lport = None
            ok = g(client_address, lport)
        except Exception:
            return True
        if not ok:
            # 弾く接続は shutdown(SHUT_WR) を挟まず、すぐ閉じる(syscall を減らす)。
            # SO_LINGER(on, 0) で FIN ではなく RST で破棄して、サーバ側に TIME_WAIT を溜めない。
            # フラッド中は Windows だと TIME_WAIT が溜まって受付が鈍る
            try:
                request.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            except Exception:
                pass
            try:
                request.close()
            except Exception:
                pass
        else:
            ta = self.t_acc
            if ta is not None:
                if len(ta) > 5000:
                    ta.clear()
                ta[client_address] = time.monotonic()
        return ok

    def start_extra_acceptors(self, n):
        """accept 専用スレッドを (n-1) 本追加する(serve_forever と合わせて n 本が並行で accept)。
        accept/close の待ち中は GIL が解放されるので、増やすとフラッド時にさばける接続数が増える(特に accept が遅い Windows)。
        待受ソケットは非ブロッキングにして、他のスレッドに先を越されても詰まらないようにする。
        """
        n = max(1, int(n))
        if n <= 1:
            return 1
        self.socket.setblocking(False)
        self._acc_stop = False

        def _run():
            sel = selectors.DefaultSelector()
            sel.register(self.socket, selectors.EVENT_READ)
            try:
                while not self._acc_stop:
                    try:
                        ready = sel.select(0.5)
                    except Exception:
                        if self._acc_stop:
                            return
                        time.sleep(0.05)
                        continue
                    if ready:
                        self._handle_request_noblock()
            finally:
                sel.close()
        for i in range(n - 1):
            threading.Thread(target=_run, daemon=True, name=f"acceptor-{i + 2}").start()
        return n

    def stop_acceptors(self):
        self._acc_stop = True

    def get_request(self):
        try:
            return super().get_request()
        except (BlockingIOError, TimeoutError):
            raise          # 他の accept スレッドに先を越されただけ。異常ではない
        except OSError as e:
            # accept 自体の失敗(fd やバッファの枯渇など)。数えて少し待つ。
            # 空回りすると CPU を食い、受付キューが溢れて接続拒否になる
            if self.stats is not None:
                self.stats.inc("accept_error", port=self.server_address[1])
            self.last_accept_error = f"{type(e).__name__}: {e}"[:160]
            time.sleep(0.01)
            raise

# ホップバイホップヘッダ(プロキシが転送しないヘッダ)
HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
}

DEFAULT_CONFIG = {
    "listen_host": "0.0.0.0",
    "listen_port": 8080,
    "listen_tls": True,            # 既定は HTTPS(証明書は自動生成)
    "tls_certfile": "waf_cert.pem",
    "tls_keyfile": "waf_key.pem",
    "tls_autogen": True,           # 証明書が無ければ自己署名を自動生成

    "backend_host": "127.0.0.1",
    "backend_port": 5000,
    "backend_scheme": "https",
    "backend_verify_tls": False,
    # 防御するバックエンド。複数登録して切り替え、またはホスト名で振り分ける。空なら上の backend_* を1件として使う
    #   例: {"id":"board","name":"掲示板","scheme":"https","host":"192.168.1.10","port":5000,
    #        "verify_tls":false,"health_path":"/","match_hosts":["board.example.com"],"host_header":"target"}
    "backends": [],
    "active_backend": "",          # 使用中のバックエンドの id
    "host_routing": False,         # True: アクセスされたホスト名(match_hosts)ごとに別のバックエンドへ振り分ける
    "backend_rewrite_links": True, # リダイレクト、Cookie、ページ内の元サイトURLを WAF のアドレスに書き換える

    "mode": "block",  # block または detect

    # カテゴリ単位の ON/OFF(既定は全部ON)
    "rules": {
        "xss": True, "sqli": True, "traversal": True, "cmdi": True,
        "ssrf": True, "xxe": True, "ssti": True, "nosqli": True,
        "ldap": True, "crlf": True, "redirect": True, "upload": True,
        "scanner": True, "deser": True, "protocol": True, "logic": True,
        "response": True,          # 応答HTMLの Stored XSS 検査(動作は response_inspection.action)
    },
    "disabled_rules": [],          # 無効にするルールID(例: ["XSS-022"])
    "detect_only_rules": [],       # 検知のみにするルールID。block 運用でも遮断せず記録だけ(誤検知対策)

    "inspect": {
        "query": True,
        "body": True,
        "json": True,
        "headers": True,
        "cookies": False,  # Cookie は誤検知が多いので既定 OFF
        "path": True,
    },

    "security_headers": {
        "enabled": True,
        "headers": {
            "Content-Security-Policy":
                "default-src 'self'; "
                "script-src 'self'; "                       # スクリプトは厳格(注入された <script> を無効化)
                "style-src 'self' 'unsafe-inline'; "        # アプリのインラインCSSは許可
                "img-src 'self' data:; "
                "object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
        },
    },

    "rate_limit": {
        "enabled": True,
        "max_requests": 120,
        "window_seconds": 60,
        "action": "drop",          # 上限超過時の動作。drop(無応答で切断) / 429(応答を返す)
        "ban_threshold": 5,        # window 内の違反回数がこれ以上で自動BAN(0=無効)
        "ban_seconds": 300,        # 自動BANの基本継続秒数
        "burst_max": 30,           # バースト上限(burst_seconds 内。0=無効)。超えたら即BAN
        "burst_seconds": 3,        # バースト判定窓(秒)
        "global_max_rps": 0,       # 全体の秒間リクエスト上限(0=無効)。ロードシェディング用
        "ban_escalate": True,      # 再犯ほどBAN時間を延ばす
        "max_conn_per_ip": 20,     # IPごとの同時接続数上限(0=無効)。Slowloris など接続枯渇対策
        "max_total_conn": 512,     # 全体の同時接続数上限(0=無効)。超えたら accept 段階で拒否する
        "conn_burst_max": 60,      # 接続試行の頻度上限(conn_burst_seconds 内。0=無効)。超えたら即BAN
        "conn_burst_seconds": 5,   # TLS握手だけ、接続だけのフラッドを握手前に検知する
    },
    "conn_timeout_seconds": 20,    # 接続のアイドル/低速タイムアウト(秒)。Slowloris の遅延送信を打ち切る
    "tls_handshake_timeout_seconds": 5,   # TLS握手のタイムアウト(秒)。ゲート通過後に接続ごとのスレッドで握手する
    "listen_backlog": 2048,
    "accept_threads": 4,
    "process_priority": "normal",   # Windows: WAFのCPU優先度(idle / below_normal / normal / above_normal / high)。同じPCで攻撃ツールを動かして重いときは below_normal
    "thread_switch_interval": 0.001,     # Pythonのスレッド切替間隔(秒)。小さいほど待たされたスレッドに早く回る           # 接続受付(accept)を並行で行うスレッド数。フラッド時の受付能力を上げる        # 受付キューの深さ。フラッドの山を吸収する(溢れると接続拒否)
    "blocklist": [],               # 手動ブロックするIP / CIDR(常に drop)
    "country_blocklist": [],        # 国別ブロック(国コードか国名)。該当国からのアクセスは drop

    "log_file": "waf.log",
    "health_history_file": "health_history.jsonl",   # 状態ログ(稼働の変化)の保存先。空文字で保存しない
    "health_heartbeat_file": "health_heartbeat.txt",  # 生存確認の時刻。次回起動時に停止していた期間を記録するのに使う
    "ban_history_file": "ban_history.jsonl",   # BAN履歴の保存先。再起動後も残る。空文字で保存しない
    "custom_rules_file": "config/custom_rules.json",   # 追加ルール。再起動なしで読み込む。waf_rules_tool.py で編集
    "rule_history_file": "rule_history.jsonl",   # ルール設定の変更履歴(誰が・いつ・何を)
    "tickets_file": "tickets.json",             # 例外申請・問い合わせのチケット
    "notify_email": {"enabled": False, "smtp_host": "", "smtp_port": 587, "smtp_tls": True, "smtp_ssl": False,
                     "username": "", "password": "", "from": "", "to": []},   # チケットのメール通知(SMTP)
    "mode_history_file": "mode_history.jsonl",   # 防御モード変更の履歴(誰が・いつ・何を)。空文字で保存しない
    "access_log": True,            # 通過(PASS)したリクエストもログとコンソールに出す
    "log_global_ip": True,         # ログの送信元をグローバルIPに解決して記録する
    "trust_xforwarded_for": False, # 信頼できるプロキシの背後のときだけ True(XFF は偽装できる)
    "self_ip_ttl": 60,             # 出口グローバルIPを取り直す間隔(秒)。VPN切替に追従する

    # クライアント申告方式: LAN内の端末(接続元がプライベートIP)は、WAF からは送信元の
    # プライベートIPしか見えず、VPN 等で外へ出るときの公開IPが分からない。
    # そこでブラウザに外部API(ipinfo 等)で公開IPを取得させ、Cookie/ヘッダで申告させる。
    # 申告が無い端末(curl や初回リクエスト)は WAF ホストの出口IPを使う。
    # 注意: 申告値は偽装できる。レート制限/BAN/同時接続の判定は常に実接続IP(conn_ip)で行う
    "client_ip_report": {
        "enabled": True,
        "cookie_name": "waf_cip",      # ブラウザが申告する Cookie 名
        "header_name": "X-Client-IP",  # ヘッダで直接申告するときの名前(API 等)
        "inject_script": True,         # HTML 応答に収集スクリプトを自動で注入するか
        "ttl_seconds": 45,             # 開いているページの再取得間隔(秒)。VPN切替はこの間隔以内に追従する
        "cookie_seconds": 3600,        # 申告 Cookie の寿命(秒)。長めにして、期限切れで出口IPに戻るのを防ぐ
        "private_only": True,          # 公開IPからの接続の申告は無視する(インターネット側からの偽装を防ぐ)
        # 上から順に試す。api.ipify.org は IPv4 だけ返すので、VPN が IPv6 を通さない環境でも
        # VPN側の IPv4 が取れる(ipinfo.io/ip は IPv6 を返すことがある)
        "providers": ["https://api.ipify.org", "https://ipinfo.io/ip", "https://ifconfig.me/ip"],
    },

    # 稼働モニター。掲示板アプリ(バックエンド)と WAF 自身の待受を定期的に確認して、ダッシュボードに表示する
    "health_check": {
        "enabled": True,
        "interval_seconds": 5,         # 確認の間隔(秒)
        "timeout_seconds": 3,          # 応答を待つ上限(秒)。超えたらダウン扱い
        "slow_ms": 1000,               # この応答時間(ms)を超えたら遅いと判定
        "fail_threshold": 2,           # 連続でこの回数失敗したらダウンと判定(一時的な失敗で揺れないように)
        "path": "/health",             # 外部監視用の確認アドレス(WAFのポート。例 https://WAF:8080/health)
                                       # 注意: このパスは WAF が応答するので、掲示板アプリ側の同名パスには届かない
        "backend_path": "/",           # バックエンドの確認先パス(GET)
        "waf_probe": True,             # WAF自身の待受ポートにも接続して応答時間を測る
        "allow_when_blocked": True,    # BAN/ブロック中の接続元にも /health だけは見せる(予算つきの細い通路)
        "blocked_ip_per_sec": 20,      # 1つの接続元あたり毎秒この回数まで
        "blocked_total_per_sec": 100,  # 全体で毎秒この回数まで
        "blocked_max_conn": 16,        # 同時にこの本数まで(超えた分は即切断)
    },

    "log_request_detail": True,    # リクエストのクエリ・ヘッダ・ボディを記録する
    "log_pass_body": True,         # 通過(PASS)したリクエストのボディも記録する(資格情報に注意)
    "log_response": True,          # バックエンド応答(status/ヘッダ/ボディ)も記録する(Burp風表示用)
    "log_encrypt": {"enabled": False, "org_keys": {}, "public_key": ""},   # ログ詳細(ヘッダ・Cookie・ボディ・クエリ)を組織ごとの公開鍵で暗号化して保存する。鍵はキー・オフィサーが登録
    "enc_idle_max_min": 60,                # 秘密鍵を読み込んだままにできる無操作時間の上限(分)。画面では 5/15/30/60 から選び、上限を超える選択肢は出ない
    "enc_hold_max_min": 120,               # 秘密鍵を読み込んでから、操作に関係なく消すまでの時間(分)
    "enc_demo_keys": True,                  # デモ用: 作成した秘密鍵を画面を離れるまでブラウザに保持し、コピーとダウンロードを何度でもできる(本番は false 推奨)
    "enc_audit_file": "enc_audit.jsonl",   # 暗号ログの復号・鍵変更の操作記録(改ざん検知つき)
    "max_body_inspect_bytes": 1048576,  # 1MB を超える body は先頭だけ検査する

    # 統合ダッシュボード(同一プロセスで別ポートに起動)
    "dashboard": {
        "enabled": True,
        "host": "127.0.0.1",      # 管理画面のホスト。既定はローカルのみ(LANに出すなら 0.0.0.0)
        "port": 8090,
        "tls": True,              # 管理画面も HTTPS で開く。証明書は待受用と同じものを使い、無ければ自己署名を自動生成。使えなければ HTTP
        "tls_certfile": "",       # 空なら待受用の証明書(tls_certfile)を使う
        "tls_keyfile": "",
        "password": "",           # 管理画面のパスワード(空=なし。環境変数 WAF_ADMIN_PASSWORD でも可)
                                  # host が 127.0.0.1 以外でパスワード未設定なら、起動時に自動生成して表示する
        "require_password_on_lan": True,
        "geo": True,              # 攻撃マップのジオロケーション
        "egress": True,           # 内部IPを出口グローバルIPで地図に出す
        "alert": {                # 攻撃を検知したときに管理画面へ出す警報バナー
            "enabled": True,      # ON/OFF
            "sound": False,       # 警報音(ブラウザの制約で、画面を一度クリックした後から鳴る)
            "immediate": "critical",  # この深刻度以上のルールに当たったら、件数に関係なく1件で表示(critical / high / medium / off)
            "threshold": 5,       # この件数(window 秒内)で警戒を表示
            "window": 10,         # 判定する秒数
            "critical": 100,      # この件数(window 秒内)で緊急に格上げ(0=格上げしない)
            "hold": 2,            # 攻撃が止んでから自動で消すまでの秒数
            "position": "top",    # バナーの表示位置(top=上 / both=上下)
            "bg": True,           # 警報中、画面の背景に六角形(EMERGENCY)を出す
        },
    },
}


# self_made_waf から統合した追加設定(IP許可リスト、除外IP、国の許可リスト、自動BAN、
# Slowloris 対策、ボディ上限、レスポンス検査、Webhook など)。詳細は waf_extras.EXTRA_DEFAULTS
DEFAULT_CONFIG.update(json.loads(json.dumps(wx.EXTRA_DEFAULTS)))


# ---------------------------------------------------------------------------
# 設定の読み込み(浅いマージ)
# ---------------------------------------------------------------------------

# 攻撃アラート(管理画面の警報バナー)の設定。dashboard.alert に保存する
ALERT_DEFAULTS = DEFAULT_CONFIG["dashboard"]["alert"]


def _alert_view(dash):
    a = dash.get("alert") if isinstance(dash.get("alert"), dict) else {}
    d = ALERT_DEFAULTS
    out = {"enabled": bool(a.get("enabled", d["enabled"])), "sound": bool(a.get("sound", d["sound"])), "bg": bool(a.get("bg", d["bg"]))}
    imm = str(a.get("immediate", d["immediate"]))
    out["immediate"] = imm if imm in ("critical", "high", "medium", "off") else d["immediate"]
    pos = str(a.get("position", d["position"]))
    out["position"] = pos if pos in ("top", "both") else d["position"]
    for k in ("threshold", "window", "critical", "hold"):
        try:
            out[k] = int(a.get(k, d[k]))
        except (TypeError, ValueError):
            out[k] = d[k]
    return out


def _alert_update(dash, up):
    a = dash.setdefault("alert", {})
    if not isinstance(a, dict):
        a = dash["alert"] = {}
    for k in ("enabled", "sound", "bg"):
        if k in up:
            a[k] = bool(up[k])
    if up.get("immediate") in ("critical", "high", "medium", "off"):
        a["immediate"] = up["immediate"]
    if up.get("position") in ("top", "both"):
        a["position"] = up["position"]
    lim = {"threshold": (1, 100000), "window": (1, 300), "critical": (0, 1000000), "hold": (1, 3600)}
    for k, (lo, hi) in lim.items():
        if k in up:
            try:
                a[k] = max(lo, min(hi, int(up[k])))
            except (TypeError, ValueError):
                pass


def _reserved_ports(cfg):
    """バックエンド専用の待受ポートに使えないポート(WAF本体・ダッシュボード)。"""
    out = set()
    try:
        out.add(int(cfg.get("listen_port") or 0))
        out.add(int(cfg.get("dashboard", {}).get("port") or 0))
    except (TypeError, ValueError):
        pass
    out.discard(0)
    return out


def load_config(path):
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))  # deep copy
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            user = json.load(f)
        for k, v in user.items():
            if isinstance(v, dict) and isinstance(cfg.get(k), dict):
                cfg[k].update(v)
            else:
                cfg[k] = v
    # ベンダー(提供元)の組織を最初から1つ登録しておく。古い形式の provider フラグのユーザーはベンダー所属に移す
    cfg["orgs"] = waf_org.ensure_vendor(cfg.get("orgs"))
    for u in ((cfg.get("dashboard") or {}).get("users") or []):
        if isinstance(u, dict) and u.get("provider") and u.get("role") in ("analyst", "key_officer"):
            u["org"] = waf_org.VENDOR_ID
            u["provider"] = False
    if cfg.get("backends"):
        try:
            wb.apply_to_cfg(cfg, wb.normalize_backend_settings(
                {"profiles": cfg["backends"], "active": cfg.get("active_backend"),
                 "host_routing": cfg.get("host_routing", False),
                 "rewrite_links": cfg.get("backend_rewrite_links", True)},
                reserved_ports=_reserved_ports(cfg)))
        except ValueError as e:
            print(f"警告: backends の設定が正しくありません({e})。backend_host/port の1件だけを使います。")
            cfg["backends"] = []
    return cfg


# ---------------------------------------------------------------------------
# グローバルIP解決(ログの送信元をグローバルIPにする)
# ---------------------------------------------------------------------------
GEO_CACHE_PATH = os.path.join(DATA_DIR, "geo_cache.json")

# この端末の出口グローバルIPの取得先(上から順に試す)
_SELF_IP_PROVIDERS = [
    "https://ipinfo.io/ip",
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
]


def _is_public_ip(ip):
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return obj.is_global and not obj.is_private


# ---------------------------------------------------------------------------
# クライアント申告方式(ブラウザが自分の公開IPを Cookie / ヘッダで申告する)
#
# LAN内の端末が VPN を使っても、WAF が見るTCP送信元は端末のプライベートIPのまま
# (LAN宛の通信は VPN を通らない)。外へ出るときの公開IPは端末自身しか知らない。
# そこで WAF が配る小さなスクリプトがブラウザ内で外部API(ipinfo 等)から公開IPを取得し、
# Cookie に入れる。以降のリクエストでは WAF がその Cookie を読んで、ログ・ダッシュボード・
# 攻撃マップの送信元グローバルIPに使う。
#
# 信頼境界: 申告値はクライアントが書き換えられるので、
#   * 公開IPからの接続の申告は無視する(private_only。インターネット側の偽装防止)
#   * レート制限 / BAN / 同時接続の判定は常に実接続IP(conn_ip)で行う
# ---------------------------------------------------------------------------
CIP_JS_PATH = "/__waf/cip.js"


def _parse_cookie(cookie_header, name):
    if not cookie_header:
        return None
    for part in cookie_header.split(";"):
        kv = part.strip().split("=", 1)
        if len(kv) == 2 and kv[0].strip() == name:
            return kv[1].strip()
    return None


def read_reported_ip(cfg, headers, conn_ip=None):
    """クライアントが申告した公開IPをヘッダ、Cookie の順に探して返す。
    無効/未申告/不正値/公開IPからの接続(private_only 時)なら None。返す値は ipaddress で検証・正規化済み。
    """
    cr = cfg.get("client_ip_report", {})
    if not cr.get("enabled"):
        return None
    if cr.get("private_only", True) and conn_ip and _is_public_ip(conn_ip):
        return None
    cands = []
    try:
        hv = headers.get(cr.get("header_name", "X-Client-IP"))
        if hv:
            cands.append(hv)
        cv = _parse_cookie(headers.get("Cookie", ""), cr.get("cookie_name", "waf_cip"))
        if cv:
            cands.append(unquote(cv))
    except Exception:
        return None
    for c in cands:
        c = str(c).strip()
        if not c or len(c) > 45:
            continue
        if _is_public_ip(c):
            try:
                return str(ipaddress.ip_address(c))
            except ValueError:
                continue
    return None


def _cip_js(cfg):
    """ブラウザで動く収集スクリプト。外部APIで自分の公開IPを取得して Cookie に入れる。
    再取得は、ページを開くたび / 開いている間は ttl 秒ごと / タブに戻ったとき・フォーカス時・bfcache復帰・ネットワーク変化(online / connection change)。
    Cookie は cookie_seconds(既定1時間)の長寿命にして、期限切れで出口IPに戻るのを防ぐ。HTTPS のときは Secure を付ける。
    """
    cr = cfg.get("client_ip_report", {})
    providers = cr.get("providers") or []
    cookie = cr.get("cookie_name", "waf_cip")
    ttl = max(15, int(cr.get("ttl_seconds", 45)))
    keep = max(ttl * 2, int(cr.get("cookie_seconds", 3600)))
    return (
        "(function(){try{"
        "var C=" + json.dumps(cookie) + ",T=" + str(ttl) + ",M=" + str(keep)
        + ",P=" + json.dumps(providers) + ",last=0;"
        "var S=location.protocol==='https:'?';Secure':'';"
        "function ok(s){return /^(\\d{1,3}\\.){3}\\d{1,3}$/.test(s)||/^[0-9a-fA-F:]{3,45}$/.test(s);}"
        "function set(ip){document.cookie=C+'='+encodeURIComponent(ip)+';path=/;max-age='+M+';SameSite=Lax'+S;}"
        "function get(i){if(i>=P.length)return;"
        "var ctl=window.AbortController?new AbortController():null;"
        "var tm=setTimeout(function(){if(ctl)ctl.abort();},4000);"
        "fetch(P[i],{cache:'no-store',credentials:'omit',signal:ctl?ctl.signal:undefined})"
        ".then(function(r){return r.text();})"
        ".then(function(t){clearTimeout(tm);t=(t||'').trim();if(ok(t)){set(t);}else{get(i+1);}})"
        ".catch(function(){clearTimeout(tm);get(i+1);});}"
        "function run(){var n=Date.now();if(n-last<3000)return;last=n;get(0);}"
        "run();"                                   # ページを開くたびに取り直す
        "setInterval(run,T*1000);"                 # 開いている間は ttl 秒ごと
        "window.addEventListener('online',run);"
        "window.addEventListener('focus',run);"
        "window.addEventListener('pageshow',run);"  # 戻る/進む(bfcache)からの復帰時
        "document.addEventListener('visibilitychange',function(){"
        "if(document.visibilityState==='visible')run();});"
        "if(navigator.connection&&navigator.connection.addEventListener)"
        "navigator.connection.addEventListener('change',run);"
        "}catch(e){}})();"
    )


def _augment_csp_for_report(csp, cfg):
    """収集スクリプトが外部プロバイダへ fetch できるよう、CSP の connect-src にだけプロバイダのオリジンを足す。
    script-src 'self' など他の制限はそのまま。
    """
    cr = cfg.get("client_ip_report", {})
    hosts = []
    for p in cr.get("providers") or []:
        try:
            u = urlparse(p)
            if u.scheme and u.netloc:
                origin = f"{u.scheme}://{u.netloc}"
                if origin not in hosts:
                    hosts.append(origin)
        except Exception:
            pass
    if not hosts:
        return csp
    directives = [d.strip() for d in csp.split(";") if d.strip()]
    for i, d in enumerate(directives):
        if d.lower().startswith("connect-src"):
            directives[i] = d + " " + " ".join(h for h in hosts if h not in d)
            return "; ".join(directives)
    directives.append("connect-src 'self' " + " ".join(hosts))
    return "; ".join(directives)


class GlobalIPResolver:
    """接続元(remote_addr)/ X-Forwarded-For / 自ホスト出口IP から、ログに記録するグローバルIPを決める。
    出口IPは geo_cache.json(__self_ip__)で dashboard と共有する。
    """
    def __init__(self, enabled=True, trust_xff=False, ttl=60):
        self.enabled = enabled
        self.trust_xff = trust_xff
        self.ttl = ttl                 # 出口IPを取り直す間隔(秒)。VPN切替に追従する
        self.lock = threading.Lock()
        self._self_ip = None
        self._self_ip_at = 0.0         # 取得時刻
        self._refreshing = False

    def _save_self(self, ip):
        data = {}
        try:
            with open(GEO_CACHE_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            data = {}
        data["__self_ip__"] = ip
        try:
            with open(GEO_CACHE_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False)
        except OSError:
            pass

    def _fetch(self):
        """プロバイダから出口グローバルIPを取得し、キャッシュを更新する。"""
        import urllib.request
        for url in _SELF_IP_PROVIDERS:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "waf"})
                with urllib.request.urlopen(req, timeout=4) as resp:
                    ip = resp.read().decode().strip()
                if _is_public_ip(ip):
                    with self.lock:
                        changed = (ip != self._self_ip)
                        self._self_ip = ip
                        self._self_ip_at = time.time()
                        self._save_self(ip)
                    if changed:
                        print(f"[IP] 出口グローバルIPを更新: {ip}")
                    return ip
            except Exception:
                continue
        # 取得失敗。古い値があれば TTL だけ延ばして使い続ける
        with self.lock:
            self._self_ip_at = time.time()
            self._refreshing = False
        return self._self_ip

    def _refresh_async(self):
        with self.lock:
            if self._refreshing:
                return
            self._refreshing = True
        def run():
            try:
                self._fetch()
            finally:
                with self.lock:
                    self._refreshing = False
        threading.Thread(target=run, daemon=True).start()

    def self_public_ip(self):
        """現在の出口IPを返す。古ければバックグラウンドで取り直す(経路は止めない)。"""
        if not self.enabled:
            return None
        now = time.time()
        # 初回だけ起動時キャッシュを読む(TTL を超えていれば非同期で更新)
        if self._self_ip is None:
            try:
                with open(GEO_CACHE_PATH, "r", encoding="utf-8") as f:
                    ip = json.load(f).get("__self_ip__")
                if ip and _is_public_ip(ip):
                    self._self_ip = ip
                    self._self_ip_at = 0.0  # 古い可能性があるので要更新
            except (OSError, ValueError):
                pass
        # TTL 超過なら非同期で取り直す(現在値は即返す)
        if now - self._self_ip_at >= self.ttl:
            if self._self_ip is None:
                # 値がまだ無い初回は同期で取得する(起動時のプリウォーム用)
                return self._fetch()
            self._refresh_async()
        return self._self_ip

    def resolve(self, remote_ip, headers):
        """(記録するIP, 由来) を返す。由来は remote / xff / egress / local。"""
        if _is_public_ip(remote_ip):
            return remote_ip, "remote"
        if self.trust_xff:
            xff = headers.get("X-Forwarded-For", "")
            for part in xff.split(","):
                cand = part.strip()
                if _is_public_ip(cand):
                    return cand, "xff"
        egress = self.self_public_ip()
        if egress:
            return egress, "egress"
        # オフラインなどでグローバルIPが得られないときだけ接続元を記録する
        return remote_ip, "local"


class CountryResolver:
    """公開IPから国コード/国名を解決する(キャッシュ付き)。国別ブロック/許可用。
    GeoLite2 の mmdb(オフライン)があれば優先し、無ければ外部API(online=True のとき)。
    """
    def __init__(self, offline=None, online=True):
        self.cache = {}          # ip -> {"cc": "JP", "country": "Japan"} / None(解決不可)
        self.lock = threading.Lock()
        self.offline = offline   # waf_extras.OfflineGeo(任意)
        self.online = online

    def lookup(self, ip):
        if not _is_public_ip(ip):
            return None
        with self.lock:
            if ip in self.cache:
                return self.cache[ip]
        info = None
        if self.offline is not None and self.offline.ready:
            off = self.offline.lookup(ip)
            if off:
                info = {"cc": off["cc"], "country": off["country"]}
                with self.lock:
                    self.cache[ip] = info
                return info
        if not self.online:
            with self.lock:
                self.cache[ip] = None
            return None
        import urllib.request
        for url in (f"https://ipinfo.io/{ip}/json", f"http://ip-api.com/json/{ip}?fields=countryCode,country"):
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "waf"})
                with urllib.request.urlopen(req, timeout=3) as resp:
                    d = json.loads(resp.read().decode())
                cc = (d.get("country") or d.get("countryCode") or "").strip()
                name = (d.get("country") if len(str(d.get("country", ""))) > 2
                        else d.get("country_name") or d.get("countryName") or cc)
                # ipinfo は country に国コード(2文字)。ip-api は countryCode と country(名)
                if "countryCode" in d:
                    cc = d.get("countryCode", cc)
                    name = d.get("country", cc)
                if cc:
                    info = {"cc": cc.upper(), "country": str(name or cc)}
                    break
            except Exception:
                continue
        with self.lock:
            self.cache[ip] = info   # None も記録する(再試行が連発しないように)
        return info

    def is_blocked(self, ip, country_blocklist):
        """country_blocklist(国コード or 国名)に該当すれば (True, 国名)。解決できないときはブロックしない(フェイルオープン)。"""
        if not country_blocklist:
            return False, None
        info = self.lookup(ip)
        if not info:
            return False, None
        wanted = {str(x).strip().upper() for x in country_blocklist if str(x).strip()}
        if info["cc"] in wanted or info["country"].upper() in wanted:
            return True, info["country"]
        return False, None

    def check(self, ip, cfg):
        """国別のブロック/許可リストと「国不明の拒否」をまとめて判定する。
        戻り値: (拒否するか, 理由の表示文字列, 国名)
        """
        bl = cfg.get("country_blocklist") or []
        al = cfg.get("country_allowlist") or []
        unk = bool(cfg.get("country_block_unknown"))
        if not (bl or al or unk):
            return False, None, None
        info = self.lookup(ip)
        if not info:
            if unk:
                return True, "国不明", "不明"
            return False, None, None          # 判定できないときは通過(フェイルオープン)
        cc, name = info["cc"], info["country"]
        if al:
            allowed = {str(x).strip().upper() for x in al if str(x).strip()}
            if cc not in allowed and name.upper() not in allowed:
                return True, f"許可国外({cc})", name
        if bl:
            blocked = {str(x).strip().upper() for x in bl if str(x).strip()}
            if cc in blocked or name.upper() in blocked:
                return True, f"ブロック国({cc})", name
        return False, None, name


# ---------------------------------------------------------------------------
# レート制限(スライディングウィンドウ。IP単位でメモリ内)
# ---------------------------------------------------------------------------
class RateLimiter:
    def __init__(self, max_requests, window_seconds, ban_threshold=0, ban_seconds=300,
                 burst_max=0, burst_seconds=3, global_max_rps=0, ban_escalate=True,
                 conn_burst_max=0, conn_burst_seconds=5, history_path=None):
        self.max = max_requests
        self.window = window_seconds
        self.ban_threshold = ban_threshold   # window 内の違反回数がこれ以上でBAN(0=無効)
        self.ban_seconds = ban_seconds       # BAN の基本継続秒数
        self.burst_max = burst_max           # 短時間バーストの上限(0=無効)
        self.burst_seconds = burst_seconds   # バースト判定窓(秒)
        self.global_max_rps = global_max_rps # 全体の秒間リクエスト上限(0=無効)。ロードシェディング用
        self.ban_escalate = ban_escalate     # 再犯ほどBANを延ばす
        self.hits = defaultdict(deque)
        self.bursts = defaultdict(deque)
        self.violations = defaultdict(deque)
        self.offenses = defaultdict(int)     # IPごとのBAN発動回数(エスカレーション用)
        self.banned = {}                     # ip -> 解除時刻
        self.global_hits = deque()
        self.history = deque(maxlen=1000)    # BAN履歴(新しい順。メモリ上は最新1000件): {ip, at, duration, offense, reason}
        # BAN履歴を JSON Lines でも保存して、再起動後も残す。
        # 書き込みはゲートの経路ではなく、バックグラウンドのスレッドがまとめて追記する
        self.history_path = history_path
        self._hist_pending = []
        if history_path:
            self._load_history()
            threading.Thread(target=self._history_writer, daemon=True, name="ban-history").start()
        # 接続試行の頻度を握手前に判定する。リクエストが届かないフラッドも
        # BANとログに残すため
        self.conn_burst_max = conn_burst_max       # 窓内の接続試行数の上限(0=無効)。超えたら即BAN
        self.conn_burst_seconds = conn_burst_seconds
        self.conn_hits = {}                        # ip -> 接続試行時刻の deque
        self._conn_gc_at = 0.0
        self.ban_reason = {}                       # ip -> BAN理由(一覧表示用)
        self.exempt = lambda ip: False             # BAN/レート制限の対象外か(main/make_handler が差し替える)
        self.lock = threading.Lock()

    def _load_history(self):
        """起動時に保存済みのBAN履歴を読み込む(壊れた行は飛ばす)。長すぎれば末尾だけに整理する。"""
        path = self.history_path
        rows = []
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        d = json.loads(line)
                    except ValueError:
                        continue
                    if isinstance(d, dict) and d.get("ip") and d.get("at"):
                        rows.append(d)
        except OSError:
            return
        if len(rows) > 5000:
            rows = rows[-2000:]
            try:
                with open(path, "w", encoding="utf-8") as f:
                    for d in rows:
                        f.write(json.dumps(d, ensure_ascii=False) + "\n")
            except OSError:
                pass
        for d in rows:                       # 古い順に積んで、deque の先頭を最新にする
            self.history.appendleft(d)

    def _history_writer(self):
        while True:
            time.sleep(1.0)
            self.flush_history()

    def flush_history(self):
        with self.lock:
            batch, self._hist_pending = self._hist_pending, []
        if not batch or not self.history_path:
            return
        try:
            with open(self.history_path, "a", encoding="utf-8") as f:
                for d in batch:
                    f.write(json.dumps(d, ensure_ascii=False) + "\n")
        except OSError:
            pass

    def note_conn(self, ip):
        """接続1件を記録し、頻度が上限を超えたらBANして True を返す(accept ゲートから呼ぶ)。"""
        mx = self.conn_burst_max
        if mx <= 0 or self.exempt(ip):
            return False
        now = time.time()
        win = self.conn_burst_seconds
        with self.lock:
            dq = self.conn_hits.get(ip)
            if dq is None:
                dq = self.conn_hits[ip] = deque()
            while dq and dq[0] <= now - win:
                dq.popleft()
            dq.append(now)
            if len(dq) > mx:
                dq.clear()
                self._do_ban(ip, now, reason="conn_flood")
                return True
            # 送信元IPが大量に違う攻撃でも辞書が肥大しないよう、時々掃除する
            if len(self.conn_hits) > 20000 and now - self._conn_gc_at > 5:
                self._conn_gc_at = now
                for k in [k for k, q in self.conn_hits.items() if not q or q[-1] <= now - win]:
                    self.conn_hits.pop(k, None)
        return False

    def _do_ban(self, ip, now, reason="rate", base_seconds=None):
        if self.exempt(ip):
            return
        self.offenses[ip] += 1
        mult = (2 ** min(self.offenses[ip] - 1, 5)) if self.ban_escalate else 1
        duration = (base_seconds if base_seconds is not None else self.ban_seconds) * mult
        self.banned[ip] = now + duration
        self.ban_reason[ip] = reason
        entry = {
            "ip": ip,
            "at": datetime.datetime.fromtimestamp(now).isoformat(timespec="seconds"),
            "duration": int(duration),
            "offense": self.offenses[ip],
            "reason": reason,
        }
        self.history.appendleft(entry)
        if self.history_path:
            if len(self._hist_pending) < 20000:      # 書き込みが追いつかない大量BAN時の上限
                self._hist_pending.append(entry)

    def ban_history(self, limit=200):
        with self.lock:
            return list(self.history)[:limit]

    def is_banned(self, ip):
        """記録せず、BAN中かだけを判定する(検査前の早期drop用)。"""
        with self.lock:
            exp = self.banned.get(ip)
            if exp is None:
                return False
            if exp > time.time():
                return True
            del self.banned[ip]
            return False

    def status(self, ip):
        """'ok' / 'limited' / 'banned' / 'banned_now' / 'global'(全体上限)"""
        if self.exempt(ip):
            return "ok"
        now = time.time()
        with self.lock:
            # 全体レート上限(ロードシェディング)
            if self.global_max_rps > 0:
                gh = self.global_hits
                while gh and gh[0] <= now - 1.0:
                    gh.popleft()
                if len(gh) >= self.global_max_rps:
                    return "global"
                gh.append(now)
            exp = self.banned.get(ip)
            if exp is not None:
                if exp > now:
                    return "banned"
                del self.banned[ip]
            # バースト(短時間)上限。超えたら即BAN
            if self.burst_max > 0:
                bq = self.bursts[ip]
                while bq and bq[0] <= now - self.burst_seconds:
                    bq.popleft()
                bq.append(now)
                if len(bq) > self.burst_max:
                    self._do_ban(ip, now, reason="burst")
                    return "banned_now"
            dq = self.hits[ip]
            while dq and dq[0] <= now - self.window:
                dq.popleft()
            if len(dq) >= self.max:
                if self.ban_threshold > 0:
                    vq = self.violations[ip]
                    while vq and vq[0] <= now - self.window:
                        vq.popleft()
                    vq.append(now)
                    if len(vq) >= self.ban_threshold:
                        self._do_ban(ip, now, reason="rate")
                        return "banned_now"
                return "limited"
            dq.append(now)
            return "ok"

    def ban(self, ip, seconds=None):
        with self.lock:
            self.banned[ip] = time.time() + (seconds if seconds is not None else self.ban_seconds)

    def ban_for(self, ip, seconds, reason="manual", escalate=False):
        """理由つきでBANし、BAN履歴にも残す(手動BAN・攻撃回数による自動BAN・低速接続など)。
        除外IPはBANしない(False を返す)。
        """
        if self.exempt(ip):
            return False
        now = time.time()
        with self.lock:
            if escalate:
                self._do_ban(ip, now, reason=reason, base_seconds=seconds)
                return True
            self.offenses[ip] += 1
            self.banned[ip] = now + seconds
            self.ban_reason[ip] = reason
            entry = {"ip": ip, "at": datetime.datetime.fromtimestamp(now).isoformat(timespec="seconds"),
                     "duration": int(seconds), "offense": self.offenses[ip], "reason": reason}
            self.history.appendleft(entry)
            if self.history_path and len(self._hist_pending) < 20000:
                self._hist_pending.append(entry)
        return True

    def extend(self, ip, seconds):
        """BAN中なら残り時間に seconds を足す。BAN中でなければ新規に手動BANする。"""
        with self.lock:
            exp = self.banned.get(ip)
            now = time.time()
            if exp is not None and exp > now:
                self.banned[ip] = exp + seconds
                return True
        return self.ban_for(ip, seconds, "manual")

    def unban(self, ip):
        with self.lock:
            self.banned.pop(ip, None)
            self.ban_reason.pop(ip, None)
            self.violations.pop(ip, None)
            self.bursts.pop(ip, None)
            self.hits.pop(ip, None)

    def clear_bans(self):
        with self.lock:
            self.banned.clear()
            self.ban_reason.clear()

    def current_bans(self):
        now = time.time()
        with self.lock:
            return sorted(
                ({"ip": ip, "expires_in": int(exp - now), "reason": self.ban_reason.get(ip, "rate")}
                 for ip, exp in self.banned.items() if exp > now),
                key=lambda x: -x["expires_in"])


class ConnLimiter:
    """同時接続数を制限する(Slowloris / 接続枯渇 / スレッド枯渇対策)。IPごとの上限と全体の上限がある。
    上限は get_* で都度取得するので、ライブ変更に追従する。
    acquire() は accept ループ(verify_request)から呼ぶ。拒否時はワーカースレッドを作らないので、フラッドでスレッドが増えない。
    """
    def __init__(self, get_max_per_ip, get_max_total=None):
        self._get_max_ip = get_max_per_ip
        self._get_max_total = get_max_total or (lambda: 0)
        self.counts = defaultdict(int)
        self.total = 0
        self.lock = threading.Lock()

    def acquire(self, ip, ignore_ip_limit=False):
        """戻り値: 'ok'(受理・カウント済) / 'conn_limit'(IP上限) / 'overload'(全体上限)"""
        try:
            mx = int(self._get_max_ip() or 0)
        except Exception:
            mx = 0
        try:
            tmx = int(self._get_max_total() or 0)
        except Exception:
            tmx = 0
        with self.lock:
            if tmx > 0 and self.total >= tmx:
                return "overload"      # 全体の同時接続上限。超えたら受理しない
            if mx > 0 and not ignore_ip_limit and ip is not None and self.counts[ip] >= mx:
                return "conn_limit"    # IP別の同時接続上限
            if ip is not None:
                self.counts[ip] += 1
            self.total += 1
            return "ok"

    def release(self, ip):
        with self.lock:
            if self.total > 0:
                self.total -= 1
            if ip is None:
                return
            c = self.counts.get(ip, 0)
            if c <= 1:
                self.counts.pop(ip, None)
            else:
                self.counts[ip] = c - 1

    def snapshot(self):
        with self.lock:
            return {"total": self.total, "per_ip": dict(self.counts)}


class LoopGuard:
    """同じ接続元が同じURLで自分自身へのリダイレクトを短時間に繰り返された回数を数える。
    正当なリダイレクト(Cookie を付けて同じURLへ戻す)は1〜2回で終わるので、3回目からループとみなす。
    """
    def __init__(self, window=15.0):
        self.window = window
        self.d = {}
        self.lock = threading.Lock()

    def hit(self, key):
        now = time.monotonic()
        with self.lock:
            if len(self.d) > 2000:
                self.d = {k: v for k, v in self.d.items() if v and now - v[-1] < self.window}
            q = [t for t in self.d.get(key, []) if now - t < self.window]
            q.append(now)
            self.d[key] = q
            return len(q)


LOOP_GUARD = LoopGuard()


class ConnStats:
    """接続レベルの累積カウンター(メモリ内・再起動でリセット)。

    waf.log に残るのは、HTTPリクエストとして処理できたものと受付直後に切った接続だけ。
    接続だけして何も送らない/ゴミを送る/TLS握手に失敗するといった攻撃は残らず、攻撃の規模が分からない。
    そこで、ログに残らない分も含めて接続の流れを段階ごとに数える。

      accepted         受付ゲートを通過して受理した接続
      gate_*           ゲートで切った接続(blocklist / ban / conn_limit / overload / conn_flood)
      tls_ok / tls_fail  TLS握手の成功 / 失敗(タイムアウト・不正・途中切断を含む)
      no_request       受理したが、リクエストを1件も送らずに終わった接続
      idle_timeout     上のうち、WAF側のタイムアウトで切った数(Slowloris・握手後の無言)
      bad_request      HTTPとして不正で 4xx を返したリクエスト
      requests         HTTPリクエストとして解析できた件数(通過/遮断/drop を問わない)
    """
    KEYS = ("accepted", "gate_blocklist", "gate_ban", "gate_conn_limit", "gate_overload",
            "gate_conn_flood", "tls_ok", "tls_fail", "no_request", "idle_timeout",
            "bad_request", "requests", "accept_error", "lane_ok", "lane_other")

    def __init__(self):
        self.c = dict.fromkeys(self.KEYS, 0)
        self.by_port = {}          # 待受ポート -> {項目: 件数}(接続先ごとの接続の流れ用)
        self.by_backend = {}       # バックエンドid -> {項目: 件数}(リクエスト数。ホスト名/パスで振り分けた分も正確)
        self.lock = threading.Lock()
        self.since = time.time()

    def inc(self, key, n=1, port=None):
        with self.lock:
            self.c[key] = self.c.get(key, 0) + n
            if port:
                d = self.by_port.setdefault(int(port), {})
                d[key] = d.get(key, 0) + n

    def inc_backend(self, bid, key="requests", n=1):
        if not bid:
            return
        with self.lock:
            d = self.by_backend.setdefault(bid, {})
            d[key] = d.get(key, 0) + n

    def snapshot_split(self):
        """ポート別 / バックエンド別のカウンター(コピー)。"""
        with self.lock:
            return ({str(p): dict(d) for p, d in self.by_port.items()},
                    {b: dict(d) for b, d in self.by_backend.items()})

    def snapshot(self):
        with self.lock:
            d = dict(self.c)
        d["gate_total"] = sum(v for k, v in d.items() if k.startswith("gate_"))
        d["since"] = datetime.datetime.fromtimestamp(self.since).isoformat(timespec="seconds")
        return d


# ---------------------------------------------------------------------------
# IPブロックリストの照合(単一IP / CIDR 対応)
# ---------------------------------------------------------------------------
def ip_in_list(ip, patterns):
    if not patterns:
        return False
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for pat in patterns:
        pat = str(pat).strip()
        if not pat:
            continue
        try:
            if "/" in pat:
                if obj in ipaddress.ip_network(pat, strict=False):
                    return True
            elif ip == pat:
                return True
        except ValueError:
            continue
    return False


# ---------------------------------------------------------------------------
# ロガー(JSON Lines)
# ---------------------------------------------------------------------------
def wc_view(c):
    le = c.get("log_encrypt") if isinstance(c.get("log_encrypt"), dict) else {}
    v = waf_crypt.view(le)
    v["has_keys"] = waf_crypt.has_keys(le)
    v["officers"] = any(wx.norm_role(u.get("role")) == "key_officer" for u in wx.users_of(c))   # キー・オフィサーがいるか(いれば鍵の管理は担当者だけ)
    return v


def wc_apply(c, up):
    return waf_crypt.apply(c.get("log_encrypt"), up, valid_orgs={o.get("id") for o in (c.get("orgs") or []) if isinstance(o, dict)})


def wc_chain(cfg, bid):
    """バックエンドの所属組織と親組織を近い順に返す(組織ごとの暗号鍵を選ぶため)。"""
    prof = next((p for p in wb.raw_profiles(cfg) if p.get("id") == bid), None)
    if prof is None:
        return []
    org = waf_org.backend_org(prof, list(wx.users_of(cfg)))
    by = {o.get("id"): o for o in (cfg.get("orgs") or []) if isinstance(o, dict)}
    out, g = [], 0
    while org and org in by and g < 20:
        out.append(org)
        org = by[org].get("parent") or ""
        g += 1
    return out


class WafLogger:
    def __init__(self, path):
        self.path = _abs_path(path)
        self.lock = threading.Lock()
        self.webhook = None        # waf_extras.Webhook(検知イベントの外部送信。main が設定)
        self.logstore = None       # waf_logstore.LogStore(WEB別の日次ログと攻撃のまとめ。main が設定)
        self.legacy_file = True    # logstore を使うときは False(waf.log には書かない)

    def write(self, record):
        waf_crypt.seal_record(record)       # ログ詳細の暗号化(設定でONのときだけ。WAFは公開鍵しか持たない)
        if not record.get("ts"):
            record["ts"] = datetime.datetime.now().isoformat(timespec="seconds")
        line = json.dumps(record, ensure_ascii=False)
        if self.legacy_file:
            with self.lock:
                try:
                    with open(self.path, "a", encoding="utf-8") as f:
                        f.write(line + "\n")
                except OSError:
                    pass
        if self.logstore is not None:
            self.logstore.write(record, line)       # 失敗しても WAF の処理は止めない(LogStore 内で握りつぶす)
        if self.webhook is not None:
            try:
                self.webhook.submit(record)
            except Exception:
                pass
        # コンソールにも要約を出す
        act = record.get("action")
        if act in ("BLOCK", "DETECT", "RATELIMIT", "PASS", "ERROR"):
            extra = ""
            if act in ("BLOCK", "DETECT"):
                extra = " :: " + (",".join(sorted({h["id"] for h in record.get("hits", [])})) or "-")
            elif act == "PASS":
                extra = f" -> {record.get('status','?')}"
            elif act == "ERROR":
                extra = f" :: {record.get('error','')}"
            cnt = record.get("count", 1)
            cnt_disp = f" ×{cnt}" if cnt and cnt > 1 else ""
            disp = record.get("disposition")
            disp_disp = f" [{disp}]" if disp else ""
            gip = record.get("client_ip", "?")
            cip = record.get("conn_ip", "")
            # 接続元がプライベートIPなら、グローバルIPと併記する
            ipdisp = f"{gip} (接続元 {cip})" if cip and cip != gip else gip
            print(f"[{act}{cnt_disp}]{disp_disp} {ipdisp} "
                  f"{record.get('method','?')} {record.get('path','?')}{extra}")


class DropAggregator:
    """高頻度の drop 系イベント(RATELIMIT/BAN/ブロック/同時接続制限)を、(送信元IP × アクション × 種別)ごとに集約する。
    一定間隔で count 付きの 1 行にまとめてログへ書くので、大量フラッドでもログI/Oが増えない。
    集約キーに path/method を含めないので、多様なパスへの攻撃でも IP ごと 1 行/間隔に収まる。
    """
    def __init__(self, logger, interval=1.0, max_buckets=5000, gip_resolver=None):
        self.logger = logger
        self.interval = interval
        self.max_buckets = max_buckets
        self.gip_resolver = gip_resolver   # conn_ip -> global IP。フラッシュ時に1回だけ解決する
        self.buckets = {}            # key -> [record(dict), count]
        self.lock = threading.Lock()
        threading.Thread(target=self._loop, daemon=True).start()

    def add(self, record):
        key = (record.get("client_ip"), record.get("conn_ip"),
               record.get("action"), record.get("disposition"), record.get("backend"))
        over = None
        with self.lock:
            b = self.buckets.get(key)
            if b is None:
                self.buckets[key] = [record, 1]
                if len(self.buckets) > self.max_buckets:
                    over = self.buckets
                    self.buckets = {}
            else:
                b[1] += 1
        if over is not None:        # バケットが多すぎたら即フラッシュ(多様なIPからの攻撃対策)
            self._emit(over)

    def _emit(self, buckets):
        for record, count in buckets.values():
            r = dict(record)
            r["count"] = count
            # accept 段階の記録は conn_ip のみ。グローバルIPはここで1回だけ解決する(接続ごとには解決しない)
            if not r.get("client_ip") and self.gip_resolver:
                try:
                    r["client_ip"] = self.gip_resolver(r.get("conn_ip"))
                except Exception:
                    r["client_ip"] = r.get("conn_ip")
            try:
                self.logger.write(r)
            except Exception:
                pass

    def flush(self):
        with self.lock:
            buckets = self.buckets
            self.buckets = {}
        self._emit(buckets)

    def _loop(self):
        while True:
            time.sleep(self.interval)
            try:
                self.flush()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# 検出エンジンのラッパー
# ---------------------------------------------------------------------------
class Inspector:
    def __init__(self, cfg):
        self.cfg = cfg
        self.enabled = [c for c, on in cfg["rules"].items() if on]
        self.disabled_rules = set(cfg.get("disabled_rules", []))
        self.inspect = cfg["inspect"]
        self.max_body = cfg.get("max_body_inspect_bytes", 1048576)
        self.custom = None          # waf_custom.CustomRules(追加ルール。main が設定。再起動なしで入れ替わる)

    def detect_only_ids(self):
        """遮断せず検知のみにするルールID(設定のルール単位の検知のみ + モードが detect の追加ルール)。"""
        s = set(self.cfg.get("detect_only_rules") or ())
        if self.custom is not None:
            s |= self.custom.detect_ids()
        return s

    def _collect(self, method, path, query, headers, body_bytes, content_type):
        """検査対象の (場所ラベル, 値) のリストを返す。"""
        fields = []
        if self.inspect.get("path"):
            fields.append(("path", path))
        if self.inspect.get("query") and query:
            for k, v in parse_qsl(query, keep_blank_values=True):
                fields.append((f"query:{k}", v))
        if self.inspect.get("headers"):
            # 受信した全ヘッダを検査対象にする。ただしプロキシ由来やサイズ系の無害なヘッダは
            # 除外して誤検知を抑える(例: Accept の "*/*" が SQLコメントに誤検知される)
            _skip = {"host", "connection", "content-length", "content-type",
                     "accept", "accept-encoding", "accept-language", "accept-charset",
                     "cache-control", "pragma", "upgrade-insecure-requests", "date",
                     "if-modified-since", "if-none-match", "if-match", "if-range", "range",
                     "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "sec-fetch-user",
                     "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "dnt", "te",
                     "priority", "max-forwards", "expect"}
            _seen = set()
            for h in headers.keys():
                hl = h.lower()
                if hl in _skip or hl in _seen:
                    continue
                _seen.add(hl)
                if hl == "cookie" and not self.inspect.get("cookies"):
                    continue
                for val in headers.get_all(h) or []:
                    if val:
                        fields.append((f"header:{hl}", val))

        if self.inspect.get("body") and body_bytes:
            raw = body_bytes[: self.max_body]
            text = raw.decode("utf-8", errors="replace")
            ct = (content_type or "").lower()
            if "application/json" in ct and self.inspect.get("json"):
                try:
                    data = json.loads(text)
                    for label, value in _flatten_json(data):
                        fields.append((f"json:{label}", value))
                except (ValueError, TypeError):
                    fields.append(("body", text))
            elif "application/x-www-form-urlencoded" in ct:
                for k, v in parse_qsl(text, keep_blank_values=True):
                    fields.append((f"form:{k}", v))
            else:
                fields.append(("body", text))
        return fields

    # URL系ヘッダ。サイト自身のオリジンを含むので、URLを狙うルールは誤検知になる
    _URLISH_HEADERS = {"header:referer", "header:origin", "header:host"}
    _URL_CATEGORIES = {"ssrf", "redirect"}   # これらは上記ヘッダでは評価しない

    def inspect_request(self, method, path, query, headers, body_bytes, content_type):
        fields = self._collect(method, path, query, headers, body_bytes, content_type)
        all_hits = []
        for label, value in fields:
            cats = self.enabled
            if label in self._URLISH_HEADERS:
                # Referer/Origin/Host は自サイトのURLを含むので、SSRF/オープンリダイレクト判定から外す(誤検知防止)
                cats = [c for c in self.enabled if c not in self._URL_CATEGORIES]
            hits = waf_rules.scan_value(value, cats, self.disabled_rules)
            if self.custom is not None:
                hits = hits + self.custom.scan(label, value)
            for h in hits:
                h2 = dict(h)
                h2["field"] = label
                all_hits.append(h2)
        return all_hits


def _flatten_json(obj, prefix=""):
    out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.extend(_flatten_json(v, f"{prefix}.{k}" if prefix else str(k)))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out.extend(_flatten_json(v, f"{prefix}[{i}]"))
    else:
        out.append((prefix or "(root)", obj))
    return out


# ---------------------------------------------------------------------------
# リクエストハンドラ
# ---------------------------------------------------------------------------
DEFAULT_HEALTH_PATH = "/health"      # 外部監視用のパス(waf_config.json の health_check.path で変更可)


class BlockedLane:
    """BAN/ブロック中の接続元にも /health だけ見せるための細い通路(予算つき)。

    通常、BAN済みの接続は accept 直後に切るので /health も見えない。この通路は、遮断対象のうち予算内の接続だけを例外的に受け入れ、短いタイムアウトで1リクエストだけ読む。
    /health 以外のパスは何も返さず切る(検査もプロキシもしない)。
    予算は「IPごとの毎秒回数」「全体の毎秒回数」「同時接続数」の3つ。超えた分は即切断するので、フラッドで暗号計算が増えない。
    """

    def __init__(self, cfg_get):
        self._c = cfg_get                 # health_check 設定の取得関数 _c(key, default)
        self.lock = threading.Lock()
        self.active = 0
        self.ip = {}                      # ip ごとの [tokens, last]
        self.glob = None
        self.pending = set()              # ゲートが通した (ip, port)。ハンドラが setup で受け取る

    def _bucket(self, b, rate, burst, now):
        b[0] = min(burst, b[0] + (now - b[1]) * rate)
        b[1] = now
        if b[0] >= 1.0:
            b[0] -= 1.0
            return True
        return False

    def admit(self, client_address):
        if not self._c("allow_when_blocked", True):
            return False
        try:
            ip = client_address[0]
        except Exception:
            return False
        ip_rate = float(self._c("blocked_ip_per_sec", 20))
        glob_rate = float(self._c("blocked_total_per_sec", 100))
        mx = int(self._c("blocked_max_conn", 16))
        now = time.monotonic()
        with self.lock:
            if self.active >= mx:
                return False
            b = self.ip.get(ip)
            if b is None:
                if len(self.ip) > 4096:
                    self.ip.clear()
                b = self.ip[ip] = [ip_rate, now]          # IPごとのバケツは満タンで開始
            if self.glob is None:
                self.glob = [glob_rate, now]              # 全体バケツも満タンで開始
            # 先にIP別、次に全体。どちらかが空なら拒否
            if not self._bucket(b, ip_rate, ip_rate, now):
                return False
            if not self._bucket(self.glob, glob_rate, glob_rate, now):
                return False
            self.active += 1
            if len(self.pending) > 2000:
                self.pending.clear()
            self.pending.add(tuple(client_address[:2]))
            return True

    def take(self, client_address):
        """ハンドラ側の確認。この接続が通路経由なら True(pending から外す)。"""
        with self.lock:
            k = tuple(client_address[:2]) if client_address else None
            if k in self.pending:
                self.pending.discard(k)
                return True
        return False

    def release(self):
        with self.lock:
            if self.active > 0:
                self.active -= 1


class HealthMonitor:
    """稼働モニター。バックエンド(掲示板アプリ)とWAF自身の待受ポートを定期的に確認する。
    状態: up(稼働中) / slow(遅い) / error(5xx応答) / down(応答なし) / unknown(未確認)。
    一時的な失敗で表示が揺れないよう、連続 fail_threshold 回失敗して初めて down/error にする(復旧は即時)。
    WAF自身への確認は、受付ゲートの BAN/頻度制限を受けない専用の接続(送信元ポートで識別)で行う。
    プロセスごと止まると同じプロセスのダッシュボードも止まるので、外部からの確認が必要。外部の監視には health_check.path(既定 /health)が使える。
    """
    STATES = ("up", "slow", "error", "down", "unknown")
    LABELS = {"up": "稼働中", "slow": "遅い", "error": "異常応答(5xx)", "down": "ダウン", "unknown": "未確認",
              "paused": "稼働停止中"}

    def __init__(self, cfg):
        self.cfg = cfg
        self.lock = threading.Lock()
        self._probe_ports = set()
        self._stop = threading.Event()
        self._thread = None
        now = datetime.datetime.now().isoformat(timespec="seconds")
        self.targets = {}
        for name in ("backend", "waf"):
            self.targets[name] = {"state": "unknown", "latency_ms": None, "detail": "", "since": now,
                                  "last_ok": None, "fails": 0, "samples": deque(maxlen=60)}
        self.be_status = {}                 # 使用中以外で受け付けているバックエンドごとの状態 {id: {...}}
        self.history = deque(maxlen=100)    # 状態変化の履歴
        self.server = None                  # GatedHTTPServer。受付エラーの参照用で、main が代入する
        self.lat = None                     # make_handler が代入する deque
        # 状態ログの保存。main が enable_persistence で有効化する(テストでは無効)
        self.history_path = None
        self.beat_path = None
        self._pending = []
        self._lags = deque(maxlen=100)      # スケジューラ遅延(ms)。0.1秒ごとに測る

    # 設定
    def _c(self, key, default):
        try:
            return self.cfg.get("health_check", {}).get(key, default)
        except Exception:
            return default

    def path(self):
        p = str(self._c("path", DEFAULT_HEALTH_PATH) or DEFAULT_HEALTH_PATH)
        return p if p.startswith("/") else "/" + p

    # 受付ゲートからの問い合わせ。自分の確認用の接続か
    def is_probe(self, client_address):
        try:
            key = (client_address[0], client_address[1])
        except Exception:
            return False
        with self.lock:
            return key in self._probe_ports

    # 確認処理
    def probe_backend(self, prof=None):
        """戻り値: (成否, 応答時間ms, 詳細, HTTPステータス)"""
        prof = prof or wb.active_profile(self.cfg)       # 既定は使用中のバックエンド(切替に追従)
        to = float(self._c("timeout_seconds", 3))
        t0 = time.perf_counter()
        conn = None
        try:
            conn = wb.make_conn(prof, to)
            conn.request("GET", prof.get("health_path") or self._c("backend_path", "/"),
                         headers={"Host": wb.host_header(prof), "User-Agent": "waf-health/1.0",
                                  "Connection": "close"})
            resp = conn.getresponse()
            resp.read(1024)
            ms = (time.perf_counter() - t0) * 1000.0
            return True, ms, f"HTTP {resp.status}", resp.status
        except Exception as e:
            ms = (time.perf_counter() - t0) * 1000.0
            return False, ms, f"{type(e).__name__}: {e}"[:160], None
        finally:
            try:
                if conn:
                    conn.close()
            except Exception:
                pass

    def probe_waf(self):
        lh = self.cfg.get("listen_host", "127.0.0.1")
        host = "127.0.0.1" if lh in ("0.0.0.0", "", "::", "::0") else lh
        port = self.cfg["listen_port"]
        to = float(self._c("timeout_seconds", 3))
        t0 = time.perf_counter()
        s = None
        key = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(to)
            # 送信元ポートを自分で決めて登録し、受付ゲートが確認用の接続と識別できるようにする
            s.bind((host, 0))
            key = (host, s.getsockname()[1])
            with self.lock:
                self._probe_ports.add(key)
            s.connect((host, port))
            if self.cfg.get("listen_tls"):
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=None)
            s.sendall(f"GET {self.path()} HTTP/1.1\r\nHost: waf\r\nConnection: close\r\n\r\n".encode())
            buf = b""
            while b"\r\n\r\n" not in buf and len(buf) < 4096:
                d = s.recv(1024)
                if not d:
                    break
                buf += d
            if not buf.startswith(b"HTTP/1."):
                raise RuntimeError("HTTP応答なし")
            ms = (time.perf_counter() - t0) * 1000.0
            return True, ms, buf.split(b"\r\n", 1)[0].decode("latin-1")[:40], None
        except Exception as e:
            ms = (time.perf_counter() - t0) * 1000.0
            return False, ms, f"{type(e).__name__}: {e}"[:160], None
        finally:
            with self.lock:
                self._probe_ports.discard(key)
            try:
                if s:
                    s.close()
            except Exception:
                pass

    # 判定の反映
    def _apply(self, name, ok, ms, detail, status):
        thr = max(1, int(self._c("fail_threshold", 2)))
        slow = float(self._c("slow_ms", 1000))
        now = datetime.datetime.now().isoformat(timespec="seconds")
        msg = None
        with self.lock:
            t = self.targets[name]
            t["samples"].append((now, round(ms, 1) if ok else None))
            t["latency_ms"] = round(ms, 1) if ok else None
            t["detail"] = detail
            if ok and (status is None or status < 500):
                t["fails"] = 0
                new = "slow" if ms > slow else "up"
                t["last_ok"] = now
            else:
                t["fails"] += 1
                if t["fails"] < thr and t["state"] in ("up", "slow"):
                    return                          # 一時的な失敗かもしれないので、まだ確定しない
                new = "error" if ok else "down"
            old = t["state"]
            if new != old:
                ev = {"ts": now, "target": name, "from": old, "to": new, "detail": detail}
                if name == "backend":
                    ev.update(self._active_tag())
                self.history.append(ev)
                if self.history_path and len(self._pending) < 5000:
                    self._pending.append(ev)
                t["state"] = new
                t["since"] = now
                msg = (f"[稼働モニター] {self._backend_label() if name == 'backend' else 'WAF待受'}: "
                       f"{self.LABELS.get(old, old)} → {self.LABELS.get(new, new)}  ({detail})")
        if msg:
            print(msg, flush=True)

    def enable_persistence(self, history_path, beat_path):
        """状態の変化をファイル(JSON Lines)に残し、WAFを再起動しても履歴が消えないようにする。
        生存確認の時刻も定期的に書き、次の起動時に、その間WAFプロセスが止まっていたことも記録する。
        """
        self.history_path = history_path
        self.beat_path = beat_path
        now = datetime.datetime.now()
        events = []
        last = None
        try:
            with open(beat_path, "r", encoding="utf-8") as f:
                last = datetime.datetime.fromisoformat(f.read().strip())
        except (OSError, ValueError):
            last = None
        if last is not None and (now - last).total_seconds() > 30:
            events.append({"ts": last.isoformat(timespec="seconds"), "target": "process", "from": "up",
                           "to": "down", "detail": "WAFプロセスが停止(最後に生きていた時刻)"})
        events.append({"ts": now.isoformat(timespec="seconds"), "target": "process",
                       "from": "down" if events else "unknown", "to": "up", "detail": "WAFを起動"})
        self._pending.extend(events)
        self._trim_history_file()
        self.flush_history()
        self._beat()

    def _trim_history_file(self, keep=2000, limit=5000):
        try:
            with open(self.history_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            if len(lines) > limit:
                with open(self.history_path, "w", encoding="utf-8") as f:
                    f.writelines(lines[-keep:])
        except OSError:
            pass

    def _beat(self):
        if not self.beat_path:
            return
        try:
            with open(self.beat_path, "w", encoding="utf-8") as f:
                f.write(datetime.datetime.now().isoformat(timespec="seconds"))
        except OSError:
            pass

    def flush_history(self):
        if not self.history_path:
            return
        with self.lock:
            batch, self._pending = self._pending, []
        if not batch:
            return
        try:
            with open(self.history_path, "a", encoding="utf-8") as f:
                for d in batch:
                    f.write(json.dumps(d, ensure_ascii=False) + "\n")
        except OSError:
            pass

    def in_service(self):
        """いま実際に受け付けているバックエンド(使用中 / 専用ポート / ホスト名振り分けの対象)。"""
        act = wb.active_profile(self.cfg)
        out = []
        for p in wb.get_profiles(self.cfg):
            if p["id"] == act["id"]:
                continue
            if int(p.get("listen_port") or 0) or (self.cfg.get("host_routing") and p.get("match_hosts")):
                out.append(p)
        return out

    def _active_tag(self):
        try:
            p = wb.active_profile(self.cfg)
            return {"backend": p.get("id", ""), "backend_name": p.get("name", "")}
        except Exception:
            return {}

    def _probe_others(self):
        """使用中(メインの待受の転送先)以外の登録済みバックエンドも、すべて稼働チェックして状態ログに残す。"""
        slow = float(self._c("slow_ms", 1000))
        thr = max(1, int(self._c("fail_threshold", 2)))
        alive = {}
        act_id = wb.active_profile(self.cfg).get("id")
        for p in wb.get_profiles(self.cfg):
            if p["id"] == act_id:
                continue
            old = self.be_status.get(p["id"], {})
            if p.get("stopped"):
                state = "paused"
                alive[p["id"]] = {"state": "paused", "latency_ms": None, "detail": "稼働停止中(設定で停止しています)", "fails": 0}
                good = False; ms = 0
            else:
                ok, ms, detail, status = self.probe_backend(p)
                good = ok and (status is None or status < 500)
                fails = 0 if good else old.get("fails", 0) + 1
                if good:
                    state = "slow" if ms > slow else "up"
                elif fails < thr and old.get("state") in ("up", "slow"):
                    state = old["state"]
                else:
                    state = "error" if ok else "down"
                alive[p["id"]] = {"state": state, "latency_ms": round(ms, 1) if good else None,
                                  "detail": detail, "fails": fails}
            prev = old.get("state") or "unknown"
            now = datetime.datetime.now().isoformat(timespec="seconds")
            samples = list(old.get("samples") or [])
            samples.append(round(ms, 1) if good else None)
            alive[p["id"]].update({"samples": samples[-60:], "since": old.get("since") if prev == state else now,
                                   "last_ok": now if good else old.get("last_ok")})
            if prev != state:
                ev = {"ts": now, "target": "backend", "from": prev, "to": state, "detail": alive[p["id"]]["detail"],
                      "backend": p["id"], "backend_name": p["name"]}
                with self.lock:
                    self.history.append(ev)
                    if self.history_path and len(self._pending) < 5000:
                        self._pending.append(ev)
                print(f"[稼働モニター] {p['name']}: {self.LABELS.get(prev, prev)} → {self.LABELS.get(state)}  ({alive[p['id']]['detail']})", flush=True)
        with self.lock:
            self.be_status = alive

    def _backend_label(self):
        try:
            return str(wb.active_profile(self.cfg).get("name") or "バックエンド")
        except Exception:
            return "バックエンド"

    def _mark_paused(self, name="backend"):
        """稼働停止中のバックエンドは稼働チェックせず「稼働停止中」と表示する。"""
        now = datetime.datetime.now().isoformat(timespec="seconds")
        msg = None
        with self.lock:
            t = self.targets[name]
            t["latency_ms"] = None
            t["detail"] = "稼働停止中(設定で停止しています)"
            t["fails"] = 0
            if t["state"] != "paused":
                old = t["state"]
                ev = {"ts": now, "target": name, "from": old, "to": "paused", "detail": t["detail"]}
                if name == "backend":
                    ev.update(self._active_tag())
                self.history.append(ev)
                if self.history_path and len(self._pending) < 5000:
                    self._pending.append(ev)
                t["state"] = "paused"
                t["since"] = now
                msg = f"[稼働モニター] {self._backend_label()}: {self.LABELS.get(old, old)} → 稼働停止中"
        if msg:
            print(msg, flush=True)

    def check_once(self):
        if wb.active_profile(self.cfg).get("stopped"):
            self._mark_paused("backend")
        else:
            ok, ms, detail, status = self.probe_backend()
            self._apply("backend", ok, ms, detail, status)
        try:
            self._probe_others()
        except Exception:
            pass
        if self._c("waf_probe", True):
            ok, ms, detail, status = self.probe_waf()
            self._apply("waf", ok, ms, detail, status)

    def _loop(self):
        self._stop.wait(1.0)
        while not self._stop.is_set():
            try:
                if self._c("enabled", True):
                    self.check_once()
            except Exception:
                pass
            self.flush_history()
            self._beat()
            self._stop.wait(max(1.0, float(self._c("interval_seconds", 5))))

    def _lag_loop(self):
        """スレッドの起床遅れを測る。0.05秒眠って、実際に起きるまでの超過分が処理の渋滞の目安になる
        (CPU飽和/GILの奪い合いで WAF の全スレッドが待たされるほど大きくなる)。
        """
        while not self._stop.is_set():
            t0 = time.perf_counter()
            time.sleep(0.05)
            lag = (time.perf_counter() - t0 - 0.05) * 1000.0
            with self.lock:
                self._lags.append(max(0.0, lag))
            self._stop.wait(0.05)

    def start(self):
        if self._thread is None:
            self._thread = threading.Thread(target=self._loop, daemon=True, name="health")
            self._thread.start()
            threading.Thread(target=self._lag_loop, daemon=True, name="health-lag").start()

    def stop(self):
        self._stop.set()

    def snapshot(self):
        with self.lock:
            out = {"enabled": bool(self._c("enabled", True)),
                   "interval": self._c("interval_seconds", 5), "slow_ms": self._c("slow_ms", 1000),
                   "targets": {}, "history": list(self.history)[-30:][::-1]}
            for k, t in self.targets.items():
                out["targets"][k] = {"state": t["state"], "latency_ms": t["latency_ms"], "detail": t["detail"],
                                     "since": t["since"], "last_ok": t["last_ok"], "fails": t["fails"],
                                     "samples": [v for _, v in t["samples"]]}
            act = wb.active_profile(self.cfg)
            bl = []
            tb = self.targets["backend"]
            for p in wb.get_profiles(self.cfg):
                if p["id"] == act["id"]:
                    bl.append({"id": p["id"], "name": p["name"], "active": True, "listen_port": int(p.get("listen_port") or 0),
                               "state": tb["state"], "latency_ms": tb["latency_ms"], "detail": tb["detail"],
                               "since": tb["since"], "last_ok": tb["last_ok"], "samples": [v for _, v in tb["samples"]]})
                elif p["id"] in self.be_status:
                    b_ = self.be_status[p["id"]]
                    bl.append({"id": p["id"], "name": p["name"], "active": False, "listen_port": int(p.get("listen_port") or 0),
                               "state": b_["state"], "latency_ms": b_["latency_ms"], "detail": b_["detail"],
                               "since": b_.get("since"), "last_ok": b_.get("last_ok"), "samples": b_.get("samples") or []})
            out["backends"] = bl
            lags = list(self._lags)[-50:]
            out["lag_ms"] = round(max(lags), 1) if lags else None          # 直近約10秒の最大
            out["lag_avg_ms"] = round(sum(lags) / len(lags), 1) if lags else None
        # 正規の接続(稼働チェック・遮断中の通路を除く)の直近10秒の遅れ。時間を食っている箇所の手掛かり
        lat = list(self.lat) if self.lat is not None else []
        now_m = time.monotonic()
        recent = [x for x in lat if now_m - x[0] <= 10.0]
        qs = [x[1] for x in recent if x[1] is not None]
        hs = [x[2] for x in recent if x[2] is not None]
        out["conns_10s"] = len(recent)
        out["queue_ms_max"] = round(max(qs), 1) if qs else None
        out["queue_ms_avg"] = round(sum(qs) / len(qs), 1) if qs else None
        out["tls_ms_max"] = round(max(hs), 1) if hs else None
        out["tls_ms_avg"] = round(sum(hs) / len(hs), 1) if hs else None
        srv = self.server
        st = getattr(srv, "stats", None) if srv is not None else None
        out["accept_errors"] = st.snapshot().get("accept_error", 0) if st is not None else 0
        out["accept_last_error"] = getattr(srv, "last_accept_error", "") if srv is not None else ""
        return out

    def external_status(self):
        """外部確認用(既定 /health)の応答。(HTTPステータス, 本文JSON) を返す。WAFが応答できている時点で waf は ok。"""
        with self.lock:
            b = self.targets["backend"]["state"]
        code = 503 if b in ("down", "error") else 200
        return code, json.dumps({"waf": "ok", "backend": b}, ensure_ascii=False)


def make_handler(cfg, inspector, limiter, logger, ipresolver=None, country_resolver=None):

    # 転送先(backends / active_backend / host_routing)と以下の設定は、ライブ変更を反映するため cfg から都度読む
    #   mode / security_headers / access_log / log_request_detail / rate_limit / rules
    if ipresolver is None:
        ipresolver = GlobalIPResolver(
            enabled=cfg.get("log_global_ip", True),
            trust_xff=cfg.get("trust_xforwarded_for", False),
            ttl=cfg.get("self_ip_ttl", 60))

    # 同時接続数リミッタ(IP別 + 全体)。上限は cfg から都度読む
    conn_limiter = ConnLimiter(
        lambda: cfg["rate_limit"].get("max_conn_per_ip", 0),
        lambda: cfg["rate_limit"].get("max_total_conn", 0))
    stats = ConnStats()                 # 接続レベルの累積カウンター(ダッシュボード/コンソール用)
    conn_limiter.stats = stats          # make_handler の戻り値は変えず、ここ経由で参照する
    health = HealthMonitor(cfg)         # 稼働モニター。開始は main() が start() を呼ぶ
    conn_limiter.health = health
    lat = deque(maxlen=400)              # (時刻, 受付から処理開始までms, TLS握手ms)。正規の接続のみ
    health.lat = lat
    lane = BlockedLane(health._c)       # 遮断中の接続元に /health だけ見せる通路(予算つき)

    # 除外IP / 信頼する逆プロキシ / 繰り返し違反の自動BAN
    strikes = wx.StrikeCounter(cfg)     # 攻撃・低速接続・同時接続上限の繰り返しを数える
    conn_limiter.strikes = strikes

    def _exempt(ip):
        return wx.in_list(cfg.get("exempt_ips", []), ip)
    limiter.exempt = _exempt

    def _trusted(ip):
        return wx.in_list(cfg.get("trusted_proxies", []), ip)

    _STRIKE_REASON = {"attack": "attack", "slow": "slow", "connlimit": "connlimit"}

    def _strike(kind, ip, base_rec=None):
        """違反を1件数え、しきい値に達したら BAN する(detect モードでは BAN せず DETECT として記録)。"""
        try:
            if not strikes.note(kind, ip):
                return False
        except Exception:
            return False
        rec = {"method": "-", "path": "-", "hits": [], "conn_ip": ip}
        if base_rec:
            rec.update({k: v for k, v in base_rec.items() if k in ("client_ip", "conn_ip", "ip_src", "backend", "backend_name", "method", "path")})
        if cfg.get("mode") == "detect":
            rec.update({"action": "DETECT", "disposition": "autoban_would_" + kind})
            drop_agg.add(rec)
            return False
        limiter.ban_for(ip, strikes.ban_seconds(), _STRIKE_REASON[kind], escalate=True)
        rec.update({"action": "RATELIMIT", "disposition": "autoban_" + kind})
        drop_agg.add(rec)
        print(f"[自動BAN] {ip} ({strikes.LABELS[kind]}の繰り返し)")
        return True

    # 直近に申告された公開IP(接続元IPごと)。ヘッダのない drop 系イベント(レート制限/BAN/接続過多)でも、その端末の申告IPを使うため
    reported_cache = {}                 # conn_ip ごとの (申告IP, 受信時刻)
    reported_lock = threading.Lock()

    def _note_reported(conn_ip, rip):
        with reported_lock:
            if len(reported_cache) > 5000:        # 肥大防止。古い順に半分捨てる
                for k, _ in sorted(reported_cache.items(), key=lambda kv: kv[1][1])[:2500]:
                    reported_cache.pop(k, None)
            reported_cache[conn_ip] = (rip, time.time())

    def _recent_reported(conn_ip):
        cr = cfg.get("client_ip_report", {})
        if not cr.get("enabled"):
            return None
        keep = max(60, int(cr.get("cookie_seconds", 3600)))
        with reported_lock:
            v = reported_cache.get(conn_ip)
        if v and time.time() - v[1] <= keep:
            return v[0]
        return None

    def _resolve_gip(conn_ip):
        rep = _recent_reported(conn_ip)
        if rep:
            return rep
        try:
            return ipresolver.resolve(conn_ip, {})[0]
        except Exception:
            return conn_ip

    # drop系の高頻度イベントをまとめてログI/Oを抑える(DoS耐性)。グローバルIPはまとめる時に解決
    drop_agg = DropAggregator(logger, interval=1.0, gip_resolver=_resolve_gip)

    # ─────────────────────────────────────────────────────────────
    # accept ゲート。TCP accept 直後、ワーカースレッド生成の前に判定する。
    # False を返すとスレッドを作らず接続を即クローズするので、BAN/ブロック/接続過多のフラッドをHTTP解析なしで弾ける。
    # 判定は dict/set 参照だけの軽い処理にして、グローバルIP解決は集約フラッシュ側に回す
    # ─────────────────────────────────────────────────────────────
    def accept_gate(client_address, port=None):
        try:
            cip = client_address[0]
        except Exception:
            return True

        def _bt():
            # どのバックエンドへの接続か。専用ポート、またはホスト名振り分けOFFのときだけ分かる。ログの絞り込み用
            try:
                pr = wb.pick_for_port(cfg, port)
                return wb.tag(pr) if pr else {}
            except Exception:
                return {}
        rl = cfg["rate_limit"]
        # 稼働モニターの確認用接続(WAFが送信元ポートで識別)は、BAN/頻度制限の対象外。
        # 全体の同時接続上限には従う(上限に達していれば応答なしと判定されるのが正しい)
        if health.is_probe(client_address):
            return conn_limiter.acquire(cip, ignore_ip_limit=True) == "ok"
        # このゲートは TLS 握手の前に走る(待受ソケットが握手を遅延させている)。
        # BAN/ブロック/頻度超過の接続は、暗号計算なしで切れる
        def _reject(stat, rec):
            # 遮断対象でも、/health だけ見せる通路の予算内なら受け入れる。/health 以外はハンドラ側で即切断
            if lane.admit(client_address):
                return True
            stats.inc(stat, port=port)
            drop_agg.add(rec)
            return False
        # 信頼する逆プロキシからの接続は、送信元をリクエストの X-Forwarded-For で判定するので、ここでは止めない
        if _trusted(cip):
            st = conn_limiter.acquire(cip, ignore_ip_limit=True)
            if st != "ok":
                return _reject("gate_overload", {"action": "RATELIMIT", "disposition": st,
                                                 "method": "-", "path": "-", "hits": [], "conn_ip": cip, **_bt()})
            stats.inc("accepted", port=port)
            return True
        try:
            if ip_in_list(cip, cfg.get("blocklist", [])):
                return _reject("gate_blocklist", {"action": "RATELIMIT", "disposition": "blocklist",
                                                  "method": "-", "path": "-", "hits": [], "conn_ip": cip, **_bt()})
            al = cfg.get("ip_allowlist") or []
            if al and not wx.in_list(al, cip) and not _exempt(cip):
                return _reject("gate_blocklist", {"action": "RATELIMIT", "disposition": "allowlist",
                                                  "method": "-", "path": "-", "hits": [], "conn_ip": cip, **_bt()})
            # BAN中は、レート制限のON/OFFに関係なく遮断(レート制限・手動BAN・攻撃回数による自動BAN など)
            if limiter.is_banned(cip):
                return _reject("gate_ban", {"action": "RATELIMIT", "disposition": "ban",
                                            "method": "-", "path": "-", "hits": [], "conn_ip": cip, **_bt()})
            if rl.get("enabled"):
                # 接続試行の頻度(握手だけ・接続だけのフラッド対策)。超過したらBAN
                if limiter.note_conn(cip):
                    # BANが発動した事実は、通路で受け入れる場合も必ず数えて記録する
                    stats.inc("gate_conn_flood", port=port)
                    drop_agg.add({"action": "RATELIMIT", "disposition": "ban_triggered",
                                  "method": "-", "path": "-", "hits": [], "conn_ip": cip, **_bt()})
                    return lane.admit(client_address)
        except Exception:
            pass
        st = conn_limiter.acquire(cip, ignore_ip_limit=_exempt(cip))      # 同時接続数(IP別/全体)
        if st == "conn_limit":
            _strike("connlimit", cip, {"conn_ip": cip, **_bt()})   # 上限超過を繰り返す送信元はBAN
        if st != "ok":
            return _reject("gate_conn_limit" if st == "conn_limit" else "gate_overload",
                           {"action": "RATELIMIT", "disposition": st,
                            "method": "-", "path": "-", "hits": [], "conn_ip": cip, **_bt()})
        stats.inc("accepted", port=port)
        return True   # 受理した時点で conn_limiter に1加算済み。finish() で必ず release する

    class WafHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "WAF/1.0"
        # Slowloris 対策。アイドル/低速接続はこの秒数で打ち切る(StreamRequestHandler が socket に適用)
        timeout = cfg.get("conn_timeout_seconds", 20)

        # ログは標準の stderr ではなく自前ロガーへ出す
        def log_message(self, fmt, *args):
            pass

        def _sp(self):
            """この接続を受けた待受ポート(接続先ごとの集計用)。"""
            try:
                return self.server.server_address[1]
            except Exception:
                return None

        def setup(self):
            # setup は例外を外に出さない。__init__ の try/finally に必ず到達させて finish を保証する
            self._cl_ip = self.client_address[0] if self.client_address else None
            self._reqs = 0               # この接続で解析できたリクエスト数
            self._hs_failed = False      # TLS握手に失敗した接続(rfile/wfile は未作成)
            self._probe = health.is_probe(self.client_address) if self.client_address else False
            # 遮断中だが /health 用の通路で受け入れた接続。1リクエストだけ読み、/health 以外は切る
            self._lane = (not self._probe) and lane.take(self.client_address)
            # 受付(accept)から処理開始までの待ち(ms)。スレッド生成やGIL待ちの渋滞が分かる
            t_acc = getattr(self.server, "t_acc", None)
            t0 = t_acc.pop(self.client_address, None) if t_acc is not None else None
            self._q_ms = (time.monotonic() - t0) * 1000.0 if t0 is not None else None
            self._hs_ms = None
            # TLS握手はここ(ゲート通過後、接続ごとのスレッドでタイムアウト付き)で行う。
            # accept ループ内で握手すると、BAN済みの接続にも暗号計算がかかり、無応答の接続1本で accept ループ全体が止まる
            self._wrapped = False        # このハンドラでTLS化したソケット(finishで必ず閉じる)
            try:
                # 待受が ssl_context 方式のとき、ゲートを通った接続だけここでTLS化する
                sctx = getattr(self.server, "ssl_context", None)
                if sctx is not None and not isinstance(self.request, ssl.SSLSocket):
                    try:
                        self.request = sctx.wrap_socket(self.request, server_side=True,
                                                        do_handshake_on_connect=False)
                        self._wrapped = True
                    except Exception:
                        if not self._probe:
                            stats.inc("tls_fail", port=self._sp())
                        self._hs_failed = True
                        self.close_connection = True
                        return
                if isinstance(self.request, ssl.SSLSocket):
                    try:
                        self.request.settimeout(2 if self._lane else cfg.get("tls_handshake_timeout_seconds", 5))
                        _th = time.monotonic()
                        self.request.do_handshake()
                        self._hs_ms = (time.monotonic() - _th) * 1000.0
                        if not self._probe:
                            stats.inc("tls_ok", port=self._sp())
                    except Exception:
                        if not self._probe:
                            stats.inc("tls_fail", port=self._sp())
                        self._hs_failed = True
                        self.close_connection = True
                        return
                super().setup()
                to = 3 if self._lane else cfg.get("conn_timeout_seconds", 20)
                if to and to > 0:
                    self.connection.settimeout(to)
                if not self._probe and not self._lane:
                    lat.append((time.monotonic(), self._q_ms, self._hs_ms))
            except Exception:
                self.close_connection = True

        def handle(self):
            if self._hs_failed:
                return
            try:
                super().handle()
            except (ConnectionError, BrokenPipeError, TimeoutError, socket.timeout, ssl.SSLError):
                self.close_connection = True
            except Exception:
                self.close_connection = True

        def finish(self):
            if not self._hs_failed:
                try:
                    super().finish()
                except Exception:
                    pass
                # リクエストを1件も送らずに終わった接続(接続だけ/ゴミ/握手後の無言/タイムアウト)。
                # waf.log に残らないので、カウンターで見えるようにする
                if self._reqs == 0:
                    stats.inc("no_request", port=self._sp())
            # ここでTLS化したソケットは socketserver が持つ元のソケットとは別物なので、自分で閉じる
            if getattr(self, "_wrapped", False):
                try:
                    self.request.close()
                except Exception:
                    pass
            # accept_gate で受理した接続は1加算済み。漏れないようここで必ず release
            if getattr(self, "_lane", False):
                lane.release()          # 通路経由の接続は同時接続スロットを使っていない
            else:
                conn_limiter.release(getattr(self, "_cl_ip", None))

        def handle_one_request(self):
            # クライアント切断(リセット/中断)やタイムアウトは正常系なので、トレースバックを出さず静かに終了する。
            # Slowloris 対策: 次のリクエストの1バイト目が届いたら、header_timeout_seconds 以内にヘッダを受け取り終えないと低速接続として切断する。
            # 1バイトずつ送って conn_timeout をすり抜ける攻撃を止めるため
            self._hdr_token = None
            try:
                ht = cfg.get("header_timeout_seconds", 10) or 0
                if ht > 0 and not self._probe and not self._lane:
                    try:
                        if not self.rfile.peek(1):
                            self.close_connection = True
                            return
                    except (socket.timeout, TimeoutError):
                        if self._reqs == 0:
                            stats.inc("idle_timeout", port=self._sp())
                        self.close_connection = True
                        return
                    self._hdr_token = wx.DEADLINES.add(ht, lambda: self._slow("ヘッダ", ht))
                return super().handle_one_request()
            except (ConnectionError, BrokenPipeError, TimeoutError, socket.timeout, ssl.SSLError):
                self.close_connection = True
            except Exception:
                self.close_connection = True
            finally:
                if self._hdr_token is not None:
                    wx.DEADLINES.cancel(self._hdr_token)
                    self._hdr_token = None

        def parse_request(self):
            ok = super().parse_request()
            tok, self._hdr_token = getattr(self, "_hdr_token", None), None
            if tok is not None and not wx.DEADLINES.cancel(tok) and cfg.get("mode") != "detect":
                self.close_connection = True       # 締め切り超過。低速接続として記録・切断済み
                return False
            return ok

        def _slow(self, what, secs):
            """締め切りを過ぎた接続。低速接続として記録・カウントし、block モードなら切断する(監視スレッドから呼ばれる)。"""
            ip = getattr(self, "_cl_ip", None) or (self.client_address[0] if self.client_address else "?")
            rec = {"action": "RATELIMIT" if cfg.get("mode") != "detect" else "DETECT",
                   "disposition": "slow_conn", "method": "-", "path": f"(低速接続: {what}が{secs}秒以内に届かない)",
                   "hits": [], "conn_ip": ip}
            try:
                pr = wb.pick_for_port(cfg, self.server.server_address[1])
                if pr:
                    rec.update(wb.tag(pr))
            except Exception:
                pass
            drop_agg.add(rec)
            _strike("slow", ip)
            if cfg.get("mode") != "detect":
                try:
                    self.connection.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass

        def log_error(self, fmt, *args):
            # 標準の handle_one_request は読み取りタイムアウトを内部で処理して log_error を呼ぶ。
            # リクエストを1件も受け取れないまま WAF 側で打ち切った接続(Slowloris 等)を数える
            if isinstance(fmt, str) and fmt.startswith("Request timed out") and self._reqs == 0:
                stats.inc("idle_timeout", port=self._sp())

        def send_error(self, code, message=None, explain=None):
            # HTTPとして不正なリクエスト(request line が壊れている等)。ログに残らないので数える
            stats.inc("bad_request", port=self._sp())
            return super().send_error(code, message, explain)

        # すべてのメソッドを共通処理へ
        def do_GET(self):      self._handle()
        def do_POST(self):     self._handle()
        def do_PUT(self):      self._handle()
        def do_DELETE(self):   self._handle()
        def do_PATCH(self):    self._handle()
        def do_HEAD(self):     self._handle()
        def do_OPTIONS(self):  self._handle()

        def _client_ip(self):
            # 直結を想定。XFF は信頼境界の外なので参考情報のみ
            return self.client_address[0]

        def _read_body(self):
            """リクエストボディを読む(Content-Length / chunked 両対応、締め切り・上限つき)。
            (body, error) を返す。error は None / (status, rule_id, 説明) / "cut"(締め切り超過で切断)。
            """
            te = (self.headers.get("Transfer-Encoding") or "").strip().lower()
            cl = self.headers.get("Content-Length")
            if te and cl is not None:
                return b"", (400, "PROTO-SMUGGLE", "Content-Length と Transfer-Encoding の同時指定(リクエストスマグリング対策)")
            if te and te != "chunked":
                return b"", (400, "PROTO-SMUGGLE", f"未対応の Transfer-Encoding: {te[:40]}")
            if not te and cl is None:
                return b"", None
            mx = int(cfg.get("max_body_bytes", 0) or 0)
            bt = cfg.get("body_timeout_seconds", 30) or 0
            token = wx.DEADLINES.add(bt, lambda: self._slow("ボディ", bt)) if bt > 0 else None
            err = None
            body = b""
            try:
                if te == "chunked":
                    parts, total = [], 0
                    while True:
                        line = self.rfile.readline(1024)
                        if not line:
                            raise ValueError("chunked ボディが途中で終わった")
                        size = int(line.split(b";")[0].strip(), 16)
                        if size == 0:
                            while self.rfile.readline(8192) not in (b"\r\n", b"\n", b""):
                                pass
                            break
                        total += size
                        if mx and total > mx:
                            err = (413, "PROTO-TOOLARGE", f"ボディが上限 {mx} バイトを超えた")
                            break
                        parts.append(self.rfile.read(size))
                        self.rfile.readline(8)
                    body = b"".join(parts)
                else:
                    n = int(cl)
                    if n < 0:
                        raise ValueError("負の Content-Length")
                    if mx and n > mx:
                        err = (413, "PROTO-TOOLARGE", f"ボディが上限 {mx} バイトを超えた")
                    elif n > 0:
                        body = self.rfile.read(n)
            except (ValueError, OSError):
                if token is not None and not wx.DEADLINES.cancel(token):
                    return b"", "cut"
                return b"", (400, "PROTO-BADBODY", "ボディの形式が不正")
            if token is not None and not wx.DEADLINES.cancel(token) and cfg.get("mode") != "detect":
                return b"", "cut"
            if err:
                self.close_connection = True     # 読み残しがあるので、この接続は使い回さない
                return b"", err
            return body, None

        def _req_detail(self, query, body, content_type, include_body):
            detail = {"query": query}
            # 受信した全ヘッダを順序どおり記録する(DevTools と同等の生リクエスト再現用)
            hdrs = {}
            for k, v in self.headers.items():
                if v is None:
                    continue
                # 同名ヘッダは改行で連結
                if k in hdrs:
                    hdrs[k] = hdrs[k] + "\n" + str(v)[:2000]
                else:
                    hdrs[k] = str(v)[:2000]
            detail["headers"] = hdrs
            detail["body_len"] = len(body)
            if include_body and body:
                text = body[:4096].decode("utf-8", errors="replace")
                detail["body"] = text
                detail["body_truncated"] = len(body) > 4096
            return detail

        def _handle(self):
            self._reqs += 1                  # この接続で解析できたリクエスト数
            if self._lane:
                # 遮断中の接続元は /health(GET/HEAD)だけ答える。検査・ログ・プロキシはしない
                self.close_connection = True
                if self.command in ("GET", "HEAD") and urlparse(self.path).path == health.path():
                    stats.inc("lane_ok", port=self._sp())
                    return self._serve_health()
                stats.inc("lane_other", port=self._sp())
                return
            if self._probe:
                # 稼働モニターの確認用接続は、検査・ログ・集計の対象外。軽く応答して終わる
                if urlparse(self.path).path == health.path():
                    self.close_connection = True
                    return self._serve_health(probe=True)
            stats.inc("requests", port=self._sp())
            # 実際の接続元。レート制限のキーに使い、偽装できない。信頼する逆プロキシ経由のときだけ XFF から決める
            conn_ip = wx.effective_client_ip(self._client_ip(), self.headers.get("X-Forwarded-For"),
                                             cfg.get("trusted_proxies"))
            self._cl_conn = conn_ip
            # 信頼できるグローバルIP(公開接続元 / XFF / WAFホストの出口IP)
            sec_ip, sec_src = ipresolver.resolve(conn_ip, self.headers)
            # ブラウザが申告した公開IP(VPN出口など)があれば、表示・ジオ用にそちらを優先
            reported = read_reported_ip(cfg, self.headers, conn_ip)
            if reported:
                _note_reported(conn_ip, reported)
            client_ip = reported or sec_ip
            ip_src = "reported" if reported else sec_src
            self._log_ip = client_ip
            parsed = urlparse(self.path)
            path = parsed.path
            query = parsed.query
            content_type = self.headers.get("Content-Type", "")

            # 送信元IPは接続元(ローカル/プライベート)とグローバル(出口)の両方を記録
            ip_pair = {"client_ip": client_ip, "conn_ip": conn_ip, "ip_src": ip_src}
            # このリクエストの転送先(専用ポート > ホスト名振り分け > 使用中)。バックエンド別に見られるよう、ログにも印を付ける
            try:
                self._prof = wb.pick(cfg, self.headers.get("Host"), self.server.server_address[1], path)
            except Exception:
                self._prof = wb.pick(cfg, self.headers.get("Host"), None, path)
            ip_pair.update(wb.tag(self._prof))
            try:
                stats.inc_backend(self._prof.get("id"), "requests")
            except Exception:
                pass

            # 稼働停止中のバックエンドには転送せず、503(メンテナンス中)を返す
            if self._prof and self._prof.get("stopped"):
                self.close_connection = True
                data = ("<h1>503 Service Unavailable</h1><p>このアプリは現在、稼働を停止しています"
                        "(メンテナンス中)。しばらくしてからもう一度お試しください。</p>").encode("utf-8")
                self.send_response(503)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Retry-After", "300")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Connection", "close")
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(data)
                return

            rl = cfg["rate_limit"]

            # 0) 手動ブロックリスト(DDoS対策: 常にdrop)
            blocklist = cfg.get("blocklist", [])
            # 申告IP(画面に出ているIP)・信頼IP・実接続IP のどれかが該当すればdrop。
            # 申告を偽装してもブロックは逃れられない(実接続IPも必ず照合する)
            if (ip_in_list(client_ip, blocklist) or ip_in_list(sec_ip, blocklist)
                    or ip_in_list(conn_ip, blocklist)):
                drop_agg.add({
                    "action": "RATELIMIT", "disposition": "blocklist",
                    "method": self.command, "path": path, "hits": [], **ip_pair,
                })
                return self._drop()

            # 0.2) IP許可リスト。指定時は許可したIP/CIDR以外を拒否する(実接続IPで判定)
            al = cfg.get("ip_allowlist") or []
            if al and not wx.in_list(al, conn_ip) and not _exempt(conn_ip):
                drop_agg.add({
                    "action": "RATELIMIT", "disposition": "allowlist",
                    "method": self.command, "path": path, "hits": [], **ip_pair,
                })
                return self._drop()

            # 0.3) このバックエンド専用のIP制限(ブロック / 許可リスト)
            pol = (self._prof or {}).get("ip_policy") or {}
            if pol:
                pbl = pol.get("blocklist") or []
                if pbl and (ip_in_list(client_ip, pbl) or ip_in_list(sec_ip, pbl) or ip_in_list(conn_ip, pbl)):
                    drop_agg.add({
                        "action": "RATELIMIT", "disposition": "blocklist",
                        "method": self.command, "path": path, "hits": [], **ip_pair,
                    })
                    return self._drop()
                pal = pol.get("ip_allowlist") or []
                if pal and not wx.in_list(pal, conn_ip) and not _exempt(conn_ip):
                    drop_agg.add({
                        "action": "RATELIMIT", "disposition": "allowlist",
                        "method": self.command, "path": path, "hits": [], **ip_pair,
                    })
                    return self._drop()

            # 0.5) BAN中は検査せず即drop(悪性と判定済みで最も軽い)。手動/自動BANはレート制限OFFでも有効
            if limiter.is_banned(conn_ip):
                drop_agg.add({
                    "action": "RATELIMIT", "disposition": "ban",
                    "method": self.command, "path": path, "hits": [], **ip_pair,
                })
                return self._drop()

            # 0.7) 国別ブロック / 国の許可リスト / 国不明の拒否(本文は読まない)
            if country_resolver is not None and not _exempt(conn_ip):
                blocked, why, cname = country_resolver.check(client_ip, cfg)
                if blocked:
                    geo_hit = [{"id": "GEO-BLOCK", "category": "geo", "severity": "high",
                                "description": "国別アクセス制限(" + str(why) + ")",
                                "field": "client_ip", "matched": str(cname)}]
                    logger.write({
                        "action": "BLOCK", "disposition": "country:" + str(cname),
                        "method": self.command, "path": path,
                        "hits": geo_hit, **ip_pair,
                    })
                    return self._send_block_page(geo_hit)

            # 0.8) このバックエンド専用の国の制限
            if pol and country_resolver is not None and not _exempt(conn_ip) and (
                    pol.get("country_blocklist") or pol.get("country_allowlist")):
                blocked, why, cname = country_resolver.check(client_ip, {
                    "country_blocklist": pol.get("country_blocklist") or [],
                    "country_allowlist": pol.get("country_allowlist") or []})
                if blocked:
                    geo_hit = [{"id": "GEO-BLOCK", "category": "geo", "severity": "high",
                                "description": "国別アクセス制限(" + str(why) + "・このバックエンド)",
                                "field": "client_ip", "matched": str(cname)}]
                    logger.write({
                        "action": "BLOCK", "disposition": "country:" + str(cname),
                        "method": self.command, "path": path,
                        "hits": geo_hit, **ip_pair,
                    })
                    return self._send_block_page(geo_hit)

            # 1) レート制限。本文を読む前に判定し、超過分は body を読まず破棄する
            #    上限内のリクエストだけが本文読み取りと攻撃検査に進む
            if rl.get("enabled"):
                st = limiter.status(conn_ip)
                if st != "ok":
                    banned = st in ("banned", "banned_now")
                    if st == "global":
                        disp = "global_shed"      # 全体上限。常にdrop(ロードシェディング)
                    elif banned:
                        disp = "ban"
                    else:
                        disp = rl.get("action", "429")
                    drop_agg.add({
                        "action": "RATELIMIT",
                        "disposition": ("ban_triggered" if st == "banned_now" else disp),
                        "method": self.command, "path": path, "hits": [], **ip_pair,
                    })
                    if disp == "429":
                        return self._send_simple(429, "Too Many Requests",
                                                 "レート制限により一時的に拒否されました。")
                    return self._drop()   # drop / ban / global は本文を読まず無応答で切断

            # 1.5) クライアント申告用スクリプトの配信。WAF自身が応答し、検査/転送の対象外
            #      レート制限・BAN・ブロックは上で適用済み。同一オリジンなので script-src 'self' で動く
            if path == CIP_JS_PATH and self.command in ("GET", "HEAD"):
                return self._serve_cip_js()

            # 1.6) 外部監視用の稼働チェック。WAFが応答できれば 200、掲示板アプリがダウンなら 503
            #      レート制限・BANは上で適用済み。定期確認でログが埋まらないよう、ログには残さない
            if path == health.path() and self.command in ("GET", "HEAD"):
                return self._serve_health()

            # 2) 本文読み取り。ここに来るのは上限内の正当なリクエストだけ。締め切り・サイズ上限つき
            body, berr = self._read_body()
            if berr == "cut":
                return self._drop()          # 低速送信(Slow POST)。記録は _slow で済んでいる
            if berr:
                code, rid, desc = berr
                hit = [{"id": rid, "category": "protocol", "severity": "medium",
                        "description": desc, "field": "body", "matched": ""}]
                logger.write({"action": "BLOCK", "method": self.command, "path": path, "query": query,
                              "status": code, "hits": hit, **ip_pair})
                return self._send_simple(code, "Payload Too Large" if code == 413 else "Bad Request", desc)

            # 3) 攻撃検査(シグネチャ + ロジック検出)
            hits = inspector.inspect_request(
                self.command, path, query, self.headers, body, content_type)

            mode = wb.effective_mode(cfg, self._prof)   # バックエンド別の上書き/期限を反映した防御モード

            # バックエンド別のルール設定(使わないルール、場所を絞った除外)を適用
            hits, _excluded, _path_detect = wb.apply_rule_overrides_ex(self._prof, hits, path)

            log_detail = cfg.get("log_request_detail", True)
            if hits:
                detect_only = inspector.detect_only_ids() | wb.detect_ids(self._prof) | _path_detect   # パス別の検知のみも含める
                blocking = [h for h in hits if h.get("id") not in detect_only]   # 遮断対象の一致(検知のみルールを除く)
                do_block = (mode == "block" and bool(blocking))
                if blocking:
                    # 検知のみルールだけの一致では自動BANしない(誤検知でBANしないため)
                    _strike("attack", conn_ip, {**ip_pair, "method": self.command, "path": path})   # 攻撃の繰り返しで自動BAN
                action = "BLOCK" if do_block else "DETECT"
                rec = {
                    "action": action, "method": self.command, "path": path,
                    "query": query, "hits": hits, **ip_pair,
                }
                if log_detail:
                    rec["req"] = self._req_detail(query, body, content_type, include_body=True)
                if do_block:
                    logger.write(rec)
                    return self._send_block_page(blocking)
                # 検知のみ(アプリ/ルールが検知モード)。転送して応答も記録する

            # 3) バックエンドへ転送
            try:
                self._resp_hits, self._resp_act = [], None
                status, resp_detail = self._proxy(path, query, body)
                if self._resp_hits and not hits:
                    # 応答の Stored XSS 検知(無害化 / 遮断 / 記録のみ)
                    rec = {
                        "action": "DETECT" if self._resp_act == "monitor" else "BLOCK",
                        "disposition": "response_" + str(self._resp_act),
                        "method": self.command, "path": path, "query": query, "status": status,
                        "hits": self._resp_hits, **ip_pair,
                    }
                    if log_detail:
                        rec["req"] = self._req_detail(query, body, content_type,
                                                      include_body=cfg.get("log_pass_body", True))
                    if cfg.get("log_response", True):
                        rec["resp"] = resp_detail
                    logger.write(rec)
                elif hits:
                    rec["hits"] = hits + self._resp_hits
                    # DETECT: 応答も付けて記録
                    if cfg.get("log_response", True):
                        rec["resp"] = resp_detail
                    rec["status"] = status
                    logger.write(rec)
                elif cfg.get("access_log", True):
                    rec = {
                        "action": "PASS", "method": self.command, "path": path,
                        "query": query, "status": status, "hits": [], **ip_pair,
                    }
                    if log_detail:
                        # PASS も GET/POST のボディを記録(log_pass_body=false で無効化可)
                        rec["req"] = self._req_detail(
                            query, body, content_type,
                            include_body=cfg.get("log_pass_body", True))
                    if cfg.get("log_response", True):
                        rec["resp"] = resp_detail
                    logger.write(rec)
            except Exception as e:  # 転送失敗
                logger.write({
                    "action": "ERROR", "method": self.command, "path": path,
                    "error": str(e), "hits": [], **ip_pair,
                })
                self._send_simple(502, "Bad Gateway",
                                  "バックエンドへの転送に失敗しました。")

        # バックエンド転送
        def _proxy(self, path, query, body):
            # 転送先を決める(専用ポート > パス振り分け > ホスト名振り分け > 使用中)。毎回読むので切替は即時
            req_host = self.headers.get("Host")
            prof = getattr(self, "_prof", None) or wb.pick(cfg, req_host, None, path)
            # パス振り分け(例: /shop をバックエンドの / に)ではプレフィックスを外して転送する
            target = wb.forward_path(prof, path) + (("?" + query) if query else "")
            c_host = req_host or f'{cfg["listen_host"]}:{cfg["listen_port"]}'
            c_origin = f'{"https" if cfg["listen_tls"] else "http"}://{c_host}'
            rewrite = bool(cfg.get("backend_rewrite_links", True))
            conn = wb.make_conn(prof, 30)

            # 転送ヘッダを作る。ホップバイホップを除き、Host を書き換える
            cr = cfg.get("client_ip_report", {})
            inject_on = bool(cr.get("enabled") and cr.get("inject_script", True))
            fwd_headers = {}
            for k, v in self.headers.items():
                if k.lower() in HOP_BY_HOP:
                    continue
                if inject_on and k.lower() == "accept-encoding":
                    continue   # HTMLに収集スクリプトを差し込むため、圧縮なしで受け取る
                if rewrite and not inject_on and k.lower() == "accept-encoding":
                    v = wb.accept_encoding_for_rewrite(v)   # 展開できる圧縮(gzip/deflate)だけ依頼する
                if rewrite and k.lower() in ("origin", "referer"):
                    v = wb.rewrite_request_header_value(v, c_origin, prof)   # WAFのアドレスを元サイトのアドレスに戻す
                fwd_headers[k] = v
            if inject_on:
                fwd_headers["Accept-Encoding"] = "identity"
            fwd_headers["Host"] = c_host if prof.get("host_header") == "client" else wb.host_header(prof)
            fwd_headers["X-Forwarded-Host"] = c_host
            fwd_headers["X-Forwarded-For"] = getattr(self, "_log_ip", self._client_ip())
            fwd_headers["X-Forwarded-Proto"] = "https" if cfg["listen_tls"] else "http"
            fwd_headers = wb.strip_xf(fwd_headers, prof)      # 接続先ごとに付けない設定の転送ヘッダを外す(クライアント付与分も)

            conn.request(self.command, target, body=body or None, headers=fwd_headers)
            resp = conn.getresponse()
            resp_body = resp.read()
            resp_headers = resp.getheaders()
            conn.close()

            # 応答詳細を記録(Burp風表示用)
            resp_detail = {
                "status": resp.status, "reason": resp.reason,
                "headers": {k: v[:500] for k, v in resp_headers},
                "body_len": len(resp_body),
                "backend": wb.origin(prof),
            }
            ct = next((v for k, v in resp_headers if k.lower() == "content-type"), "")
            resp_detail["content_type"] = ct
            # テキスト系のみボディを保存(バイナリ/巨大は要約のみ)
            is_text = any(t in ct.lower() for t in
                          ("text", "json", "javascript", "xml", "html", "csv", "")) \
                      and "image" not in ct.lower() and "octet-stream" not in ct.lower() \
                      and "font" not in ct.lower()
            if cfg.get("log_response", True) and is_text and resp_body:
                resp_detail["body"] = resp_body[:4096].decode("utf-8", errors="replace")
                resp_detail["body_truncated"] = len(resp_body) > 4096

            # 応答の Stored XSS 検査。HTML のみ。無害化 / 遮断 / 記録のみ
            drop_ce = False
            if self.command != "HEAD" and resp.status not in (204, 304) and resp_body:
                lh = {k.lower(): v for k, v in resp_headers}
                act, new_body, rhits, decomp = wx.inspect_response(cfg, resp_body, lh, wb.effective_mode(cfg, self._prof), self._prof, path)
                if act:
                    self._resp_hits, self._resp_act = rhits, act
                    if act == "blocked":
                        self._send_block_page(rhits)
                        return 403, resp_detail
                    if act == "sanitized" and new_body is not None:
                        resp_body = new_body
                        if decomp:
                            drop_ce = True          # 展開して書き換えたので無圧縮で返す

            # ページ内の元サイトの絶対URLを WAF のアドレスに書き換える。別ドメインのサイトでもリンク先がWAFを通るようにするため
            enc0 = "" if drop_ce else next((v for k, v in resp_headers if k.lower() == "content-encoding"), "").lower()
            if rewrite and self.command != "HEAD" and resp.status not in (204, 304) and resp_body:
                if enc0 in ("gzip", "x-gzip", "deflate") and wb.is_text_ct(ct):
                    raw_ = wb.decompress(resp_body, enc0)       # 書き換えのために展開する(以後は無圧縮で返す)
                    if raw_ is not None:
                        resp_body, enc0, drop_ce = raw_, "", True
                if wb.can_rewrite_body(ct, enc0, len(resp_body)):
                    resp_body = wb.rewrite_body(resp_body, prof, c_origin)

            # クライアント申告用スクリプトを HTML 応答に差し込む(記録は上で取った元の応答)。
            # バイト列のまま扱うので Shift_JIS 等のページも壊れない
            enc = "" if drop_ce else next((v for k, v in resp_headers if k.lower() == "content-encoding"), "")
            if (inject_on and "text/html" in ct.lower() and not enc and resp_body
                    and self.command != "HEAD" and resp.status not in (204, 304)
                    and CIP_JS_PATH.encode() not in resp_body):
                tag = b'<script src="' + CIP_JS_PATH.encode() + b'" defer></script>'
                m = (re.search(rb"</head\s*>", resp_body, re.I)
                     or re.search(rb"</body\s*>", resp_body, re.I))
                if m:
                    resp_body = resp_body[:m.start()] + tag + resp_body[m.start():]
                else:
                    resp_body = resp_body + tag

            # リダイレクトループの検知。Location を WAF のアドレスに書き換えた結果が今要求したURLと同じで、
            # それが短時間に繰り返されるとブラウザが無限に繰り返すので、説明ページを返して止める
            if rewrite and 300 <= resp.status < 400 and self.command in ("GET", "HEAD"):
                loc0 = next((v for k, v in resp_headers if k.lower() == "location"), "")
                if loc0:
                    loc1 = wb.rewrite_location(wb.prefix_location(prof, loc0), prof, c_origin)
                    if wb.is_self_redirect(loc1, c_host, path + (("?" + query) if query else "")):
                        n_ = LOOP_GUARD.hit((getattr(self, "_log_ip", self._client_ip()), prof.get("id"), path, query))
                        if n_ >= 3:
                            resp_detail["redirect_loop"] = {"location": loc0, "count": n_}
                            self._send_loop_page(prof, loc0)
                            return 508, resp_detail

            # レスポンス返却
            self.send_response(resp.status)

            sec = cfg["security_headers"]            # ライブ読み込み
            injected = set()
            if sec.get("enabled"):
                injected = {h.lower() for h in sec.get("headers", {})}

            for k, v in resp.getheaders():
                kl = k.lower()
                if kl in HOP_BY_HOP:
                    continue
                if kl == "content-length":
                    continue  # 後で正しい長さを付ける
                if drop_ce and kl == "content-encoding":
                    continue  # 展開して返すので圧縮の表示は外す
                if kl in injected:
                    continue  # セキュリティヘッダは WAF 側の値で上書き
                if kl in ("location", "content-location"):
                    v = wb.prefix_location(prof, v)      # パス振り分け: / 始まりのリダイレクトにプレフィックスを戻す
                if rewrite:
                    if kl in ("location", "content-location", "access-control-allow-origin"):
                        v = wb.rewrite_location(v, prof, c_origin)
                    elif kl == "set-cookie":
                        v = wb.rewrite_set_cookie(v)
                    elif kl == "refresh":
                        v = wb.rewrite_body(v.encode("latin-1", "replace"), prof, c_origin).decode("latin-1")
                self.send_header(k, v)

            # セキュリティヘッダ付与
            if sec.get("enabled"):
                for k, v in sec.get("headers", {}).items():
                    if cr.get("enabled") and k.lower() == "content-security-policy":
                        # 収集スクリプトが外部プロバイダへ fetch できるよう、connect-src だけ緩める
                        v = _augment_csp_for_report(v, cfg)
                    self.send_header(k, v)

            self.send_header("Content-Length", str(len(resp_body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(resp_body)
            return resp.status, resp_detail

        # クライアント申告用スクリプト
        def _serve_health(self, probe=False):
            code, body = health.external_status()
            if probe:
                code = 200      # WAF自身の確認用。応答できた時点でWAFは生きている(アプリの状態は別枠で確認)
            data = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)

        def _serve_cip_js(self):
            if not cfg.get("client_ip_report", {}).get("enabled"):
                return self._send_simple(404, "Not Found", "無効です。")
            data = _cip_js(cfg).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)

        # 遮断ページ
        def _send_block_page(self, hits):
            rules = ", ".join(sorted({h["id"] for h in hits}))
            html_body = f"""<!doctype html>
<html lang="ja"><head><meta charset="utf-8">
<title>403 Forbidden — WAF</title>
<style>
body{{font-family:system-ui,sans-serif;background:#0f1115;color:#e6e6e6;
display:flex;align-items:center;justify-content:center;height:100vh;margin:0}}
.card{{max-width:560px;padding:32px 36px;background:#1a1d24;border-radius:12px;
border:1px solid #333;box-shadow:0 8px 30px rgba(0,0,0,.4)}}
h1{{margin:0 0 8px;font-size:22px;color:#ff6b6b}}
code{{background:#222;padding:2px 6px;border-radius:4px}}
.small{{color:#8a8f98;font-size:13px;margin-top:16px}}
</style></head>
<body><div class="card">
<h1>&#128683; リクエストを遮断しました</h1>
<p>このリクエストは WAF により危険と判定されました。</p>
<p>検知ルール: <code>{rules}</code></p>
<p class="small">正当なリクエストがブロックされた場合は管理者にお問い合わせください。</p>
</div></body></html>"""
            data = html_body.encode("utf-8")
            self.send_response(403)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-WAF-Block", rules)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)

        def _send_loop_page(self, prof, loc0):
            nm = html.escape(str(prof.get("name") or prof.get("id") or ""))
            body = f"""<!doctype html><html lang="ja"><head><meta charset="utf-8"><title>508 リダイレクトの繰り返しを検知 — WAF</title>
<style>body{{font-family:system-ui,sans-serif;background:#0f1115;color:#e6e6e6;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}}
.card{{max-width:640px;padding:30px 34px;background:#1a1d24;border-radius:12px;line-height:1.7}}h1{{font-size:20px;margin:0 0 12px}}
code{{background:#0f1115;padding:2px 6px;border-radius:4px;word-break:break-all}}.s{{color:#9aa3b2;font-size:13px}}</style></head><body><div class="card">
<h1>508 リダイレクトの繰り返しを検知しました</h1>
<p>接続先「{nm}」が、同じURLへのリダイレクト(<code>{html.escape(loc0[:200])}</code>)を返し続けています。
このまま続けるとブラウザが無限に繰り返すため、WAF が止めました。</p>
<p class="s">管理者の方へ: ダッシュボードの設定 → 該当の接続先を「接続テスト」すると、原因の転送ヘッダ(X-Forwarded-Host / Proto / For)を特定できます。
その接続先の「編集」で該当ヘッダを OFF にしてください。</p></div></body></html>""".encode("utf-8")
            self.close_connection = True
            self.send_response(508)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _send_simple(self, code, reason, message):
            data = f"<h1>{code} {reason}</h1><p>{message}</p>".encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)

        def _drop(self):
            """DDoS対策。応答を返さず接続を切断する(攻撃者に情報を与えない)。"""
            self.close_connection = True
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                self.connection.close()
            except Exception:
                pass

    return WafHandler, accept_gate, conn_limiter


# ---------------------------------------------------------------------------
# 自己署名証明書の自動生成(WAF を HTTPS 待受にするため)
# ---------------------------------------------------------------------------
def get_lan_ips():
    """この端末の LAN(プライベート)IPv4 アドレスを列挙する。"""
    ips = []
    # 主たる外向き IP(デフォルトルート側)を UDP ソケットで推定
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.append(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    # ホスト名解決からも集める
    try:
        host = socket.gethostname()
        for info in socket.getaddrinfo(host, None, socket.AF_INET):
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    # プライベート/リンクローカルのみ。ループバックは除く
    out = []
    for ip in ips:
        try:
            obj = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if obj.is_loopback:
            continue
        if obj.is_private or obj.is_link_local:
            if ip not in out:
                out.append(ip)
    return out


def _cert_san_ips(certfile):
    """既存証明書の SAN に含まれる IP 文字列の集合を返す(取得不可なら None)。"""
    try:
        from cryptography import x509
        with open(certfile, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        return {str(ip) for ip in san.get_values_for_type(x509.IPAddress)}
    except Exception:
        return None


def dashboard_tls_context(cfg):
    """管理画面用のTLS設定。証明書は dashboard.tls_certfile/keyfile、空なら待受用と同じものを使う。
    無ければ自己署名を自動生成する。作れない/読めないときは None(HTTPで起動)。
    """
    dc = cfg.get("dashboard", {})
    if not dc.get("tls", True):
        return None
    certfile = dc.get("tls_certfile") or cfg.get("tls_certfile") or "waf_cert.pem"
    keyfile = dc.get("tls_keyfile") or cfg.get("tls_keyfile") or "waf_key.pem"
    certfile = _abs_path(certfile)
    keyfile = _abs_path(keyfile)
    try:
        lan_ips = get_lan_ips()
        need_gen = not (os.path.exists(certfile) and os.path.exists(keyfile))
        if not need_gen and lan_ips:
            san = _cert_san_ips(certfile)
            if san is not None and not set(lan_ips).issubset(san):
                need_gen = True                # LAN IP が変わったので証明書を作り直す
        if need_gen:
            if not cfg.get("tls_autogen", True) or not ensure_tls_cert(certfile, keyfile):
                print("[警告] 管理画面用の証明書を用意できなかったため HTTP で起動します。")
                return None
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
        return ctx
    except Exception as e:
        print(f"[警告] 管理画面のTLSを初期化できなかったため HTTP で起動します: {e}")
        return None


def ensure_tls_cert(certfile, keyfile, extra_ips=None, extra_names=None):
    """cert/key が無ければ自己署名証明書を生成する。
    SAN には localhost / 127.0.0.1 に加え、この端末の LAN IP とホスト名、extra_ips / extra_names を含める(LAN からの HTTPS アクセス用)。
    生成は cryptography があればそれで、無ければ openssl CLI を試す。どちらも不可なら False。
    """
    lan_ips = get_lan_ips()
    ip_strs = ["127.0.0.1"] + [ip for ip in lan_ips if ip != "127.0.0.1"]
    for ip in (extra_ips or []):
        if ip not in ip_strs:
            ip_strs.append(ip)
    names = ["localhost"]
    try:
        hn = socket.gethostname()
        if hn and hn not in names:
            names.append(hn)
    except Exception:
        pass
    for nm in (extra_names or []):
        if nm not in names:
            names.append(nm)

    try:
        import datetime as _dt
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"waf.local")])
        san_entries = [x509.DNSName(n) for n in names]
        for ip in ip_strs:
            try:
                san_entries.append(x509.IPAddress(ipaddress.ip_address(ip)))
            except ValueError:
                pass
        san = x509.SubjectAlternativeName(san_entries)
        now = _dt.datetime.now(_dt.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _dt.timedelta(days=1))
            .not_valid_after(now + _dt.timedelta(days=825))
            .add_extension(san, critical=False)
            .sign(key, hashes.SHA256())
        )
        with open(keyfile, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()))
        with open(certfile, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        print("自己署名証明書を生成しました(SAN: "
              + ", ".join(names + ip_strs) + ")。")
        return True
    except Exception:
        pass

    # openssl CLI へのフォールバック
    try:
        import subprocess
        san = ",".join([f"DNS:{n}" for n in names] + [f"IP:{ip}" for ip in ip_strs])
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", keyfile, "-out", certfile, "-days", "825",
             "-subj", "/CN=waf.local", "-addext", "subjectAltName=" + san],
            check=True, capture_output=True)
        print("openssl で自己署名証明書を生成しました(SAN: " + san + ")。")
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# ランタイム設定(ダッシュボードからのライブ編集を反映)
# ---------------------------------------------------------------------------
class _ExtraServer(GatedHTTPServer):
    """バックエンド専用ポート用。他のプログラムが使用中のポートを黙って奪わない(Windowsの SO_REUSEADDR 対策)。"""
    allow_reuse_address = (os.name != "nt")

    def server_bind(self):
        if os.name == "nt" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            try:
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            except OSError:
                pass
        super().server_bind()


class ListenerManager:
    """複数のバックエンドを同時に防御するための専用の待受ポートを管理する。
    メイン待受と同じハンドラ・受付ゲート(BAN/レート制限)・TLS・ログを共有し、ポート番号だけが違う。
    設定(バックエンドの listen_port)に合わせて起動/停止する。設定画面からの変更は再起動なしで反映される。
    """

    def __init__(self, cfg, main_httpd, handler, gate, stats):
        self.cfg = cfg
        self.main = main_httpd
        self.handler = handler
        self.gate = gate
        self.stats = stats
        self.servers = {}          # port ごとのサーバ
        self.errors = {}           # port ごとの起動できなかった理由
        self.lock = threading.RLock()

    def _open(self, port):
        srv = _ExtraServer((self.cfg["listen_host"], int(port)), self.handler)
        srv.gate = self.gate
        srv.t_acc = {}
        srv.stats = self.stats
        srv.ssl_context = getattr(self.main, "ssl_context", None)
        threading.Thread(target=srv.serve_forever, daemon=True, name=f"listen-{port}").start()
        return srv

    def _close(self, port):
        srv = self.servers.pop(port, None)
        if srv is None:
            return
        try:
            srv.shutdown()
        except Exception:
            pass
        try:
            srv.server_close()
        except Exception:
            pass

    def prepare(self, ports):
        """追加が必要なポートを先に開く。1つでも開けなければ、今回開いた分を閉じて ValueError(設定は変更しない)。"""
        with self.lock:
            opened = []
            try:
                for port in sorted(ports):
                    if port in self.servers:
                        continue
                    try:
                        self.servers[port] = self._open(port)
                    except OSError as e:
                        raise ValueError(f"待受ポート {port} を開けません({e.strerror or e})。"
                                         "他のプログラムが使っている可能性があります") from None
                    opened.append(port)
                    self.errors.pop(port, None)
            except ValueError:
                for port in opened:
                    self._close(port)
                raise

    def commit(self, ports):
        """設定から外れたポートの待受を閉じる。"""
        with self.lock:
            for port in [p for p in self.servers if p not in ports]:
                self._close(port)
            for port in [p for p in self.errors if p not in ports]:
                self.errors.pop(port, None)

    def start(self):
        """起動時に、設定済みの専用ポートを全部開く。失敗しても本体は止めず、理由を残す。"""
        for port in sorted(wb.listen_ports(self.cfg)):
            try:
                self.prepare({port} | set(self.servers))
            except ValueError as e:
                self.errors[port] = str(e)
                print(f"[警告] {e}")

    def status(self):
        with self.lock:
            out = []
            for port, p in sorted(wb.listen_ports(self.cfg).items()):
                out.append({"port": port, "backend": p["id"], "name": p["name"],
                            "listening": port in self.servers, "error": self.errors.get(port, "")})
            return out

    def stop(self):
        with self.lock:
            for port in list(self.servers):
                self._close(port)


class Runtime:
    """稼働中の WAF 設定を保持し、ダッシュボードの設定APIからの変更をライブ反映する。
    待受ポート/TLS/バックエンド/ダッシュボードのポートは再起動が要る。
    """
    def __init__(self, cfg, config_path, inspector, limiter, ipresolver):
        self.cfg = cfg
        self.config_path = config_path
        self.inspector = inspector
        self.limiter = limiter
        self.ipresolver = ipresolver
        self.geo = None            # ダッシュボードの GeoResolver(後で設定)
        self.conn_limiter = None   # 同時接続数リミッタ(後で設定)
        self.listeners = None      # ListenerManager(バックエンド専用ポート。main が設定)
        self.lock = threading.Lock()

    def get(self):
        c = self.cfg
        dash = c.get("dashboard", {})
        return {
            "editable": {
                "mode": c["mode"],
                "rules": dict(c["rules"]),
                "security_headers_enabled": bool(c["security_headers"].get("enabled", True)),
                "rate_limit": {
                    "enabled": bool(c["rate_limit"]["enabled"]),
                    "max_requests": c["rate_limit"]["max_requests"],
                    "window_seconds": c["rate_limit"]["window_seconds"],
                    "action": c["rate_limit"].get("action", "drop"),
                    "ban_threshold": c["rate_limit"].get("ban_threshold", 0),
                    "ban_seconds": c["rate_limit"].get("ban_seconds", 300),
                    "burst_max": c["rate_limit"].get("burst_max", 0),
                    "burst_seconds": c["rate_limit"].get("burst_seconds", 3),
                    "global_max_rps": c["rate_limit"].get("global_max_rps", 0),
                    "ban_escalate": bool(c["rate_limit"].get("ban_escalate", True)),
                    "max_conn_per_ip": c["rate_limit"].get("max_conn_per_ip", 0),
                    "max_total_conn": c["rate_limit"].get("max_total_conn", 0),
                    "conn_burst_max": c["rate_limit"].get("conn_burst_max", 0),
                    "conn_burst_seconds": c["rate_limit"].get("conn_burst_seconds", 5),
                },
                "conn_timeout_seconds": c.get("conn_timeout_seconds", 20),
                "access_log": bool(c.get("access_log", True)),
                "log_global_ip": bool(c.get("log_global_ip", True)),
                "trust_xforwarded_for": bool(c.get("trust_xforwarded_for", False)),
                "self_ip_ttl": c.get("self_ip_ttl", 60),
                "log_request_detail": bool(c.get("log_request_detail", True)),
                "log_pass_body": bool(c.get("log_pass_body", True)),
                "log_response": bool(c.get("log_response", True)),
                "log_encrypt": wc_view(c),
                "geo": bool(dash.get("geo", True)),
                "egress": bool(dash.get("egress", True)),
                "alert": _alert_view(dash),
                "backend": wb.public_view(c),
                "extra": wx.extra_view(c),
            },
            "readonly": {
                "listen": f'{"https" if c["listen_tls"] else "http"}://{c["listen_host"]}:{c["listen_port"]}',
                "backend": wb.origin(wb.active_profile(c)),
                "dashboard": f'{dash.get("host","127.0.0.1")}:{dash.get("port",8090)}',
                "dashboard_tls": bool(getattr(self, "dash_tls", False)),
                "main_port": c["listen_port"],
                "tls": bool(c["listen_tls"]),
                "listeners": self.listeners.status() if self.listeners is not None else [],
                "admin_auth": bool(self.admin_password() or self.users()),
                "geoip_offline": bool(getattr(self, "offline_geo", None) and self.offline_geo.ready),
                "webhook": self.webhook.status() if getattr(self, "webhook", None) else None,
            },
            "hot_reload": True,
            "note": "変更は即時反映されます(防御するバックエンドの切替も再起動は不要)。待受ポート/TLS/ダッシュボードのポートの変更は再起動が必要です。",
        }

    def enc_apply(self, up):
        """暗号化の設定(ON/OFF・組織ごとの公開鍵)を検証して保存する。不正なら ValueError(何も変えない)。"""
        with self.lock:
            self.cfg["log_encrypt"] = wc_apply(self.cfg, up)
            self._persist()
            return wc_view(self.cfg)

    def enc_state(self):
        with self.lock:
            return dict(wc_view(self.cfg), demo_keys=bool(self.cfg.get("enc_demo_keys", True)),
                        idle_max=max(5, min(240, int(self.cfg.get("enc_idle_max_min", 60) or 60))),
                        hold_max=max(10, min(480, int(self.cfg.get("enc_hold_max_min", 120) or 120))))

    def enc_audit_path(self):
        n = self.cfg.get("enc_audit_file") or "enc_audit.jsonl"
        return _abs_path(n)

    def test_backend(self, profile):
        """設定画面の「接続テスト」。保存前の入力内容でも確認できる。"""
        return wb.test_profile(wb.normalize_profile(profile))

    def set(self, up):
        with self.lock:
            c = self.cfg
            if isinstance(up.get("extra"), dict):
                tmp = json.loads(json.dumps(c))
                wx.extra_update(tmp, up["extra"])        # 先に検証する(不正なら何も変えない)
                wx.extra_update(c, up["extra"])
            if isinstance(up.get("backend"), dict):
                # 先に検証する(不正なら他の設定も1つも反映しない)
                before_ids = {p_.get("id") for p_ in wb.raw_profiles(c)}
                st = wb.normalize_backend_settings(up["backend"], wb.public_view(c),
                                                   reserved_ports=_reserved_ports(c))
                extra = {int(p_.get("listen_port") or 0) for p_ in st["profiles"]} - {0}
                for p_ in st["profiles"]:
                    wb.check_not_loop(p_, c.get("listen_host"), c.get("listen_port"), extra)
                if self.listeners is not None:
                    self.listeners.prepare(extra)        # 新しい専用ポートを先に開く(開けなければ ValueError で何も変えない)
                wb.apply_to_cfg(c, st)
                if self.listeners is not None:
                    self.listeners.commit(extra)         # 設定から外れた専用ポートを閉じる
                if before_ids - {p_.get("id") for p_ in wb.raw_profiles(c)}:
                    self.purge_health_history()          # 削除したバックエンドの状態ログも消す
            if up.get("mode") in ("block", "detect"):
                c["mode"] = up["mode"]
            if isinstance(up.get("rules"), dict):
                for k in list(c["rules"].keys()):
                    if k in up["rules"]:
                        c["rules"][k] = bool(up["rules"][k])
                self.inspector.enabled = [k for k, on in c["rules"].items() if on]
            if "security_headers_enabled" in up:
                c["security_headers"]["enabled"] = bool(up["security_headers_enabled"])
            if isinstance(up.get("rate_limit"), dict):
                rl = up["rate_limit"]
                if "enabled" in rl:
                    c["rate_limit"]["enabled"] = bool(rl["enabled"])
                if "max_requests" in rl:
                    v = max(1, min(100000, int(rl["max_requests"])))
                    c["rate_limit"]["max_requests"] = v
                    self.limiter.max = v
                if "window_seconds" in rl:
                    v = max(1, min(86400, int(rl["window_seconds"])))
                    c["rate_limit"]["window_seconds"] = v
                    self.limiter.window = v
                if rl.get("action") in ("drop", "429"):
                    c["rate_limit"]["action"] = rl["action"]
                if "ban_threshold" in rl:
                    v = max(0, min(100000, int(rl["ban_threshold"])))
                    c["rate_limit"]["ban_threshold"] = v
                    self.limiter.ban_threshold = v
                if "ban_seconds" in rl:
                    v = max(1, min(86400, int(rl["ban_seconds"])))
                    c["rate_limit"]["ban_seconds"] = v
                    self.limiter.ban_seconds = v
                if "burst_max" in rl:
                    v = max(0, min(100000, int(rl["burst_max"])))
                    c["rate_limit"]["burst_max"] = v
                    self.limiter.burst_max = v
                if "burst_seconds" in rl:
                    v = max(1, min(60, int(rl["burst_seconds"])))
                    c["rate_limit"]["burst_seconds"] = v
                    self.limiter.burst_seconds = v
                if "global_max_rps" in rl:
                    v = max(0, min(1000000, int(rl["global_max_rps"])))
                    c["rate_limit"]["global_max_rps"] = v
                    self.limiter.global_max_rps = v
                if "ban_escalate" in rl:
                    c["rate_limit"]["ban_escalate"] = bool(rl["ban_escalate"])
                    self.limiter.ban_escalate = bool(rl["ban_escalate"])
                if "max_conn_per_ip" in rl:
                    v = max(0, min(100000, int(rl["max_conn_per_ip"])))
                    c["rate_limit"]["max_conn_per_ip"] = v   # ConnLimiter は cfg を都度参照する
                if "max_total_conn" in rl:
                    v = max(0, min(1000000, int(rl["max_total_conn"])))
                    c["rate_limit"]["max_total_conn"] = v
                if "conn_burst_max" in rl:
                    v = max(0, min(1000000, int(rl["conn_burst_max"])))
                    c["rate_limit"]["conn_burst_max"] = v
                    self.limiter.conn_burst_max = v
                if "conn_burst_seconds" in rl:
                    v = max(1, min(600, int(rl["conn_burst_seconds"])))
                    c["rate_limit"]["conn_burst_seconds"] = v
                    self.limiter.conn_burst_seconds = v
            if "conn_timeout_seconds" in up:
                v = max(0, min(600, int(up["conn_timeout_seconds"])))
                c["conn_timeout_seconds"] = v   # 次の新規接続から適用
            for k in ("access_log", "log_global_ip", "trust_xforwarded_for",
                      "log_request_detail", "log_pass_body", "log_response"):
                if k in up:
                    c[k] = bool(up[k])
            if "self_ip_ttl" in up:
                v = max(5, min(3600, int(up["self_ip_ttl"])))
                c["self_ip_ttl"] = v
                self.ipresolver.ttl = v
            self.ipresolver.enabled = c.get("log_global_ip", True)
            self.ipresolver.trust_xff = c.get("trust_xforwarded_for", False)
            dash = c.setdefault("dashboard", {})
            if "geo" in up:
                dash["geo"] = bool(up["geo"])
            if "egress" in up:
                dash["egress"] = bool(up["egress"])
            if isinstance(up.get("alert"), dict):
                _alert_update(dash, up["alert"])
            if self.geo is not None:
                self.geo.enabled = dash.get("geo", True)
                self.geo.egress = dash.get("egress", True)
                self.geo.ttl = c.get("self_ip_ttl", 60)
            self._persist()
        return self.get()

    def _persist(self):
        try:
            data = {k: v for k, v in self.cfg.items() if not str(k).startswith("_")}   # 先頭が _ のキーは実行時の状態なので保存しない
            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except OSError:
            pass

    def purge_health_history(self):
        """登録されていない(削除した)バックエンドの状態ログを、履歴ファイルから消す。"""
        name = self.health_history_file()
        if not name:
            return
        path = _abs_path(name)
        known = {p.get("id") for p in wb.raw_profiles(self.cfg)}
        try:
            fl = getattr(getattr(self.conn_limiter, "health", None), "flush_history", None)
            if fl:
                fl()
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except OSError:
            return
        keep = []
        for line in lines:
            try:
                d = json.loads(line)
            except ValueError:
                keep.append(line)
                continue
            b = d.get("backend") if isinstance(d, dict) else None
            if d.get("target") == "backend" and b and b not in known:
                continue
            keep.append(line)
        if len(keep) != len(lines):
            try:
                tmp = path + ".tmp"
                with open(tmp, "w", encoding="utf-8") as f:
                    f.writelines(keep)
                os.replace(tmp, path)
            except OSError:
                pass

    # ルール単位の有効/無効
    def get_rules(self):
        disabled = set(self.cfg.get("disabled_rules", []))
        cat_on = self.cfg.get("rules", {})
        detect_only = set(self.cfg.get("detect_only_rules") or [])
        rules = []
        for r in waf_rules.list_rules():
            rules.append({**r,
                          "enabled": (r["id"] not in disabled) and cat_on.get(r["category"], True),
                          "category_enabled": cat_on.get(r["category"], True),
                          "rule_disabled": r["id"] in disabled,
                          "detect_only": r["id"] in detect_only})
        return {
            "categories": [{"key": k, "label": waf_rules.CATEGORY_LABELS[k],
                            "enabled": cat_on.get(k, True)} for k in waf_rules.CATEGORIES],
            "rules": rules,
            "total": waf_rules.rule_count(),
            "global_mode": self.cfg.get("mode", "block"),
        }

    def set_rule(self, rule_id, enabled):
        with self.lock:
            dis = set(self.cfg.get("disabled_rules", []))
            if enabled:
                dis.discard(rule_id)
            else:
                dis.add(rule_id)
            self.cfg["disabled_rules"] = sorted(dis)
            self.inspector.disabled_rules = dis
            self._persist()
        return self.get_rules()

    def set_rule_detect(self, rule_id, detect):
        """ルール単位の防御モード。detect=True で検知のみ(block運用でも遮断せず記録だけ)。"""
        rule_id = str(rule_id or "").strip()
        if not rule_id:
            raise RuntimeError("ルールIDを指定してください")
        with self.lock:
            s = set(self.cfg.get("detect_only_rules") or [])
            if detect:
                s.add(rule_id)
            else:
                s.discard(rule_id)
            self.cfg["detect_only_rules"] = sorted(s)
            self._persist()
        return self.get_rules()

    def set_category(self, cat, enabled):
        with self.lock:
            if cat in self.cfg.get("rules", {}):
                self.cfg["rules"][cat] = bool(enabled)
                self.inspector.enabled = [k for k, on in self.cfg["rules"].items() if on]
                self._persist()
        return self.get_rules()

    # IPブロック / BAN 管理
    # ユーザー(固定のユーザー名・パスワード)/ 削除済みバックエンドの記録
    def users(self):
        return wx.users_of(self.cfg)

    def users_view(self):
        return wx.users_view(self.cfg)

    def users_apply(self, up, actor):
        with self.lock:
            wx.users_apply(self.cfg, up, actor)
            self._persist()
        return wx.users_view(self.cfg)

    def removed_backends(self):
        return list(self.cfg.get("removed_backends", []) or [])

    def note_removed(self, entries):
        with self.lock:
            lst = self.cfg.setdefault("removed_backends", [])
            have = {r.get("id") for r in lst}
            for e in entries:
                if e.get("id") and e["id"] not in have:
                    lst.append({"id": e["id"], "name": e.get("name") or e["id"], "owner": e.get("owner") or ""})
            self._persist()

    def forget_removed(self, bid):
        with self.lock:
            lst = self.cfg.get("removed_backends", []) or []
            self.cfg["removed_backends"] = [] if bid == "__all" else [r for r in lst if r.get("id") != bid]
            self._persist()

    def admin_password(self):
        return (os.environ.get("WAF_ADMIN_PASSWORD") or str(self.cfg.get("dashboard", {}).get("password") or "")
                or getattr(self, "generated_password", "") or "")

    def get_security(self):
        return {
            "blocklist": list(self.cfg.get("blocklist", [])),
            "ip_allowlist": list(self.cfg.get("ip_allowlist", [])),
            "exempt_ips": list(self.cfg.get("exempt_ips", [])),
            "country_blocklist": list(self.cfg.get("country_blocklist", [])),
            "country_allowlist": list(self.cfg.get("country_allowlist", [])),
            "country_block_unknown": bool(self.cfg.get("country_block_unknown", False)),
            "backends": [{"id": p.get("id"), "name": p.get("name"), "owner": p.get("owner") or "", "org": p.get("org") or "",
                          "stopped": bool(p.get("stopped")),
                          "mode_override": p.get("mode_override") or "",
                          "mode_until": p.get("mode_until") or 0,
                          "mode_lock": bool(p.get("mode_lock")),
                          "effective_mode": wb.effective_mode(self.cfg, p)}
                         for p in wb.get_profiles(self.cfg)],
            "backend_policies": {p.get("id"): wb.clean_ip_policy(p.get("ip_policy")) for p in wb.get_profiles(self.cfg)},
            "global_mode": self.cfg.get("mode", "block"),
            "mode_history": wb.read_mode_history(_abs_path(self.cfg.get("mode_history_file", "mode_history.jsonl")) if self.cfg.get("mode_history_file", "mode_history.jsonl") else "", 100),
            "autoban": wx.extra_view(self.cfg)["autoban"],
            "online": True,
            "bans": self.limiter.current_bans(),
            "ban_history": self.limiter.ban_history(200),
            "ban_threshold": self.cfg["rate_limit"].get("ban_threshold", 0),
            "ban_seconds": self.cfg["rate_limit"].get("ban_seconds", 300),
            "action": self.cfg["rate_limit"].get("action", "drop"),
            "connections": self._connections(),
            "health": self._health(),
        }

    def get_health(self):
        return self._health()

    # ホーム画面用。BANのしきい値に近い送信元と稼働状況の補足
    def get_watch(self):
        """BAN のしきい値の半分以上に達している送信元を、近い順に返す(最大8件)。
        対象はレート制限の違反回数と、攻撃・低速接続・同時接続上限の繰り返し回数。
        """
        out = []
        now = time.time()
        lim = self.limiter
        try:
            th = int(getattr(lim, "ban_threshold", 0) or 0)
            win = float(getattr(lim, "window", 60) or 60)
            if th > 0:
                with lim.lock:
                    for ip, vq in list(lim.violations.items()):
                        n = sum(1 for t in vq if t > now - win)
                        if n > 0 and ip not in lim.banned:
                            out.append({"ip": ip, "kind": "rate", "label": "レート超過",
                                        "count": n, "threshold": th})
        except Exception:
            pass
        strikes = getattr(self.conn_limiter, "strikes", None)
        if strikes is not None:
            try:
                with strikes.lock:
                    items = [(k, list(dq)) for k, dq in strikes.times.items()]
                for (kind, ip), ts in items:
                    c = self.cfg.get(strikes.CFG_KEY[kind]) or {}
                    if not c.get("enabled", True):
                        continue
                    thr = max(1, int(c.get("threshold", 10)))
                    win = max(1, int(c.get("window_seconds", 60)))
                    n = sum(1 for t in ts if t > now - win)
                    if n > 0:
                        out.append({"ip": ip, "kind": kind, "label": strikes.LABELS.get(kind, kind),
                                    "count": n, "threshold": thr})
            except Exception:
                pass
        out = [o for o in out if o["count"] * 2 >= o["threshold"]]
        out.sort(key=lambda o: -o["count"] / max(1, o["threshold"]))
        return out[:8]

    def get_overview_extra(self):
        og = getattr(self, "offline_geo", None)
        wh = getattr(self, "webhook", None)
        url = str((self.cfg.get("webhook") or {}).get("url") or "").strip()
        return {
            "geoip": {"ready": bool(og is not None and og.ready),
                      "online": bool((self.cfg.get("geoip") or {}).get("online", True))},
            "webhook": {"enabled": bool(url),
                        "pending": (wh.q.qsize() if wh is not None else 0),
                        "dropped": (wh.dropped if wh is not None else 0)},
            "log_file": self.cfg.get("log_file", "waf.log"),
        }

    def health_history_file(self):
        return self.cfg.get("health_history_file", "health_history.jsonl")

    def _health(self):
        h = getattr(self.conn_limiter, "health", None)
        return h.snapshot() if h is not None else None

    def _connections(self):
        """IPごとの現在の同時接続数(多い順)と全体合計。"""
        if self.conn_limiter is None:
            return {"total": 0, "per_ip": [], "max_per_ip": 0, "max_total": 0, "stats": None}
        snap = self.conn_limiter.snapshot()
        per_ip = sorted(({"ip": k, "count": v} for k, v in snap.get("per_ip", {}).items()),
                        key=lambda x: -x["count"])
        st = getattr(self.conn_limiter, "stats", None)
        return {
            "total": snap.get("total", 0),
            "per_ip": per_ip[:50],
            "max_per_ip": self.cfg["rate_limit"].get("max_conn_per_ip", 0),
            "max_total": self.cfg["rate_limit"].get("max_total_conn", 0),
            # 接続レベルの累積カウンター(waf.log に残らない分も含む)
            "stats": st.snapshot() if st is not None else None,
            **self._conn_split(st),
        }

    def _conn_split(self, st):
        """接続先ごとの接続の流れを見るための材料。ポート別/バックエンド別カウンターと、ポート->バックエンドの対応。"""
        if st is None or not hasattr(st, "snapshot_split"):
            return {}
        by_port, by_be = st.snapshot_split()
        pm = {}
        try:
            main = int(self.cfg.get("listen_port") or 0)
            pr = wb.pick_for_port(self.cfg, main)
            pm[str(main)] = pr["id"] if pr else ""          # 空はホスト名/パスで振り分ける共有ポート。接続時点では接続先が決まらない
            for lp, p in wb.listen_ports(self.cfg).items():
                pm[str(lp)] = p["id"]
        except Exception:
            pass
        return {"by_port": by_port, "by_backend": by_be, "port_map": pm}

    def block_country(self, country):
        country = str(country).strip()
        if not country:
            raise RuntimeError("国コード/国名を入力してください。")
        with self.lock:
            cl = self.cfg.setdefault("country_blocklist", [])
            if country not in cl:
                cl.append(country)
            self._persist()
        return self.get_security()

    def unblock_country(self, country):
        country = str(country).strip()
        with self.lock:
            cl = self.cfg.setdefault("country_blocklist", [])
            if country in cl:
                cl.remove(country)
            self._persist()
        return self.get_security()

    def block_ip(self, ip):
        ip = str(ip).strip()
        # 妥当性チェック(単一IP / CIDR)
        try:
            if "/" in ip:
                ipaddress.ip_network(ip, strict=False)
            else:
                ipaddress.ip_address(ip)
        except ValueError:
            raise RuntimeError("無効なIP/CIDRです: " + ip)
        with self.lock:
            bl = self.cfg.setdefault("blocklist", [])
            if ip not in bl:
                bl.append(ip)
            self._persist()
        return self.get_security()

    def unblock_ip(self, ip):
        ip = str(ip).strip()
        with self.lock:
            bl = self.cfg.setdefault("blocklist", [])
            if ip in bl:
                bl.remove(ip)
            self._persist()
        return self.get_security()

    def unban_ip(self, ip):
        ip = str(ip).strip()
        self.limiter.unban(ip)
        st = getattr(self.conn_limiter, "strikes", None)
        if st is not None:
            st.reset(ip)
        return self.get_security()

    # 手動BAN(時間指定)/延長、IP許可リスト、除外IP、国の許可リスト
    def ban_ip(self, ip, minutes):
        ip = wx.validate_ip_or_cidr(ip)
        if "/" in ip:
            raise RuntimeError("BAN は単一のIPで指定してください(範囲はブロックリストへ)")
        try:
            minutes = max(1, min(60 * 24 * 365, int(minutes)))
        except (TypeError, ValueError):
            raise RuntimeError("分数を指定してください")
        if not self.limiter.ban_for(ip, minutes * 60, "manual"):
            raise RuntimeError(ip + " は除外IP(BANしないIP)に登録されています")
        return self.get_security()

    def extend_ban(self, ip, minutes):
        ip = wx.validate_ip_or_cidr(ip)
        try:
            minutes = max(1, min(60 * 24 * 365, int(minutes)))
        except (TypeError, ValueError):
            raise RuntimeError("分数を指定してください")
        self.limiter.extend(ip, minutes * 60)
        return self.get_security()

    def list_add(self, kind, ip):
        with self.lock:
            wx.list_add(self.cfg, kind, ip)
            self._persist()
        if kind == "exempt":
            self.limiter.unban(str(ip).strip())   # 除外IPに入れたらBAN中でも解除する
        return self.get_security()

    def list_remove(self, kind, ip):
        with self.lock:
            wx.list_remove(self.cfg, kind, ip)
            self._persist()
        return self.get_security()

    def be_policy(self, up):
        """バックエンド別のIP/国の制限を1件追加・削除する。up={backend, kind, op, value}"""
        bid = str(up.get("backend") or "")
        with self.lock:
            prof = next((p for p in (self.cfg.get("backends") or []) if p.get("id") == bid), None)
            if prof is None:
                raise RuntimeError("バックエンドが見つかりません")
            pol = prof.get("ip_policy")
            if not isinstance(pol, dict):
                pol = prof["ip_policy"] = {}
            wx.policy_op(pol, str(up.get("kind") or ""), str(up.get("op") or ""), up.get("value", ""))
            self._persist()
        return self.get_security()

    def be_mode(self, up):
        """バックエンド別の防御モードを変更する。up={backend, mode(""/"block"/"detect"), minutes, reason, by, lock(任意)}"""
        bid = str(up.get("backend") or "")
        want = str(up.get("mode") or "")
        if "mode" in up and want not in ("", "block", "detect"):
            raise RuntimeError("モードの指定が不正です")
        with self.lock:
            prof = next((p for p in (self.cfg.get("backends") or []) if p.get("id") == bid), None)
            if prof is None:
                raise RuntimeError("バックエンドが見つかりません")
            if "lock" in up:
                prof["mode_lock"] = bool(up["lock"])
            if "mode" in up:
                prev = wb.effective_mode(self.cfg, prof)
                until = 0
                if want == "":
                    prof["mode_override"] = ""
                    prof["mode_until"] = 0
                else:
                    prof["mode_override"] = want
                    mins = up.get("minutes")
                    if mins not in (None, "", 0, "0"):
                        try:
                            until = time.time() + max(1, min(60 * 24 * 30, int(mins))) * 60
                        except (TypeError, ValueError):
                            until = 0
                    prof["mode_until"] = until
                wb.append_mode_history(dict(self.cfg, mode_history_file=(_abs_path(self.cfg.get("mode_history_file", "mode_history.jsonl")) if self.cfg.get("mode_history_file", "mode_history.jsonl") else "")), {
                    "backend": bid, "backend_name": prof.get("name") or bid,
                    "by": str(up.get("by") or ""), "from": prev,
                    "to": wb.effective_mode(self.cfg, prof),
                    "override": prof.get("mode_override") or "",
                    "until": until, "reason": str(up.get("reason") or "")[:200],
                })
            self._persist()
        return self.get_security()

    # バックエンド別のルール設定 / 追加ルール / 履歴 / チケット
    def get_be_rules(self):
        return wb.get_be_rules(self.cfg)

    def reinspect_events(self, events):
        """ログ中のリクエスト(クエリ・ヘッダ・本文)を今のルールで検査し直す。プリセットの影響試算用で手動実行。
        戻り値: ([(パス, 一致の一覧)], 全体の検知のみルールID)
        """
        insp = self.inspector

        class _H:
            def __init__(self, d):
                self._d = {str(k): str(v).split("\n") for k, v in (d or {}).items()}

            def keys(self):
                return list(self._d.keys())

            def get_all(self, k):
                return self._d.get(k) or []

        items = []
        for e in events:
            req = e.get("req") or {}
            hd = req.get("headers") or {}
            ct = next((str(v) for k, v in hd.items() if str(k).lower() == "content-type"), "")
            body = str(req.get("body") or "").encode("utf-8", "replace")
            try:
                hits = insp.inspect_request(e.get("method") or "GET", e.get("path") or "/", req.get("query") or e.get("query") or "", _H(hd), body, ct)
            except Exception:
                hits = []
            items.append((e.get("path") or "/", hits))
        return items, insp.detect_only_ids()

    def be_rules(self, up, by=""):
        with self.lock:
            ent = wb.be_rules_op(self.cfg, up, by)
            self._persist()
        self.note_rule_change(dict(ent, kind="backend_rule"))
        return wb.get_be_rules(self.cfg)

    # 組織(提供元 / 直接契約 / 中間企業 / エンドユーザー企業)
    def org_context(self):
        with self.lock:
            return (list(self.cfg.get("orgs") or []), list(wx.users_of(self.cfg)))

    def orgs_view(self):
        with self.lock:
            return waf_org.orgs_view(self.cfg)

    def orgs_op(self, up, by=""):
        with self.lock:
            ent = waf_org.orgs_op(self.cfg, up)
            self._persist()
            view = waf_org.orgs_view(self.cfg)
        self.note_rule_change(dict(ent, kind="org", by=by))
        return view

    def prune_logs(self, log_path=None):
        """保存期間を過ぎたログの行を削除し、削除した行数を返す。組織に属するバックエンドだけが対象。"""
        with self.lock:
            orgs = list(self.cfg.get("orgs") or [])
            users = list(wx.users_of(self.cfg))
            limits = {}
            for p in (self.cfg.get("backends") or []):
                a = waf_org.retention_for(orgs, p, users)
                if a:
                    limits[p.get("id")] = (a, waf_org.attack_retention_for(orgs, waf_org.backend_org(p, users)))
        n = waf_org.prune_log(_abs_path(self.cfg.get("log_file", "waf.log")), limits, getattr(self, "log_lock", None))
        ls = getattr(self, "logstore", None)
        if ls is not None:
            n += ls.prune()
        return n

    def export_org(self, org_id, log_path=None):
        with self.lock:
            orgs = list(self.cfg.get("orgs") or [])
            users = list(wx.users_of(self.cfg))
            profs = list(self.cfg.get("backends") or [])
        ls = getattr(self, "logstore", None)
        if ls is not None:
            counts, dst = ls.export_org_tree(org_id, os.path.join(DATA_DIR, "log_exports"))
            return {"dir": os.path.relpath(dst, ROOT), "counts": counts}
        stamp = time.strftime("%Y%m%d-%H%M%S")
        root = os.path.join(DATA_DIR, "log_exports", f"{org_id}-{stamp}")
        counts = waf_org.export_org_logs(_abs_path(self.cfg.get("log_file", "waf.log")), orgs, profs, org_id, root, users)
        return {"dir": os.path.relpath(root, ROOT), "counts": counts}

    def note_rule_change(self, entry):
        waf_custom.append_history(_abs_path(self.cfg.get("rule_history_file") or "rule_history.jsonl")
                                  if self.cfg.get("rule_history_file", "rule_history.jsonl") else "", entry)

    def rule_history(self, limit=200):
        n = self.cfg.get("rule_history_file", "rule_history.jsonl")
        return waf_custom.read_history(_abs_path(n) if n else "", limit)

    def custom_status(self):
        c = getattr(self.inspector, "custom", None)
        return {"status": c.status() if c else None, "rules": c.rules_view() if c else []}

    def custom_reload(self):
        c = getattr(self.inspector, "custom", None)
        if c is None:
            raise RuntimeError("追加ルールは使えません")
        c.reload(force=True)
        return self.custom_status()

    def ticket_store(self):
        st = getattr(self, "_tickets", None)
        if st is None:
            st = self._tickets = waf_tickets.TicketStore(
                _abs_path(self.cfg.get("tickets_file") or "tickets.json"),
                mailer=waf_tickets.make_mailer(lambda: self.cfg.get("notify_email")))
        return st

    def country_add(self, mode, cc):
        with self.lock:
            wx.country_add(self.cfg, mode, cc)
            self._persist()
        return self.get_security()

    def country_remove(self, mode, cc):
        with self.lock:
            wx.country_remove(self.cfg, mode, cc)
            self._persist()
        return self.get_security()

    def set_country_unknown(self, on):
        with self.lock:
            self.cfg["country_block_unknown"] = bool(on)
            self._persist()
        return self.get_security()

    def clear_bans(self):
        self.limiter.clear_bans()
        return self.get_security()


# ---------------------------------------------------------------------------
# エントリポイント
# ---------------------------------------------------------------------------
def _tune_process(cfg):
    """同じPCで攻撃ツールなどがCPUを奪い合っても、WAFが後回しにされにくくする。
    Windowsはプロセス優先度を「通常より上」にする(設定で high も可)。Pythonのスレッド切替間隔も短くする
    """
    try:
        sys.setswitchinterval(float(cfg.get("thread_switch_interval", 0.001)))
    except Exception:
        pass
    pr = str(cfg.get("process_priority", "normal")).lower()
    flags = {"idle": (0x00000040, "低"), "below_normal": (0x00004000, "通常より下"),
             "above_normal": (0x00008000, "通常より上"), "high": (0x00000080, "高")}
    if os.name == "nt" and pr in flags:
        try:
            import ctypes
            flag, label = flags[pr]
            k32 = ctypes.windll.kernel32
            if k32.SetPriorityClass(k32.GetCurrentProcess(), flag):
                print(f"プロセス優先度: {label}")
        except Exception:
            pass


def build_arg_parser():
    """コマンドライン引数。self_made_waf の waf_proxy.py と同じオプションを持つ。
    指定したものだけ waf_config.json の値を上書きする。
    """
    ap = argparse.ArgumentParser(
        description="リバースプロキシ型 WAF(WAF2 + self_made_waf 統合版)。引数は waf_config.json を上書きします。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="例:\n"
               "  python3 waf.py --backend http://127.0.0.1:3000 --no-listen-tls\n"
               "  python3 waf.py --site shop=8081=https://192.168.200.88:5000 --site blog=8082=http://192.168.200.90:3000\n"
               "  python3 waf.py --path-route /shop=https://192.168.200.88:5000 --path-route /blog=http://192.168.200.90:3000\n"
               "  python3 waf.py --rate-limit 100 --rate-window 10 --block-ip 203.0.113.0/24 --allow-country JP\n")
    g = ap.add_argument_group("基本")
    g.add_argument("--config", default=os.path.join(CONFIG_DIR, "waf_config.json"),
                   help="設定ファイルのパス (既定: waf_config.json)")
    g.add_argument("--mode", choices=["block", "detect"], help="block=遮断 / detect=記録のみ")
    g.add_argument("--save-config", action="store_true", help="引数で上書きした設定を設定ファイルに保存する")
    g = ap.add_argument_group("転送先(バックエンド)")
    g.add_argument("--backend", metavar="URL", help="前段に置くページのURL(使用中のバックエンドにする)")
    g.add_argument("--site", action="append", default=[], metavar="名前=ポート=URL",
                   help="専用の待受ポートで別アプリを同時に防御(繰り返し可)")
    g.add_argument("--path-route", action="append", default=[], metavar="/prefix=URL",
                   help="1つのポートでパスごとに振り分け(繰り返し可。プレフィックスは外して転送)")
    g.add_argument("--backend-verify", action="store_true", help="バックエンドのTLS証明書を検証する")
    g.add_argument("--preserve-host", action="store_true", help="クライアントのHostヘッダをそのまま転送")
    g = ap.add_argument_group("待受")
    g.add_argument("--listen-host", help="WAFの待受アドレス")
    g.add_argument("--listen-port", type=int, help="WAFの待受ポート")
    g.add_argument("--listen-tls", dest="listen_tls", action="store_true", default=None,
                   help="ブラウザ→WAF を HTTPS にする(証明書が無ければ自動生成)")
    g.add_argument("--no-listen-tls", dest="listen_tls", action="store_false", help="ブラウザ→WAF を HTTP にする")
    g.add_argument("--cert", help="受信側TLSの証明書(PEM)")
    g.add_argument("--key", help="受信側TLSの秘密鍵(PEM)")
    g.add_argument("--conn-timeout", type=int, metavar="SEC", help="アイドル接続のタイムアウト")
    g.add_argument("--header-timeout", type=int, metavar="SEC", help="ヘッダ受信の締め切り(Slowloris対策)")
    g.add_argument("--body-timeout", type=int, metavar="SEC", help="ボディ受信の締め切り(Slow POST対策)")
    g.add_argument("--max-body", type=int, metavar="BYTES", help="リクエストボディの上限(超えたら413)")
    g.add_argument("--tls-handshake-timeout", type=int, metavar="SEC", help="TLS握手の制限時間")
    g.add_argument("--max-conn", type=int, metavar="N", help="全体の同時接続数上限")
    g.add_argument("--max-conn-per-ip", type=int, metavar="N", help="IPごとの同時接続数上限")
    g = ap.add_argument_group("ダッシュボード(管理画面)")
    g.add_argument("--dashboard-host", "--admin-host", dest="dashboard_host", help="管理画面の待受アドレス")
    g.add_argument("--dashboard-port", "--admin-port", dest="dashboard_port", type=int, help="管理画面のポート")
    g.add_argument("--no-dashboard", "--no-admin", dest="no_dashboard", action="store_true", help="管理画面を無効化")
    g.add_argument("--no-dashboard-tls", dest="no_dashboard_tls", action="store_true", help="管理画面をHTTPで開く(既定はHTTPS)")
    g.add_argument("--admin-password", metavar="PW", help="管理画面のパスワード(環境変数 WAF_ADMIN_PASSWORD でも可)")
    g = ap.add_argument_group("ログ / 通知")
    g.add_argument("--log-file", help="ログファイル(JSON Lines)")
    g.add_argument("--no-log-allowed", action="store_true", help="通過(PASS)は記録しない")
    g.add_argument("--webhook", metavar="URL", help="検知イベントを外部へPOST送信")
    g.add_argument("--webhook-allowed", action="store_true", help="通過(PASS)も Webhook 送信")
    g = ap.add_argument_group("DoS対策 / IP制限")
    g.add_argument("--rate-limit", type=int, metavar="N", help="ウィンドウ内の最大リクエスト数")
    g.add_argument("--rate-window", type=int, metavar="SEC", help="レート制限のウィンドウ(秒)")
    g.add_argument("--rate-ban", type=int, metavar="SEC", help="BAN の基本秒数")
    g.add_argument("--no-rate-limit", action="store_true", help="レート制限を無効化")
    g.add_argument("--block-ip", action="append", default=[], metavar="IP/CIDR", help="ブロックするIP(繰り返し可)")
    g.add_argument("--allow-ip", action="append", default=[], metavar="IP/CIDR", help="このIP以外を拒否(繰り返し可)")
    g.add_argument("--exempt-ip", action="append", default=[], metavar="IP/CIDR", help="BAN/レート制限しないIP(繰り返し可)")
    g.add_argument("--trusted-proxy", action="append", default=[], metavar="IP/CIDR",
                   help="信頼する逆プロキシ(X-Forwarded-For で送信元を判定。繰り返し可)")
    g.add_argument("--block-country", action="append", default=[], metavar="CC", help="ブロックする国(繰り返し可)")
    g.add_argument("--allow-country", action="append", default=[], metavar="CC", help="この国以外を拒否(繰り返し可)")
    g.add_argument("--block-unknown-country", action="store_true", help="国が判定できないIPも拒否")
    g.add_argument("--geoip-mmdb", metavar="PATH", help="GeoLite2 mmdb のパス(オフライン国判定)")
    g.add_argument("--no-autoban", action="store_true", help="攻撃回数による自動BANを無効化")
    g.add_argument("--autoban-threshold", type=int, metavar="N", help="自動BANのしきい値(60秒あたりの攻撃回数)")
    g.add_argument("--no-slow-ban", action="store_true", help="低速接続の繰り返しによるBANを無効化")
    g.add_argument("--slow-ban-threshold", type=int, metavar="N", help="低速接続BANのしきい値")
    g.add_argument("--no-connlimit-ban", action="store_true", help="同時接続上限の繰り返し超過によるBANを無効化")
    g.add_argument("--connlimit-ban-threshold", type=int, metavar="N", help="同時接続上限BANのしきい値")
    g = ap.add_argument_group("レスポンス保護")
    g.add_argument("--response-xss", choices=list(wx.RESPONSE_ACTIONS),
                   help="応答の Stored XSS: sanitize(無害化)/block(403)/monitor(記録)/off")
    g.add_argument("--no-security-headers", action="store_true", help="セキュリティヘッダを付けない")
    return ap


def apply_cli(cfg, args):
    """引数で指定された項目だけ cfg を上書きする。"""
    if args.mode:
        cfg["mode"] = args.mode
    # 転送先
    extra_profiles = []
    for spec in args.site:
        try:
            name, port, url = spec.split("=", 2)
            extra_profiles.append({"name": name.strip(), "url": url.strip(), "listen_port": int(port)})
        except ValueError:
            raise SystemExit(f"--site の形式が正しくありません: {spec}(名前=ポート=URL)")
    for spec in args.path_route:
        try:
            prefix, url = spec.split("=", 1)
        except ValueError:
            raise SystemExit(f"--path-route の形式が正しくありません: {spec}(/prefix=URL)")
        extra_profiles.append({"name": prefix.strip("/") or "root", "url": url.strip(),
                               "path_prefix": prefix.strip(), "strip_prefix": True})
    if args.backend or extra_profiles:
        profiles = []
        active = None
        if args.backend:
            profiles.append({"id": "cli", "name": "コマンドライン指定", "url": args.backend})
            active = "cli"
        profiles += extra_profiles
        for p_ in profiles:
            if args.backend_verify:
                p_["verify_tls"] = True
            elif "verify_tls" not in p_:
                p_["verify_tls"] = False
            if args.preserve_host:
                p_["host_header"] = "client"
        if active is None:
            # パス振り分け/専用ポートのみのときは、使用中の既存を残す。無ければ最初の1件
            keep = [p_ for p_ in cfg.get("backends") or [] if not p_.get("listen_port") and not p_.get("path_prefix")]
            if keep:
                profiles = keep[:1] + profiles
                active = keep[0].get("id")
        try:
            st = wb.normalize_backend_settings(
                {"profiles": profiles, "active": active or "",
                 "host_routing": cfg.get("host_routing", False),
                 "rewrite_links": cfg.get("backend_rewrite_links", True)},
                reserved_ports=_reserved_ports(cfg))
        except ValueError as e:
            raise SystemExit(f"転送先の指定が正しくありません: {e}")
        wb.apply_to_cfg(cfg, st)
    # 待受
    if args.listen_host:
        cfg["listen_host"] = args.listen_host
    if args.listen_port:
        cfg["listen_port"] = args.listen_port
    if args.listen_tls is not None:
        cfg["listen_tls"] = args.listen_tls
    if args.cert:
        cfg["tls_certfile"] = args.cert
    if args.key:
        cfg["tls_keyfile"] = args.key
    simple = {"conn_timeout": "conn_timeout_seconds", "header_timeout": "header_timeout_seconds",
              "body_timeout": "body_timeout_seconds", "max_body": "max_body_bytes",
              "tls_handshake_timeout": "tls_handshake_timeout_seconds"}
    for a, k in simple.items():
        v = getattr(args, a)
        if v is not None:
            cfg[k] = v
    rl = cfg["rate_limit"]
    if args.max_conn is not None:
        rl["max_total_conn"] = args.max_conn
    if args.max_conn_per_ip is not None:
        rl["max_conn_per_ip"] = args.max_conn_per_ip
    # ダッシュボード
    dash = cfg.setdefault("dashboard", {})
    if args.dashboard_host:
        dash["host"] = args.dashboard_host
    if args.dashboard_port:
        dash["port"] = args.dashboard_port
    if args.no_dashboard:
        dash["enabled"] = False
    if args.no_dashboard_tls:
        dash["tls"] = False
    if args.admin_password:
        dash["password"] = args.admin_password
    # ログ / 通知
    if args.log_file:
        cfg["log_file"] = args.log_file
    if args.no_log_allowed:
        cfg["access_log"] = False
    if args.webhook is not None:
        cfg.setdefault("webhook", {})["url"] = args.webhook
    if args.webhook_allowed:
        cfg.setdefault("webhook", {})["send_pass"] = True
    # DoS / IP
    if args.rate_limit is not None:
        rl["max_requests"] = args.rate_limit
        rl["enabled"] = True
    if args.rate_window is not None:
        rl["window_seconds"] = args.rate_window
    if args.rate_ban is not None:
        rl["ban_seconds"] = args.rate_ban
    if args.no_rate_limit:
        rl["enabled"] = False
    for a, k in (("block_ip", "blocklist"), ("allow_ip", "ip_allowlist"),
                 ("exempt_ip", "exempt_ips"), ("trusted_proxy", "trusted_proxies")):
        for ip in getattr(args, a):
            try:
                ip = wx.validate_ip_or_cidr(ip)
            except RuntimeError as e:
                raise SystemExit(str(e))
            lst = cfg.setdefault(k, [])
            if ip not in lst:
                lst.append(ip)
    for a, k in (("block_country", "country_blocklist"), ("allow_country", "country_allowlist")):
        for cc in getattr(args, a):
            lst = cfg.setdefault(k, [])
            if cc.upper() not in lst:
                lst.append(cc.upper())
    if args.block_unknown_country:
        cfg["country_block_unknown"] = True
    if args.geoip_mmdb:
        cfg.setdefault("geoip", {})["mmdb"] = args.geoip_mmdb
    ab = cfg.setdefault("autoban", {})
    if args.no_autoban:
        ab["enabled"] = False
    if args.autoban_threshold is not None:
        ab["threshold"] = args.autoban_threshold
    sb = cfg.setdefault("slow_ban", {})
    if args.no_slow_ban:
        sb["enabled"] = False
    if args.slow_ban_threshold is not None:
        sb["threshold"] = args.slow_ban_threshold
    cb = cfg.setdefault("connlimit_ban", {})
    if args.no_connlimit_ban:
        cb["enabled"] = False
    if args.connlimit_ban_threshold is not None:
        cb["threshold"] = args.connlimit_ban_threshold
    if args.response_xss:
        cfg.setdefault("response_inspection", {})["action"] = args.response_xss
    if args.no_security_headers:
        cfg["security_headers"]["enabled"] = False
    return cfg


def main(argv=None):
    ap = build_arg_parser()
    args = ap.parse_args(argv)

    cfg = load_config(args.config)
    apply_cli(cfg, args)
    if args.save_config:
        try:
            with open(args.config, "w", encoding="utf-8") as f:
                json.dump(cfg, f, ensure_ascii=False, indent=2)
            print(f"設定を保存しました: {args.config}")
        except OSError as e:
            print(f"[警告] 設定を保存できませんでした: {e}")

    inspector = Inspector(cfg)
    try:
        inspector.custom = waf_custom.CustomRules(_abs_path(cfg.get("custom_rules_file") or "config/custom_rules.json"),
                                                  log=lambda m: print(m, flush=True))
        inspector.custom.start()           # 追加ルール(custom_rules.json)を読み込み、以降は数秒ごとに更新を確認して入れ替える
    except Exception as e:
        print(f"[警告] 追加ルールを開始できません: {e}", flush=True)
    _rl = cfg["rate_limit"]
    limiter = RateLimiter(_rl["max_requests"], _rl["window_seconds"],
                          ban_threshold=_rl.get("ban_threshold", 0),
                          ban_seconds=_rl.get("ban_seconds", 300),
                          burst_max=_rl.get("burst_max", 0),
                          burst_seconds=_rl.get("burst_seconds", 3),
                          global_max_rps=_rl.get("global_max_rps", 0),
                          ban_escalate=_rl.get("ban_escalate", True),
                          conn_burst_max=_rl.get("conn_burst_max", 0),
                          conn_burst_seconds=_rl.get("conn_burst_seconds", 5),
                          history_path=_abs_path(cfg.get("ban_history_file", "ban_history.jsonl")))
    import atexit
    atexit.register(limiter.flush_history)       # 終了時に未書き込み分を保存
    logger = WafLogger(cfg["log_file"])
    waf_crypt.set_chain_fn(lambda bid, _c=cfg: wc_chain(_c, bid))
    _bad = waf_crypt.configure(cfg.get("log_encrypt"))
    if _bad:
        print(f"[ログ暗号化] 使えない公開鍵があります(その組織の詳細は保存しません): {', '.join(x or '既定' for x in _bad)}")
    access_log_on = cfg.get("access_log", True)
    ipresolver = GlobalIPResolver(
        enabled=cfg.get("log_global_ip", True),
        trust_xff=cfg.get("trust_xforwarded_for", False),
        ttl=cfg.get("self_ip_ttl", 60))
    # 出口グローバルIPを起動時に取得し、以後 TTL ごとに更新する(VPN切替に追従)
    if ipresolver.enabled:
        def _ip_keeper():
            ipresolver.self_public_ip()  # 先読み
            interval = max(15, ipresolver.ttl)
            while True:
                time.sleep(interval)
                try:
                    ipresolver._fetch()  # 強制再取得(変化があればログ出力)
                except Exception:
                    pass
        threading.Thread(target=_ip_keeper, daemon=True).start()
    runtime = Runtime(cfg, args.config, inspector, limiter, ipresolver)
    runtime.log_lock = logger.lock      # ダッシュボードのログ削除と書き込みが衝突しないよう共有
    # ログの置き場所の窓口(WEB別の日次ログと攻撃のまとめ)。ダッシュボードの表示もここから読む
    def _org_snapshot():
        c = runtime.cfg                     # ロックは取らない。設定のロック中にログを書いても詰まらないため
        return (list(c.get("orgs") or []), list(c.get("backends") or []), list(wx.users_of(c)))
    logstore = waf_logstore.LogStore(_abs_path(cfg.get("log_dir") or "logs"), _org_snapshot)
    runtime.logstore = logstore
    try:
        _m = logstore.migrate_legacy(logger.path)
        if _m:
            print(f"[ログ] 既存の waf.log {_m} 行を logs/ の新しい構成へ変換しました(元の waf.log は waf.log.migrated に名前を変えました)", flush=True)
    except Exception as e:
        print(f"[ログ] 既存ログの変換に失敗: {e}", flush=True)
    try:
        _u = logstore.upgrade_layout()
        if _u:
            print(f"[ログ] 旧い構成の attacks/ を、_all(ログすべてのまとめ)に作り直しました({_u} 行)", flush=True)
    except Exception as e:
        print(f"[ログ] まとめの作り直しに失敗: {e}", flush=True)
    logger.logstore = logstore
    logger.legacy_file = False          # 以後 waf.log には書かない(既存分は上で変換済み)
    runtime.logstore = logstore

    def _retention_loop():
        """保存期間を過ぎたログを1日1回削除する。組織に属するバックエンドだけが対象で、割り当てのないものは消さない。"""
        time.sleep(60)
        while True:
            try:
                n = runtime.prune_logs()
                if n:
                    print(f"[保存期間] 期限を過ぎたログ {n} 行を削除しました", flush=True)
            except Exception as e:
                print(f"[保存期間] 削除に失敗: {e}", flush=True)
            time.sleep(86400)
    threading.Thread(target=_retention_loop, daemon=True, name="log-retention").start()
    # オフライン GeoIP(GeoLite2 mmdb があれば使う。無ければ外部APIで国判定)
    _gcfg = cfg.get("geoip") or {}
    offline_geo = wx.OfflineGeo(_gcfg.get("mmdb", ""), BASE_DIR)
    runtime.offline_geo = offline_geo
    country_resolver = CountryResolver(offline=offline_geo, online=_gcfg.get("online", True))
    # Webhook(検知イベントの外部送信)
    runtime.webhook = wx.Webhook(cfg)
    logger.webhook = runtime.webhook
    handler, accept_gate, conn_limiter = make_handler(
        cfg, inspector, limiter, logger, ipresolver, country_resolver)
    runtime.conn_limiter = conn_limiter   # ダッシュボードからIPごとの接続数を見られるようにする

    # 受付キュー(listen backlog)。フラッドの瞬間的な山を吸収する。溢れた新規接続は接続拒否になる
    GatedHTTPServer.request_queue_size = max(128, int(cfg.get("listen_backlog", 2048)))
    httpd = GatedHTTPServer((cfg["listen_host"], cfg["listen_port"]), handler)
    httpd.gate = accept_gate   # accept 段階で BAN/ブロック/接続過多を遮断
    httpd.t_acc = {}           # accept 時刻(処理開始までの遅れの計測用)
    _tune_process(cfg)
    httpd.stats = conn_limiter.stats
    conn_limiter.health.server = httpd

    scheme = "http"
    if cfg["listen_tls"]:
        certfile = cfg["tls_certfile"]
        keyfile = cfg["tls_keyfile"]
        certfile = _abs_path(certfile)
        keyfile = _abs_path(keyfile)

        lan_ips = get_lan_ips()
        need_gen = not (os.path.exists(certfile) and os.path.exists(keyfile))
        # 既存証明書に現在の LAN IP が含まれなければ再生成する(ネットワーク変更への追従)
        if not need_gen and lan_ips:
            san = _cert_san_ips(certfile)
            if san is not None and not set(lan_ips).issubset(san):
                print("LAN IP が証明書に含まれていないため再生成します。")
                need_gen = True

        ok = True
        if need_gen:
            if cfg.get("tls_autogen", True):
                ok = ensure_tls_cert(certfile, keyfile)
            else:
                ok = not (not os.path.exists(certfile))

        if ok:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
                # TLS握手は accept 時ではなく、ゲート通過後に接続ごとのスレッドで行う(WafHandler.setup)。
                # BAN済みの接続に暗号計算をせず、無応答の接続1本で待受全体が止まることもない
                httpd.ssl_context = ctx      # ゲート通過後にワーカー側でTLS化(待受ソケットは素のまま)
                scheme = "https"
            except Exception as e:
                print(f"[警告] TLS の初期化に失敗したため HTTP で起動します: {e}")
        else:
            print("[警告] 証明書を用意できなかったため HTTP で起動します。")
            print("       https ではなく http:// でアクセスしてください。")

    runtime.listeners = ListenerManager(cfg, httpd, handler, accept_gate, conn_limiter.stats)
    runtime.listeners.start()          # バックエンド専用ポート(複数同時防御)

    on_lan = cfg["listen_host"] in ("0.0.0.0", "", "::")
    browse_host = "127.0.0.1" if on_lan else cfg["listen_host"]
    lan_ips = get_lan_ips()

    # 統合ダッシュボードを同一プロセスで起動
    dash_cfg = cfg.get("dashboard", {})
    dash_httpd = None
    dash_url = None
    if dash_cfg.get("enabled", True):
        try:
            import dashboard as _dash
            geo = _dash.GeoResolver(enabled=dash_cfg.get("geo", True),
                                    egress=dash_cfg.get("egress", True),
                                    ttl=cfg.get("self_ip_ttl", 60))
            runtime.geo = geo
            dhost = dash_cfg.get("host", "127.0.0.1")
            # LAN に公開するのにパスワードが無ければ自動生成する(self_made_waf と同じ)
            if (not runtime.admin_password() and not runtime.users() and not wx.is_loopback_host(dhost)
                    and dash_cfg.get("require_password_on_lan", True)):
                import secrets as _secrets
                runtime.generated_password = _secrets.token_urlsafe(9)   # 設定ファイルには保存しない
            dash_handler = _dash.make_handler(logger.path, geo, control=runtime, source=logstore)
            dport = dash_cfg.get("port", 8090)
            dash_httpd = _dash.TLSThreadingHTTPServer((dhost, dport), dash_handler)
            _dctx = dashboard_tls_context(cfg)
            if _dctx is not None:
                dash_httpd.ssl_context, dash_httpd.is_tls = _dctx, True
            runtime.dash_tls = dash_httpd.is_tls
            dscheme = "https" if dash_httpd.is_tls else "http"
            threading.Thread(target=dash_httpd.serve_forever, daemon=True).start()
            dash_on_lan = dhost in ("0.0.0.0", "", "::")
            dbrowse = "127.0.0.1" if dash_on_lan else dhost
            dash_url = f"{dscheme}://{dbrowse}:{dport}"
        except Exception as e:
            print(f"[警告] ダッシュボードの起動に失敗しました: {e}")

    print("=" * 70)
    print(" Reverse-Proxy WAF + ダッシュボード 起動")
    print(f"  待受       : {scheme}://{cfg['listen_host']}:{cfg['listen_port']}")
    print(f"  アクセス   : {scheme}://{browse_host}:{cfg['listen_port']}  ← ローカル")
    if on_lan and lan_ips:
        for ip in lan_ips:
            print(f"  LAN から   : {scheme}://{ip}:{cfg['listen_port']}  ← 同一ネットワークの端末はこちら")
    _ap = wb.active_profile(cfg)
    _nb = len(wb.get_profiles(cfg))
    for _lp, _pp in sorted(wb.listen_ports(cfg).items()):
        _ok = _lp in runtime.listeners.servers if getattr(runtime, "listeners", None) else False
        print(f"  専用ポート : {scheme}://{browse_host}:{_lp}  → {_pp['name']} ({wb.origin(_pp)})" + ("" if _ok else "  ※開けませんでした"))
    print(f"  転送先     : {wb.origin(_ap)}" + (f"  (使用中: {_ap['name']} / 登録 {_nb} 件" + (" / ホスト名で振り分け" if cfg.get("host_routing") else "") + ")" if _nb > 1 else ""))
    if dash_url:
        print(f"  ダッシュボード: {dash_url}  (攻撃マップ・統計)"
              + ("  [パスワード認証あり]" if runtime.admin_password() else ""))
        if getattr(runtime, "generated_password", None):
            print(f"  ★管理画面のパスワード(自動生成): {runtime.generated_password}")
            print("    固定するには --admin-password / 環境変数 WAF_ADMIN_PASSWORD / dashboard.password")
        if dash_cfg.get("host") in ("0.0.0.0", "", "::") and lan_ips:
            for ip in lan_ips:
                print(f"    LAN から : {dash_url.split(':')[0]}://{ip}:{dash_cfg.get('port',8090)}")
    print(f"  モード     : {cfg['mode']}  (block=遮断 / detect=監視のみ)")
    _cr = cfg.get("client_ip_report", {})
    print(f"  公開IP申告 : {'ON' if _cr.get('enabled') else 'OFF'}"
          + (f"  (ブラウザが外部APIで自分の公開IPを取得して申告 / 再取得 {_cr.get('ttl_seconds', 45)}秒)"
             if _cr.get("enabled") else ""))
    print(f"  有効ルール : {', '.join(c for c,on in cfg['rules'].items() if on)}")
    print(f"  レート制限 : {cfg['rate_limit']['max_requests']}req / "
          f"{cfg['rate_limit']['window_seconds']}s "
          f"({'ON' if cfg['rate_limit']['enabled'] else 'OFF'})")
    print(f"  ログ       : {logger.path}  (access_log={'ON' if access_log_on else 'OFF'})")
    _bits = []
    if cfg.get("ip_allowlist"):
        _bits.append(f"許可IPのみ {len(cfg['ip_allowlist'])}件")
    if cfg.get("blocklist"):
        _bits.append(f"ブロックIP {len(cfg['blocklist'])}件")
    if cfg.get("country_allowlist"):
        _bits.append("許可国のみ " + ",".join(cfg["country_allowlist"]))
    if cfg.get("country_blocklist"):
        _bits.append("ブロック国 " + ",".join(map(str, cfg["country_blocklist"])))
    _ab = cfg.get("autoban", {})
    if _ab.get("enabled"):
        _bits.append(f"攻撃で自動BAN {_ab.get('threshold')}回/{_ab.get('window_seconds')}秒→{_ab.get('ban_seconds')}秒")
    _bits.append(f"応答のXSS検査={cfg.get('response_inspection', {}).get('action', 'sanitize')}")
    if offline_geo.ready:
        _bits.append("GeoIP=オフライン(" + os.path.basename(offline_geo.path) + ")")
    if (cfg.get("webhook") or {}).get("url"):
        _bits.append("Webhook=" + cfg["webhook"]["url"])
    for _pp, _p in wb.path_routes(cfg):
        _bits.append(f"パス振り分け {_pp} → {_p['name']}({wb.origin(_p)})")
    print("  追加の防御 : " + " / ".join(_bits))
    print("=" * 70)
    if on_lan:
        _ports = str(cfg['listen_port'])
        if dash_cfg.get("host") in ("0.0.0.0", "", "::"):
            _ports += f" と {dash_cfg.get('port',8090)}(ダッシュボード)"
        print(" LAN の他端末からアクセスできない場合は、Windows ファイアウォールで")
        print(f" 受信 TCP {_ports} を許可してください(README 参照)。")
    print(" 自己署名証明書のため警告が出ます(詳細設定→アクセス)。停止は Ctrl+C。")

    # 接続レベルの動きを30秒ごとにコンソールへ要約する(変化があったときだけ)。
    # waf.log に残らない握手失敗/リクエストなし切断/不正リクエストも分かる
    def _stats_printer():
        prev = dict.fromkeys(ConnStats.KEYS, 0)
        while True:
            time.sleep(30)
            try:
                cur = conn_limiter.stats.snapshot()
                d = {k: cur[k] - prev.get(k, 0) for k in ConnStats.KEYS}
                prev = {k: cur[k] for k in ConnStats.KEYS}
                if any(d.values()):
                    gate = (d["gate_ban"] + d["gate_blocklist"] + d["gate_conn_limit"]
                            + d["gate_overload"] + d["gate_conn_flood"])
                    print(f"[接続/30秒] 受理 {d['accepted']} / ゲート遮断 {gate}"
                          f"(ban {d['gate_ban']}, 頻度BAN {d['gate_conn_flood']}, 接続数上限 "
                          f"{d['gate_conn_limit'] + d['gate_overload']}, blocklist {d['gate_blocklist']})"
                          f" / TLS成功 {d['tls_ok']} 失敗 {d['tls_fail']}"
                          f" / リクエストなし切断 {d['no_request']}(うちタイムアウト {d['idle_timeout']})"
                          f" / 不正リクエスト {d['bad_request']} / 処理リクエスト {d['requests']}"
                          + (f" / ★受付エラー {d['accept_error']}(直近: {getattr(httpd, 'last_accept_error', '')})"
                             if d.get("accept_error") else ""))
            except Exception:
                pass
    threading.Thread(target=_stats_printer, daemon=True).start()
    if cfg.get("health_history_file", "health_history.jsonl"):
        runtime.purge_health_history()     # 起動時に、削除済みバックエンドの状態ログが残っていれば消す
        conn_limiter.health.enable_persistence(
            _abs_path(cfg.get("health_history_file", "health_history.jsonl")),
            _abs_path(cfg.get("health_heartbeat_file", "health_heartbeat.txt")))
        atexit.register(conn_limiter.health.flush_history)
    conn_limiter.health.start()        # 稼働モニター(掲示板アプリとWAF待受)
    n_acc = httpd.start_extra_acceptors(cfg.get("accept_threads", 4))
    if n_acc > 1:
        print(f"受付スレッド: {n_acc} 本で並行 accept")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n停止しました。")
        httpd.stop_acceptors()
        runtime.listeners.stop()
        httpd.shutdown()
        if dash_httpd:
            dash_httpd.shutdown()


if __name__ == "__main__":
    main()
