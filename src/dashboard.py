#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dashboard.py: WAF ダッシュボードと攻撃マップ(waf.log を可視化)

waf.log(JSON Lines)を読んで集計し、別ポートでブラウザ向けに表示する。WAF本体とは別プロセスで、ログは読むだけ。
プライベート/ループバックIPは地図に出さず「内部ネットワーク」にまとめる。パブリックIPだけ ip-api.com で位置を引き、geo_cache.json に保存する。ネットワークが使えなくても動く。

    python3 dashboard.py                 # http://127.0.0.1:8090
    python3 dashboard.py --port 9000 --log waf.log --no-geo
"""

import argparse
import collections
import time
import ipaddress
import json
import re
import os
import sys
import socket
import datetime
import threading
import time
import urllib.request
import waf_backend as wb
import waf_extras as wx
import waf_custom
import waf_crypt
import waf_org
import waf_tickets
from urllib.parse import urlparse, parse_qs
from collections import Counter, defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE_DIR = os.path.dirname(os.path.abspath(__file__))          # src/
ROOT = os.path.dirname(BASE_DIR)                                # waf.py のあるフォルダ
CONFIG_DIR = os.path.join(ROOT, "config")
DATA_DIR = os.path.join(ROOT, "data")


def _dpath(p):
    """相対パスの置き場所。「config/」「data/」で始まるものは ROOT 基準、それ以外は data/ の中(waf.py の _abs_path と同じ)"""
    if os.path.isabs(p):
        return p
    if p.replace("\\", "/").startswith(("config/", "data/")):
        return os.path.join(ROOT, p)
    return os.path.join(DATA_DIR, p)


class QuietThreadingHTTPServer(ThreadingHTTPServer):
    """SSE切断やポーリング中断などの接続断でトレースバックを出さない ThreadingHTTPServer"""
    daemon_threads = True

    def handle_error(self, request, client_address):
        et = sys.exc_info()[0]
        if et is not None and issubclass(
                et, (ConnectionError, BrokenPipeError, TimeoutError, socket.timeout)):
            return
        super().handle_error(request, client_address)
sys.path.insert(0, BASE_DIR)
try:
    import waf_rules
    CATEGORIES = waf_rules.CATEGORIES
    CATEGORY_LABELS = waf_rules.CATEGORY_LABELS
except Exception:
    waf_rules = None
    CATEGORIES = ["xss", "sqli", "traversal", "cmdi"]
    CATEGORY_LABELS = {c: c for c in CATEGORIES}

ACTIONS = ["PASS", "BLOCK", "DETECT", "RATELIMIT", "ERROR"]
MAP_ACTIONS = ["PASS", "BLOCK", "DETECT", "RATELIMIT"]

GEO_CACHE_PATH = os.path.join(DATA_DIR, "geo_cache.json")


# ---------------------------------------------------------------------------
# ジオロケーション。パブリックIPのみ、キャッシュあり、オフラインでも動く
# ---------------------------------------------------------------------------
GEO_BATCH_URL = "http://ip-api.com/batch"
# 一括APIが使えないとき(HTTP遮断、レート制限、VPN等)の予備。HTTPSの無料API。
# 上から並行して問い合わせ、最初に成功したものを使う
GEO_FALLBACKS = [
    "https://ipwho.is/{ip}",
    "https://get.geojs.io/v1/ip/geo/{ip}.json",
    "https://ipapi.co/{ip}/json/",
    "https://ipinfo.io/{ip}/json",
]


def _geo_parse(d, ip):
    """各APIの応答を {country, cc, lat, lon} にそろえる。位置がなければ None"""
    try:
        if not isinstance(d, dict) or d.get("success") is False or d.get("error") or d.get("status") == "fail":
            return None
        cc = d.get("country_code") or d.get("countryCode") or ""
        name = d.get("country_name") or d.get("country") or cc
        if d.get("country") and len(str(d.get("country"))) == 2 and not d.get("country_code"):   # ipinfo は country が国コード
            cc = d.get("country"); name = d.get("country_name") or cc
        lat = d.get("latitude", d.get("lat")); lon = d.get("longitude", d.get("lon", d.get("lng")))
        if (lat is None or lon is None) and d.get("loc"):
            lat, lon = str(d["loc"]).split(",")[:2]
        lat = float(lat); lon = float(lon)
        if not (-90 <= lat <= 90 and -180 <= lon <= 180):
            return None
        cc = str(cc).upper()
        if not name or str(name).upper() == cc:           # 国名がなければ国コードから英語名を補う
            try:
                import waf_countries
                name = (waf_countries.COUNTRIES.get(cc) or {}).get("en") or cc
            except Exception:
                name = cc
        return {"country": str(name), "cc": cc, "lat": lat, "lon": lon}
    except (TypeError, ValueError):
        return None


class GeoResolver:
    def __init__(self, enabled=True, egress=True, ttl=60):
        self.enabled = enabled
        self.egress = egress          # 内部IPを自ホストの出口グローバルIPで地図に出すか
        self.ttl = ttl                # 出口IPを取り直す間隔(秒)。VPN切替に追従する
        self.lock = threading.Lock()
        self.cache = self._load()
        self._self_ip = None          # 自ホストの出口グローバルIP
        self._self_ip_at = 0.0        # 取得時刻
        self._refreshing = False
        self._fail = {}               # 位置取得に失敗したIP -> (失敗時刻, 連続失敗回数)。間隔を延ばして再試行する

    # 自ホストの出口(パブリック)IPを取得する。順番は ipinfo、ipify、ifconfig.me
    SELF_IP_PROVIDERS = [
        "https://ipinfo.io/ip",
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
    ]

    def _reload_self_from_file(self):
        """geo_cache.json の __self_ip__ を読み直して、WAF 側の更新を拾う"""
        try:
            with open(GEO_CACHE_PATH, "r", encoding="utf-8") as f:
                ip = json.load(f).get("__self_ip__")
            if ip and self.is_public(ip):
                return ip
        except (OSError, ValueError):
            pass
        return None

    def _fetch_self(self):
        for url in self.SELF_IP_PROVIDERS:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "waf-dashboard"})
                with urllib.request.urlopen(req, timeout=4) as resp:
                    ip = resp.read().decode().strip()
                if self.is_public(ip):
                    with self.lock:
                        self._self_ip = ip
                        self._self_ip_at = time.time()
                        self.cache["__self_ip__"] = ip
                        self._save()
                    return ip
            except Exception:
                continue
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
                self._fetch_self()
            finally:
                with self.lock:
                    self._refreshing = False
        threading.Thread(target=run, daemon=True).start()

    def self_public_ip(self):
        """現在の出口IPを返す。古ければ再取得する(VPN切替に追従)"""
        if not (self.enabled and self.egress):
            return None
        now = time.time()
        # geo_cache.json の最新値を先に拾う。WAF側が更新していればすぐ反映される
        file_ip = self._reload_self_from_file()
        if file_ip and file_ip != self._self_ip:
            self._self_ip = file_ip
            self._self_ip_at = now
        if self._self_ip is None:
            if self._self_ip_at == 0.0:
                return self._fetch_self()       # 初回だけ同期で取得
            # 取得失敗中は待たずに裏で取り直す。リアルタイム配信を止めないため
            if now - self._self_ip_at >= 20:
                self._refresh_async()
            return None
        if now - self._self_ip_at >= self.ttl:
            self._refresh_async()               # 期限切れは裏で取り直す
        return self._self_ip

    def _load(self):
        try:
            with open(GEO_CACHE_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

    def _save(self):
        try:
            with open(GEO_CACHE_PATH, "w", encoding="utf-8") as f:
                json.dump(self.cache, f, ensure_ascii=False)
        except OSError:
            pass

    @staticmethod
    def is_public(ip):
        try:
            obj = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return obj.is_global and not obj.is_private

    def _lookup_fallback(self, ip, timeout=4):
        """予備のHTTPS APIに並行で問い合わせ、最初に位置が取れた結果を返す"""
        out = []
        done = threading.Event()

        def one(url):
            try:
                rq = urllib.request.Request(url.format(ip=ip), headers={"User-Agent": "waf-dashboard"})
                with urllib.request.urlopen(rq, timeout=timeout) as resp:
                    rec = _geo_parse(json.loads(resp.read().decode()), ip)
                if rec:
                    out.append(rec)
                    done.set()
            except Exception:
                pass
        ths = [threading.Thread(target=one, args=(u,), daemon=True) for u in GEO_FALLBACKS]
        for t in ths:
            t.start()
        t_end = time.time() + timeout + 0.5
        while not done.is_set() and time.time() < t_end and any(t.is_alive() for t in ths):
            done.wait(0.05)
        return out[0] if out else None

    def server_ip(self):
        """防御サーバの出口グローバルIP(地図のサーバー印用)
        出口IP取得が無効でも、WAF が記録した __self_ip__(geo_cache.json)があれば使う
        """
        ip = self.self_public_ip()
        if ip:
            return ip
        try:
            ip = (self.cache or {}).get("__self_ip__") or self._reload_self_from_file()
        except Exception:
            ip = None
        return ip if ip and self.is_public(ip) else None

    def lookup(self, ips, timeout=4):
        """未キャッシュのパブリックIPを解決してキャッシュする
        戻り値は解決できたものだけの {ip: {country, cc, lat, lon}}
        """
        result = {}
        todo = []
        for ip in ips:
            if ip in self.cache:
                if self.cache[ip]:  # None は解決失敗の記録
                    result[ip] = self.cache[ip]
                continue
            if self.is_public(ip):
                ft, fn = self._fail.get(ip, (0, 0))
                if time.time() - ft < min(300, 15 * (2 ** max(0, fn - 1))):   # 失敗したIPは間隔を延ばして再試行。配信を止めず、APIも叩きすぎない
                    continue
                todo.append(ip)

        if todo and self.enabled:
            todo = todo[:100]  # ip-api の batch は最大100件
            try:
                payload = json.dumps(
                    [{"query": ip, "fields": "status,country,countryCode,lat,lon,query"}
                     for ip in todo]).encode()
                req = urllib.request.Request(
                    GEO_BATCH_URL, data=payload,
                    headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    arr = json.loads(resp.read().decode())
                with self.lock:
                    for item in arr:
                        ip = item.get("query")
                        if item.get("status") == "success":
                            rec = {"country": item.get("country"),
                                   "cc": item.get("countryCode"),
                                   "lat": item.get("lat"), "lon": item.get("lon")}
                            self.cache[ip] = rec
                            result[ip] = rec
                        else:
                            self.cache[ip] = None
                    self._save()
            except Exception:
                pass  # ネット不通やレート制限でも画面は動く。下の予備APIで再取得する
            # 一括APIで解決できなかったIPは予備のHTTPS APIで取り直す(5件ずつ)
            left = [ip for ip in todo if ip not in result and ip not in self.cache]
            for ip in left[:5]:
                rec = self._lookup_fallback(ip, timeout)
                if rec:
                    with self.lock:
                        self.cache[ip] = rec
                        self._save()
                    result[ip] = rec
                    self._fail.pop(ip, None)
                else:
                    ft, fn = self._fail.get(ip, (0, 0))
                    self._fail[ip] = (time.time(), fn + 1)
            for ip in left[5:]:
                ft, fn = self._fail.get(ip, (0, 0)); self._fail[ip] = (time.time(), fn + 1)

        return result


# ---------------------------------------------------------------------------
# ログの読み込みと集計
# ---------------------------------------------------------------------------
def read_events(log_path, limit=200000):
    """ログ末尾 limit 行を読む。limit=None は全行(上限は ALL_EVENTS_CAP 行)
    戻り値は events のみ。詳細が要るときは read_events_all を使う
    """
    return read_events_all(log_path, limit)[0]


ALL_EVENTS_CAP = 1000000


def read_events_all(log_path, limit=None):
    """(events, 読んだ行数, ファイル全体の行数, 打ち切ったか)。limit=None は ALL_EVENTS_CAP まで
    新しい方を優先し、deque で末尾だけ保持する
    """
    cap = ALL_EVENTS_CAP if limit is None else max(1, int(limit))
    cap = min(cap, ALL_EVENTS_CAP)
    if not os.path.exists(log_path):
        return [], 0, 0, False
    tail = collections.deque(maxlen=cap)
    total = 0
    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                total += 1
                tail.append(line)
    except OSError:
        return [], 0, 0, False
    events = []
    for line in tail:
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if isinstance(e, dict):
            events.append(e)
    return events, len(tail), total, total > len(tail)


def read_events_store(source, webs, limit=None):
    """read_events_all の日次ログ(LogStore)版。(events, 読んだ行数, 全体の行数, 打ち切ったか)。新しい方を残す"""
    cap = ALL_EVENTS_CAP if limit is None else min(max(1, int(limit)), ALL_EVENTS_CAP)
    tail = collections.deque(maxlen=cap)
    total = 0
    it, _reset = source.reader(webs).poll()
    for e in it:
        total += 1
        tail.append(e)
    return list(tail), len(tail), total, total > len(tail)


def _dt(ts):
    try:
        return datetime.datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return None

def _hourfull_key(ts):
    d = _dt(ts); return d.strftime("%Y-%m-%d %H") if d else "?"

def _day_key(ts):
    d = _dt(ts); return d.strftime("%Y-%m-%d") if d else "?"

def _month_key(ts):
    d = _dt(ts); return d.strftime("%Y-%m") if d else "?"

def _row(bucket, key, label):
    c = bucket.get(key, {})
    return {"t": label,
            "PASS": c.get("PASS", 0), "BLOCK": c.get("BLOCK", 0),
            "DETECT": c.get("DETECT", 0), "RATELIMIT": c.get("RATELIMIT", 0)}

def _add_months(d, k):
    m = d.month - 1 + k
    return d.replace(year=d.year + m // 12, month=m % 12 + 1, day=1)

def _srow(bucket, key, label):
    """トレンドグラフ用の1行(通常 / 攻撃 / 制限 + 判定別 + カテゴリ別)"""
    c = bucket.get(key, {})
    return {"t": label,
            "ALLOW": c.get("ALLOW", 0), "ATTACK": c.get("ATTACK", 0), "LIMIT": c.get("LIMIT", 0),
            "BLOCK": c.get("J:BLOCK", 0), "SANITIZE": c.get("J:SANITIZE", 0), "DETECT": c.get("J:DETECT", 0),
            "cats": {k[2:]: v for k, v in c.items() if k.startswith("C:") and v}}

def _fill_hours(bucket, now, n=24, offset=0, row=_row):
    base = now.replace(minute=0, second=0, microsecond=0)
    return [row(bucket, (base - datetime.timedelta(hours=i + offset)).strftime("%Y-%m-%d %H"),
                (base - datetime.timedelta(hours=i)).strftime("%H:00"))
            for i in range(n - 1, -1, -1)]

def _fill_days(bucket, now, n, offset=0, row=_row):
    base = now.replace(hour=0, minute=0, second=0, microsecond=0)
    return [row(bucket, (base - datetime.timedelta(days=i + offset)).strftime("%Y-%m-%d"),
                (base - datetime.timedelta(days=i)).strftime("%m-%d"))
            for i in range(n - 1, -1, -1)]

def _fill_months(bucket, now, n=12, offset=0, row=_row):
    base = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    out = []
    for i in range(n - 1, -1, -1):
        d = _add_months(base, -i)
        k = _add_months(base, -(i + offset))
        out.append(row(bucket, k.strftime("%Y-%m"), d.strftime("%Y-%m")))
    return out


MAP_PERIODS = ("today", "week", "year", "all")


def _in_period(ts, period, now):
    if period == "all" or not period:
        return True
    d = _dt(ts)
    if d is None:
        return False
    if period == "today":
        return d.date() == now.date()
    if period == "week":
        return d >= now - datetime.timedelta(days=7)
    if period == "year":
        return d >= now - datetime.timedelta(days=365)
    return True


def _cnt_of(e):
    try:
        return max(1, int(e.get("count", 1)))
    except (TypeError, ValueError):
        return 1


def build_map(events, geo, period="all", now=None):
    """期間で絞った送信元ノードと防御サーバの攻撃マップ集計。イベント列から直接集計する"""
    now = now or datetime.datetime.now()
    node_counts = defaultdict(lambda: Counter())   # client_ip -> action -> n
    node_conns = defaultdict(set)                   # client_ip -> {conn_ip,...}
    for e in events:
        if not _in_period(e.get("ts", ""), period, now):
            continue
        ip = e.get("client_ip", "?")
        if ip == "?":
            continue
        node_counts[ip][e.get("action", "?")] += _cnt_of(e)
        cn = e.get("conn_ip")
        if cn and cn != ip:
            node_conns[ip].add(cn)
    return build_map_from_nodes(node_counts, node_conns, geo, period)


def build_map_from_nodes(node_counts, node_conns, geo, period="all"):
    """集計済み(client_ip -> action -> n)から攻撃マップ用データを作る。ジオ解決もここで行う"""
    internal_count = 0
    internal_counts = Counter()
    public_ips = []
    for ip in node_counts:
        if GeoResolver.is_public(ip):
            public_ips.append(ip)
        else:
            internal_count += sum(node_counts[ip].values())
            internal_counts.update(node_counts[ip])

    nodes = []
    country_counter = Counter()
    server = None
    self_ip = None
    if geo is not None:
        self_ip = geo.server_ip()
        lookup_ips = list(set(public_ips) | ({self_ip} if self_ip else set()))
        resolved = geo.lookup(lookup_ips) if lookup_ips else {}
        if self_ip and resolved.get(self_ip, {}).get("lat") is not None:
            rs = resolved[self_ip]
            server = {"ip": self_ip, "lat": rs.get("lat"), "lon": rs.get("lon"),
                      "country": rs.get("country"), "cc": rs.get("cc")}
        for ip in public_ips:
            r = resolved.get(ip)
            if not (r and r.get("lat") is not None):
                continue
            cnt = node_counts[ip]
            total_n = sum(cnt.values())
            nodes.append({
                "ip": ip,
                "lat": r.get("lat"), "lon": r.get("lon"),
                "country": r.get("country"), "cc": r.get("cc"),
                "kind": "egress" if ip == self_ip else "external",
                "counts": {a: cnt.get(a, 0) for a in MAP_ACTIONS},
                "total": total_n,
                "blocked": cnt.get("BLOCK", 0),
                "conns": sorted(node_conns.get(ip, []))[:8],
            })
            if r.get("country"):
                country_counter[r["country"]] += total_n
    nodes.sort(key=lambda x: -x["total"])
    public_unresolved = max(0, len(public_ips) - len(nodes))
    return {
        "server": server,
        "nodes": nodes,
        "internal_count": internal_count,
        "internal_counts": {a: internal_counts.get(a, 0) for a in MAP_ACTIONS},
        "countries": [{"country": k, "count": v} for k, v in country_counter.most_common(10)],
        "public_unresolved": public_unresolved,
        "period": period,
    }


# メモリ膨張の対策。送信元IP偽装の大量攻撃でも辞書が増え続けないようにする
_MAX_IPS = 50000
_KEEP_IPS = 20000


def _trim_counter(c):
    if len(c) > _MAX_IPS:
        keep = dict(c.most_common(_KEEP_IPS))
        c.clear()
        c.update(keep)


_LIMIT_DISP_PREFIX = ("country:", "autoban_", "slow_conn")
_BAN_FIRED_DISP = ("ban_triggered",)


def _classify(e):
    """イベントを (種別, 判定) に分類する
    種別: ALLOW(通常) / ATTACK(SQLi・XSSなど) / LIMIT(DoS・アクセス制限) / None(転送エラー等)
    判定: BLOCK(遮断) / SANITIZE(応答の無害化) / DETECT(検知のみ) / None
    """
    act = e.get("action")
    disp = str(e.get("disposition") or "")
    if act == "PASS":
        return "ALLOW", None
    if act == "RATELIMIT":
        return "LIMIT", None
    if act in ("BLOCK", "DETECT"):
        if disp.startswith(_LIMIT_DISP_PREFIX):
            return "LIMIT", None            # 国/IP制限・自動BAN・低速接続は「制限」に数える
        if act == "DETECT":
            return "ATTACK", "DETECT"
        return "ATTACK", ("SANITIZE" if disp == "response_sanitize" else "BLOCK")
    return None, None


_SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


class Aggregates:
    """イベントを1件ずつ足せる累計集計。aggregate() と EventStore の共通部品
    add(e) のコストは1イベント分だけ
    """
    def __init__(self):
        self.action_counts = Counter()
        self.category_counts = Counter()
        self.rule_counts = Counter()
        self.severity_counts = Counter()
        self.ip_total = Counter()
        self.ip_blocked = Counter()
        self.field_counts = Counter()
        self.path_blocked = Counter()
        self.by_hour = defaultdict(Counter)
        self.by_day = defaultdict(Counter)
        self.by_month = defaultdict(Counter)
        # 攻撃マップ用の期間別集計。全期間と日別(today/week/year は日別の合計で作る)
        self.map_all = defaultdict(Counter)            # client_ip -> action -> n
        self.map_day = defaultdict(lambda: defaultdict(Counter))   # day -> client_ip -> action -> n
        self.map_conns = defaultdict(set)              # client_ip -> {conn_ip,...}(IPごとに最大64件)
        self.map_day_conns = defaultdict(lambda: defaultdict(set))   # day -> client_ip -> {conn_ip,...}
        self.backend_counts = defaultdict(Counter)     # backend id -> action -> n(バックエンド別の件数)
        self.backend_names = {}                        # backend id -> 最後に見た表示名
        self.heat_day = defaultdict(Counter)           # day -> (曜日0=月..6, 時0..23) -> 攻撃件数(ヒートマップ用)
        # トレンドグラフ用(通常/攻撃/制限、判定別、カテゴリ別)。キーは ALLOW/ATTACK/LIMIT/J:判定/C:カテゴリ
        self.ser_h = defaultdict(Counter)
        self.ser_d = defaultdict(Counter)
        self.ser_m = defaultdict(Counter)
        # DoS・アクセス制限の規模(日別)。制限した送信元IP、BAN発動回数、10秒ごとの制限リクエスト数
        self.lim_ip_day = defaultdict(Counter)
        self.lim_ban_day = Counter()
        self.lim_10s = defaultdict(Counter)

    def add(self, e):
        act = e.get("action", "?")
        cnt = _cnt_of(e)
        self.action_counts[act] += cnt
        bid = e.get("backend") or ""
        if len(self.backend_counts) < 200 or bid in self.backend_counts:
            self.backend_counts[bid][act] += cnt
            if bid and e.get("backend_name"):
                self.backend_names[bid] = str(e["backend_name"])[:40]
        ip = e.get("client_ip", "?")
        self.ip_total[ip] += cnt
        ts = e.get("ts", "")
        d = _dt(ts)
        if d is not None:
            hk, dk, mk = d.strftime("%Y-%m-%d %H"), d.strftime("%Y-%m-%d"), d.strftime("%Y-%m")
        else:
            hk = dk = mk = "?"
        self.by_hour[hk][act] += cnt
        self.by_day[dk][act] += cnt
        self.by_month[mk][act] += cnt

        kind, judge = _classify(e)
        if kind:
            keys = [kind]
            if judge:
                keys.append("J:" + judge)
            if kind == "ATTACK":
                cats = {h.get("category") for h in (e.get("hits") or []) if h.get("category")}
                keys += ["C:" + c for c in cats]
            for k in keys:
                self.ser_h[hk][k] += cnt
                self.ser_d[dk][k] += cnt
                self.ser_m[mk][k] += cnt
            if kind == "LIMIT" and d is not None and ip != "?":
                self.lim_ip_day[dk][ip] += cnt
                disp = str(e.get("disposition") or "")
                if disp in _BAN_FIRED_DISP or (disp.startswith("autoban_") and not disp.startswith("autoban_would_")):
                    self.lim_ban_day[dk] += cnt
                self.lim_10s[dk][int(d.timestamp()) // 10] += cnt

        if ip != "?":
            self.map_all[ip][act] += cnt
            self.map_day[dk][ip][act] += cnt
            cn = e.get("conn_ip")
            if cn and cn != ip:
                s = self.map_conns[ip]
                if len(s) < 64:
                    s.add(cn)
                sd = self.map_day_conns[dk][ip]
                if len(sd) < 64:
                    sd.add(cn)

        if act in ("BLOCK", "DETECT") and d is not None and dk != "?":
            self.heat_day[dk][(d.weekday(), d.hour)] += cnt
        if act in ("BLOCK", "DETECT"):
            if ip != "?":
                self.ip_blocked[ip] += cnt
            if e.get("path"):
                self.path_blocked[e["path"]] += cnt
            seen_cat = set()
            for h in (e.get("hits") or []):
                cat = h.get("category")
                if cat and cat not in seen_cat:
                    self.category_counts[cat] += 1
                    seen_cat.add(cat)
                if h.get("id"):
                    self.rule_counts[h["id"]] += 1
                if h.get("field"):
                    self.field_counts[h["field"]] += 1
            # 深刻度は1件の攻撃につき、当たったルールのうち一番重いもので数える
            # ルールごとに数えると、複数ルールに当たった攻撃で合計が攻撃総数を超える
            sevs = [h.get("severity") for h in (e.get("hits") or []) if h.get("severity") in _SEV_RANK]
            if sevs:
                self.severity_counts[max(sevs, key=lambda x: _SEV_RANK[x])] += cnt

    def trim(self):
        for c in self.lim_ip_day.values():
            _trim_counter(c)
        _trim_counter(self.ip_total)
        _trim_counter(self.ip_blocked)
        if len(self.map_all) > _MAX_IPS:
            keep = dict(sorted(self.map_all.items(), key=lambda kv: -sum(kv[1].values()))[:_KEEP_IPS])
            self.map_all.clear(); self.map_all.update(keep)
            for ip in [i for i in self.map_conns if i not in self.map_all]:
                self.map_conns.pop(ip, None)
        for dk, m in self.map_day.items():
            if len(m) > _MAX_IPS:
                keep = dict(sorted(m.items(), key=lambda kv: -sum(kv[1].values()))[:_KEEP_IPS])
                m.clear(); m.update(keep)
                dc = self.map_day_conns.get(dk)
                if dc:
                    for ip in [i for i in dc if i not in m]:
                        dc.pop(ip, None)

    def heatmap(self, now, days=(7, 30)):
        """曜日×時間帯の攻撃件数(直近7日 / 30日)"""
        out = {}
        for n in days:
            lo = (now - datetime.timedelta(days=n - 1)).date().isoformat()
            agg = Counter()
            for dk, c in self.heat_day.items():
                if dk >= lo:
                    agg.update(c)
            out[f"{n}d"] = [[w, h, v] for (w, h), v in sorted(agg.items())]
        # 古い日は捨てる(最大40日分)
        if len(self.heat_day) > 40:
            for dk in sorted(self.heat_day)[:-40]:
                self.heat_day.pop(dk, None)
        return out

    def limit_scale(self, now, days=30):
        """直近 days 日の制限の規模: 制限した送信元IP数 / 制限したリクエスト数 / ピーク(毎秒・10秒平均) / BAN発動回数"""
        lo = (now.date() - datetime.timedelta(days=days - 1)).isoformat()
        ips = Counter()
        req = bans = peak10 = 0
        for dk, c in self.lim_ip_day.items():
            if dk >= lo:
                ips.update(c)
        for dk, c in self.ser_d.items():
            if dk != "?" and dk >= lo:
                req += c.get("LIMIT", 0)
        for dk, n in self.lim_ban_day.items():
            if dk >= lo:
                bans += n
        for dk, c in self.lim_10s.items():
            if dk >= lo and c:
                peak10 = max(peak10, max(c.values()))
        # 古い日は捨てる(最大45日分)
        for store in (self.lim_ip_day, self.lim_10s, self.lim_ban_day):
            if len(store) > 45:
                for dk in sorted(store)[:-45]:
                    store.pop(dk, None)
        return {"ips": len(ips), "requests": req, "peak_rps": round(peak10 / 10.0, 1), "bans": bans,
                "top": [{"ip": k, "count": v} for k, v in ips.most_common(5)], "days": days}

    def map_nodes(self, period, now):
        """期間で絞った (client_ip -> action -> n)。ロック内で呼ぶ軽い処理で、ジオ解決は含まない"""
        if period == "all" or not period:
            return {ip: Counter(c) for ip, c in self.map_all.items()}, self.map_conns
        if period == "today":
            days = {now.strftime("%Y-%m-%d")}
        elif period == "week":
            lo = (now - datetime.timedelta(days=7)).date()
            days = {k for k in self.map_day if k != "?" and k >= lo.isoformat()}
        elif period == "year":
            lo = (now - datetime.timedelta(days=365)).date()
            days = {k for k in self.map_day if k != "?" and k >= lo.isoformat()}
        else:
            days = set(self.map_day)
        out = defaultdict(Counter)
        conns = defaultdict(set)
        for dk in days:
            for ip, c in self.map_day.get(dk, {}).items():
                out[ip].update(c)
            for ip, cs in self.map_day_conns.get(dk, {}).items():
                conns[ip] |= cs
        return out, conns

    def snapshot_data(self, map_period, now):
        """ロック内で作る軽量スナップショット。ジオ解決や重い整形はロック外で行う"""
        nodes, conns = self.map_nodes(map_period, now)
        _hk48, _dk60, _mk24 = _recent_hour_keys(now, 48), _recent_day_keys(now, 60), _recent_month_keys(now, 24)
        return {
            "action_counts": Counter(self.action_counts),
            "category_counts": Counter(self.category_counts),
            "rule_top": self.rule_counts.most_common(8),
            "severity": dict(self.severity_counts),
            "ip_blocked_top": self.ip_blocked.most_common(8),
            "ip_total_top": self.ip_total.most_common(8),
            "ip_total_of": {k: self.ip_total.get(k, 0) for k, _ in self.ip_blocked.most_common(8)},
            "field_top": self.field_counts.most_common(8),
            "path_top": self.path_blocked.most_common(8),
            "by_hour": {k: Counter(v) for k, v in self.by_hour.items() if k in _recent_hour_keys(now, 24)},
            "by_day": {k: Counter(v) for k, v in self.by_day.items() if k in _recent_day_keys(now, 30)},
            "by_month": {k: Counter(v) for k, v in self.by_month.items() if k in _recent_month_keys(now, 12)},
            # トレンド用。現在と1つ前の期間の2期間分
            "ser_h": {k: Counter(v) for k, v in self.ser_h.items() if k in _hk48},
            "ser_d": {k: Counter(v) for k, v in self.ser_d.items() if k in _dk60},
            "ser_m": {k: Counter(v) for k, v in self.ser_m.items() if k in _mk24},
            "limit_scale": self.limit_scale(now),
            "nodes": nodes,
            "node_conns": {ip: set(conns.get(ip, ())) for ip in nodes},
            "heatmap": self.heatmap(now),
            "backends": [{"id": b, "name": self.backend_names.get(b, b),
                          "counts": {a: c.get(a, 0) for a in ACTIONS},
                          "total": sum(c.get(a, 0) for a in ACTIONS)}
                         for b, c in self.backend_counts.items()],
        }


def _recent_hour_keys(now, n):
    base = now.replace(minute=0, second=0, microsecond=0)
    return {(base - datetime.timedelta(hours=i)).strftime("%Y-%m-%d %H") for i in range(n)}


def _recent_day_keys(now, n):
    base = now.date()
    return {(base - datetime.timedelta(days=i)).strftime("%Y-%m-%d") for i in range(n)}


def _recent_month_keys(now, n):
    keys = set()
    d = now.replace(day=1)
    for i in range(n):
        keys.add(_add_months(d, -i).strftime("%Y-%m"))
    return keys


def render_stats(snap, geo, map_period, now, recent_events):
    """snapshot_data() の結果から /api/stats の応答を作る(ロック外)"""
    action_counts = snap["action_counts"]
    total = sum(action_counts.get(a, 0) for a in ACTIONS)
    blocked = action_counts.get("BLOCK", 0)
    block_rate = round(100.0 * blocked / total, 1) if total else 0.0
    traffic_hour = _fill_hours(snap["by_hour"], now, 24)
    traffic_week = _fill_days(snap["by_day"], now, 7)
    traffic_month = _fill_days(snap["by_day"], now, 30)
    traffic_year = _fill_months(snap["by_month"], now, 12)
    trend = {
        "hour": {"cur": _fill_hours(snap["ser_h"], now, 24, 0, _srow), "prev": _fill_hours(snap["ser_h"], now, 24, 24, _srow)},
        "week": {"cur": _fill_days(snap["ser_d"], now, 7, 0, _srow), "prev": _fill_days(snap["ser_d"], now, 7, 7, _srow)},
        "month": {"cur": _fill_days(snap["ser_d"], now, 30, 0, _srow), "prev": _fill_days(snap["ser_d"], now, 30, 30, _srow)},
        "year": {"cur": _fill_months(snap["ser_m"], now, 12, 0, _srow), "prev": _fill_months(snap["ser_m"], now, 12, 12, _srow)},
    }
    map_data = build_map_from_nodes(snap["nodes"], snap["node_conns"], geo, map_period)
    ip_total = snap["ip_total_of"]
    top_ips = ([{"ip": k, "total": ip_total.get(k, 0), "blocked": v} for k, v in snap["ip_blocked_top"]]
               or [{"ip": k, "total": v, "blocked": 0} for k, v in snap["ip_total_top"]])
    cc = snap["category_counts"]
    return {
        "total": total,
        "actions": {a: action_counts.get(a, 0) for a in ACTIONS},
        "block_rate": block_rate,
        "categories": [{"name": c, "label": CATEGORY_LABELS.get(c, c),
                        "count": cc.get(c, 0)} for c in CATEGORIES],
        "severity": snap["severity"],
        "top_rules": [{"id": k, "count": v} for k, v in snap["rule_top"]],
        "top_ips": top_ips,
        "top_fields": [{"field": k, "count": v} for k, v in snap["field_top"]],
        "top_paths": [{"path": k, "count": v} for k, v in snap["path_top"]],
        "timeline": traffic_hour,
        "traffic": {"hour": traffic_hour, "week": traffic_week, "month": traffic_month, "year": traffic_year},
        "trend": trend,
        "limit_scale": snap.get("limit_scale") or {},
        "map": map_data,
        "backends": snap.get("backends", []),
        "heatmap": snap.get("heatmap") or {},
        "recent": _recent(recent_events, 800),   # 初期表示用の種。以降はSSEでリアルタイムに追加する
        "total_events": total,
        "generated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def aggregate(events, geo=None, map_period="all"):
    """イベント列の全件集計(単体利用・テスト用)。本体は EventStore の差分集計を使う"""
    agg = Aggregates()
    for e in events:
        agg.add(e)
    now = datetime.datetime.now()
    return render_stats(agg.snapshot_data(map_period, now), geo, map_period, now, events)


class EventStore:
    """waf.log を前回の続きから読んで累計集計に足す(差分読み込み)
    - 更新コストは増えた行数だけに比例する
    - 集計は起動後ずっと累積する。行数の上限なし
    - 直近イベントは最大 recent_max 件だけメモリに保持(イベントログ/詳細表示用)
    - ログが小さくなった/差し替わったら最初から読み直す
    初回の全読み込み中は、同じプロセスの WAF の CPU を奪わないよう一定行ごとに実行権を譲る
    """
    YIELD_EVERY = 2000

    def __init__(self, log_path, recent_max=20000, min_interval=0.25, accept=None, source=None, webs=None):
        self.path = log_path
        self.source = source          # waf_logstore.LogStore(WEBごとの日次ログ)。None なら1ファイル(log_path)
        self.webs = webs              # source 使用時に読んでよいWEBのid(None=すべて)
        self.accept = accept          # イベントを取り込む条件。ユーザーが見られるバックエンドで絞る。None=全部
        self.recent_max = recent_max
        self.min_interval = min_interval
        self.lock = threading.RLock()
        self._reset()
        self._last = 0.0

    def _reset(self):
        self.agg = Aggregates()
        self.recent = collections.deque(maxlen=self.recent_max)
        self.offset = 0
        self.ino = None
        self.lines = 0
        self.version = 0
        self.reader = self.source.reader(self.webs) if getattr(self, "source", None) is not None else None

    def _refresh_source(self):
        it, reset = self.reader.poll()
        if reset:                      # 保存期間・削除でファイルが消えたので最初から集計し直す
            self._reset()
            it, reset = self.reader.poll()
        n = 0
        for e in it:
            if self.accept is not None and not self.accept(e):
                continue
            self.agg.add(e)
            self.recent.append(e)
            self.lines += 1
            n += 1
            if n % self.YIELD_EVERY == 0:
                self.agg.trim()
                time.sleep(0.0005)
        if n:
            self.agg.trim()
            self.version += 1

    def refresh(self, force=False):
        with self.lock:
            now = time.monotonic()
            if not force and now - self._last < self.min_interval:
                return
            self._last = now
            if self.source is not None:
                return self._refresh_source()
            try:
                st = os.stat(self.path)
            except OSError:
                if self.offset:
                    self._reset()
                return
            if st.st_size < self.offset or (self.ino and st.st_ino and st.st_ino != self.ino):
                self._reset()          # 切り詰め/ローテーションなので最初から
            self.ino = st.st_ino
            if st.st_size == self.offset:
                return
            try:
                f = open(self.path, "rb")
            except OSError:
                return
            n = 0
            with f:
                f.seek(self.offset)
                while True:
                    line = f.readline()
                    if not line or not line.endswith(b"\n"):
                        break                      # 末尾の書きかけ行は次回に回す
                    self.offset += len(line)
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        e = json.loads(line)
                    except ValueError:
                        continue
                    if not isinstance(e, dict):
                        continue
                    if self.accept is not None and not self.accept(e):
                        continue
                    self.agg.add(e)
                    self.recent.append(e)
                    self.lines += 1
                    n += 1
                    if n % self.YIELD_EVERY == 0:
                        self.agg.trim()
                        time.sleep(0.0005)         # WAF側スレッドに実行権を譲る
            if n:
                self.agg.trim()
                self.version += 1

    def counts_and_pos(self):
        """KPIの種(アクション別累計)と、その時点の読み終わり位置(SSEの追尾開始位置)"""
        self.refresh(force=True)
        with self.lock:
            return {a: self.agg.action_counts.get(a, 0) for a in ACTIONS}, (dict(self.reader.pos) if self.source is not None else self.offset)

    def recent_events(self, n=None):
        with self.lock:
            lst = list(self.recent)
        return lst if n is None else lst[-n:]

    def stats(self, geo, map_period="all"):
        self.refresh()
        now = datetime.datetime.now()
        with self.lock:
            snap = self.agg.snapshot_data(map_period, now)
            recent = list(self.recent)[-800:]
            ver = self.version
        return render_stats(snap, geo, map_period, now, recent), ver


def delete_log_events(path, backend, lock=None):
    """waf.log から指定バックエンドのイベント行を削除する(その場で書き換え)
    backend: バックエンドID / __none(バックエンド不明の行) / __all(すべて)。削除した行数を返す
    WAFの書き込みと衝突しないよう、WAFのログ用ロックを共有する
    """
    import contextlib
    ctx = lock if lock is not None else contextlib.nullcontext()
    removed = 0
    with ctx:
        if not os.path.exists(path):
            return 0
        keep = []
        with open(path, "rb") as f:
            for raw in f:
                if backend == "__all":
                    removed += 1
                    continue
                try:
                    e = json.loads(raw)
                    bid = (e.get("backend") or "") if isinstance(e, dict) else ""
                except ValueError:
                    keep.append(raw)
                    continue
                if (backend == "__none" and not bid) or (backend != "__none" and bid == backend):
                    removed += 1
                else:
                    keep.append(raw)
        if removed:
            # 他のプロセス(SSE配信など)が開いていても壊れないよう、置き換えずに同じファイルへ書き直す
            with open(path, "r+b") as f:
                f.seek(0)
                f.write(b"".join(keep))
                f.truncate()
    return removed


def _merge_key(e):
    # drop系(RATELIMIT)は、連続する同一IP×種別を1行にまとめる。それ以外はまとめない
    if e.get("action") != "RATELIMIT":
        return None
    return (e.get("client_ip"), e.get("conn_ip"), e.get("disposition"), e.get("backend"))


def _recent(events, n, merge=True):
    src = events if n is None else events[-n:]
    out = []
    prev_key = None
    for e in src[::-1]:
        rules = ",".join(sorted({h.get("id", "") for h in (e.get("hits") or [])}))
        cnt = e.get("count", 1)
        try:
            cnt = max(1, int(cnt))
        except (TypeError, ValueError):
            cnt = 1
        # 直前の行と同じ drop(RATELIMIT・同一IP・同一種別)なら、まとめて ×N を増やす
        mk = _merge_key(e) if merge else None
        if mk is not None and mk == prev_key and out:
            prev = out[-1]
            prev["count"] += cnt
            prev["ts_from"] = e.get("ts", "")   # 最古側(表示は範囲)
            continue
        prev_key = mk
        row = {
            "ts": e.get("ts", ""), "ts_from": e.get("ts", ""), "ip": e.get("client_ip", ""),
            "conn_ip": e.get("conn_ip", ""), "ip_src": e.get("ip_src", ""),
            "action": e.get("action", ""), "disposition": e.get("disposition", ""),
            "count": cnt,
            "backend": e.get("backend", ""), "backend_name": e.get("backend_name", ""),
            "method": e.get("method", ""),
            "path": e.get("path", ""), "status": e.get("status", ""),
            "rules": rules,
            "req": e.get("req"),         # リクエスト詳細(クエリ/ヘッダ/ボディ)
            **_enc_public(e),      # 暗号化された詳細は暗号文を返さない。復号はキー・オフィサーが申請・承認を経て行う
            "resp": e.get("resp"),       # レスポンス詳細(status/ヘッダ/ボディ)
            "hits": e.get("hits") or [],  # 検知ルールの詳細(field/matched)
        }
        out.append(row)
    return out


# ---------------------------------------------------------------------------
# HTTPハンドラ
# ---------------------------------------------------------------------------
STATUS_TARGETS = (("process", "WAFプロセス"), ("waf", "WAF待受ポート"), ("backend", "接続先アプリ"))
STATUS_LABELS = {"paused": "稼働停止中", "up": "稼働中", "slow": "遅い", "error": "異常応答(5xx)", "down": "ダウン",
                 "unknown": "未確認", "stopped": "監視停止(WAF停止中)"}


def read_health_events(path, limit=5000):
    """保存された状態ログ(JSON Lines)を古い順に読む。壊れた行は飛ばす"""
    rows = []
    if not path:
        return rows
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()[-limit:]
    except OSError:
        return rows
    for line in lines:
        try:
            d = json.loads(line)
            datetime.datetime.fromisoformat(d["ts"])
        except (ValueError, KeyError, TypeError):
            continue
        if isinstance(d, dict) and d.get("target") and d.get("to"):
            rows.append(d)
    rows.sort(key=lambda d: d["ts"])
    return rows


def build_status_log(events, now=None, window_hours=24, backends=None, active_id=None, live=None):
    """状態ログから稼働率・直近の時間帯ごとの状態・変化の一覧を作る
    backends: 登録済みバックエンド [{id,name}](接続先ごとの集計用) / active_id: id無しの古い記録の持ち主 / live: 現在の状態 {id: state}(あれば記録より優先)
    """
    now = now or datetime.datetime.now()
    ts = lambda d: datetime.datetime.fromisoformat(d["ts"])
    backends = [dict(b) for b in (backends or [])]
    reg = {b["id"]: b.get("name") or b["id"] for b in backends}
    if active_id is None and backends:
        active_id = backends[0]["id"]

    def tkey(e):
        if e.get("target") != "backend":
            return e.get("target")
        return "backend:" + str(e.get("backend") or active_id or "")

    keys = ["process", "waf"] + ["backend:" + b["id"] for b in backends]
    by = {k: [] for k in keys}
    for e in events:
        if backends and e.get("target") == "backend" and e.get("backend") and e["backend"] not in reg:
            continue        # 削除済み、または持ち主が未ログインで休止中のバックエンドの履歴は出さない
        by.setdefault(tkey(e), []).append(e)
    names = {"process": "WAFプロセス", "waf": "WAF待受ポート"}
    for b in backends:
        names["backend:" + b["id"]] = b.get("name") or b["id"]
    for k, evs in by.items():
        if k not in names:      # 削除済みのバックエンド(履歴にだけ残る)
            names[k] = next((e.get("backend_name") for e in reversed(evs) if e.get("backend_name")), "接続先アプリ")

    # 対象ごとに区間 [(開始, 終了, 状態)] を作る
    ivs = {}
    for k in by:
        arr = []
        evs = by[k]
        for i, e in enumerate(evs):
            end = ts(evs[i + 1]) if i + 1 < len(evs) else now
            if end > ts(e):
                arr.append([ts(e), end, e["to"]])
        ivs[k] = arr
    # WAFプロセスの停止中は、WAF/接続先アプリの監視も止まっていたものとして上書きする
    downs = [(a, b) for a, b, st in ivs.get("process", []) if st == "down"]
    for k in [x for x in by if x != "process"]:
        out = []
        for a, b, st in ivs[k]:
            cur = [(a, b)]
            for da, db in downs:
                nxt = []
                for x, y in cur:
                    if db <= x or da >= y:
                        nxt.append((x, y)); continue
                    if da > x: nxt.append((x, da))
                    if db < y: nxt.append((db, y))
                cur = nxt
            out += [[x, y, st] for x, y in cur]
            for da, db in downs:
                x, y = max(a, da), min(b, db)
                if y > x:
                    out.append([x, y, "stopped"])
        ivs[k] = sorted(out, key=lambda r: r[0])

    def uptime_parts(k, since):
        avail = total = 0.0
        for a, b, st in ivs.get(k, []):
            a = max(a, since)
            if b <= a:
                continue
            sec = (b - a).total_seconds()
            if st in ("unknown", "paused") or (st == "stopped" and k.startswith("backend")):
                continue
            total += sec
            if st in ("up", "slow"):
                avail += sec
        return avail, total

    def pct(parts):
        return round(parts[0] * 100.0 / parts[1], 2) if parts[1] > 0 else None

    w_start = now - datetime.timedelta(hours=window_hours)
    d1, d7 = now - datetime.timedelta(hours=24), now - datetime.timedelta(days=7)

    def one(k, label, state_override=None):
        arr = ivs.get(k, [])
        cur = arr[-1] if arr else None
        return {
            "label": label,
            "state": state_override or (cur[2] if cur else "unknown"),
            "since": cur[0].isoformat(timespec="seconds") if cur else None,
            "uptime_24h": pct(uptime_parts(k, d1)),
            "uptime_7d": pct(uptime_parts(k, d7)),
            "downs_24h": sum(1 for e in by.get(k, []) if e["to"] in ("down", "error") and ts(e) >= d1),
            "timeline": [{"from": max(a, w_start).isoformat(timespec="seconds"), "to": b.isoformat(timespec="seconds"),
                          "state": st} for a, b, st in arr if b > w_start],
        }

    summary = {"process": one("process", "WAFプロセス"), "waf": one("waf", "WAF待受ポート")}
    live = live or {}
    per = []
    for b in backends:
        k = "backend:" + b["id"]
        d = one(k, b.get("name") or b["id"], live.get(b["id"]) if live.get(b["id"]) not in (None, "unknown") else None)
        d["id"] = b["id"]
        per.append(d)
    # 接続先アプリ全体の、状態ごとの件数
    counts = {"total": len(per)}
    for d in per:
        counts[d["state"]] = counts.get(d["state"], 0) + 1
    order = ["down", "error", "slow", "up", "paused", "unknown"]
    worst = next((st for st in order if counts.get(st)), "unknown")
    ap1 = [sum(x) for x in zip(*[uptime_parts("backend:" + b["id"], d1) for b in backends])] if backends else [0, 0]
    ap7 = [sum(x) for x in zip(*[uptime_parts("backend:" + b["id"], d7) for b in backends])] if backends else [0, 0]
    summary["backend"] = {"label": "接続先アプリ", "state": worst, "counts": counts,
                          "since": None, "uptime_24h": pct(ap1), "uptime_7d": pct(ap7),
                          "downs_24h": sum(d["downs_24h"] for d in per), "timeline": []}
    # 変化の一覧(新しい順)。継続時間は同じ対象で次に状態が変わるまで
    rows = []
    for k, evs in by.items():
        for i, e in enumerate(evs):
            end = ts(evs[i + 1]) if i + 1 < len(evs) else None
            r = {"ts": e["ts"], "target": e["target"] if e["target"] != "backend" else "backend",
                 "from": e.get("from", ""), "to": e["to"], "detail": e.get("detail", ""),
                 "duration_sec": int(((end or now) - ts(e)).total_seconds()), "ongoing": end is None}
            if k.startswith("backend:"):
                r["backend"] = k[8:]
                r["backend_name"] = names.get(k, "")
            rows.append(r)
    rows.sort(key=lambda r: r["ts"], reverse=True)
    return {"now": now.isoformat(timespec="seconds"), "window_hours": window_hours,
            "summary": summary, "backends": per, "events": rows[:2000], "total_events": len(rows)}


def _load_world():
    """同梱の世界地図パス(投影済みSVG)を読む。無ければ空"""
    p = os.path.join(BASE_DIR, "world_land.svg")
    try:
        with open(p, "r", encoding="utf-8") as f:
            return f.read()
    except OSError:
        return ""


WORLD_SVG = _load_world()


def _server_location(geo):
    """防御サーバ(自ホストの出口グローバルIP)の位置"""
    if geo is None:
        return None
    sip = geo.server_ip() if hasattr(geo, "server_ip") else geo.self_public_ip()
    if not sip:
        return None
    r = geo.lookup([sip]).get(sip)
    if r and r.get("lat") is not None:
        return {"ip": sip, "lat": r["lat"], "lon": r["lon"],
                "country": r.get("country"), "cc": r.get("cc")}
    return None


def _enrich_event(e, geo, server_loc):
    """イベントに送信元の緯度経度/国を付ける(リアルタイムマップ用)"""
    ip = e.get("client_ip", "")
    out = {
        "action": e.get("action", ""), "method": e.get("method", ""),
        "path": e.get("path", ""), "client_ip": ip,
        "conn_ip": e.get("conn_ip", ""), "ip_src": e.get("ip_src", ""),
        "ts": e.get("ts", ""), "status": e.get("status", ""),
        "disposition": e.get("disposition", ""),
        "count": e.get("count", 1),
        "backend": e.get("backend", ""), "backend_name": e.get("backend_name", ""),
        "rules": ",".join(sorted({h.get("id", "") for h in (e.get("hits") or [])})),
        "req": e.get("req"), "resp": e.get("resp"), "hits": e.get("hits") or [],
        **_enc_public(e),
    }
    loc = None
    if geo is not None and ip and GeoResolver.is_public(ip):
        r = geo.lookup([ip]).get(ip)
        if r and r.get("lat") is not None:
            loc = {"lat": r["lat"], "lon": r["lon"],
                   "country": r.get("country"), "cc": r.get("cc"),
                   "kind": "egress" if (server_loc and ip == server_loc["ip"]) else "external"}
    if loc is None and server_loc and getattr(geo, "egress", True) and not (ip and GeoResolver.is_public(ip)):
        # 非パブリック(内部/ローカル)は、出口である防御サーバの位置にまとめる
        # パブリックIPの位置が取れないだけなら、防御サーバの位置に置き換えない(VPN先のIPが日本に見えてしまう)
        loc = {"lat": server_loc["lat"], "lon": server_loc["lon"],
               "country": server_loc.get("country"), "cc": server_loc.get("cc"), "kind": "egress"}
    if loc:
        out.update(loc)
    return out


_SENS_HDR = {"cookie", "set-cookie", "authorization", "proxy-authorization", "x-api-key", "x-auth-token", "x-csrf-token"}
_SENS_KEY = re.compile(r"(pass(?:word|wd)?|pwd|token|secret|api[_-]?key|session(?:id)?|auth|credential|csrf)", re.I)
_SENS_PAIR = re.compile(r"((?:pass(?:word|wd)?|pwd|token|secret|api[_-]?key|session(?:id)?|auth|credential|csrf)[A-Za-z0-9_-]*[\"']?\s*[=:]\s*[\"']?)([^&\s\"',}]+)", re.I)


def _mask_text(v):
    return _SENS_PAIR.sub(lambda m: m.group(1) + "***", v) if isinstance(v, str) else v


def mask_event(e):
    """アナリスト向け: イベントから機微情報(Cookie・認証ヘッダー・パスワード/トークン等の値)を伏せた複製を返す"""
    if isinstance(e, list):
        return [mask_event(x) for x in e]
    if not isinstance(e, dict):
        return e
    out = {}
    for k, v in e.items():
        if k in ("headers",) and isinstance(v, dict):
            out[k] = {hk: ("***" if (hk.lower() in _SENS_HDR or _SENS_KEY.search(hk)) else _mask_text(hv)) for hk, hv in v.items()}
        elif isinstance(v, dict):
            out[k] = mask_event(v)
        elif isinstance(v, list):
            out[k] = [mask_event(x) if isinstance(x, (dict, list)) else _mask_text(x) for x in v]
        elif k in ("query", "body", "matched", "path"):
            out[k] = _mask_text(v)
        else:
            out[k] = v
    return out


def _ts_norm(v, end):
    """画面から来た日時(分まで)を秒まで補う。end はその分の :59 秒まで含める"""
    v = str(v or "").strip().replace(" ", "T")[:19]
    if len(v) == 16:
        v += ":59" if end else ":00"
    return v


def _enc_public(e):
    """イベントに含める暗号化の情報。暗号文は含めず、暗号化済みであることと鍵の指紋・識別子(eid)だけ"""
    en = e.get("enc")
    if isinstance(en, dict):
        return {"enc_locked": True, "kid": en.get("kid", ""), "eid": en.get("iv", ""), "enc_error": False}
    return {"enc_locked": False, "enc_error": bool(e.get("enc_error"))}


def _drop_enc(e):
    """書き出し用に暗号文を外す(eid だけ残す)"""
    if not isinstance(e, dict) or "enc" not in e:
        return e
    o = {k: v for k, v in e.items() if k != "enc"}
    en = e.get("enc")
    if isinstance(en, dict):
        o["eid"], o["kid"], o["enc_locked"] = en.get("iv", ""), en.get("kid", ""), True
    return o


class TLSThreadingHTTPServer(QuietThreadingHTTPServer):
    """管理画面をHTTPSで待ち受けるサーバー。TLSの握手は接続ごとのスレッドで行い、握手しない接続があっても待受が止まらない"""
    ssl_context = None
    is_tls = False

    def finish_request(self, request, client_address):
        if self.ssl_context is not None:
            request.settimeout(10)
            conn = self.ssl_context.wrap_socket(request, server_side=True, do_handshake_on_connect=False)
            conn.do_handshake()          # 失敗(平文HTTPで来た等)は例外になり、handle_error で静かに閉じる
            conn.settimeout(None)
            request = conn
        super().finish_request(request, client_address)

    def handle_error(self, request, client_address):
        import sys as _sys
        if isinstance(_sys.exc_info()[1], OSError):
            return                       # 握手の失敗・切断は静かに捨てる
        super().handle_error(request, client_address)

    def shutdown_request(self, request):
        try:
            super().shutdown_request(request)
        except Exception:
            pass


def make_handler(log_path, geo, control=None, source=None):
    # control: WAF設定の get()/set() を持つオブジェクト(統合時は waf.Runtime)。
    # None なら waf_config.json を直接読み書きする(単体起動。反映は再起動)
    if control is None:
        control = FileConfigControl(os.path.join(CONFIG_DIR, "waf_config.json"))

    # ログは前回の続きだけ読んで累計に足す。毎回は全読み込みしない
    store = EventStore(log_path, source=source)
    threading.Thread(target=store.refresh, kwargs={"force": True}, daemon=True).start()   # 起動直後に先読み
    stores = {None: store}           # 閲覧できるバックエンドの集合(frozenset) -> そのユーザー用の集計(None=全部=管理者)
    stores_lock = threading.Lock()
    _impact_cache = {}
    _scope_cache = {}                # username -> (取得時刻, frozenset)
    stats_cache = {}                 # map_period -> (取得時刻, json文字列)。複数タブや連続更新で計算を共有する
    log_gen = [0]                    # ログを削除するたびに増やす。SSE配信が追尾位置を取り直す合図
    stats_lock = threading.Lock()
    # 管理画面のパスワード認証(self_made_waf から取り込み)。未設定なら認証なし
    _pw_fn = getattr(control, "admin_password", None)
    auth = wx.AdminAuth(_pw_fn() if _pw_fn else "", users_fn=getattr(control, "users", None))

    def profiles_now():
        try:
            return (control.get().get("editable", {}).get("backend") or {}).get("profiles", [])
        except Exception:
            return []

    def removed_now():
        fn = getattr(control, "removed_backends", None)
        try:
            return fn() if fn else []
        except Exception:
            return []

    def org_ctx():
        """(組織の一覧, ユーザー一覧)。組織の範囲判定に使う"""
        fn = getattr(control, "org_context", None)
        try:
            return fn() if fn else ([], [])
        except Exception:
            return ([], [])

    def allowed_ids(user):
        """そのユーザーが見られるバックエンドID。管理者(提供元)は None で全部
        一般ユーザーは所属組織(と配下)のバックエンドと自分の登録分。アナリストは担当範囲の組織(と配下)だけ
        """
        if user is None or user.get("role") == "admin":
            return None
        name = user.get("username", "")
        ck = (name, user.get("role"), user.get("org") or "", tuple(user.get("scope") or ()), bool(user.get("provider")))
        hit = _scope_cache.get(ck)
        if hit and time.monotonic() - hit[0] < 1.5:
            return hit[1]
        orgs, users = org_ctx()
        res = waf_org.scope_backends(orgs, profiles_now(), user, users, removed_now())
        _scope_cache[ck] = (time.monotonic(), res)
        return res

    def store_for(key):
        if key is None:
            return store
        with stores_lock:
            st = stores.get(key)
            if st is None:
                if len(stores) > 12:                       # 古い集計を捨てる(管理者用は残す)
                    for k in [k for k in stores if k is not None][:4]:
                        stores.pop(k, None)
                st = stores[key] = EventStore(log_path, accept=(lambda e, k=key: (e.get("backend") or "") in k), source=source, webs=key)
        return st

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype):
            if isinstance(body, str):
                body = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _serve_health_log(self):
            name = "health_history.jsonl"
            try:
                fn = getattr(control, "health_history_file", None)
                if fn:
                    name = fn()
            except Exception:
                pass
            path = None
            if name:
                path = _dpath(name)
            be_ = None
            try:
                be_ = (control.get().get("editable") or {}).get("backend")
            except Exception:
                be_ = None
            profs = (be_ or {}).get("profiles") or []
            live_ = {}
            try:
                live_ = {b["id"]: b["state"] for b in self._overview_backends(be_)} if be_ else {}
            except Exception:
                live_ = {}
            events_ = read_health_events(path)
            mine_ = None
            if not self._is_admin():
                # 一般ユーザー・アナリストは範囲内のバックエンドの記録だけ。WAFプロセス/待受の記録や他人の分は含めない
                mine_ = self._my_backend_ids()
                events_ = [e for e in events_ if e.get("target") == "backend"]
            data = build_status_log(events_,
                                    backends=[{"id": p.get("id"), "name": p.get("name")} for p in profs
                                              if mine_ is None or p.get("id") in mine_],
                                    active_id=(be_ or {}).get("active") or (profs[0].get("id") if profs else None),
                                    live={k: v for k, v in live_.items() if mine_ is None or k in mine_})
            if mine_ is not None:
                data["summary"].pop("process", None)
                data["summary"].pop("waf", None)
                data["events"] = [dict(e, detail="") for e in data["events"] if e.get("backend") in mine_]
                data["total_events"] = len(data["events"])
                data["limited"] = True
            if "format=csv" in self.path:
                import csv, io
                buf = io.StringIO()
                buf.write("\ufeff")
                w = csv.writer(buf)
                w.writerow(["時刻", "対象", "変化前", "変化後", "続いた秒数", "継続中", "詳細"])
                names = dict(STATUS_TARGETS)
                for e in data["events"]:
                    w.writerow([e["ts"].replace("T", " "), e.get("backend_name") or names.get(e["target"], e["target"]),
                                STATUS_LABELS.get(e["from"], e["from"]), STATUS_LABELS.get(e["to"], e["to"]),
                                e["duration_sec"], "はい" if e["ongoing"] else "", e["detail"]])
                body = buf.getvalue().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/csv; charset=utf-8")
                self.send_header("Content-Disposition", 'attachment; filename="waf_status_log.csv"')
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self._json(200, data)

        def _json(self, code, obj):
            self._send(code, json.dumps(obj, ensure_ascii=False),
                       "application/json; charset=utf-8")

        # 認証
        def _redirect(self, loc, cookie=None):
            self.send_response(302)
            self.send_header("Location", loc)
            if cookie:
                self.send_header("Set-Cookie", cookie)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _auth_gate(self):
            """認証が必要で未ログインなら応答して True を返す(呼び出し側は処理を止める)"""
            route = urlparse(self.path).path
            if route == "/health":
                return False                     # 外部監視用は認証なし
            if route == "/login":
                if self.command == "POST":
                    try:
                        n = min(int(self.headers.get("Content-Length") or 0), 4096)
                    except ValueError:
                        n = 0
                    raw = self.rfile.read(n).decode("utf-8", "replace") if n else ""
                    form = parse_qs(raw)
                    pw = (form.get("password") or [""])[0]
                    un = (form.get("username") or [""])[0]
                    ck = auth.login(pw, un)
                    if ck:
                        if getattr(self.server, "is_tls", False):
                            ck += "; Secure"          # HTTPSのときは Cookie をHTTPSでだけ送る
                        self._redirect("/", ck)
                    else:
                        msg = "ユーザー名またはパスワードが違います" if auth.user_mode else "パスワードが違います"
                        self._send(401, wx.login_page(auth.user_mode, f'<div class="err">{msg}</div>'),
                                   "text/html; charset=utf-8")
                elif not auth.enabled or auth.authed(self.headers.get("Cookie")):
                    self._redirect("/")
                else:
                    self._send(200, wx.login_page(auth.user_mode), "text/html; charset=utf-8")
                return True
            if route == "/logout":
                auth.logout(self.headers.get("Cookie"))
                self._redirect("/login" if auth.enabled else "/", "waf_session=; Max-Age=0; Path=/")
                return True
            if self.command == "POST":
                self.close_connection = True     # 拒否時に本文が読み残されても、次の要求と混ざらないようにする
            self._user = auth.user(self.headers.get("Cookie"))
            if self._user is None:
                if route.startswith("/api/") or route.startswith("/assets/"):
                    self._json(401, {"error": "login required"})
                else:
                    self._redirect("/login")
                return True
            if self.command == "POST":
                # CSRF対策。別サイトからの POST は拒否する(Origin があればホストが一致すること)
                origin = self.headers.get("Origin")
                if origin and origin != "null" and urlparse(origin).netloc != (self.headers.get("Host") or ""):
                    self._json(403, {"error": "cross-origin request rejected"})
                    return True
            if self._user.get("role") == "key_officer":
                # キー・オフィサーに許すのは暗号ログの復号に必要なものだけ。設定・ログ・統計・ユーザー管理には触れない
                if not (route == "/" or route.startswith(("/api/auth", "/api/enc/", "/api/tickets", "/api/users"))):
                    self._json(403, {"error": "キー・オフィサーは暗号ログの復号だけを担当します(この操作の権限がありません)"})
                    return True
            return False

        _user = None

        def _is_admin(self):
            return (self._user or {}).get("role") == "admin"

        def _is_analyst(self):
            return (self._user or {}).get("role") == "analyst"

        def _masker(self):
            """アナリスト向けのマスク関数。組織が「マスクしない」にしているバックエンドのログは伏せない"""
            if not self._is_analyst():
                return lambda x: x
            orgs, users = org_ctx()
            nomask = {p.get("id") for p in profiles_now() if not waf_org.mask_for_analyst(orgs, p, users)}
            if not nomask:
                return mask_event

            def f(x):
                if isinstance(x, list):
                    return [f(i) for i in x]
                if isinstance(x, dict) and (x.get("backend") or "") in nomask:
                    return x
                return mask_event(x)
            return f

        def _org_has_analyst(self, org):
            """その組織を担当するアナリスト(提供元アナリスト含む)がいるか"""
            if not org:
                return False
            try:
                orgs, users = org_ctx()
                for u in users:
                    if u.get("role") == "analyst" and org in (waf_org.scope_orgs(orgs, u, users) or set()):
                        return True
            except Exception:
                pass
            return False

        def _org_has_officer(self, org):
            """その組織を担当するキー・オフィサー(ベンダー所属を含む)がいるか"""
            if not org:
                return False
            try:
                orgs, users = org_ctx()
                for u in users:
                    if u.get("role") == "key_officer" and org in (waf_org.scope_orgs(orgs, u, users) or set()):
                        return True
            except Exception:
                pass
            return False

        def _org_of_backend(self, bid):
            orgs, users = org_ctx()
            prof = next((p for p in profiles_now() if p.get("id") == bid), None)
            return waf_org.backend_org(prof, users) if prof else ""

        def _ticket_visible(self, t):
            if self._is_admin():
                return True
            me = (self._user or {}).get("username", "")
            if t.get("by") == me:
                return True
            if self._is_analyst():
                orgs, _u = org_ctx()
                so = waf_org.scope_orgs(orgs, self._user, _u) or set()
                return (t.get("org") in so) if t.get("org") else (t.get("backend") in self._my_backend_ids())
            if (self._user or {}).get("role") == "user" and t.get("kind") == "decrypt":
                return self._covers_org(t.get("org"))
            if self._is_officer() and t.get("kind") == "log_review":       # アナリストからのログ確認依頼は、担当範囲の組織のものだけ
                return self._covers_org(t.get("org"))
            return False

        def _analyst_guard(self, up, st=None):
            """アナリストの設定変更の検査。担当範囲内か、「使わない」は不可(申請が必要)、除外は申請に紐づく、全ルール除外(*)は期限つき。問題があれば文言を返す"""
            if not self._is_analyst():
                return ""
            bid = str(up.get("backend") or "")
            if bid not in self._my_backend_ids():
                return "担当範囲外のバックエンドは変更できません"
            if up.get("op") == "disable":
                return "ルールを使わない設定は管理者だけが行えます。「ルール変更の提案」として申請してください"
            if up.get("op") in ("enable", "block", "detect", "remove_exclusion", "set_preset", "undo"):
                return ""                      # 次の操作は申請なしでできる(変更は履歴に残る)。遮断と検知のみの切替、再び使う、除外を消す、プリセットの選択、直前の変更の取り消し
            if up.get("op") == "add_exclusion":
                if str(up.get("mode") or "") != "detect":
                    return "このパスでルールを使わない設定は管理者だけが行えます。「ルール変更の提案」として申請してください"
                if str(up.get("rule") or "").strip() == "*" and up.get("minutes") in (None, "", 0, "0"):
                    return "全ルール(*)のパス別設定は期限を指定してください"
                return ""                      # パス別の「検知のみ」は申請なしでできる
            return "この操作は管理者だけが行えます"

        def _undo_target(self, bid):
            """「1つ前に戻す」の対象。バックエンドの最新のルール設定変更で、取り消し自身や控えなしなら戻せない"""
            try:
                for e in control.rule_history(1000):
                    if e.get("kind") == "backend_rule" and e.get("backend") == bid:
                        if e.get("op") == "undo" or not isinstance(e.get("before"), dict):
                            return None
                        me = (self._user or {}).get("username", "")
                        if not self._is_admin() and e.get("by") != me:
                            return None            # アナリストが戻せるのは自分の変更だけ。管理者の変更は戻せない
                        return e
            except Exception:
                pass
            return None

        def _with_undo(self, rl):
            out = []
            for b in rl:
                t = self._undo_target(b.get("id"))
                b = dict(b)
                b["undo"] = ({"time": t.get("time"), "op": t.get("op"), "rule": t.get("rule"), "by": t.get("by")} if t else None)
                out.append(b)
            return out

        def _preset_info(self, p):
            c = wb.effective_counts(p)
            nm = (wb.PRESETS.get(p.get("rule_preset") or "") or {}).get("name") or "従来(全ルール遮断)"
            return {"name": nm, "id": p.get("rule_preset") or "", "diff": len(wb.preset_overrides(p)), "block": c["block"], "detect": c["detect"], "off": c["off"]}

        def _backend_events(self, bid, days, cap=20000):
            """そのバックエンドの、ヒットのある直近のログ(新しい順に cap 件まで)"""
            lo = (datetime.date.today() - datetime.timedelta(days=days)).isoformat()
            out = []
            try:
                if source is not None:
                    it = source.read_backend(bid, lo=lo)
                else:
                    def _f():
                        with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
                            for ln in fh:
                                try:
                                    e = json.loads(ln)
                                except ValueError:
                                    continue
                                if isinstance(e, dict) and (e.get("backend") or "") == bid and str(e.get("ts") or "")[:10] >= lo:
                                    yield e
                    it = _f()
                for e in it:
                    out.append(e)
                    if len(out) > cap * 5:
                        out = out[-cap * 3:]
            except OSError:
                pass
            return out

        def _is_staff(self):
            """管理者またはアナリスト(提供側)。全バックエンドを閲覧できる"""
            return (self._user or {}).get("role") in ("admin", "analyst")

        def _staff_config(self, cfg):
            """アナリスト向けの設定。閲覧に必要な部分だけで、通知先・SMTP・webhook・ユーザー等は含めない"""
            ed = dict(cfg.get("editable") or {})
            ed.pop("extra", None)
            ro = {k: v for k, v in (cfg.get("readonly") or {}).items() if k not in ("webhook",)}
            be = dict(ed.get("backend") or {})
            mine_ = self._my_backend_ids()
            be["profiles"] = [dict({k: v for k, v in p.items() if k not in ("exclusions", "rule_disabled", "rule_detect", "rule_block")}, preset_info=self._preset_info(p))
                              for p in be.get("profiles", []) if p.get("id") in mine_]
            ed["backend"] = be
            try:
                orgs_, _u = org_ctx()
                so_ = waf_org.scope_orgs(orgs_, self._user, _u) or set()
                sco = [{"id": o["id"], "name": o.get("name") or o["id"]} for o in orgs_ if o.get("id") in so_]
            except Exception:
                sco = []
            return {"analyst": True, "scope_orgs": sco, "user": self._user, "editable": ed, "readonly": ro,
                    "hot_reload": cfg.get("hot_reload"), "note": cfg.get("note", "")}

        def _rule_orgs(self):
            """バックエンド別ルールの選択用。見える組織(管理者は全部、アナリストは担当範囲と配下)"""
            try:
                orgs_, _u = org_ctx()
                so_ = waf_org.scope_orgs(orgs_, self._user, _u)
                return [{"id": o["id"], "name": o.get("name") or o["id"], "type": o.get("type"), "parent": o.get("parent") or ""}
                        for o in orgs_ if so_ is None or o.get("id") in so_]
            except Exception:
                return []

        def _need_admin(self):
            """管理者以外なら 403 を返して True"""
            if self._is_admin():
                return False
            self._json(403, {"error": "管理者だけが使える機能です"})
            return True

        # 暗号化ログ(キー・オフィサー)
        def _is_officer(self):
            return (self._user or {}).get("role") == "key_officer"

        def _enc_ready(self):
            if not (hasattr(control, "enc_state") and hasattr(control, "enc_apply")):
                self._json(400, {"ok": False, "error": "暗号化の設定は統合起動(python waf.py)でだけ使えます"})
                return False
            return True

        def _enc_can_manage(self):
            """鍵・暗号化のON/OFFを変えられるのはキー・オフィサー。1人もいない間だけ管理者(初期設定用)"""
            return self._is_officer() or (self._is_admin() and not control.enc_state().get("officers"))

        def _enc_audit(self, action, **kw):
            try:
                waf_crypt.audit_append(control.enc_audit_path(), dict({"user": (self._user or {}).get("username", ""),
                                                                      "role": (self._user or {}).get("role", ""), "action": action}, **kw))
            except Exception:
                pass

        def _covers_org(self, org):
            """一般ユーザー: その組織(上位組織を含む)の担当者か"""
            if not org:
                return False
            try:
                orgs_, users_ = org_ctx()
                return org in (waf_org.scope_orgs(orgs_, self._user, users_) or set())
            except Exception:
                return False

        def _can_approve_decrypt(self, t):
            """復号申請を承認できるのは、その組織側の一般ユーザーと組織側のアナリスト(ベンダー所属は除く)。どちらもいなければ管理者"""
            if t.get("kind") != "decrypt" or t.get("status") not in ("open", "in_progress", "escalated"):
                return False
            me = (self._user or {}).get("username", "")
            if me == t.get("by"):
                return False
            role = (self._user or {}).get("role")
            if role == "user":
                return self._covers_org(t.get("org"))
            if role == "analyst":
                return (not waf_org.is_vendor_user(self._user)) and self._covers_org(t.get("org"))
            if role == "admin":
                orgs_, users_ = org_ctx()
                for u in users_:
                    if (u.get("role") == "user" or (u.get("role") == "analyst" and not waf_org.is_vendor_user(u))) \
                            and t.get("org") in (waf_org.scope_orgs(orgs_, u, users_) or set()):
                        return False
                return True
            return False

        def _grant_for(self, bid, ts):
            """このキー・オフィサーが、バックエンド bid の時刻 ts のログを復号してよい承認済みの申請(期限内)。なければ None"""
            me = (self._user or {}).get("username", "")
            now = datetime.datetime.now().isoformat(timespec="seconds")
            ts = str(ts or "")[:19].replace(" ", "T")
            for t in control.ticket_store().list(me):
                g = t.get("grant") or {}
                if (t.get("kind") == "decrypt" and t.get("status") == "done" and t.get("backend") == bid and g.get("approved_by")
                        and g.get("from", "") <= ts <= g.get("to", "") and str(g.get("until") or "") > now):
                    return t
            return None

        def _enc_overview(self):
            st_ = control.enc_state()
            orgs_, users_ = org_ctx()
            so_ = waf_org.scope_orgs(orgs_, self._user, users_)
            can_ = self._enc_can_manage()
            key_at = {}
            try:
                for r_ in reversed(waf_crypt.audit_read(control.enc_audit_path(), 100000)[0]):       # 古い順に見るので、最後の登録が残る
                    if r_.get("action") == "key_set" and r_.get("org"):
                        key_at[r_["org"]] = (r_.get("kid") or "", str(r_.get("ts") or ""))
            except Exception:
                key_at = {}
            rows = [{"id": o.get("id"), "name": o.get("name") or o.get("id"), "parent": o.get("parent") or "",
                     "kid": (st_.get("org_kids") or {}).get(o.get("id"), ""),
                     "key_at": ((key_at.get(o.get("id")) or ("", ""))[1] if (key_at.get(o.get("id")) or ("",))[0] == (st_.get("org_kids") or {}).get(o.get("id"), "") else ""),
                     "editable": bool(can_ and (so_ is None or o.get("id") in so_))}
                    for o in orgs_ if isinstance(o, dict) and o.get("id") and (so_ is None or o.get("id") in so_)]
            me = (self._user or {}).get("username", "")
            tks = [t for t in control.ticket_store().list(me) if t.get("kind") == "decrypt"] if self._is_officer() else []
            return {"enabled": st_.get("enabled"), "officers": st_.get("officers"), "available": st_.get("available"),
                    "default_kid": st_.get("default_kid"), "demo_keys": bool(st_.get("demo_keys")), "idle_max": st_.get("idle_max", 60), "hold_max": st_.get("hold_max", 120), "orgs": rows, "can_manage": can_, "is_officer": self._is_officer(),
                    "tickets": tks[:50],
                    "reviews": ([t for t in control.ticket_store().list(None) if t.get("kind") == "log_review" and self._ticket_visible(t)][:50] if self._is_officer() else []),
                    "backends": [{"id": x.get("id"), "name": x.get("name") or x.get("id"), "org": waf_org.backend_org(x, users_)}
                                 for x in profiles_now() if x.get("id") in self._my_backend_ids()] if self._is_officer() else []}

        def _enc_select(self, g1, force_granted=False):
            """条件(平文の項目だけ)に合う暗号化ログを [(行, イベント)] で返す。g1(キー, 既定値) で条件を取り出す"""
            mine = self._my_backend_ids()
            bsel = g1("backend")
            ids = [bsel] if bsel else sorted(mine)
            ids = [x for x in ids if x in mine]
            osel = g1("org")
            if osel and not bsel:            # 組織で絞る(配下の組織の接続先を含む)
                orgs_, users_ = org_ctx()
                in_org = waf_org.closure(orgs_, [osel])
                ids = [x.get("id") for x in profiles_now() if x.get("id") in ids and waf_org.backend_org(x, users_) in in_org]
            try:
                days = max(1, min(93, int(g1("days", "7"))))
            except ValueError:
                days = 7
            f_method, f_action, f_status = g1("method").upper(), g1("action").upper(), g1("status")
            f_ip, f_path = g1("ip").lower(), g1("path").lower()
            f_from, f_to = _ts_norm(g1("from"), False), _ts_norm(g1("to"), True)
            if f_from:                    # 期間指定のときはその日付まで遡って読む
                try:
                    days = max(days, min(400, (datetime.date.today() - datetime.date.fromisoformat(f_from[:10])).days + 1))
                except ValueError:
                    f_from = ""
            only_granted = force_granted or g1("granted") == "1"
            sort = g1("sort", "ts")
            if sort not in ("ts", "backend_name", "method", "path", "client_ip", "action", "status"):
                sort = "ts"
            rev = g1("dir", "desc") != "asc"
            names = {x.get("id"): (x.get("name") or x.get("id")) for x in profiles_now()}
            rows = []
            for bid in ids:
                for e in self._backend_events(bid, days, cap=100000):
                    en = e.get("enc")
                    if not isinstance(en, dict):
                        continue
                    if f_method and str(e.get("method", "")).upper() != f_method:
                        continue
                    if f_action and str(e.get("action", "")).upper() != f_action:
                        continue
                    if f_status and str(e.get("status", "")) != f_status:
                        continue
                    if f_ip and f_ip not in str(e.get("client_ip", "")).lower():
                        continue
                    if f_path and f_path not in str(e.get("path", "")).lower():
                        continue
                    ts_e = str(e.get("ts", ""))[:19].replace(" ", "T")
                    if (f_from and ts_e < f_from) or (f_to and ts_e > f_to):
                        continue
                    gr = self._grant_for(bid, e.get("ts"))
                    if only_granted and not gr:
                        continue
                    rows.append(({"eid": en.get("iv", ""), "ts": e.get("ts", ""), "backend": bid, "backend_name": names.get(bid, bid),
                                  "method": e.get("method", ""), "path": e.get("path", ""), "client_ip": e.get("client_ip", ""),
                                  "action": e.get("action", ""), "status": e.get("status", ""), "kid": en.get("kid", ""),
                                  "granted": bool(gr), "ticket": (gr or {}).get("id", "")}, e))
            rows.sort(key=lambda r: (str(r[0].get(sort, "")), r[0]["ts"]), reverse=rev)
            return rows

        def _enc_count_range(self, bid, frm, to):
            """バックエンド bid の期間 [frm, to] にある暗号化ログの件数(承認の判断材料)"""
            frm, to = _ts_norm(frm, False), _ts_norm(to, True)
            try:
                days = max(1, min(400, (datetime.date.today() - datetime.date.fromisoformat(frm[:10])).days + 1))
            except ValueError:
                return 0
            n = 0
            for e in self._backend_events(bid, days, cap=100000):
                if isinstance(e.get("enc"), dict) and frm <= str(e.get("ts", ""))[:19].replace(" ", "T") <= to:
                    n += 1
            return n

        def _enc_events(self):
            """暗号化ログの一覧。絞り込み・並べ替え・ページ分けはサーバー側で行い、絞り込みは平文の項目だけ(復号は不要)"""
            q = parse_qs(urlparse(self.path).query)
            g1 = lambda k, d="": (q.get(k, [d])[0] or d).strip()
            try:
                per = max(10, min(200, int(g1("per", "50"))))
                page = max(1, int(g1("page", "1")))
            except ValueError:
                per, page = 50, 1
            rows = [r for r, _ in self._enc_select(g1)]
            total = len(rows)
            pages = max(1, (total + per - 1) // per)
            page = min(page, pages)
            return {"events": rows[(page - 1) * per: page * per], "total": total, "page": page, "pages": pages, "per": per,
                    "granted": sum(1 for r in rows if r["granted"])}

        def _enc_post(self, p):
            """暗号ログの操作。キー・オフィサーの申請・復号・鍵管理と、組織側の承認"""
            up = self._read_json() or {}
            if not self._enc_ready():
                return
            me = (self._user or {}).get("username", "") or "admin"
            try:
                if p == "/api/enc/config":
                    if not self._enc_can_manage():
                        self._enc_audit("denied", detail="設定の変更(権限なし)")
                        return self._json(403, {"ok": False, "error": "暗号化の設定は、キー・オフィサーだけが変更できます"})
                    orgs_, users_ = org_ctx()
                    so_ = waf_org.scope_orgs(orgs_, self._user, users_)
                    ok_ = up.get("org_keys") if isinstance(up.get("org_keys"), dict) else {}
                    if so_ is not None and any(o not in so_ for o in ok_):
                        return self._json(403, {"ok": False, "error": "担当範囲の外の組織の鍵は変更できません"})
                    before = control.enc_state()
                    inp = {k: up[k] for k in ("enabled", "org_keys") if k in up}
                    after = control.enc_apply(inp)
                    for o, pem in ok_.items():
                        self._enc_audit("key_set" if pem else "key_remove", org=o, kid=(after.get("org_kids") or {}).get(o, ""),
                                        old_kid=(before.get("org_kids") or {}).get(o, ""))
                    if "enabled" in up and bool(up["enabled"]) != bool(before.get("enabled")):
                        self._enc_audit("enable" if up["enabled"] else "disable")
                    return self._json(200, {"ok": True, "state": after})
                if p == "/api/enc/request":
                    if not self._is_officer():
                        return self._json(403, {"ok": False, "error": "復号の申請はキー・オフィサーだけができます"})
                    bid = str(up.get("backend") or "")
                    if bid not in self._my_backend_ids():
                        return self._json(403, {"ok": False, "error": "担当範囲のバックエンドだけ申請できます"})
                    reason = str(up.get("reason") or "").strip()
                    if len(reason) < 5:
                        return self._json(400, {"ok": False, "error": "復号が必要な理由を入力してください(5文字以上)"})
                    org_ = self._org_of_backend(bid)
                    t = control.ticket_store().create(me, "decrypt", bid, str(up.get("subject") or "暗号化ログの復号の申請"), reason, None,
                                                      role="key_officer", org=org_, stage="admin",
                                                      grant={"from": up.get("from"), "to": up.get("to")})
                    m_ = re.search(r"【ログ確認依頼 (T-\d+)】", reason)       # 「この依頼で復号を申請する」から来た申請は、元の確認依頼を自動で「対応中」にする
                    if m_:
                        r_ = control.ticket_store().get(m_.group(1))
                        if r_ and r_.get("kind") == "log_review" and self._ticket_visible(r_):
                            control.ticket_store().link_review(t["id"], r_["id"], me)
                    self._enc_audit("request", ticket=t["id"], backend=bid, org=org_, detail=f"{t['grant']['from']} 〜 {t['grant']['to']}")
                    return self._json(200, {"ok": True, "ticket": t})
                if p == "/api/enc/approve":
                    st = control.ticket_store()
                    t = st.get(str(up.get("id") or ""))
                    if t is None or t.get("kind") != "decrypt":
                        return self._json(404, {"ok": False, "error": "復号の申請が見つかりません"})
                    if not self._can_approve_decrypt(t):
                        self._enc_audit("denied", ticket=t.get("id"), detail="承認(権限なし)")
                        return self._json(403, {"ok": False, "error": "この申請を承認できるのは、その組織側の担当者(一般ユーザー・アナリスト)です"})
                    ok = bool(up.get("approve"))
                    t = st.decide_grant(t["id"], me, ok, up.get("hours") or 24, str(up.get("comment") or ""), role=(self._user or {}).get("role") or "user")
                    self._enc_audit("grant" if ok else "grant_reject", ticket=t["id"], backend=t.get("backend"), org=t.get("org"),
                                    detail=("until " + str((t.get("grant") or {}).get("until", ""))) if ok else "")
                    return self._json(200, {"ok": True, "ticket": t})
                if p == "/api/enc/fetch":
                    if not self._is_officer():
                        return self._json(403, {"ok": False, "error": "復号できるのはキー・オフィサーだけです"})
                    bid, eid = str(up.get("backend") or ""), str(up.get("eid") or "")
                    if bid not in self._my_backend_ids():
                        return self._json(403, {"ok": False, "error": "担当範囲のバックエンドではありません"})
                    ev = next((e for e in self._backend_events(bid, 400, cap=100000)
                               if isinstance(e.get("enc"), dict) and e["enc"].get("iv") == eid), None)
                    if ev is None:
                        return self._json(404, {"ok": False, "error": "ログが見つかりません"})
                    g = self._grant_for(bid, ev.get("ts"))
                    if g is None:
                        self._enc_audit("denied", eid=eid, backend=bid, detail="復号(承認なし)")
                        return self._json(403, {"ok": False, "error": "このログは、承認された申請の期間・期限の外です(復号を申請して、組織側の承認を受けてください)"})
                    self._enc_audit("decrypt", eid=eid, backend=bid, org=g.get("org"), ticket=g.get("id"))
                    meta = {k: ev.get(k) for k in ("ts", "action", "method", "path", "status", "hits", "client_ip", "conn_ip", "ip_src",
                                                   "backend", "backend_name", "disposition", "count") if k in ev}
                    meta["ip"] = ev.get("client_ip", "")
                    return self._json(200, {"ok": True, "enc": ev["enc"], "meta": meta, "ticket": g.get("id")})
                if p == "/api/enc/unmask_log":
                    if not self._is_officer():
                        return self._json(403, {"ok": False, "error": "キー・オフィサーだけが使えます"})
                    act = "unmask" if str(up.get("action")) == "unmask" else "mask"
                    self._enc_audit(act, detail=("復号結果のマスクを外した(表示中 %d件)" % int(up.get("count") or 0)) if act == "unmask" else "マスクをかけ直した")
                    return self._json(200, {"ok": True})
                if p == "/api/enc/fetch_many":
                    if not self._is_officer():
                        return self._json(403, {"ok": False, "error": "復号できるのはキー・オフィサーだけです"})
                    g1 = lambda k, d="": str(up.get(k) if up.get(k) not in (None, False) else d).strip()
                    lim = 500
                    sel = self._enc_select(g1, force_granted=True)          # 承認済み(期間内・期限内)のログだけ
                    out = []
                    tks = {}
                    for r_, e_ in sel[:lim]:
                        meta = {k: e_.get(k) for k in ("ts", "action", "method", "path", "status", "hits", "client_ip", "conn_ip", "ip_src",
                                                       "backend", "backend_name", "disposition", "count") if k in e_}
                        meta["ip"] = e_.get("client_ip", "")
                        out.append({"meta": meta, "enc": e_["enc"], "eid": r_["eid"], "ticket": r_["ticket"]})
                        tks[r_["ticket"]] = tks.get(r_["ticket"], 0) + 1
                    if out:
                        self._enc_audit("decrypt", ticket=",".join(sorted(tks)), backend=g1("backend") or "(担当の全接続先)",
                                        detail="まとめて復号 %d件(条件: %s)" % (len(out), " ".join("%s=%s" % (k, up[k]) for k in ("days", "method", "action", "ip", "path", "status") if up.get(k))))
                    else:
                        self._enc_audit("denied", detail="まとめて復号(承認済みのログなし)")
                    return self._json(200, {"ok": True, "items": out, "total": len(sel), "truncated": len(sel) > lim})
                return self._json(404, {"ok": False, "error": "not found"})
            except ValueError as e:
                self._json(400, {"ok": False, "error": str(e)})
            except Exception as e:
                self._json(500, {"ok": False, "error": str(e)})

        def _tickets_post(self, p):
            """チケットの作成・コメント・状態変更(承認すると除外を入れる)"""
            up = self._read_json() or {}
            me = (self._user or {}).get("username", "") or "admin"
            role = (self._user or {}).get("role", "admin")
            st = control.ticket_store()
            mine = self._my_backend_ids()
            try:
                if p.rstrip("/") == "/api/tickets":
                    kind = str(up.get("kind") or "")
                    backend = str(up.get("backend") or "")
                    if kind == "decrypt":
                        return self._json(403, {"ok": False, "error": "復号の申請は、キー・オフィサーが暗号ログの画面から行います"})
                    if role == "admin":
                        return self._json(403, {"ok": False, "error": "管理者は申請を出せません(申請を受けて対応する側です。設定はルール・設定の画面で直接変更できます)"})
                    if role == "user":
                        if kind not in ("false_positive", "inquiry", "mode_unlock"):
                            return self._json(403, {"ok": False, "error": "この種類の申請はできません"})
                        if backend and backend not in mine:
                            return self._json(403, {"ok": False, "error": "自分のバックエンドの申請だけできます"})
                        if kind in ("false_positive", "mode_unlock") and not backend:
                            return self._json(400, {"ok": False, "error": "接続先を指定してください"})
                    elif role == "key_officer":
                        if kind != "inquiry":
                            return self._json(403, {"ok": False, "error": "この種類の申請はできません(復号の申請は暗号ログの画面から)"})
                        if backend and backend not in mine:
                            return self._json(403, {"ok": False, "error": "担当範囲のバックエンドの申請だけできます"})
                    elif role == "analyst":
                        if kind not in ("rule_proposal", "inquiry", "false_positive", "log_review"):
                            return self._json(403, {"ok": False, "error": "この種類の申請はできません"})
                        if backend and backend not in mine:
                            return self._json(403, {"ok": False, "error": "担当範囲のバックエンドの申請だけできます"})
                    org_ = self._org_of_backend(backend) if backend else str((self._user or {}).get("org") or "")
                    if kind == "log_review":
                        if not backend:
                            return self._json(400, {"ok": False, "error": "確認してほしいログの接続先を指定してください"})
                        if not self._org_has_officer(org_):
                            return self._json(400, {"ok": False, "error": "この組織を担当するキー・オフィサーがいません(管理者に確認してください)"})
                    prop_ = up.get("proposal") if (role == "analyst" and kind == "rule_proposal") else None   # {op: disable|exclude, rule, ...}
                    if prop_ and not backend:
                        return self._json(400, {"ok": False, "error": "接続先を指定してください"})
                    # 一次対応。申請者が一般ユーザーで、その組織に担当アナリスト(提供元アナリスト含む)がいればアナリストへ。
                    # いない場合やアナリスト自身の申請は管理者へ
                    stage_ = "ko" if kind == "log_review" else ("analyst" if (role == "user" and self._org_has_analyst(org_)) else "admin")
                    t = st.create(me, kind, backend, up.get("subject"), up.get("body"), up.get("evidence"), role=role, org=org_, proposal=prop_, stage=stage_)
                    return self._json(200, {"ok": True, "ticket": t})
                t = st.get(str(up.get("id") or ""))
                if t is None:
                    return self._json(404, {"ok": False, "error": "申請が見つかりません"})
                if not self._ticket_visible(t):
                    return self._json(403, {"ok": False, "error": "この申請は操作できません"})
                if p.endswith("/comment"):
                    if role == "user" and t.get("by") != me:
                        return self._json(403, {"ok": False, "error": "自分の申請だけコメントできます"})
                    return self._json(200, {"ok": True, "ticket": st.comment(t["id"], me, up.get("text"), role=role)})
                if p.endswith("/escalate"):
                    if t.get("kind") == "log_review":
                        return self._json(403, {"ok": False, "error": "ログの確認依頼は、キー・オフィサーが対応します"})
                    if role != "analyst":
                        return self._json(403, {"ok": False, "error": "管理者への依頼はアナリストだけができます"})
                    return self._json(200, {"ok": True, "ticket": st.escalate(t["id"], me, up.get("reason"))})
                if p.endswith("/to_ko"):
                    if role != "analyst":
                        return self._json(403, {"ok": False, "error": "キー・オフィサーへの依頼はアナリストだけができます"})
                    if t.get("kind") in ("log_review", "decrypt"):
                        return self._json(400, {"ok": False, "error": "この種類の申請からは依頼できません"})
                    if t.get("status") in ("done", "rejected"):
                        return self._json(400, {"ok": False, "error": "対応が終わった申請からは依頼できません"})
                    reason_ = str(up.get("reason") or "").strip()
                    if not reason_:
                        return self._json(400, {"ok": False, "error": "依頼する理由を入力してください"})
                    bid_ = t.get("backend") or ""
                    if not bid_ or bid_ not in self._my_backend_ids():
                        return self._json(400, {"ok": False, "error": "接続先のある、担当範囲の申請だけ依頼できます"})
                    org_ = self._org_of_backend(bid_)
                    if not self._org_has_officer(org_):
                        return self._json(400, {"ok": False, "error": "この組織を担当するキー・オフィサーがいません(管理者に確認してください)"})
                    nt_ = st.create(me, "log_review", bid_, "【" + t["id"] + "】" + str(t.get("subject") or ""),
                                    reason_ + "\n\n(元の申請 " + t["id"] + ": " + waf_tickets.KINDS.get(t.get("kind"), "") + " / 申請者 " + str(t.get("by") or "") + ")",
                                    t.get("evidence"), role=role, org=org_, stage="ko")
                    st.comment(t["id"], me, "キー・オフィサーへ確認を依頼しました(" + nt_["id"] + ")", role=role)
                    return self._json(200, {"ok": True, "ticket": nt_})
                if p.endswith("/status"):
                    if t.get("kind") == "log_review":
                        if role != "key_officer":
                            return self._json(403, {"ok": False, "error": "ログの確認依頼は、キー・オフィサーが対応します(状態の変更もキー・オフィサーだけです)"})
                        if str(up.get("status") or "") not in ("in_progress", "done", "rejected"):
                            return self._json(400, {"ok": False, "error": "状態の指定が正しくありません"})
                        return self._json(200, {"ok": True, "ticket": st.set_status(t["id"], str(up.get("status")), me, str(up.get("resolution") or ""), role=role)})
                    if t.get("kind") == "decrypt":
                        return self._json(403, {"ok": False, "error": "復号の申請は、組織側の承認者が承認・却下します(「承認」「却下」ボタン)"})
                    if role not in ("admin", "analyst"):
                        return self._json(403, {"ok": False, "error": "管理者・アナリストだけが使える機能です"})
                    if role == "analyst" and t.get("status") == "escalated":
                        return self._json(403, {"ok": False, "error": "管理者へ依頼中のため、状態は管理者が変更します(コメントは書けます)"})
                    ap = up.get("approve")
                    res = str(up.get("resolution") or "")
                    if isinstance(ap, dict) and (ap.get("disable") or ap.get("apply")):
                        if role != "admin":
                            return self._json(403, {"ok": False, "error": "「使わない」設定の提案は管理者だけが承認できます"})
                        pr_ = t.get("proposal") or {}
                        bid = str(t.get("backend") or "")
                        if pr_.get("op") not in ("disable", "exclude") or not bid:
                            return self._json(400, {"ok": False, "error": "この申請には、承認できる提案が含まれていません"})
                        rsn_ = f"{t['id']} {t.get('subject','')}"[:200]
                        if pr_.get("op") == "disable":
                            control.be_rules({"backend": bid, "op": "disable", "rule": pr_.get("rule"), "ticket": t["id"], "reason": rsn_}, me)
                            res = res or f"このバックエンドでルール {pr_.get('rule')} を使わない設定にしました"
                        else:
                            control.be_rules({"backend": bid, "op": "add_exclusion", "mode": "off", "rule": pr_.get("rule"),
                                              "path_prefix": pr_.get("path_prefix"), "minutes": pr_.get("minutes"),
                                              "ticket": t["id"], "reason": rsn_}, me)
                            res = res or f"パス {pr_.get('path_prefix')} でルール {pr_.get('rule')} を使わない設定にしました"
                        up["status"] = "done"
                    elif isinstance(ap, dict):
                        bid = str(ap.get("backend") or t.get("backend") or "")
                        mode_ = "detect" if ap.get("mode") == "detect" else "off"
                        bad_ = self._analyst_guard({"backend": bid, "ticket": t["id"], "op": "add_exclusion", "mode": mode_,
                                                    "rule": ap.get("rule"), "minutes": ap.get("minutes")}, st)
                        if bad_:
                            return self._json(403, {"ok": False, "error": bad_})
                        control.be_rules({"backend": bid, "op": "add_exclusion", "rule": ap.get("rule"), "mode": mode_,
                                          "path_prefix": ap.get("path_prefix"), "minutes": ap.get("minutes"),
                                          "reason": f"{t['id']} {t.get('subject','')}"[:200], "ticket": t["id"]}, me)
                        res = res or f"{'検知のみ' if mode_ == 'detect' else '使わない'}のパス別設定を追加: {ap.get('rule')} @ {ap.get('path_prefix') or '全パス'}"
                        up["status"] = "done"
                    return self._json(200, {"ok": True, "ticket": st.set_status(t["id"], str(up.get("status") or ""), me, res, role=role)})
                return self._json(404, {"ok": False, "error": "not found"})
            except ValueError as e:
                self._json(400, {"ok": False, "error": str(e)})
            except Exception as e:
                self._json(500, {"ok": False, "error": str(e)})

        def _limited_security(self, sec):
            """一般ユーザー・アナリスト向け。範囲内のバックエンドとそのIP/国の制限・防御モードだけ(共通のBAN・ブロック等は含めない)"""
            mine = self._my_backend_ids()
            out = {"limited": True,
                   "backends": [b for b in (sec.get("backends") or []) if b.get("id") in mine],
                   "backend_policies": {k: v for k, v in (sec.get("backend_policies") or {}).items() if k in mine}}
            # BAN中の状況はアナリスト・一般ユーザーも見られる。解除と追加は管理者だけ
            out["bans"] = [{"ip": b.get("ip"), "expires_in": b.get("expires_in"), "reason": b.get("reason")}
                           for b in (sec.get("bans") or [])]
            if self._is_analyst():
                out["global_mode"] = sec.get("global_mode")
                out["mode_history"] = [e for e in (sec.get("mode_history") or []) if e.get("backend") in mine]
            return out

        def _my_backend_ids(self):
            """このユーザーの範囲のバックエンドID(管理者は全部)"""
            a = allowed_ids(self._user)
            return {x.get("id") for x in profiles_now()} if a is None else set(a)

        def _limited_health(self, h):
            """一般ユーザー向けの稼働情報。自分のバックエンドの状態・応答時間と、WAF全体の稼働(一行)だけ
            詳細文言・内部の負荷・構成は含めない
            """
            if not h:
                return None
            mine = self._my_backend_ids()
            bl = [{"id": b.get("id"), "name": b.get("name"), "state": b.get("state"),
                   "latency_ms": b.get("latency_ms"), "since": b.get("since"), "last_ok": b.get("last_ok"),
                   "samples": b.get("samples") or []}
                  for b in (h.get("backends") or []) if b.get("id") in mine]
            waf = ((h.get("targets") or {}).get("waf") or {}).get("state", "unknown")
            return {"limited": True, "interval": h.get("interval"), "slow_ms": h.get("slow_ms"),
                    "backends": bl, "waf": {"state": waf}}

        def _key(self):
            return allowed_ids(self._user)

        def _store(self):
            return store_for(self._key())

        def _limited_config(self, cfg):
            """管理者以外には、所属組織の範囲のバックエンド設定だけを返す"""
            be = (cfg.get("editable") or {}).get("backend") or {}
            allowed = self._my_backend_ids() or set()
            mine = [dict({k: v for k, v in p.items() if k not in ("exclusions", "rule_disabled", "rule_detect", "rule_block", "preset_allowed")}, preset_info=self._preset_info(p))
                    for p in be.get("profiles", []) if p.get("id") in allowed]
            return {"limited": True, "user": self._user,
                    "editable": {"alert": (cfg.get("editable") or {}).get("alert"),
                                 "backend": {"profiles": mine, "active": be.get("active"),
                                             "host_routing": be.get("host_routing"),
                                             "rewrite_links": be.get("rewrite_links")}},
                    "readonly": cfg.get("readonly", {}), "hot_reload": cfg.get("hot_reload"),
                    "note": cfg.get("note", "")}

        def do_GET(self):
            if self._auth_gate():
                return
            if self.path.split("?")[0] == "/api/countries":
                return self._json(200, {"countries": wx.country_list()})
            if self.path.split("?")[0] == "/api/auth":
                return self._json(200, {"enabled": auth.enabled, "user_mode": auth.user_mode, "user": self._user})
            if self.path.split("?")[0] == "/api/scope":
                # 画面の「組織 → バックエンド」選択用。見られる範囲の組織(親子関係つき)とバックエンド(所属組織つき)だけ返す
                orgs_, users_ = org_ctx()
                so_ = waf_org.scope_orgs(orgs_, self._user, users_)
                mine_ = self._my_backend_ids()
                ol_ = [{"id": o.get("id"), "name": o.get("name") or o.get("id"),
                        "parent": (o.get("parent") if (so_ is None or o.get("parent") in so_) else "") or ""}
                       for o in orgs_ if isinstance(o, dict) and o.get("id") and (so_ is None or o.get("id") in so_)]
                bl_ = [{"id": x.get("id"), "name": x.get("name") or x.get("id"), "org": waf_org.backend_org(x, users_)}
                       for x in profiles_now() if x.get("id") in mine_]
                return self._json(200, {"orgs": ol_, "backends": bl_, "all_scope": so_ is None})
            if self.path.split("?")[0] == "/api/enc/overview":
                if not (self._is_officer() or self._is_admin()):
                    return self._json(403, {"error": "管理者またはキー・オフィサーだけが使える機能です"})
                if not self._enc_ready():
                    return
                return self._json(200, self._enc_overview())
            if self.path.split("?")[0] == "/api/enc/count":
                if not self._is_officer():
                    return self._json(403, {"error": "キー・オフィサーだけが使える機能です"})
                q_ = parse_qs(urlparse(self.path).query)
                bid_ = (q_.get("backend", [""])[0] or "").strip()
                if bid_ not in self._my_backend_ids():
                    return self._json(403, {"error": "担当範囲のバックエンドではありません"})
                return self._json(200, {"count": self._enc_count_range(bid_, (q_.get("from", [""])[0] or ""), (q_.get("to", [""])[0] or ""))})
            if self.path.split("?")[0] == "/api/enc/events":
                if not self._is_officer():
                    return self._json(403, {"error": "キー・オフィサーだけが使える機能です"})
                return self._json(200, self._enc_events())
            if self.path.split("?")[0] == "/api/enc/audit":
                if not (self._is_officer() or self._is_admin()):
                    return self._json(403, {"error": "管理者またはキー・オフィサーだけが使える機能です"})
                if not self._enc_ready():
                    return
                rows_, ok_ = waf_crypt.audit_read(control.enc_audit_path())
                if self._is_officer():
                    me_ = (self._user or {}).get("username", "")
                    rows_ = [r for r in rows_ if r.get("user") == me_ or r.get("action") in ("grant", "grant_reject", "key_set", "key_remove", "enable", "disable")]
                return self._json(200, {"rows": rows_, "chain_ok": ok_})
            if self.path.split("?")[0] == "/api/users":
                if self._need_admin():
                    return
                vf = getattr(control, "users_view", None)
                return self._json(200, {"users": vf() if vf else []})
            if self.path.startswith("/api/stats"):
                mp = "all"
                q = {}
                try:
                    q = parse_qs(urlparse(self.path).query)
                    mp = (q.get("map_period", ["all"])[0] or "all")
                    if mp not in MAP_PERIODS:
                        mp = "all"
                except Exception:
                    mp = "all"
                key_ = self._key()
                bsel = (q.get("backend", [""])[0] or "").strip()
                if bsel:
                    # backend=ID または backend=ID1,ID2,...(組織で絞ったとき)。見られる範囲外のIDは無視する
                    ids_ = [x.strip() for x in bsel.split(",") if x.strip()]
                    key_ = frozenset(x for x in ids_ if key_ is None or x in key_)
                ckey = (key_, mp)
                with stats_lock:
                    hit = stats_cache.get(ckey)
                    if hit and time.monotonic() - hit[0] < 1.0:
                        body = hit[1]
                    else:
                        stats, _ver = store_for(key_).stats(geo, mp)
                        body = json.dumps(stats, ensure_ascii=False)
                        stats_cache[ckey] = (time.monotonic(), body)
                if self._is_analyst():
                    # キャッシュは共有なので、アナリストにはリクエストごとにマスクして返す
                    try:
                        _st = json.loads(body)
                        _mkr = self._masker()
                        for _k in ("recent", "events"):
                            if isinstance(_st.get(_k), list):
                                _st[_k] = _mkr(_st[_k])
                        body = json.dumps(_st, ensure_ascii=False)
                    except Exception:
                        body = json.dumps({"error": "masking failed"})
                self._send(200, body, "application/json; charset=utf-8")
            elif self.path.startswith("/api/events"):
                # イベントログの読み出し。limit=数値(末尾から) / limit=all(全行。安全上限あり)。
                # merge=0 なら同じIPの連続した遮断ログをまとめず、ログ1行を1行で返す(全件読み込み用)
                q = parse_qs(urlparse(self.path).query)
                lim = (q.get("limit", ["20000"])[0] or "20000").lower()
                merge = (q.get("merge", ["1"])[0] != "0")
                store = self._store()
                acc = store.accept
                store.refresh()
                _rd = (lambda n_: read_events_store(source, store.webs, n_)) if source is not None else (lambda n_: read_events_all(log_path, n_))
                if lim == "all":
                    evs, nread, nfile, trunc = _rd(None)
                else:
                    try:
                        n = min(ALL_EVENTS_CAP, max(1, int(lim)))
                    except ValueError:
                        n = 20000
                    if n <= store.recent_max:
                        evs = store.recent_events()               # メモリ上の直近イベント(再読み込みなし)
                        nread = nfile = len(evs); trunc = False
                    else:
                        evs, nread, nfile, trunc = _rd(n)
                    evs = evs[-n:]
                if acc is not None:
                    evs = [e for e in evs if acc(e)]
                rows = _recent(evs, None, merge=merge)
                if self._is_analyst():
                    rows = self._masker()(rows)
                requests = 0
                for e in evs:
                    try:
                        requests += max(1, int(e.get("count", 1)))
                    except (TypeError, ValueError):
                        requests += 1
                self._json(200, {"events": rows, "returned": len(rows), "lines_read": nread,
                                 "lines_in_file": nfile, "truncated": bool(trunc),
                                 "requests": requests, "total": store.lines})
            elif self.path.startswith("/api/config"):
                cfg_ = control.get()
                self._json(200, cfg_ if self._is_admin() else (self._staff_config(cfg_) if self._is_analyst() else self._limited_config(cfg_)))
            elif self.path.split("?")[0] == "/api/health-log":
                if not self._is_admin() and "format=csv" in self.path:
                    return self._json(403, {"error": "管理者だけが使える機能です"})
                self._serve_health_log()
            elif self.path.split("?")[0] == "/health":
                # ダッシュボード側の稼働チェック用。8080(WAF本体)がフラッド中やBAN中でも確認できる
                fn = getattr(control, "get_health", None)
                h = fn() if fn else None
                if h is None:
                    self._json(200, {"dashboard": "ok", "waf": "unknown"})
                else:
                    t = h.get("targets", {})
                    b = (t.get("backend") or {}).get("state", "unknown")
                    w = (t.get("waf") or {}).get("state", "unknown")
                    self._json(503 if b in ("down", "error") else 200, {
                        "dashboard": "ok", "waf_process": "ok", "waf_port": w, "backend": b,
                        "lag_ms": h.get("lag_ms"), "accept_errors": h.get("accept_errors", 0)})
            elif self.path.startswith("/api/health"):
                fn = getattr(control, "get_health", None)
                h_ = fn() if fn else None
                self._json(200, {"health": h_ if self._is_admin() else self._limited_health(h_)})
            elif self.path.split("?")[0] == "/api/logs/summary":
                store = self._store()
                store.refresh(force=True)
                prof = {p.get("id"): p for p in profiles_now()}
                gone = {r.get("id"): r for r in removed_now()}
                with store.lock:
                    agg = store.agg
                    rows = []
                    for b, c in agg.backend_counts.items():
                        if not b:
                            continue
                        meta = prof.get(b) or gone.get(b) or {}
                        rows.append({"id": b, "name": meta.get("name") or agg.backend_names.get(b, b),
                                     "owner": meta.get("owner", ""), "removed": b not in prof,
                                     "count": sum(c.get(a, 0) for a in ACTIONS)})
                    none_n = (sum(agg.backend_counts.get("", {}).get(a, 0) for a in ACTIONS)
                              if self._is_admin() else 0)
                    total = sum(agg.action_counts.get(a, 0) for a in ACTIONS)
                try:
                    size = source.total_size() if source is not None else os.path.getsize(log_path)
                except OSError:
                    size = 0
                self._json(200, {"backends": rows, "none": none_n, "total": total, "size": size})
            elif self.path.split("?")[0] == "/api/logs/export":
                # ログの書き出しは管理者とアナリストだけ(一般ユーザーは不可)。範囲は画面表示と同じ判定で、アナリストにはマスクをかけ、記録を残す
                if not (self._is_admin() or self._is_analyst()):
                    return self._json(403, {"error": "ログの書き出しは管理者とアナリストだけができます"})
                if source is None:
                    return self._json(400, {"error": "この構成では書き出せません(WEBごとの日次ログがありません)"})
                q = parse_qs(urlparse(self.path).query)
                allowed = self._my_backend_ids()
                sel = [x for x in (q.get("backend", [""])[0] or "").split(",") if x]
                if sel and any(x not in allowed for x in sel):
                    return self._json(403, {"error": "担当範囲の外のバックエンドは書き出せません"})
                if not sel:
                    sel = sorted(allowed)
                lo = (q.get("from", [""])[0] or "")[:10] or None
                hi = (q.get("to", [""])[0] or "")[:10] or None
                for d_ in (lo, hi):
                    if d_ and not re.match(r"^\d{4}-\d{2}-\d{2}$", d_):
                        return self._json(400, {"error": "期間は YYYY-MM-DD で指定してください"})
                atk = (q.get("attacks_only", ["0"])[0] == "1")
                fmt = "csv" if (q.get("format", [""])[0] == "csv") else "jsonl"
                rollups = None
                if atk:
                    if self._is_admin():
                        rollups = [source.rollup_dir(None)]
                    else:
                        orgs_, _u = org_ctx()
                        ids_ = waf_org.by_id(orgs_)
                        scope_ = list((self._user or {}).get("scope") or [])
                        rollups = [source.rollup_dir(o) for o in scope_ if o in ids_ and ids_[o].get("parent") not in scope_]
                _mk = self._masker() if self._is_analyst() else None
                body, n, trunc, fmt = source.export(sel, lo, hi, atk, fmt, mask=(lambda e_: _drop_enc(_mk(e_) if _mk else e_)),
                                                    rollup_dirs=rollups)
                try:
                    nm = {p.get("id"): (p.get("name") or p.get("id")) for p in profiles_now()}
                    control.note_rule_change({"kind": "log_export", "by": (self._user or {}).get("username", ""), "op": "ログ書き出し",
                                              "backend_name": ", ".join(nm.get(x, x) for x in sel)[:120],
                                              "reason": f"{n}行 / {lo or '-'}〜{hi or '-'} / {'攻撃のみ' if atk else '通過を含む'} / {fmt}"
                                                        + (" / 上限で打ち切り" if trunc else "")})
                except Exception:
                    pass
                fname = "waf-log-" + time.strftime("%Y%m%d-%H%M%S") + (".csv" if fmt == "csv" else ".jsonl")
                self.send_response(200)
                self.send_header("Content-Type", "text/csv; charset=utf-8" if fmt == "csv" else "application/x-ndjson; charset=utf-8")
                self.send_header("Content-Disposition", f'attachment; filename="{fname}"')
                self.send_header("Content-Length", str(len(body)))
                self.send_header("X-Rows", str(n))
                self.send_header("X-Truncated", "1" if trunc else "0")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)
            elif self.path.split("?")[0] == "/api/overview":
                self._json(200, self._overview())
            elif self.path.startswith("/api/security"):
                sec_ = control.get_security()
                if not self._is_admin():
                    sec_ = self._limited_security(sec_)      # 一般ユーザー・アナリストには範囲内のバックエンド分だけ返す
                self._json(200, sec_)
            elif self.path.split("?")[0] == "/api/backend-rules":
                if not (self._is_admin() or self._is_analyst()):
                    return self._json(403, {"error": "管理者・アナリストだけが使える機能です"})
                mine_ = self._my_backend_ids()
                self._json(200, {"backends": self._with_undo([b for b in control.get_be_rules() if self._is_admin() or b.get("id") in mine_]),
                                 "orgs": self._rule_orgs(), "presets": wb.presets_view()})
            elif self.path.split("?")[0] == "/api/rule-presets/impact":
                if not (self._is_admin() or self._is_analyst()):
                    return self._json(403, {"error": "管理者・アナリストだけが使える機能です"})
                qs_ = parse_qs(urlparse(self.path).query)
                bid_ = (qs_.get("backend") or [""])[0]
                try:
                    days_ = max(1, min(90, int((qs_.get("days") or ["30"])[0])))
                except ValueError:
                    days_ = 30
                if bid_ not in self._my_backend_ids():
                    return self._json(403, {"error": "担当範囲外のバックエンドです"})
                prof_ = next((p for p in profiles_now() if p.get("id") == bid_), None)
                if prof_ is None:
                    return self._json(404, {"error": "バックエンドが見つかりません"})
                ck_ = (bid_, days_)
                hit_ = _impact_cache.get(ck_)
                if hit_ and time.monotonic() - hit_[0] < 60 and hit_[2] == json.dumps(wb.preset_snapshot(prof_), sort_keys=True):
                    ev_ = hit_[1]
                else:
                    ev_ = self._backend_events(bid_, days_)
                    _impact_cache[ck_] = (time.monotonic(), ev_, json.dumps(wb.preset_snapshot(prof_), sort_keys=True))
                    if len(_impact_cache) > 20:
                        _impact_cache.pop(next(iter(_impact_cache)))
                att_ = sum(1 for e in ev_ if e.get("hits"))
                res_ = {k: wb.impact_of(ev_, prof_, k) for k in wb.PRESET_ORDER}
                self._json(200, {"backend": bid_, "days": days_, "events": len(ev_), "with_hits": att_, "impact": res_,
                                 "note": "記録されたヒットだけからの試算です(再検査はしていません)"})
            elif self.path.split("?")[0] == "/api/orgs":
                if self._need_admin():
                    return
                self._json(200, control.orgs_view())
            elif self.path.split("?")[0] == "/api/custom-rules":
                if self._need_admin():
                    return
                self._json(200, control.custom_status())
            elif self.path.split("?")[0] == "/api/rule-history":
                if not (self._is_admin() or self._is_analyst()):
                    return self._json(403, {"error": "管理者・アナリストだけが使える機能です"})
                h_ = control.rule_history(500 if self._is_analyst() else 200)
                if not self._is_admin():
                    mine_ = self._my_backend_ids()
                    h_ = [x for x in h_ if x.get("backend") in mine_]       # 担当範囲のバックエンドの変更だけ
                self._json(200, {"history": h_})
            elif self.path.split("?")[0] == "/api/tickets":
                st_ = control.ticket_store()
                if self._is_admin():
                    ts_ = st_.list(None)
                elif self._is_analyst():
                    ts_ = [t for t in st_.list(None) if self._ticket_visible(t)]
                else:
                    ts_ = st_.list((self._user or {}).get("username", ""))
                    if self._is_officer():
                        have_ = {t.get("id") for t in ts_}
                        ts_ = ts_ + [t for t in st_.list(None) if t.get("kind") == "log_review" and t.get("id") not in have_ and self._ticket_visible(t)]
                        ts_.sort(key=lambda t: t.get("id", ""), reverse=True)
                    if (self._user or {}).get("role") == "user":      # 自組織の「復号の申請」は承認のために見える
                        have_ = {t.get("id") for t in ts_}
                        ts_ = ts_ + [t for t in st_.list(None) if t.get("kind") == "decrypt" and t.get("id") not in have_ and self._covers_org(t.get("org"))]
                        ts_.sort(key=lambda t: t.get("id", ""), reverse=True)
                if self._is_admin() or (self._user or {}).get("role") in ("user", "analyst"):
                    ts_ = [dict(t, can_approve=self._can_approve_decrypt(t)) if t.get("kind") == "decrypt" else t for t in ts_]
                    for t_ in ts_:        # 承認する人に、対象期間の暗号化ログ件数を見せる(範囲を判断する材料)
                        if t_.get("kind") == "decrypt" and t_.get("can_approve"):
                            g_ = t_.get("grant") or {}
                            try:
                                t_["enc_count"] = self._enc_count_range(t_.get("backend"), g_.get("from"), g_.get("to"))
                            except Exception:
                                t_["enc_count"] = None
                self._json(200, {"tickets": ts_, "kinds": waf_tickets.KINDS, "statuses": waf_tickets.STATUSES,
                                 "role": (self._user or {}).get("role", "admin")})
            elif self.path.split("?")[0] == "/api/rules/catalog":
                # ルール一覧(IDと説明だけ)。アナリストがバックエンド別に設定するための参照用で、全体のON/OFF状態は含めない
                if not (self._is_admin() or self._is_analyst()):
                    return self._json(403, {"error": "管理者・アナリストだけが使える機能です"})
                g_ = control.get_rules()
                self._json(200, {"categories": [{"key": c.get("key"), "label": c.get("label")} for c in g_.get("categories", [])],
                                 "rules": [{k: r.get(k) for k in ("id", "category", "severity", "description")} for r in g_.get("rules", [])],
                                 "total": g_.get("total")})
            elif self.path.startswith("/api/rules"):
                if self._need_admin():
                    return
                self._json(200, control.get_rules())
            elif self.path.startswith("/api/stream"):
                self._stream()
            elif self.path.startswith("/assets/world"):
                self._send(200, WORLD_SVG, "text/plain; charset=utf-8")
            elif self.path == "/" or self.path.startswith("/?"):
                self._send(200, PAGE, "text/html; charset=utf-8")
            else:
                self._send(404, "<h1>404</h1>", "text/html; charset=utf-8")

        def _overview(self):
            """ホーム画面の「稼働状況」「要注意IP」用の要約。設定・BAN・接続数・補足情報を1回で返す"""
            def safe(fn, default):
                try:
                    return fn()
                except Exception:
                    return default
            cfg = safe(control.get, {}) or {}
            ed = cfg.get("editable", {}) or {}
            ex = ed.get("extra", {}) or {}
            rl = ed.get("rate_limit", {}) or {}
            if not self._is_admin():
                mine_ids_ = self._my_backend_ids()
                be_ = dict(ed.get("backend") or {})
                be_["profiles"] = [x for x in be_.get("profiles", []) if x.get("id") in mine_ids_]
                return {"limited": True, "backends": self._overview_backends(be_, ro_listen=(cfg.get("readonly") or {}).get("listen", ""))}
            rules = safe(control.get_rules, {}) or {}
            rlist = rules.get("rules", []) or []
            sec = safe(control.get_security, {}) or {}
            conn = sec.get("connections", {}) or {}
            wfn = getattr(control, "get_watch", None)
            efn = getattr(control, "get_overview_extra", None)
            extra = (safe(efn, {}) if efn else {}) or {}
            exit_ip = None
            if geo is not None and getattr(geo, "enabled", False) and getattr(geo, "egress", True):
                exit_ip = safe(geo.self_public_ip, None)
            bind = ""
            try:
                bind = self.server.server_address[0]
            except Exception:
                pass
            local_only = bind in ("127.0.0.1", "::1", "localhost")
            return {
                "mode": ed.get("mode", "block"),
                "rules_on": sum(1 for r in rlist if r.get("enabled")),
                "rules_total": len(rlist),
                "bans": len(sec.get("bans") or []),
                "bans_known": sec.get("online", True) is not False,
                "autoban": ex.get("autoban", {}),
                "geoip": extra.get("geoip"),
                "country_rules": (len(sec.get("country_blocklist") or []) + len(sec.get("country_allowlist") or [])
                                  + (1 if sec.get("country_block_unknown") else 0)),
                "auth": {"enabled": bool(auth.enabled), "local_only": local_only, "bind": bind},
                "response_inspection": (ex.get("response_inspection") or {}).get("action", "sanitize"),
                "connections": {"total": conn.get("total", 0), "max_total": conn.get("max_total", 0),
                                "max_per_ip": conn.get("max_per_ip", 0), "known": not conn.get("offline")},
                "rate_limit": {"enabled": bool(rl.get("enabled")), "max_requests": rl.get("max_requests"),
                               "window_seconds": rl.get("window_seconds")},
                "slow": {"header": ex.get("header_timeout_seconds"), "body": ex.get("body_timeout_seconds"),
                         "ban": ex.get("slow_ban", {})},
                "global_ip": {"enabled": bool(ed.get("log_global_ip", True)), "ip": exit_ip},
                "webhook": extra.get("webhook"),
                "watch": (safe(wfn, []) if wfn else []) or [],
                "backends": self._overview_backends(ed.get("backend"), ro_listen=(cfg.get("readonly") or {}).get("listen", "")),
            }

        def _overview_backends(self, be, ro_listen=""):
            """ホームの「監視中のアプリ(接続先)」一覧。待ち受け(利用者の接続先)、転送先、状態"""
            if not be:
                return []
            m = re.match(r"^(https?)://([^:/]+):(\d+)$", ro_listen or "")
            sch, lhost, lport = (m.group(1), m.group(2), m.group(3)) if m else ("http", "0.0.0.0", "")
            hfn = getattr(control, "get_health", None)
            try:
                h = hfn() if hfn else None
            except Exception:
                h = None
            st = {b.get("id"): b.get("state") for b in ((h or {}).get("backends") or [])}
            out = []
            for p in be.get("profiles", []):
                act = p.get("id") == be.get("active")
                lp = int(p.get("listen_port") or 0)
                if lp:
                    listen = f"{sch}://{lhost}:{lp}"
                elif p.get("path_prefix"):
                    listen = f"{sch}://{lhost}:{lport}{p['path_prefix']}/…"
                elif act:
                    listen = f"{sch}://{lhost}:{lport}"
                elif be.get("host_routing") and p.get("match_hosts"):
                    listen = "ホスト名: " + ", ".join(p["match_hosts"])
                else:
                    listen = ""
                try:
                    origin = wb.origin(p)
                except Exception:
                    origin = ""
                state = "paused" if p.get("stopped") else (st.get(p.get("id")) or "unknown")
                out.append({"id": p.get("id"), "name": p.get("name"), "active": act, "listen": listen,
                            "origin": origin, "state": state, "stopped": bool(p.get("stopped")),
                            "owner": p.get("owner", ""), "org": p.get("org", "")})
            return out

        def _stream(self):
            """Server-Sent Events。waf.log に追記された新規イベントを即時配信する"""
            try:
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "keep-alive")
                self.send_header("X-Accel-Buffering", "no")
                self.end_headers()
            except Exception:
                return

            def emit(evtype, payload):
                try:
                    msg = ""
                    if evtype:
                        msg += f"event: {evtype}\n"
                    msg += "data: " + json.dumps(payload, ensure_ascii=False) + "\n\n"
                    self.wfile.write(msg.encode("utf-8"))
                    self.wfile.flush()
                    return True
                except Exception:
                    return False

            server_loc = _server_location(geo)
            if not emit("server", {"server": server_loc}):
                return

            # ファイル末尾から追記分だけ追う。位置は自前で管理して EOF キャッシュを避ける
            f = None
            buf = ""
            pos = 0
            last_beat = time.time()
            # KPI用の絶対カウントを、このストリームの開始位置と一致させて種として配信する。
            # EventStore が読み終えた位置(pos)までの累計を種にして、以降は pos から追尾する。二重計上も取りこぼしもなく、全体の読み直しも不要
            my_gen = log_gen[0]
            _mk = self._masker()
            ustore = self._store()
            acc = ustore.accept
            seed_counts, pos = ustore.counts_and_pos()
            try:
                if source is None and os.path.exists(log_path):
                    f = open(log_path, "r", encoding="utf-8", errors="replace")
            except OSError:
                f = None
            emit("counts", {"actions": seed_counts, "total": sum(seed_counts.values())})

            refresh_srv = time.time()
            if source is not None:
                # WEBごとの日次ログから、増えた分だけを時刻順に配信する(集計の読み終わり位置の続きから)
                tail = source.reader(ustore.webs, pos=pos)
                while True:
                    try:
                        it, reset = tail.poll()
                        if reset:                          # 保存期間・削除でファイルが消えたので、今の末尾から追い直す
                            tail = source.reader(ustore.webs)
                            tail.seek_end()
                            time.sleep(0.3)
                            continue
                        sent = False
                        for e in it:
                            if acc is not None and not acc(e):
                                continue
                            sent = True
                            if not emit(None, _mk(_enrich_event(e, geo, server_loc))):
                                return
                        if not sent:
                            time.sleep(0.3)
                        now = time.time()
                        if now - refresh_srv > (60 if server_loc else 5):
                            nl = _server_location(geo) or server_loc
                            if nl != server_loc:                  # 出口IPが取れた・変わったら画面へ知らせる
                                server_loc = nl
                                if not emit("server", {"server": server_loc}):
                                    return
                            refresh_srv = now
                        if now - last_beat > 15:
                            if not emit(None, {"heartbeat": True}):
                                return
                            last_beat = now
                    except (BrokenPipeError, ConnectionResetError):
                        return
                    except Exception:
                        time.sleep(0.5)
            while True:
                try:
                    if f is None:
                        if os.path.exists(log_path):
                            f = open(log_path, "r", encoding="utf-8", errors="replace")
                            f.seek(0, os.SEEK_END)
                            pos = f.tell()
                        else:
                            time.sleep(0.4)
                            continue
                    if my_gen != log_gen[0]:          # ログが削除されたので末尾から追い直す(古い行は再配信しない)
                        my_gen = log_gen[0]
                        try:
                            pos = os.path.getsize(log_path)
                        except OSError:
                            pos = 0
                        buf = ""
                    f.seek(pos)
                    chunk = f.read()
                    pos = f.tell()
                    if chunk:
                        buf += chunk
                        while "\n" in buf:
                            line, buf = buf.split("\n", 1)
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                e = json.loads(line)
                            except ValueError:
                                continue
                            if acc is not None and not acc(e):
                                continue
                            if not emit(None, _mk(_enrich_event(e, geo, server_loc))):
                                return
                    else:
                        time.sleep(0.3)
                        try:
                            if os.path.getsize(log_path) < pos:   # ログが切り詰められたので先頭から追尾し直す
                                pos = 0
                                buf = ""
                        except OSError:
                            pass
                    now = time.time()
                    # サーバ位置の更新(VPN切替等に追従)
                    if now - refresh_srv > (60 if server_loc else 5):
                        nl = _server_location(geo) or server_loc
                        if nl != server_loc:                      # 出口IPが取れた・変わったら画面へ知らせる
                            server_loc = nl
                            if not emit("server", {"server": server_loc}):
                                return
                        refresh_srv = now
                    # ハートビート(接続維持)
                    if now - last_beat > 15:
                        if not emit(None, {"heartbeat": True}):
                            return
                        last_beat = now
                except (BrokenPipeError, ConnectionResetError):
                    return
                except Exception:
                    time.sleep(0.5)

        def _read_json(self):
            try:
                n = int(self.headers.get("Content-Length") or 0)
                return json.loads(self.rfile.read(n).decode("utf-8")) if n else {}
            except (ValueError, TypeError):
                return None

        def do_POST(self):
            if self._auth_gate():
                return
            p = self.path
            if self._is_analyst() and not p.startswith(("/api/tickets", "/api/users", "/api/backend-rules", "/api/config",
                                                         "/api/backend-test", "/api/enc/approve",
                                                         "/api/security/bepolicy", "/api/security/bemode", "/api/rule-presets")):
                return self._json(403, {"error": "アナリストにはこの操作の権限がありません(担当範囲の閲覧・設定変更・申請の対応ができます)"})
            if p.startswith("/api/config"):
                up = self._read_json()
                if up is None:
                    return self._json(400, {"error": "invalid JSON"})
                if isinstance(up, dict):
                    up.pop("log_encrypt", None)        # 暗号化の設定は /api/enc/config だけ(キー・オフィサーの権限)
                try:
                    cur = (control.get().get("editable", {}).get("backend") or {})
                    if not self._is_admin() and not self._is_analyst():
                        return self._json(403, {"ok": False, "error": "バックエンドの追加・編集・稼働停止・削除は、管理者またはアナリストだけができます(管理者に依頼してください)"})
                    if not self._is_admin():
                        # アナリストは担当範囲の組織のバックエンドだけ追加・編集・削除できる(他の設定は不可)
                        my_org = str((self._user or {}).get("org") or "")
                        sub = (up.get("backend") or {}).get("profiles")
                        if not isinstance(sub, list):
                            return self._json(400, {"ok": False, "error": "バックエンドの設定が正しくありません"})
                        mine_ids = set(self._my_backend_ids() or ())
                        new_ = [x for x in sub if str((x or {}).get("id", "")).startswith("tmp-")]
                        added_ = []
                        if new_:
                            if not self._is_analyst():
                                return self._json(403, {"ok": False, "error": "バックエンドの追加は管理者・アナリストだけができます(管理者に依頼してください)"})
                            # アナリストが追加できるのは担当範囲の組織だけ(組織の指定は必須)
                            orgs_, _u = org_ctx()
                            so_ = waf_org.scope_orgs(orgs_, self._user, _u) or set()
                            for x in new_:
                                o_ = str((x or {}).get("org") or "")
                                if o_ not in so_:
                                    return self._json(403, {"ok": False, "error": "追加先の組織が担当範囲にありません(組織を選んでください)"})
                                added_.append((str(x.get("name") or x.get("host") or ""), o_))
                            sub = [x for x in sub if x not in new_] + new_      # 新規は末尾に足す(既存のIDを変えないため)
                        seen_ids = set()
                        for x in sub:
                            xid = str((x or {}).get("id", ""))
                            if xid.startswith("tmp-"):
                                if xid in seen_ids:
                                    return self._json(403, {"ok": False, "error": "同じバックエンドが重複しています"})
                                seen_ids.add(xid)
                                continue
                            if xid not in mine_ids:
                                return self._json(403, {"ok": False, "error": "他の組織のバックエンドは変更できません(追加は管理者だけです)"})
                            if xid in seen_ids:          # 同じidを2回送って複製=追加することも許さない
                                return self._json(403, {"ok": False, "error": "バックエンドの追加は管理者だけができます(同じバックエンドが重複しています)"})
                            seen_ids.add(xid)
                        for nm_, o_ in added_:
                            try:
                                control.note_rule_change({"kind": "backend_add", "by": (self._user or {}).get("username", ""),
                                                          "name": nm_, "org": o_})
                            except Exception:
                                pass
                        kept = {(x or {}).get("id") for x in sub}
                        if cur.get("active") in (mine_ids - kept):
                            return self._json(400, {"ok": False, "error": "メインの待受ポートの転送先(一覧の先頭)のバックエンドは削除できません(管理者に依頼してください)"})
                        others = [x for x in cur.get("profiles", []) if x.get("id") not in mine_ids]
                        up = {"backend": {"active": cur.get("active"), "host_routing": cur.get("host_routing"),
                                          "rewrite_links": cur.get("rewrite_links"),
                                          "profiles": others + list(sub)}}
                    old_profiles = list(cur.get("profiles", []))
                    res = control.set(up)
                    _scope_cache.clear()
                    try:
                        new_ids = {x.get("id") for x in ((res.get("editable") or {}).get("backend") or {}).get("profiles", [])}
                        gone_ = [{"id": x.get("id"), "name": x.get("name"), "owner": x.get("owner", "")}
                                 for x in old_profiles if x.get("id") not in new_ids]
                        nf = getattr(control, "note_removed", None)
                        if gone_ and nf:
                            nf(gone_)               # 削除したバックエンドのログを、持ち主が後から消せるよう記録する
                    except Exception:
                        pass
                    self._json(200, {"ok": True, "config": res if self._is_admin() else self._limited_config(res)})
                except Exception as e:
                    self._json(500, {"ok": False, "error": str(e)})
            elif p.startswith("/api/enc/"):
                self._enc_post(p.split("?")[0])
            elif p.startswith("/api/users"):
                up = self._read_json() or {}
                fn = getattr(control, "users_apply", None)
                if fn is None or not auth.user_mode:
                    return self._json(400, {"ok": False, "error": "ユーザー管理は使えません(dashboard.users が未設定です)"})
                try:
                    # 暗号鍵の登録中は、キー・オフィサーのアカウントを他人(管理者)が削除・変更・パスワード再設定できない
                    if hasattr(control, "enc_state") and str(up.get("action")) in ("delete", "update", "set_password"):
                        tgt_ = str(up.get("username") or "")
                        if tgt_ and tgt_ != (self._user or {}).get("username") and control.enc_state().get("has_keys"):
                            if any(u.get("username") == tgt_ and u.get("role") == "key_officer" for u in org_ctx()[1]):
                                return self._json(403, {"ok": False, "error": "暗号鍵が登録されている間は、キー・オフィサーのアカウントは本人以外が変更・削除できません(先に鍵を外してください)"})
                    users_ = fn(up, self._user or {})
                    _scope_cache.clear()
                    self._json(200, {"ok": True, "users": users_ if self._is_admin() else []})
                except ValueError as e:
                    self._json(400, {"ok": False, "error": str(e)})
                except Exception as e:
                    self._json(500, {"ok": False, "error": str(e)})
            elif p.startswith("/api/backend-test"):
                up = self._read_json() or {}
                fn = getattr(control, "test_backend", None)
                if fn is None:
                    return self._json(501, {"ok": False, "error": "この構成では接続テストできません"})
                try:
                    self._json(200, {"ok": True, "result": fn(up.get("profile") or {})})
                except ValueError as e:
                    self._json(400, {"ok": False, "error": str(e)})
                except Exception as e:
                    self._json(500, {"ok": False, "error": str(e)})
            elif p.startswith("/api/security/"):
                up = self._read_json() or {}
                if not self._is_admin():
                    # 一般ユーザー・アナリストが設定できるのは、範囲内のバックエンド宛のIP/国の制限(bepolicy)と防御モード(bemode)だけ。
                    # 共通のBANは全社に効くので管理者だけ
                    if not self._is_analyst():
                        return self._json(403, {"error": "防御モードの変更・IP/国のブロック設定は、管理者またはアナリストだけができます(閲覧のみ)"})
                    mine_ = self._my_backend_ids()
                    if not (p.endswith("/bepolicy") or p.endswith("/bemode")) or str(up.get("backend") or "") not in mine_:
                        return self._json(403, {"error": "管理者だけが使える機能です(担当範囲のバックエンド宛の設定だけ変更できます)"})
                    if p.endswith("/bemode"):
                        up.pop("lock", None)        # モードのロックは提供側(管理者)だけ
                        locked_ = next((x for x in profiles_now() if x.get("id") == str(up.get("backend") or "")), {}).get("mode_lock")
                        if locked_:
                            return self._json(403, {"error": "このバックエンドの防御モードは提供側がロックしています。変更は申請してください。"})
                        bad_ = self._analyst_guard(up)       # アナリストは申請に紐づけて変更する
                        if bad_:
                            return self._json(403, {"error": bad_})
                        if self._is_analyst() and not up.get("reason"):
                            up["reason"] = f"申請 {up.get('ticket')}"
                up["by"] = (self._user or {}).get("username", "")
                ip = str(up.get("ip", "")).strip()
                country = str(up.get("country", "")).strip()
                try:
                    if p.endswith("/bepolicy"):
                        fn_ = getattr(control, "be_policy", None)
                        if fn_ is None:
                            raise RuntimeError("バックエンド別の設定は統合起動(python waf.py)でのみ使えます")
                        sec = fn_(up)
                    elif p.endswith("/bemode"):
                        fn_ = getattr(control, "be_mode", None)
                        if fn_ is None:
                            raise RuntimeError("防御モードの切り替えは統合起動(python waf.py)でのみ使えます")
                        sec = fn_(up)
                    elif p.endswith("/allow"):
                        sec = control.list_add("allow", ip)
                    elif p.endswith("/unallow"):
                        sec = control.list_remove("allow", ip)
                    elif p.endswith("/exempt"):
                        sec = control.list_add("exempt", ip)
                    elif p.endswith("/unexempt"):
                        sec = control.list_remove("exempt", ip)
                    elif p.endswith("/ban"):
                        sec = control.ban_ip(ip, up.get("minutes", 60))
                    elif p.endswith("/extend"):
                        sec = control.extend_ban(ip, up.get("minutes", 10))
                    elif p.endswith("/allowcountry"):
                        sec = control.country_add("allow", country)
                    elif p.endswith("/unallowcountry"):
                        sec = control.country_remove("allow", country)
                    elif p.endswith("/countryunknown"):
                        sec = control.set_country_unknown(bool(up.get("enabled")))
                    elif p.endswith("/blockcountry"):
                        sec = control.block_country(country)
                    elif p.endswith("/unblockcountry"):
                        sec = control.unblock_country(country)
                    elif p.endswith("/block"):
                        sec = control.block_ip(ip)
                    elif p.endswith("/unblock"):
                        sec = control.unblock_ip(ip)
                    elif p.endswith("/unban"):
                        sec = control.unban_ip(ip)
                    elif p.endswith("/clearbans"):
                        sec = control.clear_bans()
                    else:
                        return self._send(404, "<h1>404</h1>", "text/html; charset=utf-8")
                    self._json(200, {"ok": True, "security": sec if self._is_admin() else self._limited_security(sec)})
                except Exception as e:
                    self._json(400, {"ok": False, "error": str(e)})
            elif p.startswith("/api/logs/delete"):
                up = self._read_json() or {}
                target = str(up.get("backend", "")).strip()
                if not target:
                    return self._json(400, {"ok": False, "error": "削除するバックエンドを指定してください"})
                if self._need_admin():          # ログ削除は証跡の消去になるので管理者だけ
                    return
                try:
                    if source is not None:
                        n = source.delete_events(target)
                    else:
                        n = delete_log_events(log_path, target, getattr(control, "log_lock", None))
                    log_gen[0] += 1
                    with stats_lock:
                        stats_cache.clear()
                    for st_ in list(stores.values()):
                        st_.refresh(force=True)
                    try:
                        ff = getattr(control, "forget_removed", None)
                        if ff and (target == "__all" or target in {r.get("id") for r in removed_now()}):
                            ff(target)
                        _scope_cache.clear()
                    except Exception:
                        pass
                    self._json(200, {"ok": True, "removed": n})
                except Exception as e:
                    self._json(500, {"ok": False, "error": str(e)})
            elif p.startswith("/api/rule-presets/reinspect"):
                # 過去ログの再検査(手動)。ログ中のリクエストを今のルールで検査し直し、プリセットを変えたときの影響を数える
                if not (self._is_admin() or self._is_analyst()):
                    return self._json(403, {"error": "管理者・アナリストだけが使える機能です"})
                up = self._read_json() or {}
                bid_ = str(up.get("backend") or "")
                if bid_ not in self._my_backend_ids():
                    return self._json(403, {"ok": False, "error": "担当範囲外のバックエンドです"})
                fn_ = getattr(control, "reinspect_events", None)
                if fn_ is None:
                    return self._json(501, {"ok": False, "error": "再検査は統合起動(python waf.py)でのみ使えます"})
                prof_ = next((x for x in profiles_now() if x.get("id") == bid_), None)
                if prof_ is None:
                    return self._json(404, {"ok": False, "error": "バックエンドが見つかりません"})
                try:
                    days_ = max(1, min(90, int(up.get("days") or 30)))
                    lim_ = max(10, min(2000, int(up.get("limit") or 500)))
                except (TypeError, ValueError):
                    return self._json(400, {"ok": False, "error": "期間と件数は数字で指定してください"})
                try:
                    all_ = self._backend_events(bid_, days_)
                    evs_ = [e for e in all_ if isinstance(e.get("req"), dict)][-lim_:]
                    items_, gdet_ = fn_(evs_)
                    res_ = {k: wb.impact_items(items_, prof_, k, global_detect=gdet_, cap=lim_) for k in wb.PRESET_ORDER}
                    miss_ = sum(1 for e in all_ if not isinstance(e.get("req"), dict))
                    self._json(200, {"ok": True, "backend": bid_, "days": days_, "scanned": len(evs_), "no_detail": miss_, "impact": res_,
                                     "note": "ログのリクエスト内容(本文は先頭4KBまで)を検査し直した試算です"})
                except Exception as e:
                    self._json(500, {"ok": False, "error": str(e)})
                return
            elif p.startswith("/api/backend-rules"):
                if not (self._is_admin() or self._is_analyst()):
                    return self._json(403, {"error": "管理者・アナリストだけが使える機能です"})
                up = self._read_json() or {}
                up.pop("_target", None)
                up["_role"] = "admin" if self._is_admin() else "analyst"       # 操作者の権限。画面から送られた値は使わない
                bad_ = self._analyst_guard(up)
                if bad_:
                    return self._json(403, {"ok": False, "error": bad_})
                try:
                    if up.get("op") == "undo":
                        if str(up.get("backend") or "") not in self._my_backend_ids():
                            return self._json(403, {"ok": False, "error": "担当範囲外のバックエンドです"})
                        tg_ = self._undo_target(str(up.get("backend") or ""))
                        if tg_ is None:
                            return self._json(400, {"ok": False, "error": "戻せる変更がありません(戻せるのは、そのバックエンドの直前の変更1件だけです。アナリストは自分の変更だけ戻せます)"})
                        up["_target"] = tg_
                    rl_ = control.be_rules(up, (self._user or {}).get("username", "") or "admin")
                    _impact_cache.clear()
                    if not self._is_admin():
                        mine_ = self._my_backend_ids()
                        rl_ = [x for x in rl_ if x.get("id") in mine_]      # 範囲外のバックエンドの設定は返さない
                    self._json(200, {"ok": True, "backends": self._with_undo(rl_), "orgs": self._rule_orgs(), "presets": wb.presets_view()})
                except ValueError as e:
                    self._json(400, {"ok": False, "error": str(e)})
                except Exception as e:
                    self._json(500, {"ok": False, "error": str(e)})
            elif p.startswith("/api/orgs"):
                if self._need_admin():
                    return
                up = self._read_json() or {}
                try:
                    if p.rstrip("/").endswith("/export"):
                        self._json(200, {"ok": True, **control.export_org(str(up.get("org") or ""), log_path)})
                    elif p.rstrip("/").endswith("/prune"):
                        self._json(200, {"ok": True, "removed": control.prune_logs(log_path)})
                    else:
                        v = control.orgs_op(up, (self._user or {}).get("username", "") or "admin")
                        _scope_cache.clear()
                        self._json(200, {"ok": True, **v})
                except ValueError as e:
                    self._json(400, {"ok": False, "error": str(e)})
                except Exception as e:
                    self._json(500, {"ok": False, "error": str(e)})
            elif p.startswith("/api/custom-rules"):
                if self._need_admin():
                    return
                try:
                    self._json(200, {"ok": True, **control.custom_reload()})
                except Exception as e:
                    self._json(400, {"ok": False, "error": str(e)})
            elif p.startswith("/api/tickets"):
                self._tickets_post(p)
            elif p.startswith("/api/rules/"):
                if self._need_admin():
                    return
                up = self._read_json() or {}
                try:
                    _by = (self._user or {}).get("username", "") or "admin"
                    if p.endswith("/detect"):
                        fn_ = getattr(control, "set_rule_detect", None)
                        if fn_ is None:
                            raise RuntimeError("ルール単位の検知モードは利用できません")
                        r = fn_(str(up.get("id", "")), bool(up.get("detect")))
                        control.note_rule_change({"kind": "global_rule", "by": _by, "rule": str(up.get("id", "")), "op": "detect" if up.get("detect") else "block"})
                    elif p.endswith("/rule"):
                        r = control.set_rule(str(up.get("id", "")), bool(up.get("enabled")))
                        control.note_rule_change({"kind": "global_rule", "by": _by, "rule": str(up.get("id", "")), "op": "enable" if up.get("enabled") else "disable"})
                    elif p.endswith("/category"):
                        r = control.set_category(str(up.get("category", "")), bool(up.get("enabled")))
                        control.note_rule_change({"kind": "global_category", "by": _by, "rule": str(up.get("category", "")), "op": "enable" if up.get("enabled") else "disable"})
                    else:
                        return self._send(404, "<h1>404</h1>", "text/html; charset=utf-8")
                    self._json(200, {"ok": True, "rules": r})
                except Exception as e:
                    self._json(400, {"ok": False, "error": str(e)})
            else:
                self._send(404, "<h1>404</h1>", "text/html; charset=utf-8")

        do_HEAD = do_GET

    return Handler



# 攻撃アラート(管理画面の警報バナー)の設定。dashboard.alert に保存する
ALERT_DEFAULTS = {"enabled": True, "sound": False, "immediate": "critical", "threshold": 5, "window": 10, "critical": 100, "hold": 2, "position": "top", "bg": True}


def alert_view(dash):
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


def alert_update(dash, up):
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


class FileConfigControl:
    """単体起動(WAF と別プロセス)時の設定編集。waf_config.json を読み書きするだけで、稼働中の WAF には反映されない(再起動で反映)"""
    def __init__(self, path):
        self.path = path

    def _load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

    def get(self):
        c = self._load()
        dash = c.get("dashboard", {})
        rl = c.get("rate_limit", {})
        return {
            "editable": {
                "mode": c.get("mode", "block"),
                "rules": c.get("rules", {}),
                "security_headers_enabled": bool(c.get("security_headers", {}).get("enabled", True)),
                "rate_limit": {
                    "enabled": bool(rl.get("enabled", True)),
                    "max_requests": rl.get("max_requests", 120),
                    "window_seconds": rl.get("window_seconds", 60),
                    "action": rl.get("action", "drop"),
                    "ban_threshold": rl.get("ban_threshold", 0),
                    "ban_seconds": rl.get("ban_seconds", 300),
                    "burst_max": rl.get("burst_max", 0),
                    "burst_seconds": rl.get("burst_seconds", 3),
                    "global_max_rps": rl.get("global_max_rps", 0),
                    "ban_escalate": bool(rl.get("ban_escalate", True)),
                    "max_conn_per_ip": rl.get("max_conn_per_ip", 0),
                    "max_total_conn": rl.get("max_total_conn", 0),
                    "conn_burst_max": rl.get("conn_burst_max", 0),
                    "conn_burst_seconds": rl.get("conn_burst_seconds", 5),
                },
                "conn_timeout_seconds": c.get("conn_timeout_seconds", 20),
                "access_log": bool(c.get("access_log", True)),
                "log_global_ip": bool(c.get("log_global_ip", True)),
                "trust_xforwarded_for": bool(c.get("trust_xforwarded_for", False)),
                "self_ip_ttl": c.get("self_ip_ttl", 60),
                "log_request_detail": bool(c.get("log_request_detail", True)),
                "log_pass_body": bool(c.get("log_pass_body", True)),
                "log_response": bool(c.get("log_response", True)),
                "log_encrypt": waf_crypt.view(c.get("log_encrypt")),
                "geo": bool(dash.get("geo", True)),
                "egress": bool(dash.get("egress", True)),
                "alert": alert_view(dash),
                "backend": wb.public_view(c),
                "extra": wx.extra_view(c),
            },
            "readonly": {
                "listen": f'{"https" if c.get("listen_tls") else "http"}://{c.get("listen_host")}:{c.get("listen_port")}',
                "backend": wb.origin(wb.active_profile(c)),
                "dashboard": f'{dash.get("host","127.0.0.1")}:{dash.get("port",8090)}',
                "admin_auth": bool(self.admin_password() or self.users()),
            },
            "hot_reload": False,
            "note": "単体起動のため、変更は waf_config.json に保存されますが WAF への反映には再起動が必要です。",
        }

    def test_backend(self, profile):
        return wb.test_profile(wb.normalize_profile(profile))

    def admin_password(self):
        return os.environ.get("WAF_ADMIN_PASSWORD") or str(self._load().get("dashboard", {}).get("password") or "")

    # ユーザーと削除済みバックエンドの記録(単体起動では設定ファイルを直接読み書き)
    def users(self):
        return wx.users_of(self._load())

    def users_view(self):
        return wx.users_view(self._load())

    def users_apply(self, up, actor):
        c = self._load()
        wx.users_apply(c, up, actor)
        self._save(c)
        return wx.users_view(c)

    def removed_backends(self):
        return list(self._load().get("removed_backends", []) or [])

    def note_removed(self, entries):
        c = self._load()
        lst = c.setdefault("removed_backends", [])
        have = {r.get("id") for r in lst}
        for e in entries:
            if e.get("id") and e["id"] not in have:
                lst.append({"id": e["id"], "name": e.get("name") or e["id"], "owner": e.get("owner") or ""})
        self._save(c)

    def forget_removed(self, bid):
        c = self._load()
        lst = c.get("removed_backends", []) or []
        c["removed_backends"] = [] if bid == "__all" else [r for r in lst if r.get("id") != bid]
        self._save(c)

    def set(self, up):
        c = self._load()
        if isinstance(up.get("extra"), dict):
            wx.extra_update(c, up["extra"])
        if isinstance(up.get("backend"), dict):
            st = wb.normalize_backend_settings(up["backend"], wb.public_view(c))     # 先に検証する。不正なら何も保存しない
            for p_ in st["profiles"]:
                wb.check_not_loop(p_, c.get("listen_host"), c.get("listen_port"))
            wb.apply_to_cfg(c, st)
        if up.get("mode") in ("block", "detect"):
            c["mode"] = up["mode"]
        if isinstance(up.get("rules"), dict):
            c.setdefault("rules", {})
            for k in ("xss", "sqli", "traversal", "cmdi"):
                if k in up["rules"]:
                    c["rules"][k] = bool(up["rules"][k])
        if "security_headers_enabled" in up:
            c.setdefault("security_headers", {})["enabled"] = bool(up["security_headers_enabled"])
        if isinstance(up.get("rate_limit"), dict):
            c.setdefault("rate_limit", {})
            rl = up["rate_limit"]
            if "enabled" in rl:
                c["rate_limit"]["enabled"] = bool(rl["enabled"])
            if "max_requests" in rl:
                c["rate_limit"]["max_requests"] = max(1, min(100000, int(rl["max_requests"])))
            if "window_seconds" in rl:
                c["rate_limit"]["window_seconds"] = max(1, min(86400, int(rl["window_seconds"])))
            if rl.get("action") in ("drop", "429"):
                c["rate_limit"]["action"] = rl["action"]
            if "ban_threshold" in rl:
                c["rate_limit"]["ban_threshold"] = max(0, min(100000, int(rl["ban_threshold"])))
            if "ban_seconds" in rl:
                c["rate_limit"]["ban_seconds"] = max(1, min(86400, int(rl["ban_seconds"])))
            if "burst_max" in rl:
                c["rate_limit"]["burst_max"] = max(0, min(100000, int(rl["burst_max"])))
            if "burst_seconds" in rl:
                c["rate_limit"]["burst_seconds"] = max(1, min(60, int(rl["burst_seconds"])))
            if "global_max_rps" in rl:
                c["rate_limit"]["global_max_rps"] = max(0, min(1000000, int(rl["global_max_rps"])))
            if "ban_escalate" in rl:
                c["rate_limit"]["ban_escalate"] = bool(rl["ban_escalate"])
            if "max_conn_per_ip" in rl:
                c["rate_limit"]["max_conn_per_ip"] = max(0, min(100000, int(rl["max_conn_per_ip"])))
            if "max_total_conn" in rl:
                c["rate_limit"]["max_total_conn"] = max(0, min(1000000, int(rl["max_total_conn"])))
            if "conn_burst_max" in rl:
                c["rate_limit"]["conn_burst_max"] = max(0, min(1000000, int(rl["conn_burst_max"])))
            if "conn_burst_seconds" in rl:
                c["rate_limit"]["conn_burst_seconds"] = max(1, min(600, int(rl["conn_burst_seconds"])))
        if "conn_timeout_seconds" in up:
            c["conn_timeout_seconds"] = max(0, min(600, int(up["conn_timeout_seconds"])))
        if isinstance(up.get("log_encrypt"), dict):
            c["log_encrypt"] = waf_crypt.apply(c.get("log_encrypt"), up["log_encrypt"])
        for k in ("access_log", "log_global_ip", "trust_xforwarded_for",
                  "log_request_detail", "log_pass_body", "log_response"):
            if k in up:
                c[k] = bool(up[k])
        if "self_ip_ttl" in up:
            c["self_ip_ttl"] = max(5, min(3600, int(up["self_ip_ttl"])))
        dash = c.setdefault("dashboard", {})
        if "geo" in up:
            dash["geo"] = bool(up["geo"])
        if "egress" in up:
            dash["egress"] = bool(up["egress"])
        if isinstance(up.get("alert"), dict):
            alert_update(dash, up["alert"])
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(c, f, ensure_ascii=False, indent=2)
        except OSError as e:
            raise RuntimeError(f"保存に失敗: {e}")
        return self.get()

    # IPブロック管理(単体起動時、BANは稼働中WAF側のためここでは扱えない)
    def _save(self, c):
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(c, f, ensure_ascii=False, indent=2)

    def health_history_file(self):
        return self._load().get("health_history_file", "health_history.jsonl")

    def _read_ban_history(self, name, limit=200):
        """単体起動でも、WAFが保存したBAN履歴ファイルの末尾を読んで新しい順に表示する"""
        if not name:
            return []
        path = _dpath(name)
        rows = []
        try:
            with open(path, "rb") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                f.seek(max(0, size - 256 * 1024))
                data = f.read().decode("utf-8", errors="replace")
            for line in data.splitlines()[-limit * 2:]:
                try:
                    d = json.loads(line)
                except ValueError:
                    continue
                if isinstance(d, dict) and d.get("ip") and d.get("at"):
                    rows.append(d)
        except OSError:
            return []
        return rows[-limit:][::-1]

    def get_health(self):
        return None      # 単体起動では稼働モニターの情報を持たない(WAFと同じプロセスで動かしたときのみ)

    def get_security(self):
        c = self._load()
        rl = c.get("rate_limit", {})
        return {
            "blocklist": list(c.get("blocklist", [])),
            "ip_allowlist": list(c.get("ip_allowlist", [])),
            "exempt_ips": list(c.get("exempt_ips", [])),
            "country_blocklist": list(c.get("country_blocklist", [])),
            "country_allowlist": list(c.get("country_allowlist", [])),
            "country_block_unknown": bool(c.get("country_block_unknown", False)),
            "backends": [{"id": p.get("id"), "name": p.get("name"), "owner": p.get("owner") or "", "org": p.get("org") or "",
                          "stopped": bool(p.get("stopped")),
                          "mode_override": p.get("mode_override") or "",
                          "mode_until": p.get("mode_until") or 0,
                          "mode_lock": bool(p.get("mode_lock")),
                          "effective_mode": wb.effective_mode(c, p)}
                         for p in wb.get_profiles(c)],
            "backend_policies": {p.get("id"): wb.clean_ip_policy(p.get("ip_policy")) for p in wb.get_profiles(c)},
            "global_mode": c.get("mode", "block"),
            "mode_history": wb.read_mode_history(_dpath(c.get("mode_history_file", "mode_history.jsonl")) if c.get("mode_history_file", "mode_history.jsonl") else "", 100),
            "autoban": wx.extra_view(c)["autoban"],
            "online": False,
            "bans": [],  # 自動BANは稼働中WAFのメモリ上にあり、単体起動では参照できない
            "ban_history": self._read_ban_history(c.get("ban_history_file", "ban_history.jsonl")),
            "ban_threshold": rl.get("ban_threshold", 0),
            "ban_seconds": rl.get("ban_seconds", 300),
            "action": rl.get("action", "drop"),
            "connections": {"total": 0, "per_ip": [], "max_per_ip": rl.get("max_conn_per_ip", 0),
                            "max_total": rl.get("max_total_conn", 0), "offline": True, "stats": None},
            "note": "単体起動のため自動BAN一覧・接続数は表示できません(稼働中WAFのメモリ上)。",
        }

    def block_ip(self, ip):
        ip = str(ip).strip()
        try:
            ipaddress.ip_network(ip, strict=False) if "/" in ip else ipaddress.ip_address(ip)
        except ValueError:
            raise RuntimeError("無効なIP/CIDRです: " + ip)
        c = self._load()
        bl = c.setdefault("blocklist", [])
        if ip not in bl:
            bl.append(ip)
        self._save(c)
        return self.get_security()

    def unblock_ip(self, ip):
        ip = str(ip).strip()
        c = self._load()
        bl = c.setdefault("blocklist", [])
        if ip in bl:
            bl.remove(ip)
        self._save(c)
        return self.get_security()

    def unban_ip(self, ip):
        return self.get_security()

    def clear_bans(self):
        return self.get_security()

    # self_made_waf から取り込んだ操作(単体起動では設定ファイルに保存し、WAF再起動で反映)
    def ban_ip(self, ip, minutes):
        raise RuntimeError("手動BANは稼働中のWAFのメモリ上で行うため、統合起動(python3 waf.py)でのみ使えます")

    extend_ban = ban_ip

    def _mutate(self, fn, *a):
        c = self._load()
        fn(c, *a)
        self._save(c)
        return self.get_security()

    def list_add(self, kind, ip):
        return self._mutate(wx.list_add, kind, ip)

    def list_remove(self, kind, ip):
        return self._mutate(wx.list_remove, kind, ip)

    def country_add(self, mode, cc):
        return self._mutate(wx.country_add, mode, cc)

    def country_remove(self, mode, cc):
        return self._mutate(wx.country_remove, mode, cc)

    def set_country_unknown(self, on):
        def f(c, v):
            c["country_block_unknown"] = bool(v)
        return self._mutate(f, on)

    def block_country(self, country):
        country = str(country).strip()
        if not country:
            raise RuntimeError("国コード/国名を入力してください。")
        c = self._load()
        cl = c.setdefault("country_blocklist", [])
        if country not in cl:
            cl.append(country)
        self._save(c)
        return self.get_security()

    def unblock_country(self, country):
        country = str(country).strip()
        c = self._load()
        cl = c.setdefault("country_blocklist", [])
        if country in cl:
            cl.remove(country)
        self._save(c)
        return self.get_security()

    def be_mode(self, up):
        """バックエンド別の防御モードを変更する(単体起動は設定ファイルに保存し、WAF再起動で反映)"""
        bid = str(up.get("backend") or "")
        want = str(up.get("mode") or "")
        if "mode" in up and want not in ("", "block", "detect"):
            raise RuntimeError("モードの指定が不正です")
        c = self._load()
        prof = next((p for p in (c.get("backends") or []) if p.get("id") == bid), None)
        if prof is None:
            raise RuntimeError("バックエンドが見つかりません")
        if "lock" in up:
            prof["mode_lock"] = bool(up["lock"])
        if "mode" in up:
            prev = wb.effective_mode(c, prof)
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
            wb.append_mode_history(c, {
                "backend": bid, "backend_name": prof.get("name") or bid,
                "by": str(up.get("by") or ""), "from": prev,
                "to": wb.effective_mode(c, prof),
                "override": prof.get("mode_override") or "",
                "until": until, "reason": str(up.get("reason") or "")[:200],
            })
        self._save(c)
        return self.get_security()

    # バックエンド別ルール設定、追加ルール、履歴、チケット(単体起動ではファイルを直接読み書き)
    def _rel(self, name, default):
        n = self._load().get(name, default)
        return _dpath(n) if n else ""

    def get_be_rules(self):
        return wb.get_be_rules(self._load())

    def be_rules(self, up, by=""):
        c = self._load()
        ent = wb.be_rules_op(c, up, by)
        self._save(c)
        self.note_rule_change(dict(ent, kind="backend_rule"))
        return wb.get_be_rules(c)

    def org_context(self):
        c = self._load()
        return (list(c.get("orgs") or []), list(wx.users_of(c)))

    def orgs_view(self):
        return waf_org.orgs_view(self._load())

    def orgs_op(self, up, by=""):
        c = self._load()
        ent = waf_org.orgs_op(c, up)
        self._save(c)
        self.note_rule_change(dict(ent, kind="org", by=by))
        return waf_org.orgs_view(c)

    def prune_logs(self, log_path=None):
        c = self._load()
        orgs, users = list(c.get("orgs") or []), list(wx.users_of(c))
        limits = {}
        for p in (c.get("backends") or []):
            a = waf_org.retention_for(orgs, p, users)
            if a:
                limits[p.get("id")] = (a, waf_org.attack_retention_for(orgs, waf_org.backend_org(p, users)))
        n = c.get("log_file") or "waf.log"
        lp = log_path or _dpath(n)
        return waf_org.prune_log(lp, limits)

    def export_org(self, org_id, log_path=None):
        c = self._load()
        base = ROOT
        n = c.get("log_file") or "waf.log"
        lp = log_path or _dpath(n)
        root = os.path.join(DATA_DIR, "log_exports", f"{org_id}-{time.strftime('%Y%m%d-%H%M%S')}")
        counts = waf_org.export_org_logs(lp, list(c.get("orgs") or []), list(c.get("backends") or []), org_id, root, list(wx.users_of(c)))
        return {"dir": os.path.relpath(root, base), "counts": counts}

    def note_rule_change(self, entry):
        waf_custom.append_history(self._rel("rule_history_file", "rule_history.jsonl"), entry)

    def rule_history(self, limit=200):
        return waf_custom.read_history(self._rel("rule_history_file", "rule_history.jsonl"), limit)

    def custom_status(self):
        path = self._rel("custom_rules_file", "config/custom_rules.json")
        try:
            rules, ver = waf_custom.read_file(path)
            return {"status": {"path": os.path.basename(path), "version": ver, "count": len(rules), "active": None,
                               "loaded_at": "", "error": "", "standalone": True}, "rules": rules}
        except ValueError as e:
            return {"status": {"path": os.path.basename(path), "error": str(e), "standalone": True}, "rules": []}

    def custom_reload(self):
        return self.custom_status()

    def ticket_store(self):
        st = getattr(self, "_tickets", None)
        if st is None:
            st = self._tickets = waf_tickets.TicketStore(self._rel("tickets_file", "tickets.json"),
                                                         mailer=waf_tickets.make_mailer(lambda: self._load().get("notify_email")))
        return st

    # ルール管理(単体起動では再起動で反映)
    def get_rules(self):
        c = self._load()
        disabled = set(c.get("disabled_rules", []))
        detect_only = set(c.get("detect_only_rules") or [])
        cat_on = c.get("rules", {})
        rules = []
        for r in (waf_rules.list_rules() if waf_rules else []):
            rules.append({**r,
                          "enabled": (r["id"] not in disabled) and cat_on.get(r["category"], True),
                          "category_enabled": cat_on.get(r["category"], True),
                          "rule_disabled": r["id"] in disabled,
                          "detect_only": r["id"] in detect_only})
        cats = [{"key": k, "label": (waf_rules.CATEGORY_LABELS.get(k, k) if waf_rules else k),
                 "enabled": cat_on.get(k, True)} for k in (waf_rules.CATEGORIES if waf_rules else [])]
        return {"categories": cats, "rules": rules,
                "total": (waf_rules.rule_count() if waf_rules else 0),
                "global_mode": c.get("mode", "block")}

    def set_rule(self, rule_id, enabled):
        c = self._load()
        dis = set(c.get("disabled_rules", []))
        dis.discard(rule_id) if enabled else dis.add(rule_id)
        c["disabled_rules"] = sorted(dis)
        self._save(c)
        return self.get_rules()

    def set_rule_detect(self, rule_id, detect):
        rule_id = str(rule_id or "").strip()
        if not rule_id:
            raise RuntimeError("ルールIDを指定してください")
        c = self._load()
        s = set(c.get("detect_only_rules") or [])
        s.add(rule_id) if detect else s.discard(rule_id)
        c["detect_only_rules"] = sorted(s)
        self._save(c)
        return self.get_rules()

    def set_category(self, cat, enabled):
        c = self._load()
        if cat in c.get("rules", {}):
            c["rules"][cat] = bool(enabled)
            self._save(c)
        return self.get_rules()


# ---------------------------------------------------------------------------
# 画面(単一ファイルの HTML / CSS / JS)
# ---------------------------------------------------------------------------
PAGE = r"""<!doctype html>
<html lang="ja" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WAF ダッシュボード</title>
<style>
  :root{
    --bg:#121311; --surface:#1a1a19; --surface-2:#222220; --border:#33332f;
    --ink:#f0efec; --ink-2:#c3c2b7; --ink-muted:#8b8a80;
    --pass:#1baf7a; --block:#e34948; --detect:#eda100; --rate:#9085e9;
    --c-xss:#3987e5; --c-sqli:#d95926; --c-traversal:#199e70; --c-cmdi:#c98500;
    /* 深刻度: 危険=赤紫(濃) > 高=橙赤 > 中=黄 > 低=黄緑。青系は安全色に見えるので使わない */
    --sev-critical:#e0245e; --sev-high:#f4602b; --sev-medium:#f2b01e; --sev-low:#8cc152;
    --sev-critical-ink:#fff; --sev-high-ink:#fff; --sev-medium-ink:#1a1a19; --sev-low-ink:#1a1a19;
    --land:#2b2f36; --land-stroke:#3b4049; --ocean:#15171a;
    --raw-bg:#0e0f0d; --modal-dim:#000a;
    --accent:#4a90e2; --shadow:none; --header-bg:#1a1a19; --dot:rgba(240,239,236,.10);
  }
  :root[data-theme="light"]{
    /* ライトテーマ。青みグレー基調で、影は控えめ */
    --bg:#eef1f6; --surface:#ffffff; --surface-2:#f1f4f9; --border:#e3e7ee;
    --ink:#1e2430; --ink-2:#515a6b; --ink-muted:#8a93a3;
    --pass:#0f9d63; --block:#e1473f; --detect:#f0a800; --rate:#6a5de0;
    --c-xss:#2f6fed; --c-sqli:#d2561f; --c-traversal:#0f9d63; --c-cmdi:#e09500;
    --sev-critical:#c9144f; --sev-high:#e0501a; --sev-medium:#e0a000; --sev-low:#6aa72b;
    --sev-critical-ink:#fff; --sev-high-ink:#fff; --sev-medium-ink:#1e2430; --sev-low-ink:#fff;
    --land:#b3c0d3; --land-stroke:#8695ad; --ocean:#f2f6fb;
    --raw-bg:#f6f8fb; --modal-dim:#1e2a3a66;
    --accent:#2f6fed; --shadow:0 1px 2px rgba(23,43,77,.05), 0 4px 14px rgba(23,43,77,.06);
    --header-bg:#ffffff; --dot:rgba(30,36,48,.16);
  }
  :root[data-theme="light"] .card,
  :root[data-theme="light"] .kpi{box-shadow:var(--shadow)}
  :root[data-theme="light"] header,
  :root[data-theme="light"] .nav{box-shadow:0 1px 3px rgba(23,43,77,.05)}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg) radial-gradient(var(--dot) 1px,transparent 1.5px) 0 0/22px 22px fixed;color:var(--ink);
    font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;font-size:14px}
  header{display:flex;align-items:center;gap:14px;padding:16px 22px;
    border-bottom:1px solid var(--border);background:var(--surface)}
  header h1{font-size:17px;margin:0;font-weight:650}
  header .dot{width:9px;height:9px;border-radius:50%;background:var(--pass);
    box-shadow:0 0 0 4px rgba(27,175,122,.18)}
  .health{display:flex;gap:8px;position:relative}
  /* 稼働ボタン。中身は pointer-events:none にして、どこを押してもボタン自身が押されたことにする */
  .hp{display:inline-flex;align-items:center;gap:10px;padding:5px 12px;border-radius:999px;font-size:12px;
    font-family:inherit;border:1px solid var(--border);background:var(--surface-2);color:var(--ink-2);cursor:pointer;white-space:nowrap}
  .hp *{pointer-events:none}
  .hp:hover{border-color:var(--ink-muted)}
  .hp .seg{display:inline-flex;align-items:center;gap:6px}
  .hp .sep{width:1px;height:14px;background:var(--border)}
  .hp .car{color:var(--ink-muted);font-size:10px}
  .hp i{width:9px;height:9px;border-radius:50%;background:var(--ink-muted);display:inline-block}
  .hp b{color:var(--ink);font-weight:650}
  .hp .seg.up i{background:var(--pass)} .hp .seg.slow i{background:var(--detect)}
  .hp .seg.error i,.hp .seg.down i{background:var(--block)}
  .hp .seg.down i{animation:hpPulse 1.2s infinite}
  .hp.down,.hp.error{border-color:var(--block)} .hp.slow{border-color:var(--detect)}
  @keyframes hpPulse{0%{box-shadow:0 0 0 0 rgba(227,73,72,.6)}100%{box-shadow:0 0 0 8px rgba(227,73,72,0)}}
  .hpanel{display:none;position:absolute;top:34px;left:0;z-index:60;width:460px;max-width:92vw;background:var(--surface);
    border:1px solid var(--border);border-radius:10px;padding:12px 14px;box-shadow:0 10px 30px rgba(0,0,0,.35);font-size:12.5px}
  .hpanel.on{display:block}
  .hpanel .logbtn{display:block;margin:10px 0 0;padding:7px 10px;text-align:center;border-radius:8px;font-size:12.5px;
    border:1px solid var(--border);background:var(--surface-2);color:var(--ink);text-decoration:none;font-weight:600}
  .hpanel .logbtn:hover{border-color:var(--accent)}
  .hpanel h3{margin:0 0 6px;font-size:12.5px;color:var(--ink-2)}
  .hpanel .row{display:flex;justify-content:space-between;gap:10px;padding:2px 0;color:var(--ink-2)}
  .hpanel .row b{color:var(--ink)}
  .hpanel .spark{width:100%;height:34px;display:block;margin:4px 0 10px}
  .hpanel ul{list-style:none;margin:4px 0 0;padding:0;max-height:140px;overflow:auto}
  .hpanel li{padding:2px 0;color:var(--ink-2);border-top:1px solid var(--border)}
  header .meta{margin-left:auto;color:var(--ink-muted);font-size:12px;text-align:right}
  .nav{display:flex;gap:4px;padding:0 22px;background:var(--surface);
    border-bottom:1px solid var(--border);position:sticky;top:var(--ab-h,0px);z-index:30;
    overflow-x:auto;scrollbar-width:none}
  .nav::-webkit-scrollbar{display:none}
  .nav button{background:none;border:none;color:var(--ink-2);font-size:13.5px;
    padding:12px 14px;cursor:pointer;white-space:nowrap;border-bottom:2px solid transparent;
    font-weight:550;font-family:inherit}
  .nav button:hover{color:var(--ink)}
  .nav button.on{color:var(--ink);border-bottom-color:var(--accent,#3987e5)}
  .page{display:none}
  .page.on{display:block;animation:fadein .18s ease}
  @keyframes fadein{from{opacity:.4}to{opacity:1}}
  main{padding:20px 22px;max-width:1500px;margin:0 auto}
  body[data-page="log"] main{max-width:none;padding:20px 28px}
  body[data-page="log"] .be-side{width:280px}
  main>.page>.grid{margin-top:0}
  .kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
  .kpi{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:14px 16px}
  .kpi .label{color:var(--ink-muted);font-size:12px}
  .kpi .value{font-size:26px;font-weight:680;margin-top:6px;line-height:1}
  .kpi .sub{font-size:11px;color:var(--ink-muted);margin-top:4px}
  .v-pass{color:var(--pass)} .v-block{color:var(--block)}
  .v-detect{color:var(--detect)} .v-rate{color:var(--rate)}
  .kpi.k-green{border-left:3px solid var(--pass)}
  .kpi.k-red{border-left:3px solid var(--block)}
  .kpi.k-amber{border-left:3px solid var(--detect)}
  .kpi.k-purple{border-left:3px solid var(--rate)}
  .kpi.k-neutral{border-left:3px solid var(--ink-2)}
  .kpi.k-grey{border-left:3px solid var(--border)}
  .signal-legend{display:flex;flex-wrap:wrap;gap:16px;align-items:center;margin-top:12px;
    padding:9px 14px;background:var(--surface);border:1px solid var(--border);border-radius:10px;
    font-size:12px;color:var(--ink-2)}
  .signal-legend .sl-title{font-weight:650;color:var(--ink)}
  .signal-legend span{display:inline-flex;align-items:center;gap:6px}
  .signal-legend i{width:11px;height:11px;border-radius:50%;display:inline-block}
  .signal-legend b{color:var(--ink);font-weight:600}
  .grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:16px}
  @media(max-width:820px){.grid{grid-template-columns:1fr}}
  .card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:16px 18px}
  .card h2{font-size:13px;margin:0 0 14px;color:var(--ink-2);font-weight:600}
  .full{grid-column:1 / -1}
  .bar-row{display:flex;align-items:center;gap:10px;margin:9px 0}
  .bar-row .name{width:84px;color:var(--ink-2);font-size:12.5px;flex:none}
  .bar-track{flex:1;background:var(--surface-2);border-radius:5px;height:16px;overflow:hidden}
  .bar-fill{height:100%;border-radius:5px;min-width:2px;transition:width .4s}
  .bar-row .num{width:42px;text-align:right;font-variant-numeric:tabular-nums}
  table{width:100%;border-collapse:collapse;font-size:12.5px}
  th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--border);
    white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  th{color:var(--ink-muted);font-weight:500}
  td.path{max-width:260px}
  .tag{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:600}
  .cnt-badge{display:inline-block;margin-left:5px;padding:1px 7px;border-radius:999px;
    font-size:11px;font-weight:700;background:var(--block);color:#fff;vertical-align:middle}
  .tag.PASS{background:rgba(27,175,122,.16);color:#6fd6ab}
  .tag.BLOCK{background:rgba(227,73,72,.18);color:#f08a89}
  .tag.DETECT{background:rgba(237,161,0,.18);color:#f0c257}
  .tag.RATELIMIT{background:rgba(144,133,233,.2);color:#b3abf0}
  .tag.ERROR{background:rgba(139,138,128,.2);color:#c3c2b7}
  #recent tbody tr{cursor:pointer}
  #recent tbody tr:hover{background:var(--surface-2)}
  .recent-wrap{max-height:max(540px,calc(100vh - 340px));overflow:auto;border-radius:8px}
  .recent-wrap thead th{position:sticky;top:0;background:var(--surface);z-index:1}
  .logfilter{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:10px}
  .logfilter select,.logfilter input{background:var(--surface-2);color:var(--ink);
    border:1px solid var(--border);border-radius:7px;padding:5px 9px;font-size:12.5px}
  .logfilter input{flex:1;min-width:160px}
  .logfilter .lf-chk{font-size:12.5px;color:var(--ink-2);display:inline-flex;align-items:center;gap:6px;white-space:nowrap;cursor:pointer}
  .logfilter input[type=checkbox]{flex:none;min-width:0;width:15px;height:15px;padding:0;margin:0;accent-color:var(--accent)}
  .logfilter .lf-dt{font-size:11px;color:var(--ink-muted);display:flex;align-items:center;gap:4px}
  .logfilter .lf-dt input{flex:none;min-width:0;color-scheme:dark}
  :root[data-theme="light"] .logfilter .lf-dt input{color-scheme:light}
  .logfilter .lf-clr{background:var(--surface-2);color:var(--ink-2);border:1px solid var(--border);
    border-radius:7px;padding:5px 11px;font-size:12px;cursor:pointer}
  .logfilter .lf-clr:hover{color:var(--ink)}
  .logfilter .lf-count{color:var(--ink-muted);font-size:12px;margin-left:auto}
  .ipcell small{color:var(--ink-muted);font-size:11px}
  .ctbl td{font-variant-numeric:tabular-nums}
  .ctrack{background:var(--surface-2);border-radius:5px;height:14px;overflow:hidden}
  .ctrack .cfill{height:100%;border-radius:5px;min-width:2px;transition:width .4s}
  .cblock{background:var(--surface-2);color:var(--block);border:1px solid var(--border);
    border-radius:6px;padding:3px 10px;font-size:11px;cursor:pointer}
  .cblock:hover{background:var(--block);color:#fff;border-color:var(--block)}
  .insights{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px}
  .ins{background:var(--surface-2);border:1px solid var(--border);border-radius:10px;padding:11px 13px;
    border-left:3px solid var(--ink-2)}
  .ins.k-red{border-left-color:var(--block)} .ins.k-amber{border-left-color:var(--detect)}
  .ins.k-purple{border-left-color:var(--rate)} .ins.k-neutral{border-left-color:var(--ink-2)}
  .ins-l{font-size:11.5px;color:var(--ink-muted)}
  .ins-v{font-size:17px;font-weight:650;margin-top:4px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .ins-s{font-size:11px;color:var(--ink-muted);margin-top:3px}
  .sev-wrap{margin-top:16px}
  .sev-title{font-size:12px;color:var(--ink-2);margin-bottom:6px;font-weight:600}
  .sevrow{display:flex;gap:2px;height:26px;border-radius:6px;overflow:hidden;background:var(--surface-2)}
  .sevseg{height:100%;display:flex;align-items:center;justify-content:center;font-size:11.5px;font-weight:700;
    white-space:nowrap;overflow:hidden;min-width:3px;background:var(--c);color:var(--ink-c)}
  .sev-critical{--c:var(--sev-critical);--ink-c:var(--sev-critical-ink)}
  .sev-high{--c:var(--sev-high);--ink-c:var(--sev-high-ink)}
  .sev-medium{--c:var(--sev-medium);--ink-c:var(--sev-medium-ink)}
  .sev-low{--c:var(--sev-low);--ink-c:var(--sev-low-ink)}
  .sevleg{display:flex;gap:16px;flex-wrap:wrap;margin-top:8px;font-size:12.5px;color:var(--ink-2)}
  .sevleg span{display:inline-flex;align-items:center;gap:6px}
  .sevleg i{width:12px;height:12px;border-radius:3px;background:var(--c)}
  .sevleg b{color:var(--ink);font-variant-numeric:tabular-nums}
  .banhist-wrap{max-height:320px;overflow:auto}
  /* Burp風タブ */
  .rtabs{display:flex;gap:6px;margin:4px 0 10px}
  .rtabs button{background:var(--surface-2);color:var(--ink-2);border:1px solid var(--border);
    border-radius:7px 7px 0 0;padding:6px 14px;cursor:pointer;font-size:12.5px}
  .rtabs button.on{background:var(--accent);color:#fff;font-weight:650;border-color:var(--accent)}
  pre.raw{background:var(--raw-bg);border:1px solid var(--border);border-radius:0 0 8px 8px;padding:11px 13px;
    font-size:12px;white-space:pre-wrap;word-break:break-all;max-height:440px;overflow:auto;
    color:var(--ink);margin:0;font-family:ui-monospace,Menlo,Consolas,monospace}
  pre.raw .hl{background:rgba(227,73,72,.28);color:var(--block);border-radius:3px;padding:0 1px;font-weight:650}
  pre.raw .ln1{color:var(--ink-2);font-weight:650}
  pre.raw .hk{color:var(--rate)}
  #modal .modal-card{width:min(1120px,100%)}
  .rr-cols{display:grid;grid-template-columns:1fr 1fr;gap:12px}
  @media(max-width:820px){.rr-cols{grid-template-columns:1fr}}
  .rr-pane{border:1px solid var(--border);border-radius:8px;overflow:hidden}
  .rr-head{display:flex;align-items:center;gap:8px;padding:7px 11px;background:var(--surface-2);
    border-bottom:1px solid var(--border);font-size:12px;font-weight:600;color:var(--ink-2)}
  .rr-head .st{font-variant-numeric:tabular-nums}
  .rr-head .sz{margin-left:auto;color:var(--ink-muted);font-weight:400;font-size:11px}
  .rr-head .cp{background:var(--surface);border:1px solid var(--border);border-radius:6px;
    color:var(--ink-2);font-size:11px;padding:2px 9px;cursor:pointer}
  .rr-head .cp:hover{color:var(--ink)}
  .stc-2{color:var(--pass)}.stc-3{color:var(--detect)}.stc-4{color:var(--block)}.stc-5{color:var(--block)}
  /* ルール管理 */
  .rcat{margin-bottom:14px}
  .rcat-head{display:flex;align-items:center;gap:10px;padding:7px 4px;border-bottom:1px solid var(--border)}
  .rcat-head .nm{font-weight:650;font-size:13px}
  .rcat-head .ct{color:var(--ink-muted);font-size:11.5px}
  .rrow{display:flex;align-items:center;gap:10px;padding:6px 8px;border-bottom:1px solid var(--surface-2);font-size:12.5px}
  .rrow .rid{font-family:ui-monospace,monospace;color:var(--ink-2);width:92px;flex:none}
  .rrow .rsev{width:70px;flex:none;font-size:11px}
  .rrow .rsev{font-weight:700}
  .rrow .rsev.critical{color:var(--sev-critical)}.rrow .rsev.high{color:var(--sev-high)}
  .rrow .rsev.medium{color:var(--sev-medium)}.rrow .rsev.low{color:var(--sev-low)}
  .rrow .rdesc{flex:1;color:var(--ink)}
  .rrow.off{opacity:.45}
  .seemore{font-size:11px;color:var(--ink-muted)}
  /* 詳細モーダル */
  .modal{position:fixed;inset:0;background:var(--modal-dim);display:none;align-items:flex-start;
    justify-content:center;z-index:50;padding:40px 16px;overflow:auto}
  .modal.open{display:flex}
  .modal-card{background:var(--surface);border:1px solid var(--border);border-radius:12px;
    width:min(760px,100%);max-height:85vh;overflow:auto;box-shadow:0 20px 60px #000a}
  .modal-head{display:flex;align-items:center;gap:10px;padding:14px 18px;
    border-bottom:1px solid var(--border);position:sticky;top:0;background:var(--surface)}
  .modal-head h3{margin:0;font-size:14px;font-weight:650}
  .modal-head .x{margin-left:auto;cursor:pointer;color:var(--ink-muted);font-size:20px;
    line-height:1;border:none;background:none}
  .modal-body{padding:16px 18px}
  .kv{display:grid;grid-template-columns:120px 1fr;gap:4px 12px;font-size:12.5px;margin-bottom:14px}
  .kv .k{color:var(--ink-muted)}
  .kv .v{color:var(--ink);word-break:break-all;font-variant-numeric:tabular-nums}
  .sec-title{font-size:12px;color:var(--ink-2);margin:14px 0 6px;font-weight:600}
  pre.payload{background:var(--raw-bg);border:1px solid var(--border);border-radius:8px;
    padding:10px 12px;font-size:12px;white-space:pre-wrap;word-break:break-all;
    max-height:280px;overflow:auto;color:var(--ink);margin:0}
  .hit{font-size:12px;border-left:3px solid var(--block);padding:4px 10px;margin:6px 0;
    background:var(--surface-2);border-radius:0 6px 6px 0}
  .hit code{color:#f0a; }
  /* 設定フォーム */
  .set-group{border:1px solid var(--border);border-radius:9px;padding:12px 14px;margin-bottom:12px}
  .set-group h4{margin:0 0 10px;font-size:12.5px;color:var(--ink-2);font-weight:600}
  .set-row{display:flex;align-items:center;justify-content:space-between;gap:12px;
    padding:6px 0;font-size:13px}
  .set-row .lbl{color:var(--ink)}
  .set-row .lbl small{display:block;color:var(--ink-muted);font-size:11px;margin-top:1px}
  .set-row input[type=number]{width:90px;background:var(--surface-2);color:var(--ink);
    border:1px solid var(--border);border-radius:6px;padding:4px 8px;font-size:13px}
  .seg{display:inline-flex;border:1px solid var(--border);border-radius:7px;overflow:hidden}
  .seg button{background:var(--surface-2);color:var(--ink-2);border:none;padding:5px 12px;
    cursor:pointer;font-size:12px}
  .seg button.on{background:var(--pass);color:#06281c;font-weight:650}
  .seg button.on.block{background:var(--block);color:#2a0a0a}
  .seg button.on.detect{background:var(--detect);color:#2a1f00}
  .sw{position:relative;width:38px;height:22px;flex:none;cursor:pointer}
  .sw input{opacity:0;width:0;height:0}
  .sw .track{position:absolute;inset:0;background:var(--surface-2);border:1px solid var(--border);
    border-radius:999px;transition:.2s}
  .sw .knob{position:absolute;top:2px;left:2px;width:17px;height:17px;background:#999;
    border-radius:50%;transition:.2s}
  .sw input:checked + .track{background:rgba(27,175,122,.5);border-color:var(--pass)}
  .sw input:checked + .track .knob{left:18px;background:var(--pass)}
  .set-ro{font-size:12px;color:var(--ink-muted);display:flex;justify-content:space-between;padding:3px 0}
  .set-ro code{color:var(--ink-2)}
  .set-foot{display:flex;align-items:center;gap:10px;margin-top:8px}
  .set-foot button{background:var(--pass);color:#06281c;border:none;border-radius:8px;
    padding:8px 18px;font-size:13px;font-weight:650;cursor:pointer}
  .set-foot .msg{font-size:12px;color:var(--ink-muted)}
  .set-note{font-size:11.5px;color:var(--ink-muted);margin-bottom:12px;line-height:1.5}
  .tl-wrap{width:100%;overflow:visible;position:relative}
  .tl-wrap svg{display:block;width:100%;height:auto}
  .tl-hit{cursor:crosshair}
  .tl-zoom{margin-left:14px;font-size:11.5px;color:var(--ink-muted);vertical-align:middle;
    display:inline-flex;align-items:center;gap:6px}
  .tl-zoom input[type=range]{width:120px;vertical-align:middle;accent-color:var(--accent,#3987e5)}
  .tl-zoom b{color:var(--ink-2);font-variant-numeric:tabular-nums;min-width:26px}
  #tltip .li{display:flex;align-items:center;gap:7px;margin:2px 0;font-size:12px;min-width:150px}
  #tltip .li i{width:9px;height:9px;border-radius:2px}
  #tltip .li b{margin-left:auto;font-variant-numeric:tabular-nums}
  svg{display:block}
  .legend{display:flex;gap:14px;flex-wrap:wrap;margin-top:10px;font-size:11.5px;color:var(--ink-2)}
  .legend span{display:inline-flex;align-items:center;gap:5px}
  .legend i{width:10px;height:10px;border-radius:2px;display:inline-block}
  .legend span[data-k]{user-select:none;transition:opacity .15s}
  .legend span.off{opacity:.35;text-decoration:line-through}
  .empty{color:var(--ink-muted);font-size:12.5px;padding:8px 0}
  code{background:var(--surface-2);padding:1px 5px;border-radius:4px;font-size:12px}
  .controls{display:flex;align-items:center;gap:8px}
  .controls button{background:var(--surface-2);color:var(--ink-2);border:1px solid var(--border);
    border-radius:7px;padding:5px 10px;cursor:pointer;font-size:12px}
  .controls button:hover{color:var(--ink)}
  /* 攻撃マップ */
  .map-head{display:flex;align-items:center;gap:16px;flex-wrap:wrap;margin-bottom:10px}
  .map-head .pill{font-size:12px;color:var(--ink-2);background:var(--surface-2);
    border:1px solid var(--border);border-radius:999px;padding:3px 11px}
  .map-head .pill b{color:var(--ink)}
  #mapWrap{position:relative;background:var(--ocean);border-radius:10px;overflow:hidden}
  #map{width:100%;height:auto;display:block}
  .attk{fill:var(--block);fill-opacity:.85}
  .attk-ring{fill:none;stroke:var(--block);stroke-width:1.5;opacity:.7}
  .attk.egress{fill:var(--detect);fill-opacity:.85}
  .attk-ring.egress{stroke:var(--detect)}
  .maptip{position:absolute;pointer-events:none;background:var(--surface);border:1px solid var(--border);
    border-radius:7px;padding:6px 9px;font-size:12px;color:var(--ink);display:none;z-index:5}
  .map-note{font-size:11.5px;color:var(--ink-muted);margin-top:9px;line-height:1.5}
  @keyframes pulse{0%{r:3;opacity:.9}100%{r:16;opacity:0}}
  .mapfilter{display:inline-flex;gap:6px;flex-wrap:wrap;margin-left:auto}
  .mapfilter .f{font-size:11.5px;padding:3px 10px;border-radius:999px;cursor:pointer;
    border:1px solid var(--border);background:var(--surface-2);color:var(--ink-muted);
    display:inline-flex;align-items:center;gap:5px;user-select:none}
  .mapfilter .f i{width:8px;height:8px;border-radius:50%}
  .mapfilter .f.on{color:var(--ink);border-color:var(--ink-muted)}
  .arc{fill:none;stroke-width:1;opacity:.28}
  .node{cursor:pointer}
  /* ライトテーマ: 地図の陸/海の差をはっきりさせ、線と点を濃く縁取る */
  :root[data-theme="light"] .arc{opacity:.75;stroke-width:1.6}
  :root[data-theme="light"] .node{stroke:#fff;stroke-width:1.2;vector-effect:non-scaling-stroke}
  :root[data-theme="light"] #mapWrap,:root[data-theme="light"] #rtWrap{border:1px solid var(--border)}
  /* ホバー判定は最前面の透明な当たり判定だけにする(動く弾/サーバ印/矢印に横取りさせない) */
  #arcs,#proj,#srv,#nodes,#rtproj,#rtsrv,#rtnodes{pointer-events:none}
  #hits circle{fill:transparent;pointer-events:all;cursor:pointer}
  .node.hov{stroke:var(--ink);stroke-width:2;fill-opacity:1;vector-effect:non-scaling-stroke}
  .srv-ring{fill:none;stroke:var(--ink);stroke-width:1.4}
  .rt-head{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:10px}
  .rt-live{display:inline-flex;align-items:center;gap:6px;font-size:12px;font-weight:650}
  .rt-live .p-dot{width:9px;height:9px;border-radius:50%;background:var(--block)}
  .rt-live.on .p-dot{background:var(--pass);animation:blink 1.1s infinite}
  @keyframes blink{50%{opacity:.25}}
  .rt-rate{font-size:12px;color:var(--ink-2)}
  .rt-last{font-size:12px;color:var(--ink-muted);margin-left:auto;font-variant-numeric:tabular-nums}
  .kpi .value.threat-LOW{color:var(--pass)}
  .kpi .value.threat-MEDIUM{color:var(--detect)}
  .kpi .value.threat-HIGH{color:var(--block)}
  .donut-wrap{display:flex;align-items:center;gap:18px;flex-wrap:wrap}
  .donut-legend{font-size:12.5px}
  .donut-legend .li{display:flex;align-items:center;gap:7px;margin:5px 0;min-width:170px}
  .donut-legend .li i{width:10px;height:10px;border-radius:2px}
  .donut-legend .li b{margin-left:auto;font-variant-numeric:tabular-nums;color:var(--ink)}
  .ipform{display:flex;gap:8px;margin-bottom:10px}
  .ipform input{flex:1;background:var(--surface-2);color:var(--ink);border:1px solid var(--border);
    border-radius:7px;padding:7px 10px;font-size:13px}
  .ipform button{background:var(--block);color:#fff;border:none;border-radius:7px;padding:7px 14px;
    font-size:13px;cursor:pointer;font-weight:600}
  .ipcols{display:grid;grid-template-columns:1fr 1fr;gap:16px}
  #page-ip.be-sel .ip-global{display:none!important}
  #page-ip.be-sel .ipcols{grid-template-columns:1fr}
  @media(max-width:700px){.ipcols{grid-template-columns:1fr}}
  .iplist{list-style:none;margin:0;padding:0;max-height:220px;overflow:auto}
  .iplist li{display:flex;align-items:center;gap:8px;padding:6px 8px;border-bottom:1px solid var(--border);font-size:12.5px}
  .iplist li .exp{color:var(--ink-muted);font-size:11px}
  .iplist li button{margin-left:auto;background:var(--surface-2);color:var(--ink-2);
    border:1px solid var(--border);border-radius:6px;padding:3px 9px;font-size:11px;cursor:pointer}
  .iplist li button:hover{color:var(--ink)}
  .ipsub{font-size:12px;color:var(--ink-muted);margin:0 0 8px;display:flex;align-items:center;gap:8px}
  .ipsub .clr{margin-left:auto;background:none;border:1px solid var(--border);color:var(--ink-2);
    border-radius:6px;padding:3px 9px;cursor:pointer;font-size:11px}
  .conn-sum{margin-left:auto;font-weight:400;color:var(--ink-2)}
  /* 状態ログ(タブ) */
  #page-status{--stop:#7b6fd6;--unk:#5d5c55}
  :root[data-theme="light"] #page-status{--stop:#6a5de0;--unk:#b9c0cc}
  .sl-cards{margin-top:12px;display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}
  .sl-card h2{margin:0 0 8px;font-size:13px;color:var(--ink-2);font-weight:600}
  .sl-state{display:flex;align-items:center;gap:8px;font-size:18px;font-weight:700}
  .sl-dot{width:11px;height:11px;border-radius:50%;background:var(--c,var(--unk));display:inline-block}
  .sl-up{--c:var(--pass)} .sl-slow{--c:var(--detect)} .sl-error,.sl-down{--c:var(--block)} .sl-unknown{--c:var(--unk)} .sl-stopped{--c:var(--stop)}
  .sl-sub{color:var(--ink-muted);font-size:12px;margin:2px 0 10px}
  .sl-kv{display:flex;justify-content:space-between;padding:3px 0;color:var(--ink-2);font-size:13px}
  .sl-kv b{color:var(--ink);font-variant-numeric:tabular-nums}
  .sl-tl{display:grid;grid-template-columns:130px 1fr;gap:6px 12px;align-items:center}
  .sl-tl .lab{color:var(--ink-2);font-size:13px}
  .sl-bar{position:relative;height:18px;border-radius:5px;background:var(--surface-2);border:1px solid var(--border);overflow:hidden}
  .sl-bar i{position:absolute;top:0;bottom:0;background:var(--c,var(--unk))}
  .sl-axis{display:flex;justify-content:space-between;color:var(--ink-muted);font-size:11px;margin:2px 0 0 142px}
  .sl-legend{display:flex;gap:14px;flex-wrap:wrap;font-size:12px;color:var(--ink-2);margin-top:8px}
  .sl-legend span{display:inline-flex;align-items:center;gap:5px}
  .sl-filters{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:8px}
  .sl-filters select,.sl-filters input{font:inherit;color:var(--ink);background:var(--surface-2);border:1px solid var(--border);border-radius:8px;padding:5px 10px}
  .sl-dl{color:var(--accent);text-decoration:none;font-size:12.5px}
  .sl-cnt{color:var(--ink-muted);font-size:12px;margin-left:auto}
  .sl-tablewrap{border:1px solid var(--border);border-radius:10px;overflow:auto;max-height:560px}
  .sl-table{width:100%;border-collapse:collapse;font-size:13px}
  .sl-table th,.sl-table td{padding:8px 12px;text-align:left;border-bottom:1px solid var(--border);white-space:nowrap}
  .sl-table td.d{white-space:normal;color:var(--ink-2);min-width:200px}
  .sl-table th{color:var(--ink-muted);font-weight:600;font-size:12px;position:sticky;top:0;background:var(--surface)}
  .sl-table tr:last-child td{border-bottom:none}
  .sl-chip{display:inline-flex;align-items:center;gap:6px;padding:1px 9px;border-radius:999px;font-size:12px;border:1px solid var(--border);background:var(--surface-2)}
  .sl-chip .sl-dot{width:8px;height:8px}
  .sl-empty{padding:26px;text-align:center;color:var(--ink-muted)}
  .sl-arrow{color:var(--ink-muted);padding:0 4px}
  .sl-note{color:var(--ink-muted);font-size:12px;margin-top:10px;line-height:1.7}
  .conn-n{color:var(--ink-2);font-variant-numeric:tabular-nums;font-size:12px}
  .conn-n.hot{color:var(--block);font-weight:700}

  /* 攻撃アラート(警報バナー)。赤×黒のハザードストライプと極太の明朝体で、装飾は上の帯だけ。数字・文字は下の情報行に大きく出す */
  .alertbar{position:sticky;top:0;z-index:60;background:#000;color:#fff;
    box-shadow:0 8px 26px rgba(229,16,29,.40);
    display:grid;grid-template-rows:1fr;
    transition:grid-template-rows .7s cubic-bezier(.3,.75,.3,1),opacity .45s ease,box-shadow .45s ease}
  .alertbar[hidden]{display:none}
  /* 下部表示。画面下に固定する上バナーの複製(JSで同期)。位置は body[data-abpos] で設定 */
  #alertBarB{position:fixed;top:auto;left:0;right:0;bottom:0;box-shadow:0 -8px 26px rgba(229,16,29,.40)}
  #alertBarB.collapsed .ab-wrap{transform:translateY(14px)}
  /* 下部は帯(ラベル)だけ出す。詳細・ボタンは出さず、閉じる/最小化は上のバナーで操作して下も連動する */
  #alertBarB .ab-wrap{position:relative}
  #alertBarB .ab-info{display:none!important}
  #alertBarB.min .ab-main,#alertBarB.min .ab-stripe.b{display:revert}
  body[data-abpos="top"] #alertBarB{display:none!important}
  /* 背景: 平常時は六角形を敷き、警報中は赤(EMERGENCY)に捲れてランダムに回転する。背面に敷くので操作は妨げない。1枚のcanvasで、回転中の範囲だけ描き直す */
  #alertBg{position:fixed;left:0;top:0;width:100%;height:100%;z-index:-1;pointer-events:none}
  :root[data-theme="dark"] #alertBg{background:#000000}   /* ダークモード: 六角形(黒)の隙間や捲れの途中に灰色の下地が見えないよう、下地も黒にする */
  body.hexbg{background-image:none}   /* 六角形の背景のときは、点の背景を消す */
  body{padding-bottom:var(--abb-h,0px);transition:padding-bottom .7s cubic-bezier(.3,.75,.3,1)}   /* 下バナー分の余白は一度に確定し、CSSで動かす(毎フレーム計算しない) */
  .ab-wrap{min-height:0;overflow:hidden;transition:transform .5s cubic-bezier(.25,.9,.3,1)}
  /* 消えるとき: 上に畳みながらフェードアウト */
  .alertbar.collapsed{grid-template-rows:0fr;opacity:0;box-shadow:0 0 0 rgba(229,16,29,0)}
  .alertbar.collapsed .ab-wrap{transform:translateY(-14px)}
  /* 出るとき: 上から展開し、警告文字が現れ、赤い光が左から右へ走り、情報行がせり上がる */
  .alertbar.enter .ab-main{animation:abStamp .7s cubic-bezier(.2,1.25,.4,1) both}
  @keyframes abStamp{0%{transform:scale(1.28);opacity:0;filter:brightness(2.4)}55%{opacity:1}100%{transform:none;opacity:1;filter:none}}
  .ab-main::after{content:"";position:absolute;top:0;bottom:0;left:0;width:26%;pointer-events:none;opacity:0;
    background:linear-gradient(90deg,transparent,rgba(255,70,80,.6),transparent)}
  .alertbar.enter .ab-main::after{animation:abSweep 1s .12s ease-out both}
  @keyframes abSweep{0%{transform:translateX(-110%);opacity:1}100%{transform:translateX(480%);opacity:1}}
  .alertbar.enter .ab-info{animation:abInfoIn .55s .18s ease-out both}
  @keyframes abInfoIn{from{transform:translateY(-10px);opacity:0}to{transform:none;opacity:1}}
  .alertbar.enter .ab-lv{animation:abPop .55s .25s cubic-bezier(.2,1.7,.4,1) both}
  @keyframes abPop{from{transform:scale(.3);opacity:0}to{transform:none;opacity:1}}
  .alertbar.enter .ab-stripe{animation:abStripe 1.6s linear infinite,abStripeFlash .9s ease-out}
  @keyframes abStripeFlash{0%{filter:brightness(3)}100%{filter:none}}
  /* 「警戒」から「緊急」に上がったとき一瞬ゆれる */
  .alertbar.shake .ab-wrap{animation:abShake .5s ease-in-out}
  @keyframes abShake{0%,100%{transform:none}15%{transform:translateX(-9px)}35%{transform:translateX(8px)}55%{transform:translateX(-5px)}75%{transform:translateX(3px)}}
  .ab-stripe{height:14px;background:linear-gradient(135deg,#e5101d 25%,#000 25%,#000 50%,#e5101d 50%,#e5101d 75%,#000 75%);
    background-size:24px 24px;animation:abStripe 1.6s linear infinite}
  .ab-stripe.b{animation-direction:reverse}
  @keyframes abStripe{to{background-position:24px 0}}
  .ab-main{position:relative;overflow:hidden;background:#000;padding:7px 0}
  .alertbar.crit .ab-main{animation:abGlow 2.4s ease-in-out infinite}
  @keyframes abGlow{0%,100%{background:#000}50%{background:#2a0508}}
  .ab-track{display:flex;width:max-content;animation:abScroll 60s linear infinite}
  .alertbar.crit .ab-track{animation-duration:34s}
  @keyframes abScroll{to{transform:translateX(-50%)}}
  .ab-cell{display:flex;align-items:center;gap:14px;padding:0 26px;flex:none}
  .ab-word{font-family:"Yu Mincho","YuMincho","Hiragino Mincho ProN","Noto Serif JP","Noto Serif CJK JP","MS PMincho",serif;
    font-weight:900;font-size:50px;line-height:1;letter-spacing:.05em;color:#ff2a36;
    -webkit-text-stroke:2px #ff2a36;text-shadow:0 0 16px rgba(255,42,54,.5)}
  .ab-tags{display:flex;flex-direction:column;gap:4px}
  .ab-tag{border:1.5px solid #ff2a36;color:#ff2a36;padding:2px 12px;min-width:158px;text-align:center;line-height:1.15}
  .ab-tag b{display:block;font-family:"Yu Mincho","YuMincho","Hiragino Mincho ProN","Noto Serif JP","Noto Serif CJK JP",serif;font-size:13px;font-weight:900}
  .ab-tag small{display:block;font:600 9px/1.2 "Times New Roman",serif;letter-spacing:.1em}
  .ab-info{display:flex;align-items:center;gap:8px 18px;flex-wrap:wrap;padding:9px 18px;background:#180606;
    border-top:1px solid #5a0a10;font-size:13px}
  .ab-lv{background:#ff2a36;color:#000;font-weight:800;padding:3px 12px;border-radius:4px;letter-spacing:.08em}
  .alertbar.crit .ab-lv{animation:abPulse 1.4s ease-in-out infinite}
  @keyframes abPulse{0%,100%{box-shadow:0 0 0 0 rgba(255,42,54,.7)}50%{box-shadow:0 0 0 7px rgba(255,42,54,0)}}
  .ab-title{font-weight:650;color:#fff}
  .ab-stat{display:flex;align-items:baseline;gap:6px;color:#f1dcdc}
  .ab-stat b{font-size:20px;color:#fff;font-variant-numeric:tabular-nums;line-height:1.1}
  .ab-stat b.sm{font-size:14px;word-break:break-all}
  .ab-stat small{color:#d4b4b4;font-size:11px}
  .set-row select{background:var(--surface-2);color:var(--ink);border:1px solid var(--border);border-radius:6px;padding:5px 8px;font-size:12.5px}
  .ab-btns{margin-left:auto;display:flex;gap:8px}
  .ab-btns button{background:transparent;border:1px solid #9a3038;color:#f6e4e4;padding:4px 12px;border-radius:5px;cursor:pointer;font-size:12px}
  .ab-btns button:hover{background:#3a0b0f}
  .alertbar.min .ab-main,.alertbar.min .ab-stripe.b{display:none}
  /* ライトモード: 黒ベースをやめて画面のライトテーマに合わせる(赤は同じ #e91507) */
  :root[data-theme="light"] .alertbar{background:var(--surface);color:var(--ink);box-shadow:0 8px 26px rgba(233,21,7,.22)}
  :root[data-theme="light"] #alertBarB{box-shadow:0 -8px 26px rgba(233,21,7,.22)}
  :root[data-theme="light"] .ab-stripe{background:linear-gradient(135deg,#e91507 25%,var(--surface) 25%,var(--surface) 50%,#e91507 50%,#e91507 75%,var(--surface) 75%);background-size:24px 24px}
  :root[data-theme="light"] .ab-main{background:var(--surface)}
  :root[data-theme="light"] .alertbar.crit .ab-main{animation-name:abGlowL}
  @keyframes abGlowL{0%,100%{background:#ffffff}50%{background:#fdebe9}}
  :root[data-theme="light"] .ab-word{color:#e91507;-webkit-text-stroke:2px #e91507;text-shadow:0 0 14px rgba(233,21,7,.25)}
  :root[data-theme="light"] .ab-tag{border-color:#e91507;color:#e91507}
  :root[data-theme="light"] .ab-info{background:var(--surface-2);border-top:1px solid var(--border)}
  :root[data-theme="light"] .ab-lv{background:#e91507;color:#fff}
  :root[data-theme="light"] .ab-title,:root[data-theme="light"] .ab-stat b{color:var(--ink)}
  :root[data-theme="light"] .ab-stat{color:var(--ink-2)}
  :root[data-theme="light"] .ab-stat small{color:var(--ink-muted)}
  :root[data-theme="light"] .ab-btns button{border-color:var(--border);color:var(--ink-2);background:var(--surface)}
  :root[data-theme="light"] .ab-btns button:hover{background:var(--surface-2);color:var(--ink)}
  :root[data-theme="light"] #alertChip{background:#e91507;color:#fff}
  .alertbar.min .ab-info{padding:6px 18px}
  #alertChip{display:none;background:#ff2a36;color:#000;border:none;border-radius:999px;padding:4px 12px;
    font-weight:800;font-size:12px;cursor:pointer;animation:abPulse 1.4s ease-in-out infinite}
  #alertChip.on{display:inline-block}
  @media (prefers-reduced-motion:reduce){.alertbar,.alertbar *,#alertChip{animation:none!important;transition:none!important}}

  /* 攻撃マップの全画面表示。CSSで画面いっぱいにし、アラートバナーの高さぶん下げる。ブラウザ全画面(F11相当)も試す。Escで戻る */
  .mapfs{float:right;background:var(--surface-2);color:var(--ink-2);border:1px solid var(--border);
    border-radius:7px;padding:3px 11px;font-size:12px;cursor:pointer;margin-top:-3px}
  .mapfs:hover{color:var(--ink);border-color:var(--ink-muted)}
  body.mapfs-lock{overflow:hidden}
  .card.mapfull{position:fixed;left:0;right:0;bottom:var(--abb-h,0px);top:var(--ab-h,0px);z-index:50;margin:0;border-radius:0;border:none;
    padding:10px 14px;display:flex;flex-direction:column;background:var(--bg);animation:mapfsIn .28s ease}
  @keyframes mapfsIn{from{opacity:0;transform:scale(.985)}to{opacity:1;transform:none}}
  .card.mapfull h2{margin:0 0 8px}
  .card.mapfull .rt-head,.card.mapfull .map-head{margin-bottom:8px}
  .card.mapfull .map-note{display:none}
  .card.mapfull #rtWrap,.card.mapfull #mapWrap{flex:1;min-height:0;border-radius:8px}
  .card.mapfull #rtmap,.card.mapfull #map{width:100%;height:100%}
  @media (prefers-reduced-motion:reduce){.card.mapfull{animation:none}}
  /* イベントログの全画面: 表を画面いっぱいにする */
  .card.mapfull .recent-wrap{flex:1;min-height:0;max-height:none}
  .card.mapfull .logfilter{margin-bottom:8px}
  .card.mapfull #recent{font-size:13px}
  #modal{z-index:60}
  /* バックエンド別の表示(件数チップ・表の印) */
  .health .seg[hidden],.health .sep[hidden]{display:none}
  .log-split{display:flex;gap:12px;align-items:flex-start}
  .log-main{flex:1;min-width:0}
  .be-side{width:250px;flex:none;max-height:max(540px,calc(100vh - 340px));overflow:auto;display:flex;flex-direction:column;gap:6px;
    border:1px solid var(--border);border-radius:10px;padding:10px;background:var(--surface-2)}
  .be-side[hidden]{display:none}
  .be-side .be-side-h{font-size:11.5px;font-weight:650;color:var(--ink-2);margin:0 0 2px}
  .be-side .bechip{border-radius:8px;display:flex;flex-wrap:wrap;gap:3px 7px;padding:6px 9px;background:var(--surface)}
  .be-side .bechip small{flex-basis:100%;margin-left:16px}
  .card.mapfull .log-split{flex:1;min-height:0}
  .card.mapfull .log-main{display:flex;flex-direction:column;min-height:0;align-self:stretch}
  .card.mapfull .be-side{max-height:none;align-self:stretch}
  @media(max-width:900px){.log-split{flex-direction:column}.be-side{width:auto;max-height:none;flex-direction:row;flex-wrap:wrap}}
  .bechip{display:inline-flex;align-items:center;gap:7px;background:var(--surface-2);color:var(--ink-2);border:1px solid var(--border);
    border-radius:999px;padding:4px 12px;font-size:12.5px;cursor:default;user-select:none}
  .bechip.on{color:var(--ink);border-color:var(--c,var(--accent,#3987e5));box-shadow:0 0 0 1px var(--c,var(--accent,#3987e5)) inset}
  .bechip i{width:9px;height:9px;border-radius:50%;background:var(--c,var(--ink-muted));display:inline-block}
  .bechip b{font-variant-numeric:tabular-nums}
  .bechip small{color:var(--ink-muted);font-size:11px}
  .be-tag{display:inline-block;max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;vertical-align:bottom;
    font-size:11.5px;border:1px solid var(--c,var(--border));border-radius:999px;padding:0 8px;color:var(--ink-2)}
  .be-lp{font-size:11px;border:1px solid var(--border);color:var(--ink-2);border-radius:999px;padding:0 8px;margin-left:6px;font-family:ui-monospace,Consolas,monospace}
  .be-lp.bad{color:var(--block);border-color:var(--block)}

  /* 防御するバックエンド(設定) */
  .be-row{display:flex;align-items:center;gap:12px;padding:10px 12px;border:1px solid var(--border);border-radius:10px;
    margin:7px 0 0;background:var(--surface-2);transition:border-color .2s,box-shadow .2s}
  .be-row.act{border-color:var(--pass);box-shadow:0 0 0 1px var(--pass) inset}
    .be-row.stopped{border-color:#7b6fd6;box-shadow:0 0 0 1px #7b6fd6 inset;opacity:.92}
  .be-badge.stp{background:#7b6fd6;color:#fff}
  .be-owner{font-size:11px;color:var(--ink-muted);margin-left:6px}
  .be-btns button.pri{border-color:var(--accent);color:var(--accent)}
  .be-btns button.warn{border-color:#7b6fd6;color:#7b6fd6}
  body.limited .adm-only{display:none!important}
  .mode-warn{background:rgba(227,73,72,.14);border:1px solid var(--block);color:var(--ink);
    border-radius:8px;padding:8px 12px;margin-bottom:10px;font-weight:600}
  .mode-row{display:flex;flex-wrap:wrap;align-items:center;gap:10px;padding:9px 0;border-top:1px solid var(--border)}
  .mode-row:first-child{border-top:0}
  .mode-row .mnm{font-weight:600;min-width:140px}
  .mode-badge{display:inline-block;padding:1px 9px;border-radius:999px;font-size:12px;font-weight:700}
  .mode-badge.block{background:rgba(27,175,122,.18);color:var(--pass)}
  .mode-badge.detect{background:rgba(237,161,0,.2);color:var(--detect)}
  .mode-badge.lock{background:var(--surface-2);color:var(--ink-muted);font-weight:600}
  .mode-row .grow{flex:1}
  .mode-row button{background:var(--surface-2);color:var(--ink);border:1px solid var(--border);
    border-radius:7px;padding:5px 11px;cursor:pointer;font-size:13px}
  .mode-row button:hover:not(:disabled){border-color:var(--ink-muted)}
  .mode-row button:disabled{opacity:.5;cursor:not-allowed}
  .mode-row select{background:var(--surface-2);color:var(--ink);border:1px solid var(--border);border-radius:7px;padding:4px 7px}
  .mode-row .mlocknote{color:var(--ink-muted);font-size:12px}
  body.limited:not(.analyst) #hdrRules{display:none!important}
  body.limited:not(.analyst) .lf-exp{display:none!important}
  body.analyst .adm-card{display:none!important}
  body.limited #page-ip .ipro-hide,body.limited #page-ip #banClear{display:none!important}
  body.guser #page-ip .ipform{display:none!important}
  body.kofficer .kpis, body.kofficer .signal-legend, body.kofficer #hdrRules, body.kofficer #hdrSettings, body.kofficer #hpill,
  body.kofficer #nav button:not([data-p="enc"]){display:none!important}
  body.kofficer #nav,body.kofficer #meta,body.kofficer .hdr-sep{display:none!important}
  body.kofficer header .controls{margin-left:auto}      /* メッセージ欄がないので、操作ボタンを右端に寄せる */
  .enc-page .enc-sec{margin:14px 0}.enc-page h3{margin:0 0 6px;font-size:14px}
  /* 暗号ログの配色。背景に対して文字が読める濃さにする(ライトは黄・赤を濃く、ダークは赤を明るく) */
  .enc-page{--e-ok:#34c58e;--e-warn:#f2b01e;--e-ng:#f27774;--e-mute:var(--ink-muted);--e-line:var(--border);--e-hl:rgba(74,144,226,.16)}
  :root[data-theme="light"] .enc-page{--e-ok:#0b7d4e;--e-warn:#8a5a00;--e-ng:#c4352e;--e-hl:rgba(47,111,237,.10)}
  .enc-page table{width:100%;border-collapse:collapse;font-size:12px}.enc-page th,.enc-page td{padding:5px 8px;border-bottom:1px solid var(--e-line);text-align:left;vertical-align:top}
  :root[data-theme="light"] .enc-page .seemore{color:var(--ink-2)}      /* ライトの補足文字は濃いめ(コントラスト4.5以上) */
  .enc-page th{color:var(--ink-2);font-weight:600;background:var(--surface-2)}
  .enc-page tbody tr:hover td{background:var(--e-hl)}
  /* 設定画面の文字入力・ボタンと暗号ログ画面のファイル選択を、ダークモードの色に合わせる */
  .set-row input[type=text],.set-row input[type=password],.set-row input:not([type]),.set-row textarea{background:var(--surface-2);color:var(--ink);border:1px solid var(--border);border-radius:6px;padding:5px 8px;font-size:12.5px;color-scheme:dark}
  .set-row input::placeholder{color:var(--ink-muted)}
  .set-row button{background:var(--surface-2);color:var(--ink);border:1px solid var(--border);border-radius:7px;padding:5px 11px;font-size:12px;cursor:pointer}
  .set-row button:hover{border-color:var(--accent)}
  .enc-page input[type=file]{color:var(--ink);color-scheme:dark;font-size:12px}
  .enc-page input[type=file]::file-selector-button{background:var(--surface-2);color:var(--ink);border:1px solid var(--border);border-radius:6px;padding:4px 10px;margin-right:8px;font-size:12px;cursor:pointer}
  .enc-page input[type=file]::file-selector-button:hover{border-color:var(--accent)}
  :root[data-theme="light"] .set-row input[type=text],:root[data-theme="light"] .set-row input[type=password],:root[data-theme="light"] .set-row input:not([type]),:root[data-theme="light"] .set-row textarea,:root[data-theme="light"] .enc-page input[type=file]{color-scheme:light}
  .enc-page button{background:var(--surface-2);color:var(--ink);border:1px solid var(--border);border-radius:6px;padding:4px 10px;font-size:12px;cursor:pointer}
  .enc-page button:hover:not(:disabled){border-color:var(--accent)}.enc-page button:disabled{opacity:.5;cursor:default}
  .enc-page textarea,.enc-page input[type=text],.enc-page input:not([type]),.enc-page input[type=datetime-local],.enc-page select{background:var(--surface-2);color:var(--ink);border:1px solid var(--e-line);border-radius:6px;padding:5px 7px}
  .enc-page :is(textarea,input,select):focus{outline:2px solid var(--accent);outline-offset:0}
  .enc-page .ok{color:var(--e-ok)}.enc-page .ng{color:var(--e-ng)}.enc-page .warn{color:var(--e-warn)}
  .enc-page .eb{display:inline-block;padding:1px 9px;border-radius:999px;font-size:11px;font-weight:600;border:1px solid currentColor;background:color-mix(in srgb,currentColor 12%,transparent)}
  .enc-page .eb.mute{color:var(--e-mute)}
  .enc-page .keybox{margin:8px 0;padding:8px;border:1px dashed var(--e-line);border-radius:8px;background:var(--surface)}
  .enc-page .keybox.loaded:not(.more) .kb-more{display:none}
  .enc-page .keybox.drag{border-color:var(--accent);background:var(--e-hl)}
  .enc-page .decbox{margin-top:10px;padding:8px;border:1px solid var(--e-ok);border-radius:8px;background:color-mix(in srgb,var(--e-ok) 5%,transparent)}
  .enc-page .decbox .dh{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:6px}
  .enc-page .enc-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px;margin:6px 0}
  .enc-page .enc-card{background:var(--surface);border:1px solid var(--e-line);border-radius:10px;padding:10px 12px}
  .enc-page .enc-card .k{font-size:11px;color:var(--ink-2)}.enc-page .enc-card .v{font-size:22px;font-weight:700;margin:2px 0}
  .enc-page .enc-card .v small{font-size:13px;font-weight:400;color:var(--ink-2)}
  .enc-page .enc-tabs{display:flex;flex-wrap:wrap;gap:4px;border-bottom:1px solid var(--e-line);margin:8px 0 10px}
  .enc-page .enc-tabs button{background:none;border:0;border-bottom:3px solid transparent;color:var(--ink-2);padding:8px 14px;font-size:13px;font-weight:600;cursor:pointer;border-radius:6px 6px 0 0}
  .enc-page .enc-tabs button:hover{background:var(--e-hl)}
  .enc-page .enc-tabs button.on{color:var(--ink);border-bottom-color:var(--accent)}
  .enc-page .enc-steps{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:6px}
  .enc-page .enc-steps span{padding:3px 12px;border-radius:999px;border:1px solid var(--e-line);font-size:12px;color:var(--ink-2)}
  .enc-page .enc-steps span.now{border-color:var(--accent);color:var(--ink);font-weight:600}
  .enc-page .enc-steps span.done{border-color:var(--e-ok);color:var(--e-ok)}
  .enc-page .snip{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11px;color:var(--ink-2);word-break:break-all;max-width:480px}
  .enc-page mark{background:color-mix(in srgb,var(--e-warn) 35%,transparent);color:inherit;border-radius:2px}
  body.guser #page-ip .iplist button{display:none!important}
  #page-ip.be-sel .ip-ban{display:block!important}
  .org-tbl{width:100%;border-collapse:collapse;font-size:12.5px}
  .org-tbl th,.org-tbl td{padding:6px 8px;border-top:1px solid var(--border);text-align:left;vertical-align:middle}
  .org-form{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:8px 0}
  .org-form input,.org-form select{max-width:180px}
  .tk-badge{display:inline-block;margin-left:6px;min-width:18px;padding:0 6px;border-radius:999px;background:var(--detect);color:#111;font-size:11px;font-weight:700;text-align:center}
  .tk-badge[hidden]{display:none}
  .tk-form{display:grid;grid-template-columns:120px 1fr;gap:8px 12px;align-items:center;max-width:760px}
  .tk-form input,.tk-form select,.tk-form textarea{background:var(--surface-2);color:var(--ink);border:1px solid var(--border);border-radius:7px;padding:6px 9px;font:inherit;width:100%;box-sizing:border-box}
  .tk-form textarea{min-height:84px;resize:vertical}
  .tk-ev{background:var(--surface-2);border:1px solid var(--border);border-radius:8px;padding:8px 10px;font-size:12.5px;color:var(--ink-2);word-break:break-all}
  .tk-item{border-top:1px solid var(--border);padding:10px 0}
  .tk-item:first-child{border-top:0}
  .tk-head{display:flex;flex-wrap:wrap;gap:8px;align-items:center;cursor:pointer}
  .tk-head .id{font-weight:700}
  .tk-st{display:inline-block;padding:1px 9px;border-radius:999px;font-size:12px;font-weight:700;background:var(--surface-2);color:var(--ink-2)}
  .tk-st.open{background:rgba(237,161,0,.2);color:var(--detect)} .tk-st.in_progress{background:rgba(57,135,229,.2);color:#6fa8f0}
  .tk-st.escalated{background:rgba(155,89,182,.22);color:#b58be0} .tk-hid{font-size:12.5px;margin:0 0 8px;display:flex;gap:10px;align-items:center;flex-wrap:wrap}
  .tk-stage{font-size:11.5px;color:var(--ink-muted)}
  .tk-st.done{background:rgba(27,175,122,.18);color:var(--pass)} .tk-st.rejected{background:rgba(227,73,72,.15);color:var(--block)}
  .tk-body{margin:8px 0 0 0;display:none} .tk-item.open .tk-body{display:block}
  .tk-cm{border-left:3px solid var(--border);padding:2px 10px;margin:6px 0;font-size:13px}
  .tk-act{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-top:8px}
  .tk-act input,.tk-act select{background:var(--surface-2);color:var(--ink);border:1px solid var(--border);border-radius:7px;padding:5px 8px}
  .tk-act button,.tk-form button,.ber-row button,#cusBody button{background:var(--surface-2);color:var(--ink);border:1px solid var(--border);border-radius:7px;padding:5px 11px;cursor:pointer;font-size:13px}
  #ruleGrid[data-rt="be"] #cusCard,#ruleGrid[data-rt="be"] #rhCard,#ruleGrid[data-rt="be"] #rgCard,
  #ruleGrid[data-rt="global"] #cusCard,#ruleGrid[data-rt="global"] #rhCard,#ruleGrid[data-rt="global"] #berCard,
  #ruleGrid[data-rt="custom"] #rgCard,#ruleGrid[data-rt="custom"] #rhCard,#ruleGrid[data-rt="custom"] #berCard,
  #ruleGrid[data-rt="hist"] #cusCard,#ruleGrid[data-rt="hist"] #rgCard,#ruleGrid[data-rt="hist"] #berCard{display:none!important}
  .ber-pick{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin:4px 0 12px}
  .ber-pick label{font-size:13px;font-weight:600;color:var(--ink-2)}
  .ber-pick select,.ber-pick input,.ber-flt select,.ber-flt input{background:var(--surface);color:var(--ink);border:1px solid var(--border);border-radius:8px;padding:6px 10px;font-size:13px}
  .ber-pick select{min-width:220px}
  .ber-flt{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0 6px}
  .ber-st{display:inline-flex;border:1px solid var(--border);border-radius:7px;overflow:hidden}
  .ber-st button{background:var(--surface);color:var(--ink-2);border:0;border-right:1px solid var(--border);padding:3px 9px;font-size:12px;cursor:pointer}
  .ber-st button:last-child{border-right:0}
  .ber-st button.on.ok{background:var(--pass,#1f9d55);color:#fff} .ber-st button.on.det{background:var(--detect);color:#fff} .ber-st button.on.off{background:var(--block);color:#fff}
  .ber-be{border-top:1px solid var(--border);padding:10px 0} .ber-be:first-child{border-top:0}
  .ber-st button:disabled{opacity:.45;cursor:not-allowed}
  .pset-head{display:flex;flex-wrap:wrap;align-items:center;gap:10px;margin:2px 0 10px}
  .pset-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:10px}
  .pset{border:1px solid var(--border);background:var(--surface);border-radius:12px;padding:12px;display:flex;flex-direction:column;gap:6px}
  .pset.on{border-color:var(--accent,#3987e5);box-shadow:0 0 0 1px var(--accent,#3987e5) inset}
  .pset h5{margin:0;font-size:14.5px;display:flex;align-items:center;gap:6px}
  .pset .pd{font-size:12px;color:var(--ink-muted);line-height:1.5;flex:1}
  .pset .pc{font-size:13px;font-weight:600} .pset .pc .b{color:var(--block)} .pset .pc .d{color:var(--detect)}
  .pset .pi{font-size:12px;color:var(--ink-2);line-height:1.5} .pset .pi b{color:var(--ink)}
  .pset button{background:var(--surface-2);color:var(--ink);border:1px solid var(--border);border-radius:7px;padding:5px 10px;font-size:12.5px;cursor:pointer}
  .pset button:disabled{opacity:.5;cursor:not-allowed}
  .pset.on button{background:var(--accent,#3987e5);color:#fff;border-color:transparent}
  .pset-allow{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin:10px 0;font-size:12.5px}
  .ber-adv{margin-top:14px;border-top:1px solid var(--border);padding-top:8px} .ber-adv summary{cursor:pointer;font-weight:600;padding:4px 0}
  .ber-chip{display:inline-block;margin:2px 4px 2px 0;padding:1px 8px;border-radius:999px;background:var(--surface-2);font-size:12px}
  .ber-chip.det{background:rgba(237,161,0,.2);color:var(--detect)} .ber-chip.exp{opacity:.55;text-decoration:line-through}
  .rdet{background:var(--surface-2);border:1px solid var(--border);border-radius:6px;padding:2px 9px;
    font-size:12px;cursor:pointer;color:var(--ink-2);margin-right:4px}
  .rdet.on{background:rgba(237,161,0,.2);color:var(--detect);border-color:var(--detect);font-weight:700}
  .user-chip{font-size:12px;color:var(--ink-2);border:1px solid var(--border);border-radius:999px;padding:3px 11px;background:var(--surface)}
  button.user-chip{cursor:pointer;font-family:inherit} button.user-chip:hover{border-color:var(--ink-muted)}
  button.user-chip::after{content:"▾";margin-left:6px;font-size:10px;color:var(--ink-muted)}
  .um-wrap{position:relative;display:inline-block}
  .um-menu{position:absolute;right:0;top:calc(100% + 6px);min-width:190px;background:var(--surface);border:1px solid var(--border);border-radius:10px;
    padding:5px;box-shadow:0 10px 30px rgba(0,0,0,.35);z-index:120;display:flex;flex-direction:column;gap:2px}
  .um-menu[hidden]{display:none}
  .controls .um-menu button{background:none;border:none;color:var(--ink);text-align:left;padding:8px 11px;border-radius:7px;font-size:13px;cursor:pointer;display:block;width:100%}
  .controls .um-menu button:hover{background:var(--surface-2)}
  .controls .um-menu button[hidden]{display:none}
  .controls .um-menu button.hdr-link.on{color:var(--accent);background:var(--surface-2)}
  .controls .um-menu .um-out{color:var(--block)}
  .um-sep{height:1px;background:var(--border);margin:4px 2px}.um-sep[hidden]{display:none}
  .dlg .acc-box button{background:var(--surface-2);color:var(--ink-2);border:1px solid var(--border);border-radius:7px;padding:5px 11px;font-size:12px;cursor:pointer}
  .dlg .acc-box{max-width:none} .dlg .acc-grid{grid-template-columns:130px 1fr}
  .user-chip b{color:var(--ink)} .user-chip small{color:var(--ink-muted);margin-left:4px}
  /* ボタン・入力欄の色(ダークモード対応)。.lf-clr は設定画面・アカウントでも使う */
  .lf-clr,#orgBody button,#sBody .acc-box button{background:var(--surface-2);color:var(--ink-2);border:1px solid var(--border);
    border-radius:7px;padding:5px 11px;font-size:12px;cursor:pointer}
  .lf-clr:hover,#orgBody button:hover,#sBody .acc-box button:hover{color:var(--ink)}
  #orgBody input:not([type=checkbox]),#orgBody select,#orgBody textarea{background:var(--surface-2);color:var(--ink);border:1px solid var(--border);
    border-radius:6px;padding:5px 8px;font-size:12.5px;color-scheme:dark}
  :root[data-theme="light"] #orgBody input,:root[data-theme="light"] #orgBody select{color-scheme:light}
  #orgBody input::placeholder{color:var(--ink-muted)}
  #sBody .acc-box .acc-tbl button{padding:2px 9px;font-size:11.5px}
  .acc-box{max-width:520px} .acc-box input[type=text],.acc-box input[type=password],.acc-box select{background:var(--surface-2);color:var(--ink);border:1px solid var(--border);border-radius:6px;padding:6px 9px;font-size:13px;box-sizing:border-box}
  .acc-grid{display:grid;grid-template-columns:140px 1fr;gap:8px 10px;align-items:center;margin:8px 0}
  .acc-grid input,.acc-grid select{width:100%}
  .acc-tbl{width:100%;border-collapse:collapse;font-size:12.5px;margin:6px 0 10px}
  .acc-tbl td,.acc-tbl th{padding:6px 8px;border-bottom:1px solid var(--border);text-align:left}
  .acc-tbl button{font-size:11.5px;padding:2px 9px;border:1px solid var(--border);background:var(--surface);color:var(--ink-2);border-radius:6px;cursor:pointer;margin-right:4px}
  .acc-msg{font-size:12px;margin:4px 0;min-height:1em} .acc-msg.ok{color:var(--pass)} .acc-msg.ng{color:var(--block)}
  #hBe .st.paused,.hp .seg.paused i{background:#7b6fd6}
  .hp .seg.paused i{background:#7b6fd6}
  .sl-paused{--c:#7b6fd6}
  .sl-live h3{margin:12px 0 6px;font-size:12.5px;color:var(--ink-2)} .sl-live h3:first-child{margin-top:0}
  .sl-live .row{display:flex;justify-content:space-between;gap:10px;padding:3px 0;font-size:12.5px;color:var(--ink-2)}
  .sl-live .row b{color:var(--ink);text-align:right}
  .sl-live .row.sel{cursor:pointer;border-radius:6px;padding:4px 6px} .sl-live .row.sel:hover{background:var(--surface-2)}
  .sl-live .spark{width:100%;height:34px;display:block;margin:4px 0 10px}
  .sl-live .spk-wrap{cursor:crosshair}
  .sl-live ul{list-style:none;margin:4px 0 0;padding:0;max-height:180px;overflow:auto;font-size:12.5px}
  .sl-live li{padding:3px 0;color:var(--ink-2);border-top:1px solid var(--border)}
  .sl-pick{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-top:12px}
  .sl-pick label{font-size:13px;font-weight:600;color:var(--ink-2)}
  .sl-pick select{background:var(--surface);color:var(--ink);border:1px solid var(--border);border-radius:8px;padding:6px 12px;font-size:13px;min-width:240px}
  .sl-big small{font-size:13px;font-weight:600;margin-left:6px;color:var(--ink-2)}
  .be-main{flex:1;min-width:0}
  .be-dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:7px;vertical-align:baseline}
  .be-main .nm{font-weight:650;font-size:13.5px}
  .be-main .url a{color:var(--accent);text-decoration:none} .be-main .url a:hover{text-decoration:underline}
  .be-main .url{color:var(--ink-muted);font-size:12px;font-family:ui-monospace,Consolas,monospace;word-break:break-all;margin-top:2px}
  .be-badge{background:var(--pass);color:#06281c;font-size:11px;font-weight:800;border-radius:999px;padding:1px 9px;margin-left:6px}
  .be-scope{font-size:11px;border:1px solid var(--border);color:var(--ink-2);border-radius:999px;padding:0 8px;margin-left:6px}
  .be-scope.g{color:var(--detect);border-color:var(--detect)}
  .be-btns{display:flex;gap:6px;flex:none}
  .be-btns button,.be-ed-foot button,#beAdd{background:var(--surface);color:var(--ink-2);border:1px solid var(--border);border-radius:7px;
    padding:4px 11px;font-size:12px;cursor:pointer}
  .be-btns button:hover,.be-ed-foot button:hover,#beAdd:hover{color:var(--ink);border-color:var(--ink-muted)}
  .be-btns button:disabled{opacity:.4;cursor:not-allowed}
  .be-xf{display:flex;gap:14px;flex-wrap:wrap;align-items:center}
  .be-xf label{display:flex;gap:5px;align-items:center;font-size:12.5px;color:var(--ink-2)}
  .be-res{font-size:12px;padding:3px 12px 0;line-height:1.55}
  .be-res.ok{color:var(--pass)} .be-res.ng{color:var(--block)} .be-res .hint{color:var(--detect)}
  .be-res small{color:var(--ink-muted)}
  .be-edit{scroll-margin-top:12px;margin:6px 0 0;padding:12px 14px;border:1px dashed var(--ink-muted);border-radius:10px;display:grid;
    grid-template-columns:150px 1fr;gap:9px 12px;align-items:center;background:var(--surface)}
  .be-edit label{font-size:12.5px;color:var(--ink-2)} .be-edit label small{display:block;color:var(--ink-muted);font-size:11px}
  .be-edit input[type=text],.be-edit select{background:var(--surface-2);color:var(--ink);border:1px solid var(--border);border-radius:6px;
    padding:6px 9px;font-size:13px;width:100%;box-sizing:border-box}
  .tk-live{font-size:12.5px;color:var(--accent,#3987e5);margin:0 0 8px;font-weight:600}
  .tk-item.flash{animation:tkflash 4s ease-out}
  @keyframes tkflash{from{background:rgba(57,135,229,.28)}to{background:transparent}}
  .be-ed-foot{grid-column:1/-1;display:flex;gap:10px;justify-content:flex-end;align-items:center;position:sticky;bottom:58px;z-index:3;
    background:var(--surface);padding:10px 0 4px;margin-top:2px;border-top:1px solid var(--border);box-shadow:0 -8px 10px -8px rgba(0,0,0,.45)}
  .be-ed-foot::before{content:"編集中 — 決定したあと、下の「保存して適用」で反映されます";margin-right:auto;font-size:12px;color:var(--ink-muted)}
  .be-ed-foot button{padding:7px 18px!important;font-size:13.5px!important}
  .be-ed-foot button[data-do=ok]{background:var(--accent,#3987e5)!important;color:#fff!important;border-color:transparent!important;font-weight:650}
  @media (max-width:760px){.be-edit{grid-template-columns:1fr}.be-row{flex-wrap:wrap}}
  /* ヒートマップ */
  .hm-wrap{overflow-x:auto}
  table.hm{border-collapse:separate;border-spacing:2px;width:100%;font-size:11px;table-layout:fixed}
  table.hm th{color:var(--ink-muted,#888);font-weight:500;padding:2px;text-align:center}
  table.hm td{height:22px;text-align:center;border-radius:3px;background:var(--surface-2,rgba(127,127,127,.08));color:var(--ink,#ddd);padding:0}
  table.hm td.hm-sum{background:transparent;font-weight:600}
  .hm-seg button{font-size:12px}

  /* ヘッダー右上(ルール / 設定) */
  header{flex-wrap:wrap}
  .controls .hdr-sep{width:1px;height:18px;background:var(--border);margin:0 2px}
  .controls button.hdr-link{display:inline-flex;align-items:center;gap:5px;color:var(--ink)}
  .controls button.hdr-link.on{border-color:var(--accent);color:var(--accent);background:var(--surface)}

  /* ホーム画面 */
  :root{--lim:#ef7d22;--sanitize:#4bb3c4}
  :root[data-theme="light"]{--lim:#e0661b}
  .hgrid{display:grid;grid-template-columns:minmax(0,2fr) minmax(0,1fr);gap:16px;margin-top:16px}
  .hgrid>.card{min-width:0;display:flex;flex-direction:column}
  .hgrid>.hfull{grid-column:1 / -1}
  @media(max-width:900px){.hgrid{grid-template-columns:1fr}}
  .card h2 .h2-link{float:right;font-size:11.5px;font-weight:500;color:var(--accent);text-decoration:none;cursor:pointer}
  .card h2 .h2-link:hover{text-decoration:underline}
  .card h2 .seemore{font-weight:400;margin-left:4px}
  .hs-row{margin-bottom:6px}
  .hs-head{display:flex;align-items:baseline;gap:8px;font-size:12.5px;color:var(--ink)}
  .hs-head i{width:9px;height:9px;border-radius:2px;display:inline-block;align-self:center}
  .hs-head b{font-weight:600;color:var(--ink-2)}
  .hs-row svg{display:block;width:100%;height:auto}
  .hdonut{display:flex;align-items:center;gap:22px;flex:1;cursor:pointer;flex-wrap:wrap;justify-content:center}
  .hdonut svg{width:190px;height:190px;flex:none}
  .hdonut .dl{flex:1;min-width:130px;font-size:12.5px}
  .hdonut .dl .li{display:flex;align-items:center;gap:8px;margin:7px 0}
  .hdonut .dl .li i{width:9px;height:9px;border-radius:2px;flex:none}
  .hdonut .dl .li .nm{min-width:0;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .hdonut .dl .li b{margin-left:auto;font-variant-numeric:tabular-nums;color:var(--ink)}
  .hdonut .dl .li span.pc{color:var(--ink-muted);min-width:38px;text-align:right}
  .hmap-wrap{position:relative;background:var(--ocean);border-radius:10px;overflow:hidden;flex:1;min-height:200px}
  .hmap-wrap svg{display:block;width:100%;height:100%}
  #hland path{fill:var(--land);stroke:var(--land-stroke);stroke-width:.5}
  .hmap-legend{position:absolute;left:10px;bottom:10px;display:flex;gap:10px;align-items:center;font-size:11px;
    color:#fff;background:rgba(30,36,48,.72);border-radius:8px;padding:4px 9px}
  .hmap-legend i{width:8px;height:8px;border-radius:50%;display:inline-block;margin-right:4px}
  .hmap-head{display:flex;align-items:center;gap:10px;margin-bottom:10px}
  .hmap-head .seg{margin-left:auto}
  .seg button.on.neutral{background:var(--accent);color:#fff}
  #hrecent{table-layout:fixed}
  #hrecent th,#hrecent td{padding:8px 6px}
  #hrecent th:nth-child(1){width:34%} #hrecent th:nth-child(2){width:19%} #hrecent th:nth-child(3){width:25%}
  #hrecent td.cat{font-weight:600}
  .htag{display:inline-block;padding:2px 10px;border-radius:6px;font-size:10.5px;font-weight:700;color:#fff;letter-spacing:.02em}
  .htag.BLOCK{background:var(--block)} .htag.DETECT{background:var(--detect);color:#2a1f00}
  .htag.SANITIZE{background:var(--sanitize);color:#06262c}
  .hscale{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}
  @media(max-width:700px){.hscale{grid-template-columns:repeat(2,minmax(0,1fr))}}
  .hscale .t{border:1px solid var(--border);border-radius:9px;padding:10px 12px;background:var(--surface-2)}
  .hscale .t b{display:block;font-size:24px;line-height:1.1;color:var(--lim);font-variant-numeric:tabular-nums}
  .hscale .t small{display:block;margin-top:4px;font-size:11px;color:var(--ink-muted)}
  .hsub-title{font-size:12.5px;font-weight:650;color:var(--ink);margin:14px 0 6px}
  .hlist{list-style:none;margin:0;padding:0}
  .hlist li{display:flex;align-items:center;gap:10px;padding:6px 0;border-top:1px solid var(--border);font-size:12.5px}
  .hlist li:first-child{border-top:none}
  .hlist .ip{font-variant-numeric:tabular-nums;min-width:110px}
  .hlist .bar{flex:1;height:6px;border-radius:3px;background:var(--surface-2);overflow:hidden}
  .hlist .bar>div{height:100%;border-radius:3px;background:var(--lim)}
  .hlist .n{min-width:64px;text-align:right;color:var(--ink-2);font-variant-numeric:tabular-nums}
  .hlist .why{color:var(--ink-muted);font-size:11px;min-width:84px}
  .hlist.warn .bar>div{background:var(--detect)}
  .hlist.warn li.hot .bar>div{background:var(--block)}
  .hempty{color:var(--ink-muted);font-size:12.5px;padding:6px 0}
  .hstatus{display:grid;grid-template-columns:1fr 1fr;column-gap:40px}
  @media(max-width:800px){.hstatus{grid-template-columns:1fr}}
  .hstatus .r{display:flex;gap:14px;padding:4px 0;font-size:12.5px}
  .hstatus .r span{color:var(--ink-muted);min-width:96px;flex:none}
  .hstatus .r b{font-weight:600;color:var(--ink);min-width:0;overflow-wrap:anywhere}
  .hstatus .r b.warn{color:var(--detect)}
  .hstatus .r b.good{color:var(--pass)}

  /* トラフィック: アクセス推移(3段)/ 判定別 / カテゴリ別 */
  .tr-lane{margin-top:6px}
  .tr-head{display:flex;align-items:baseline;gap:8px;flex-wrap:wrap;font-size:12.5px;color:var(--ink);margin:10px 0 2px}
  .tr-head i{width:9px;height:9px;border-radius:2px;display:inline-block;align-self:center}
  .tr-head .tt{font-weight:500}
  .tr-head .tot{font-weight:600;color:var(--ink-2)}
  .tr-badge{font-size:10.5px;font-weight:700}
  .tr-badge.good{color:var(--pass)} .tr-badge.bad{color:var(--block)} .tr-badge.flat{color:var(--ink-muted)}
  .tr-wrap{position:relative}
  .tr-wrap svg{display:block;width:100%;height:auto}
  .tr-tip{min-width:150px}
  .tr-tip .li{display:flex;align-items:center;gap:7px;margin:2px 0;font-size:12px}
  .tr-tip .li i{width:9px;height:9px;border-radius:2px;flex:none}
  .tr-tip .li b{margin-left:auto;padding-left:14px;font-variant-numeric:tabular-nums}
  .tr-tip .sub{color:var(--ink-muted);font-size:11px;margin-top:3px}
  .tr-note{font-size:11px;color:var(--ink-muted);margin-top:8px;line-height:1.5}

  /* 設定タブ / ダイアログ / ホームの接続先一覧 */
  .set-tabs{display:flex;gap:4px;border-bottom:1px solid var(--border);margin:0 0 14px;flex-wrap:wrap}
  .set-tabs button{background:none;border:none;border-bottom:2px solid transparent;color:var(--ink-2);
    padding:9px 14px;font-size:13px;cursor:pointer;margin-bottom:-1px}
  .set-tabs button:hover{color:var(--ink)}
  .set-tabs button.on{color:var(--ink);border-bottom-color:var(--accent);font-weight:650}
  .set-pane{display:none} .set-pane.on{display:block}
  #sBody{display:flex;flex-direction:column;height:calc(100vh - 260px);min-height:380px}
  #sBody>.set-scroll{flex:1 1 auto;min-height:0;overflow-y:auto;padding:0 8px 8px 0;overscroll-behavior:contain}
  #sBody>.set-tabs,#sBody>.set-note{flex:0 0 auto}
  #sBody>.set-foot{flex:0 0 auto;background:var(--surface);padding:12px 0 2px;border-top:1px solid var(--border);margin-top:8px}
  .dlg-ov{position:fixed;inset:0;background:var(--modal-dim);z-index:200;display:flex;align-items:center;justify-content:center;padding:16px}
  .dlg{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:18px 20px;max-width:460px;width:100%;
    box-shadow:0 12px 40px rgba(0,0,0,.35)}
  .dlg h3{margin:0 0 10px;font-size:15px}
  .dlg-b{font-size:13px;line-height:1.6;color:var(--ink-2)} .dlg-b p{margin:0 0 8px} .dlg-b b{color:var(--ink)}
  .dlg-f{display:flex;gap:8px;justify-content:flex-end;flex-wrap:wrap;margin-top:14px}
  .dlg-f button{border:1px solid var(--border);background:var(--surface-2);color:var(--ink);border-radius:8px;padding:7px 14px;font-size:12.5px;cursor:pointer}
  .dlg-f button.danger{background:var(--block);border-color:var(--block);color:#fff}
  .dlg-f button.ghost{background:none}
  .logmgr table{margin-top:4px}
  .logmgr td.n{text-align:right;font-variant-numeric:tabular-nums}
  .logmgr .gone{display:inline-block;margin-left:6px;padding:0 7px;border-radius:999px;font-size:10.5px;background:rgba(237,161,0,.18);color:var(--detect)}
  .logmgr button,.hbtn{background:var(--surface-2);color:var(--ink);border:1px solid var(--border);border-radius:7px;padding:4px 10px;font-size:12px;cursor:pointer}
  .logmgr button.danger{color:var(--block)} .logmgr button:disabled,.hbtn:disabled{opacity:.4;cursor:not-allowed}
  #hBe td,#hBe th{white-space:normal;overflow:visible}
  #hBe .nm{display:inline-block;margin-left:6px;padding:1px 9px;border-radius:999px;background:var(--surface-2);border:1px solid var(--border);font-size:11.5px}
  #hBe .st{display:inline-block;padding:2px 10px;border-radius:999px;font-size:11px;font-weight:700;color:#fff;background:var(--ink-muted)}
  #hBe .st.paused{background:#7b6fd6} #hBe .st.up{background:var(--pass)} #hBe .st.slow{background:var(--detect);color:#2a1f00} #hBe .st.down,#hBe .st.error{background:var(--block)}
  #hBe a{color:var(--accent);text-decoration:none} #hBe a:hover{text-decoration:underline}
  #hBe td.ops{text-align:right;white-space:nowrap} #hBe td.ops .hbtn{margin-left:6px}
  .hmap-wrap[data-hgo]{cursor:pointer}
</style>
</head>
<body>
<div class="alertbar" id="alertBar" hidden role="alert" aria-live="assertive"><div class="ab-wrap">
  <div class="ab-stripe"></div>
  <div class="ab-main"><div class="ab-track" id="abTrack"></div></div>
  <div class="ab-stripe b"></div>
  <div class="ab-info">
    <span class="ab-lv" id="abLv">警戒</span>
    <span class="ab-title" id="abTitle"></span>
    <span class="ab-stat"><b id="abN">0</b><small id="abNl">件</small></span>
    <span class="ab-stat" id="abIpsWrap"><b id="abIps">0</b><small>攻撃元IP</small></span>
    <span class="ab-stat"><b class="sm" id="abTop">-</b><small>攻撃方法</small></span>
    <span class="ab-stat"><b class="sm" id="abCty">-</b><small>攻撃元の国</small></span>
    <span class="ab-btns"><button type="button" id="abMin">最小化</button><button type="button" id="abClose">閉じる</button></span>
  </div>
</div></div>
<header>
  <span class="dot" id="dot"></span>
  <h1>WAF ダッシュボード</h1>
  <div class="health adm-only" id="health">
    <button type="button" class="hp unknown" id="hpill" title="クリックで状態ログ(稼働の詳細)を開く">
      <span class="seg" id="hp-backend"><i></i><span class="nm">接続先アプリ</span> <b>確認中…</b></span>
      <span class="sep"></span>
      <span class="seg" id="hp-waf"><i></i><span class="nm">WAF</span> <b>確認中…</b></span>
    </button>
  </div>
  <div class="meta" id="meta">読み込み中…</div>
  <div class="controls">
    <button type="button" id="alertChip" title="攻撃アラートを再表示">⚠ 警戒中</button>
    <div class="um-wrap" id="umWrap">
      <button type="button" class="user-chip" id="userChip" aria-haspopup="true" aria-expanded="false">メニュー</button>
      <div class="um-menu" id="umMenu" hidden>
        <button id="themeBtn" title="テーマ切替">🌙 ダーク</button>
        <button id="refreshBtn">更新</button>
        <button id="autoBtn">自動更新: ON</button>
        <span class="um-sep"></span>
        <button type="button" class="hdr-link" id="hdrRules" data-p="rules" title="検知ルールの一覧とON/OFF">🛡 ルール</button>
        <button type="button" class="hdr-link" id="hdrSettings" data-p="settings" title="WAFの設定">⚙ 設定</button>
        <button type="button" id="umAcc" hidden>アカウント設定</button>
        <span class="um-sep" id="umSep2" hidden></span>
        <button type="button" id="logoutBtn" class="um-out" hidden onclick="location.href='/logout'">ログアウト</button>
      </div>
    </div>
  </div>
</header>
<nav class="nav" id="nav">
  <button data-p="home" class="on">🏠 ホーム</button>
  <button data-p="map">🗺 マップ</button>
  <button data-p="traffic">📊 トラフィック</button>
  <button data-p="log">📋 イベントログ</button>
  <button data-p="ip">🚫 IP管理</button>
  <button data-p="status">🩺 状態ログ</button>
  <button data-p="tickets">📨 申請<span class="tk-badge" id="tkBadge" hidden></span></button>
  <button data-p="enc" id="navEnc" hidden>🔐 暗号ログ</button>
</nav>
<main>
  <div class="kpis" id="kpis"></div>
  <div class="signal-legend">
    <span class="sl-title">🚦 色の意味:</span>
    <span><i style="background:var(--pass)"></i><b>緑</b> 通過=正常</span>
    <span><i style="background:var(--detect)"></i><b>黄</b> 検知=要注意(監視して通過)</span>
    <span><i style="background:var(--block)"></i><b>赤</b> 遮断=危険(攻撃をブロック)</span>
    <span><i style="background:var(--rate)"></i><b>紫</b> レート制限=過剰アクセスを遮断</span>
  </div>

  <!-- ホーム ページ -->
  <section class="page on" id="page-home">
  <div class="sl-pick" style="margin-top:12px"><label for="homeOrg">組織</label><select id="homeOrg"><option value="">すべての組織</option></select><label for="homeBe">接続先</label>
    <select id="homeBe"><option value="">すべての接続先</option></select>
    <span class="seemore" id="homeBeNote"></span></div>
  <div class="hgrid">
    <div class="card">
      <h2>📈 アクセス推移 <span class="seemore">(直近1ヶ月)</span><a class="h2-link" data-hgo="traffic">詳しく →</a></h2>
      <div class="hs-row"><div class="hs-head"><i style="background:var(--pass)"></i>通常アクセス <b id="hs-allow-t"></b></div><div class="tr-wrap"><svg id="hsp-allow" preserveAspectRatio="xMidYMid meet"></svg><div class="maptip tr-tip"></div></div></div>
      <div class="hs-row"><div class="hs-head"><i style="background:var(--block)"></i>攻撃 <b id="hs-atk-t"></b></div><div class="tr-wrap"><svg id="hsp-atk" preserveAspectRatio="xMidYMid meet"></svg><div class="maptip tr-tip"></div></div></div>
      <div class="hs-row"><div class="hs-head"><i style="background:var(--lim)"></i>制限(DoS) <b id="hs-lim-t"></b></div><div class="tr-wrap"><svg id="hsp-lim" preserveAspectRatio="xMidYMid meet"></svg><div class="maptip tr-tip"></div></div></div>
    </div>
    <div class="card">
      <h2>🍩 攻撃カテゴリ <span class="seemore">(クリックで詳細)</span></h2>
      <div class="hdonut" id="hDonut" data-hgo="traffic" title="クリックでトラフィックの詳細へ"><svg id="hdonutSvg" viewBox="0 0 190 190"></svg><div class="dl" id="hDonutLg"></div></div>
    </div>

    <div class="card">
      <h2>🌐 アクセス元マップ <span class="seemore" id="hmapMeta"></span><a class="h2-link" data-hgo="map">マップの詳細 →</a></h2>
      <div class="hmap-head"><span class="seemore" id="hmapNote"></span>
        <span class="seg" id="hmapSeg"><button data-m="all" class="on neutral">すべて</button><button data-m="atk">攻撃のみ</button></span></div>
      <div class="hmap-wrap" data-hgo="map" title="クリックでマップの詳細へ">
        <svg id="hmap" viewBox="0 0 960 480" preserveAspectRatio="xMidYMid meet"><g id="hland"></g><g id="hnodes"></g></svg>
        <div class="hmap-legend"><span><i style="background:var(--block)"></i>攻撃</span><span><i style="background:var(--pass)"></i>通常アクセス</span><span>カーソルで件数を表示</span></div>
      </div>
    </div>
    <div class="card">
      <h2>🚨 最近の攻撃<a class="h2-link" data-hgo="log">ログ →</a></h2>
      <table id="hrecent"><thead><tr><th>時刻</th><th>判定</th><th>IP</th><th>カテゴリ</th></tr></thead><tbody></tbody></table>
    </div>

    <div class="card">
      <h2>🌊 DoS・アクセス制限の規模 <span class="seemore">(件数ではなく規模で表示・直近1ヶ月)</span></h2>
      <div class="hscale" id="hScale"></div>
      <div class="hsub-title">制限した送信元の上位</div>
      <div id="hScaleTop"></div>
    </div>
    <div class="card adm-only">
      <h2>👀 要注意IP <span class="seemore">(BANのしきい値に近づいている送信元)</span></h2>
      <div id="hWatch"><div class="hempty">読み込み中…</div></div>
    </div>

    <div class="card hfull">
      <h2>🔌 監視中のアプリ(接続先) <span class="seemore" id="hBeCount"></span><a class="h2-link" data-hgo="settings-backend">接続先を管理 →</a></h2>
      <table id="hBe"><thead><tr><th>アプリ</th><th>待ち受け(利用者の接続先)</th><th>転送先(アプリ本体)</th><th>状態</th><th></th></tr></thead><tbody></tbody></table>
      <div class="map-note">利用者は「待ち受け」のアドレスにアクセスします。WAFが検査して「転送先」のアプリ本体へ中継します。接続先の変更・削除は即時反映され、再起動後も保存されます。</div>
    </div>

    <div class="card hfull adm-only">
      <h2>🛡 稼働状況</h2>
      <div class="hstatus" id="hStatus"><div class="hempty">読み込み中…</div></div>
    </div>
  </div>
  </section>

  <!-- 暗号ログ ページ(キー・オフィサー / 管理者の確認用) -->
  <section class="page" id="page-enc"><div id="encBody" class="enc-page"><div class="hempty">読み込み中…</div></div></section>

  <!-- マップ ページ -->
  <section class="page" id="page-map">
  <div class="sl-pick" style="margin-top:12px"><label for="mapOrg">組織</label><select id="mapOrg"><option value="">すべての組織</option></select><label for="mapBe">接続先</label>
    <select id="mapBe"><option value="">すべての接続先</option></select>
    <span class="seemore" id="mapBeNote"></span></div>
  <div class="grid">
    <!-- リアルタイム攻撃マップ(SSE。発生した瞬間のみ) -->
    <div class="card full">
      <h2><button type="button" class="mapfs" title="全画面で表示(Escで戻る)">⛶ 全画面</button>リアルタイム攻撃マップ <span class="seemore">— 発生した瞬間のリクエストだけを表示(ライブストリーム)</span></h2>
      <div class="rt-head">
        <span class="rt-live" id="rtLive"><span class="p-dot"></span><span id="rtStatus">接続中…</span></span>
        <span class="rt-rate" id="rtRate">0 req/s</span>
        <span class="mapfilter" id="rtFilter"></span>
        <span class="rt-last" id="rtLast"></span>
      </div>
      <div id="rtWrap" style="position:relative;background:var(--ocean);border-radius:10px;overflow:hidden">
        <svg id="rtmap" viewBox="0 0 960 480" preserveAspectRatio="xMidYMid meet">
          <g id="rtland"></g><g id="rtarc"></g><g id="rtproj"></g><g id="rtsrv"></g><g id="rtnodes"></g>
        </svg>
        <div class="maptip" id="rttip"></div>
      </div>
      <div class="map-note">各点が1リクエスト(dropの集約 ×N は最大8発で表現)。発生直後に送信元→防御サーバへ流れ、数秒で消えます(累積なし)。送信元がサーバと同じ位置(LAN内・同一ホスト・同じ出口IP)の場合は、サーバ位置に大きな波紋で表示します。右上フィルタで種類を切替。<b>スクロールでズーム / ドラッグで移動 / ダブルクリックで戻す</b>。</div>
    </div>

    <!-- 攻撃マップ(集計・直近) -->
    <div class="card full">
      <h2><button type="button" class="mapfs" title="全画面で表示(Escで戻る)">⛶ 全画面</button>攻撃マップ(集計)
        <span class="seg" id="mapRange" style="margin-left:10px;vertical-align:middle">
          <button data-r="today">今日</button>
          <button data-r="week">週</button>
          <button data-r="year">年</button>
          <button data-r="all" class="on">全期間</button>
        </span>
      </h2>
      <div class="map-head">
        <span class="pill">送信元ノード <b id="m-pub">0</b></span>
        <span class="pill">内部/ローカル <b id="m-int">0</b></span>
        <span class="pill">国別トップ <b id="m-top">—</b></span>
        <span class="mapfilter" id="mapFilter"></span>
      </div>
      <div id="mapWrap">
        <svg id="map" viewBox="0 0 960 480" preserveAspectRatio="xMidYMid meet">
          <g id="land"></g><g id="arcs"></g><g id="nodes"></g><g id="proj"></g><g id="srv"></g><g id="hits"></g>
        </svg>
        <div class="maptip" id="maptip"></div>
      </div>
      <div class="map-note" id="mapNote"></div>
    </div>
  </div>
  </section>

  <!-- トラフィックページ -->
  <section class="page" id="page-traffic">
  <div class="sl-pick" style="margin-top:12px"><label for="trafOrg">組織</label><select id="trafOrg"><option value="">すべての組織</option></select><label for="trafBe">接続先</label>
    <select id="trafBe"><option value="">すべての接続先</option></select>
    <span class="seemore" id="trafBeNote"></span></div>
  <div class="grid">
    <div class="card full" id="trendCard">
      <h2>📈 アクセス推移 <span class="seemore" id="trSub">(直近1ヶ月)</span>
        <span class="seg" id="trafRange" style="margin-left:10px;vertical-align:middle">
          <button data-r="hour">時間</button>
          <button data-r="week">週</button>
          <button data-r="month" class="on">月</button>
          <button data-r="year">年</button>
        </span>
      </h2>
      <div class="tr-lane">
        <div class="tr-head"><i style="background:var(--pass)"></i><span class="tt">通常アクセス(ALLOW)</span><span class="tot" id="trt-allow"></span><span class="tr-badge" id="trb-allow"></span></div>
        <div class="tr-wrap"><svg id="trs-allow" preserveAspectRatio="xMidYMid meet"></svg><div class="maptip tr-tip"></div></div>
      </div>
      <div class="tr-lane">
        <div class="tr-head"><i style="background:var(--block)"></i><span class="tt">攻撃(SQLi・XSS など中身の攻撃。遮断+検知のみ)</span><span class="tot" id="trt-atk"></span><span class="tr-badge" id="trb-atk"></span></div>
        <div class="tr-wrap"><svg id="trs-atk" preserveAspectRatio="xMidYMid meet"></svg><div class="maptip tr-tip"></div></div>
      </div>
      <div class="tr-lane">
        <div class="tr-head"><i style="background:var(--lim)"></i><span class="tt">制限(DoS・アクセス制限: レート超過・BAN・接続上限・低速接続・IP/国の制限)</span><span class="tot" id="trt-lim"></span><span class="tr-badge" id="trb-lim"></span></div>
        <div class="tr-wrap"><svg id="trs-lim" preserveAspectRatio="xMidYMid meet"></svg><div class="maptip tr-tip"></div></div>
      </div>
      <div class="tr-note" id="trNote"></div>
    </div>
    <div class="card">
      <h2>🛡 攻撃の判定別の推移 <span class="seemore">(遮断・無害化・検知のみ)</span></h2>
      <div class="tr-wrap"><svg id="trs-judge" preserveAspectRatio="xMidYMid meet"></svg><div class="maptip tr-tip"></div></div>
      <div class="legend" id="trLegJudge"></div>
    </div>
    <div class="card">
      <h2>🏷 カテゴリ別の推移 <span class="seemore">(上位5)</span></h2>
      <div class="tr-wrap"><svg id="trs-cat" preserveAspectRatio="xMidYMid meet"></svg><div class="maptip tr-tip"></div></div>
      <div class="legend" id="trLegCat"></div>
    </div>

    <!-- 攻撃インサイト(要点) -->
    <div class="card full">
      <h2>攻撃インサイト <span class="seemore">— いま何が一番狙われているか</span></h2>
      <div class="insights" id="insights"></div>
      <div class="sev-wrap">
        <div class="sev-title">攻撃の深刻度の内訳 <span class="seemore">— 1件の攻撃を「当たったルールのうち一番重い深刻度」で数えています(合計=攻撃総数)</span></div>
        <div class="sevbar" id="sevbar"></div>
      </div>
    </div>

    <div class="card">
      <h2>攻撃カテゴリ別(検知/遮断)</h2>
      <div id="categories"></div>
    </div>
    <div class="card">
      <h2>攻撃カテゴリ構成比</h2>
      <div class="donut-wrap">
        <svg id="donut" width="150" height="150" viewBox="0 0 150 150"></svg>
        <div class="donut-legend" id="donutLegend"></div>
      </div>
    </div>
    <div class="card">
      <h2>検知ルール トップ</h2>
      <table id="rules"><thead><tr><th>ルールID</th><th>件数</th></tr></thead><tbody></tbody></table>
    </div>
    <div class="card">
      <h2>送信元IP トップ(遮断数順)</h2>
      <table id="ips"><thead><tr><th>IP</th><th>総数</th><th>遮断</th></tr></thead><tbody></tbody></table>
    </div>
    <div class="card">
      <h2>攻撃を受けた箇所 / パス</h2>
      <table id="fields"><thead><tr><th>フィールド/パス</th><th>件数</th></tr></thead><tbody></tbody></table>
    </div>

    <div class="card full">
      <h2>攻撃の時間帯ヒートマップ(曜日 × 時間)
        <span class="seg hm-seg" id="hmSeg" style="float:right"><button data-v="7d" class="on">7日</button><button data-v="30d">30日</button></span></h2>
      <div id="heatmap" class="hm-wrap"><div class="empty">データを読み込み中…</div></div>
    </div>

    <div class="card full">
      <h2>国別アクセス / 攻撃 <span class="seemore">— 上部マップの期間フィルタ(今日/週/年/全期間)に連動</span></h2>
      <div id="countryTable"><div class="empty">データを読み込み中…</div></div>
    </div>

  </div>
  </section>

  <!-- IP管理ページ -->
  <section class="page" id="page-ip">
  <div class="grid">
    <div class="card full">
      <h2>IP ブロック / BAN 管理</h2>
      <div class="sl-pick" id="ipPick" style="margin:0 0 12px"><label for="ipOrg">組織</label><select id="ipOrg"><option value="">すべての組織</option></select><label for="ipSel">設定の対象</label>
        <select id="ipSel"><option value="">共通(すべてのバックエンド)</option></select>
        <span class="seemore" id="ipSelNote"></span></div>
      <div class="ipcols">
        <div>
          <div class="ipsub">手動ブロックリスト(常にdrop・IP/CIDR対応)</div>
          <div class="ipform">
            <input id="ipInput" placeholder="例: 203.0.113.10 または 203.0.113.0/24">
            <button id="ipAdd">ブロック追加</button>
          </div>
          <ul class="iplist" id="blocklist"></ul>
        </div>
        <div class="ip-global ip-ban">
          <div class="ipsub">BAN中(レート超過・攻撃の繰り返し・手動 等)<button class="clr" id="banClear">全解除</button></div>
          <div class="ipform ipro-hide">
            <input id="banIp" placeholder="手動BAN: 例 203.0.113.10">
            <input id="banMin" type="number" min="1" value="60" style="max-width:80px;flex:0 0 80px" title="分">
            <button id="banAdd">分BAN</button>
          </div>
          <ul class="iplist" id="banlist"></ul>
        </div>
      </div>
      <div class="ipcols" style="margin-top:18px">
        <div>
          <div class="ipsub">IP許可リスト(登録すると、このIP/CIDR以外を全て拒否。空=無効)</div>
          <div class="ipform">
            <input id="allowInput" placeholder="例: 192.168.0.0/16">
            <button id="allowAdd">許可に追加</button>
          </div>
          <ul class="iplist" id="allowlist"></ul>
          <div class="seemore" id="allowWarn" style="margin-top:4px"></div>
        </div>
        <div class="ip-global">
          <div class="ipsub">除外IP(BAN・レート制限・自動BANの対象外。監視サーバ等)</div>
          <div class="ipform">
            <input id="exemptInput" placeholder="例: 10.0.0.5">
            <button id="exemptAdd">除外に追加</button>
          </div>
          <ul class="iplist" id="exemptlist"></ul>
        </div>
      </div>
      <div class="ipsub" style="margin-top:18px">国別アクセス制限(ブロックリスト / 許可リスト)</div>
      <div class="ipform">
        <input id="countryInput" list="countryOpts" placeholder="国名・国コードで検索(例: 中国 / China / CN)" style="min-width:260px">
        <datalist id="countryOpts"></datalist>
        <button id="countryAdd">ブロックに追加</button>
        <button id="countryAllowAdd">許可に追加</button>
      </div>
      <div class="ipcols">
        <div><div class="ipsub" style="font-weight:400">ブロックする国</div><ul class="iplist" id="countrylist"></ul></div>
        <div><div class="ipsub" style="font-weight:400">許可する国(登録すると、それ以外の国を全て拒否)</div><ul class="iplist" id="countryallowlist"></ul></div>
      </div>
      <label class="seemore ip-global" style="display:flex;align-items:center;gap:8px;margin-top:6px"><input type="checkbox" id="countryUnknown"> 国が判定できないIP(プライベートIP等)も拒否する</label>
      <div class="seemore" style="margin-top:6px">※ 送信元の国は GeoLite2(オフラインDB。あれば)か外部APIで判定しキャッシュします。判定できない場合は通過(上のチェックで拒否も可)。内部アクセスは出口グローバルIPの国で判定されます。</div>

      <div class="ip-global"><div class="ipsub" style="margin-top:18px">IPごとの現在の同時接続数(ライブ)
        <span class="conn-sum" id="connSum"></span></div>
      <ul class="iplist" id="connlist"></ul></div>
    </div>

    <div class="card full ip-global">
      <h2>BAN履歴 <span class="seemore">— 自動BANが発動した履歴(最新200件・WAFを再起動しても残ります)</span></h2>
      <div class="banhist-wrap">
        <table id="banhist"><thead><tr><th>発動時刻</th><th>IP</th><th>継続</th><th>回数</th><th>理由</th></tr></thead><tbody></tbody></table>
      </div>
    </div>

  </div>
  </section>

  <!-- イベントログページ -->
  <section class="page" id="page-log">
  <div class="grid">
    <div class="card full" id="logCard">
      <h2><button type="button" class="mapfs" id="logfs" title="イベントログを画面いっぱいに表示(Escで戻る)">⛶ 全画面</button>イベントログ <span class="seemore" id="recentCount">— 行をクリックでリクエスト/レスポンスを表示</span></h2>
      <div class="logfilter">
        <select id="lf-org" title="組織で絞り込み(選んだあと、その組織のバックエンドを選べます)"><option value="">全組織</option></select>
        <select id="lf-backend" title="防御しているバックエンドで絞り込み">
          <option value="">全バックエンド</option>
        </select>
        <select id="lf-action">
          <option value="">全アクション</option>
          <option value="PASS">PASS</option><option value="BLOCK">BLOCK</option>
          <option value="DETECT">DETECT</option><option value="RATELIMIT">RATELIMIT</option>
          <option value="ERROR">ERROR</option>
        </select>
        <select id="lf-method">
          <option value="">全メソッド</option>
          <option>GET</option><option>POST</option><option>PUT</option>
          <option>DELETE</option><option>PATCH</option><option>HEAD</option>
        </select>
        <input id="lf-text" placeholder="IP / パス / ルール / 時刻で検索(スペース区切りでAND)">
        <label class="lf-dt">From<input type="datetime-local" id="lf-from"></label>
        <label class="lf-dt">To<input type="datetime-local" id="lf-to"></label>
        <label class="lf-chk"><input type="checkbox" id="lf-attack">攻撃のみ</label>
        <button class="lf-clr" id="lf-loadall">全件読み込み</button>
        <span class="lf-exp"><select id="lf-expfmt" title="書き出す形式"><option value="csv">CSV</option><option value="jsonl">JSON Lines</option></select><button class="lf-clr" id="lf-export" title="いまの絞り込み(バックエンド・期間・攻撃のみ)でログをファイルに書き出します。担当範囲だけ、アナリストは機微情報を伏せて、記録が残ります">書き出し</button></span>
        <button class="lf-clr" id="lf-reset">クリア</button>
        <span class="lf-count" id="lf-count"></span>
      </div>
      <div class="log-split"><div class="log-main">
      <div class="recent-wrap">
        <table id="recent">
          <thead><tr><th>時刻</th><th>アクション</th><th>バックエンド</th><th>送信元IP</th><th>メソッド</th>
          <th>パス</th><th>ルール/状態</th></tr></thead>
          <tbody></tbody>
        </table>
      </div>
      </div>
      <aside class="be-side" id="lf-bechips" hidden></aside></div>
    </div>
  </div>
  </section>

  <!-- ルールページ -->
  <section class="page" id="page-tickets">
    <div class="card">
      <h2>申請 <span class="seemore">— 誤検知の除外・問い合わせ・防御モードの変更依頼など(アナリストは、ログの確認をキー・オフィサーに依頼することもできます)</span></h2>
      <div id="tkForm"></div>
    </div>
    <div class="card" style="margin-top:12px">
      <h2>申請の一覧 <span class="seemore">— 5秒ごとに自動更新</span></h2>
      <div id="tkLive" class="tk-live" hidden></div>
      <div id="tkList"><div class="hempty">読み込み中…</div></div>
    </div>
  </section>
  <section class="page" id="page-rules">
  <div class="set-tabs" id="ruleTabs">
    <button type="button" data-rt="be" class="on">バックエンド別の設定</button>
    <button type="button" data-rt="global" class="adm-card">検知ルール(全体)</button>
    <button type="button" data-rt="custom" class="adm-card">追加ルール</button>
    <button type="button" data-rt="hist">変更履歴</button>
  </div>
  <div class="grid" id="ruleGrid" data-rt="be">
    <div class="card full adm-card" id="cusCard">
      <h2>追加ルール <span class="seemore">— custom_rules.json(再起動なしで反映。編集は専用ツール waf_rules_tool.py)</span></h2>
      <div id="cusBody"><div class="hempty">読み込み中…</div></div>
    </div>
    <div class="card full" id="berCard">
      <h2>バックエンド別のルール設定 <span class="seemore">— 組織 → バックエンドを選んで、そのバックエンドだけ使わない・検知のみ・場所を絞った除外(期限つき)</span></h2>
      <div id="berBody"><div class="hempty">読み込み中…</div></div>
    </div>
    <div class="card full" id="rhCard">
      <h2>ルール設定の変更履歴 <span class="seemore">— 誰が・いつ・何を</span></h2>
      <div id="rhBody"><div class="hempty">読み込み中…</div></div>
    </div>
    <div class="card full adm-card" id="rgCard">
      <h2>検知ルール管理(全体) <span class="seemore" id="rTotal"></span></h2>
      <div class="logfilter" style="margin-bottom:12px">
        <select id="rf-cat"><option value="">全カテゴリ</option></select>
        <select id="rf-sev"><option value="">全深刻度</option><option>critical</option>
          <option>high</option><option>medium</option><option>low</option></select>
        <input id="rf-text" placeholder="ID / 説明で絞り込み">
      </div>
      <div id="rBody"><div class="empty">「ルール」タブを開くと読み込みます…</div></div>
    </div>
  </div>
  </section>

  <!-- 設定ページ -->
  <section class="page" id="page-status">
    <div class="sl-pick"><label for="slOrg">組織</label><select id="slOrg"><option value="">すべての組織</option></select><label for="slSel">接続先</label>
      <select id="slSel"><option value="">すべての接続先</option></select>
      <span class="seemore" id="slPickNote"></span></div>
    <div class="sl-cards" id="slCards"></div>
    <div class="card" style="margin-top:12px" id="modeCard">
      <h2>防御モード <span class="seemore">— バックエンドごとに「遮断」か「検知のみ(攻撃を通す)」を切り替えます</span></h2>
      <div id="modeWarn" class="mode-warn" hidden></div>
      <div id="modeBody"><div class="hempty">読み込み中…</div></div>
      <div class="sl-note" id="modeHist" style="margin-top:8px"></div>
    </div>
    <div class="card" style="margin-top:12px">
      <h2>稼働の詳細 <span class="seemore">— 3秒ごとに更新 / 上の「接続先」に連動</span></h2>
      <div class="sl-live" id="slLive"><div class="hempty">読み込み中…</div></div>
    </div>
    <div class="card" style="margin-top:12px">
      <h2>直近24時間の状態 <span class="seemore" id="slUpd"></span></h2>
      <div class="sl-tl" id="slTl"></div>
      <div class="sl-axis"><span id="slAx0"></span><span id="slAx1"></span><span id="slAx2"></span></div>
      <div class="sl-legend" id="slLegend"></div>
    </div>
    <div class="card adm-only" style="margin-top:12px">
      <h2>接続の流れ <span class="seemore">— 累計・WAF起動後</span> <span class="conn-sum" id="connStatsSince"></span></h2>
      <div class="seemore" style="margin:4px 0 6px">※ waf.log に残るのは「HTTPリクエストとして処理できたもの」と「受付直後に切った接続」だけです。
        接続だけ・ゴミ送信・TLS握手の失敗・無言のまま切れた接続は下のカウンターにだけ現れます(件数の差は主にここ)。</div>
      <table id="connStats"><tbody><tr><td class="empty">読み込み中…</td></tr></tbody></table>
    </div>
    <div class="card" style="margin-top:12px">
      <h2>状態の変化の履歴 <span class="seemore">— 再起動しても残ります</span></h2>
      <div class="sl-filters">
        <select id="slfTarget" class="adm-only"><option value="">対象: すべて</option></select>
        <select id="slfState"><option value="">状態: すべて</option></select>
        <input id="slfText" placeholder="日付・接続先で絞り込み(例: 2026-10-16)" size="34">
        <a class="sl-dl adm-only" href="/api/health-log?format=csv">CSVでダウンロード</a>
        <span class="sl-cnt" id="slCnt"></span>
      </div>
      <div class="sl-tablewrap"><table class="sl-table">
        <thead><tr><th>時刻</th><th>対象</th><th>変化</th><th>その状態が続いた時間</th><th class="adm-only">詳細</th></tr></thead>
        <tbody id="slTb"></tbody>
      </table></div>
      <div class="sl-note">
        ・状態の「変化」だけを記録しています(5秒ごとの確認結果そのものではありません)。<br>
        <span class="adm-only">・「WAFプロセス」の停止は、次にWAFを起動したとき「最後に生きていた時刻」から推定して記録します(強制終了・停電でも残ります)。<br></span>
        ・稼働率 = (稼働中+遅い)の時間 ÷ 記録のある時間。WAFが止まっていた間は、接続先アプリは集計から除外します。
      </div>
    </div>
  </section>
  <section class="page" id="page-settings">
  <div class="grid">
    <div class="card full">
      <h2>WAF 設定</h2>
      <div id="sBody"><div class="empty">「設定」タブを開くと読み込みます…</div></div>
    </div>
  </div>
  </section>
</main>

<!-- リクエスト詳細モーダル -->
<div class="modal" id="modal">
  <div class="modal-card">
    <div class="modal-head">
      <h3 id="mTitle">リクエスト詳細</h3>
      <button class="x" id="mClose">&times;</button>
    </div>
    <div class="modal-body" id="mBody"></div>
  </div>
</div>

<script>
// 15カテゴリの配色。識別しやすい色にする
const CAT_PALETTE = ['#3987e5','#d95926','#199e70','#c98500','#d55181','#9085e9',
  '#e66767','#4bb3c4','#8bc34a','#b07cc6','#f0a35e','#5c9ead','#e05c9b','#7a8b99','#c0a062','#e8617a'];
const CAT_COLOR = {};
let CAT_LABEL = {};  // server から label を受け取って補う
const ACT_COLOR = {PASS:'#1baf7a',BLOCK:'#e34948',DETECT:'#eda100',RATELIMIT:'#9085e9',ERROR:'#8b93a1'};
const ACT_LABEL = {PASS:'通常',BLOCK:'遮断',DETECT:'検知',RATELIMIT:'制限/drop',ERROR:'接続エラー'};
let auto = true;

function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,
  c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}

function kpi(label, value, cls, sub, tone){
  return `<div class="kpi ${tone||''}"><div class="label">${label}</div>
    <div class="value ${cls||''}">${value}</div>
    <div class="sub">${sub||'&nbsp;'}</div></div>`;
}
function renderKpis(d, bans){
  const a=d.actions;
  const nb=bans||0;
  const err=a.ERROR||0;
  let h = kpi('総リクエスト',d.total,'','PASS+BLOCK+DETECT+制限'+(err?'+ERR':''),'k-neutral')
    + kpi('🟢 通過 (PASS)',a.PASS,'v-pass','正常なアクセス','k-green')
    + kpi('🔴 遮断 (BLOCK)',a.BLOCK,'v-block','遮断率 '+d.block_rate+'%','k-red')
    + kpi('🟡 検知 (DETECT)',a.DETECT,'v-detect','監視のみ(通過)','k-amber')
    + kpi('🟣 レート制限/drop',a.RATELIMIT,'v-rate','過剰アクセスを遮断','k-purple');
  if(err>0) h += kpi('⚪ 転送エラー (502)',err,'', 'backend 到達失敗','k-grey');
  h += kpi('🚫 BAN中',nb,nb>0?'v-block':'', 'レート超過・攻撃・手動 等',nb>0?'k-red':'k-grey');
  document.getElementById('kpis').innerHTML = h;
}
function renderDonut(cats){
  const svg=document.getElementById('donut'), lg=document.getElementById('donutLegend');
  const data=cats.filter(c=>c.count>0).sort((a,b)=>b.count-a.count);
  const total=data.reduce((s,c)=>s+c.count,0);
  if(!total){ svg.innerHTML=`<text x="75" y="78" text-anchor="middle" fill="var(--ink-muted)" font-size="12">データなし</text>`; lg.innerHTML=''; return; }
  const cx=75,cy=75,r=52,w=20; let a0=-Math.PI/2, g='';
  // 単一カテゴリ(100%)は円弧が描けないので輪を描く
  if(data.length===1 || data[0].count>=total){
    const c=data[0], col=CAT_COLOR[c.name]||'#888';
    g+=`<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="${col}" stroke-width="${w}"><title>${esc(c.label||c.name)}: ${c.count} (100%)</title></circle>`;
    g+=`<text x="${cx}" y="${cy-3}" text-anchor="middle" fill="var(--ink)" font-size="20" font-weight="700">${total}</text>`;
    g+=`<text x="${cx}" y="${cy+14}" text-anchor="middle" fill="var(--ink-muted)" font-size="10">検知/遮断</text>`;
    svg.innerHTML=g;
    lg.innerHTML=`<div class="li"><i style="background:${CAT_COLOR[data[0].name]||'#888'}"></i>${esc(data[0].label||data[0].name)}<b>${data[0].count} (100%)</b></div>`;
    return;
  }
  data.forEach(c=>{
    const frac=c.count/total, a1=a0+frac*2*Math.PI;
    const x0=cx+r*Math.cos(a0), y0=cy+r*Math.sin(a0), x1=cx+r*Math.cos(a1), y1=cy+r*Math.sin(a1);
    const large=frac>0.5?1:0; const col=CAT_COLOR[c.name]||'#888';
    g+=`<path d="M ${x0} ${y0} A ${r} ${r} 0 ${large} 1 ${x1} ${y1}" fill="none"
         stroke="${col}" stroke-width="${w}"><title>${esc(c.label||c.name)}: ${c.count} (${Math.round(frac*100)}%)</title></path>`;
    a0=a1;
  });
  g+=`<text x="${cx}" y="${cy-3}" text-anchor="middle" fill="var(--ink)" font-size="20" font-weight="700">${total}</text>`;
  g+=`<text x="${cx}" y="${cy+14}" text-anchor="middle" fill="var(--ink-muted)" font-size="10">検知/遮断</text>`;
  svg.innerHTML=g;
  lg.innerHTML=data.slice(0,8).map(c=>`<div class="li"><i style="background:${CAT_COLOR[c.name]||'#888'}"></i>${esc(c.label||c.name)}<b>${c.count} (${Math.round(100*c.count/total)}%)</b></div>`).join('');
}
function renderBars(el, rows){
  const max=Math.max(1,...rows.map(r=>r.count));
  el.innerHTML = rows.map(r=>{
    const w=Math.round(100*r.count/max);
    return `<div class="bar-row"><span class="name">${esc(r.label)}</span>
      <div class="bar-track"><div class="bar-fill" style="width:${w}%;background:${r.color||'var(--c-xss)'}"
        title="${esc(r.label)}: ${r.count}"></div></div>
      <span class="num">${r.count}</span></div>`;
  }).join('') || '<div class="empty">データなし</div>';
}
let trafRange='month';
function fmtNum(v){ return v>=1000000 ? (v/1000000).toFixed(v%1000000?1:0)+'M' : v>=1000 ? (v/1000).toFixed(v%1000?1:0)+'k' : String(Math.round(v)); }
const RANGE_LABEL={hour:'直近24時間',week:'直近1週間',month:'直近1ヶ月',year:'直近1年'};
const PREV_LABEL={hour:'前日',week:'前週',month:'前月',year:'前年'};
const PREV_NOTE={hour:'前日の同じ時間帯',week:'前週の同じ曜日',month:'前月(直前30日)の同じ日',year:'前年の同じ月'};
const JUDGE=[
  {k:'BLOCK',label:'BLOCK',ja:'遮断',color:'var(--block)'},
  {k:'SANITIZE',label:'SANITIZE',ja:'無害化',color:'var(--sanitize)'},
  {k:'DETECT',label:'DETECT',ja:'検知のみ',color:'var(--detect)'}];

/* 汎用の折れ線/面グラフ(SVG)。目盛りはグラフごとに別。フラッドで増減が埋もれないようにする */
function niceAxis(maxv, minTop){
  const top=Math.max(maxv*1.12, minTop||1);
  const steps=[]; for(let p=0;p<=9;p++){ [1,2,5].forEach(m=>steps.push(m*Math.pow(10,p))); }
  const step=steps.find(s=>Math.ceil(top/s)<=5)||steps[steps.length-1];
  const n=Math.max(1,Math.ceil(top/step));
  return {step, n, top:step*n};
}
function sumKey(rows,k){ return (rows||[]).reduce((s,r)=>s+(r[k]||0),0); }
// o: {W,H,rows,series:[{color,val(row),fill,fillOpacity}],stacked,prev,prevVal,mini,tip(i)}
function trLine(svg,o){
  const W=o.W, H=o.H, mini=!!o.mini;
  const padL=mini?28:36, padR=10, padT=mini?9:12, padB=mini?4:22;
  const rows=o.rows||[], n=rows.length, S=o.series||[];
  svg.setAttribute('viewBox',`0 0 ${W} ${H}`);
  if(!n||!S.length){
    svg.innerHTML=`<text x="${W/2}" y="${H/2}" fill="var(--ink-muted)" font-size="12" text-anchor="middle">データなし</text>`;
    svg.__tr=null; return;
  }
  const plotW=W-padL-padR, plotH=H-padT-padB;
  const val=(s,i)=>s.val(rows[i])||0;
  let maxv=0;
  for(let i=0;i<n;i++){
    const v=o.stacked ? S.reduce((a,s)=>a+val(s,i),0) : Math.max(...S.map(s=>val(s,i)));
    if(v>maxv) maxv=v;
  }
  const prev=(o.prev&&o.prevVal)?o.prev:null;
  if(prev) prev.forEach(r=>{ const v=o.prevVal(r)||0; if(v>maxv) maxv=v; });
  const ax=niceAxis(maxv, 1);
  const X=i=>n===1 ? padL+plotW/2 : padL+plotW*i/(n-1);
  const Y=v=>padT+plotH*(1-v/ax.top);
  let g='';
  for(let t=0;t<=ax.n;t++){
    const v=ax.step*t, y=Y(v).toFixed(1);
    g+=`<line x1="${padL}" x2="${W-padR}" y1="${y}" y2="${y}" stroke="var(--border)" stroke-width="1"${t?' opacity=".75"':''}/>`;
    if(!mini || t===ax.n)
      g+=`<text x="${padL-6}" y="${(+y+3.5).toFixed(1)}" fill="var(--ink-muted)" font-size="${mini?9.5:10.5}" text-anchor="end">${fmtNum(v)}</text>`;
  }
  if(!mini){
    const every=Math.max(1,Math.ceil(n/8));
    rows.forEach((r,i)=>{ if(i%every===0 || i===n-1&&(n-1)%every>=every/2)
      g+=`<text x="${X(i).toFixed(1)}" y="${H-6}" fill="var(--ink-muted)" font-size="10.5" text-anchor="middle">${esc(r.t)}</text>`; });
  }
  // 1つ前の期間(点線)
  if(prev && prev.length===n){
    const d=prev.map((r,i)=>(i?'L':'M')+X(i).toFixed(1)+' '+Y(o.prevVal(r)||0).toFixed(1)).join(' ');
    g+=`<path d="${d}" fill="none" stroke="${S[0].color}" stroke-width="1.4" stroke-dasharray="4 4" opacity=".6"/>`;
  }
  const base=new Array(n).fill(0), ys=[];
  S.forEach((s,si)=>{
    const pts=[]; ys[si]=[];
    for(let i=0;i<n;i++){
      const v=val(s,i), b=o.stacked?base[i]:0;
      pts.push([X(i), Y(b+v), Y(b), v]); ys[si][i]=Y(b+v);
    }
    const line=pts.map((p,i)=>(i?'L':'M')+p[0].toFixed(1)+' '+p[1].toFixed(1)).join(' ');
    if(s.fill){
      const back=pts.slice().reverse().map(p=>'L'+p[0].toFixed(1)+' '+p[2].toFixed(1)).join(' ');
      g+=`<path d="${line} ${back} Z" fill="${s.color}" opacity="${s.fillOpacity||.16}"/>`;
    }
    g+=`<path d="${line}" fill="none" stroke="${s.color}" stroke-width="${o.lw||2}" stroke-linejoin="round" stroke-linecap="round"/>`;
    pts.forEach((p,i)=>{ if(p[3]>0 && (!mini || i===n-1))
      g+=`<circle cx="${p[0].toFixed(1)}" cy="${p[1].toFixed(1)}" r="${mini?3:3.2}" fill="${s.color}" stroke="var(--surface)" stroke-width="1.2"/>`; });
    if(o.stacked) for(let i=0;i<n;i++) base[i]+=val(s,i);
  });
  if(!mini || o.tip){
    g+=`<line class="xh" y1="${padT}" y2="${padT+plotH}" stroke="var(--ink-muted)" stroke-dasharray="3 3" style="display:none"/>`;
    S.forEach(s=>{ g+=`<circle class="hd" r="4.2" fill="${s.color}" stroke="var(--surface)" stroke-width="1.5" style="display:none"/>`; });
  }
  svg.innerHTML=g;
  svg.__tr={W,padL,plotW,n,X,ys,tip:o.tip};
  if(!mini || o.tip) trHover(svg);
}
function trHover(svg){
  if(svg.__hv) return; svg.__hv=true;
  const wrap=svg.parentNode, tip=wrap.querySelector('.tr-tip');
  const hide=()=>{ if(tip) tip.style.display='none';
    const xh=svg.querySelector('.xh'); if(xh) xh.style.display='none';
    svg.querySelectorAll('.hd').forEach(c=>c.style.display='none'); };
  svg.addEventListener('mousemove',ev=>{
    const t=svg.__tr; if(!t||!tip) return;
    const rc=svg.getBoundingClientRect();
    const x=(ev.clientX-rc.left)/rc.width*t.W;
    let i=t.n===1?0:Math.round((x-t.padL)/t.plotW*(t.n-1));
    i=Math.max(0,Math.min(t.n-1,i));
    const xh=svg.querySelector('.xh');
    if(xh){ xh.setAttribute('x1',t.X(i)); xh.setAttribute('x2',t.X(i)); xh.style.display=''; }
    svg.querySelectorAll('.hd').forEach((c,si)=>{ c.setAttribute('cx',t.X(i)); c.setAttribute('cy',t.ys[si][i]); c.style.display=''; });
    tip.innerHTML=t.tip(i); tip.style.display='block';
    const wr=wrap.getBoundingClientRect();
    let left=ev.clientX-wr.left+14; if(left>wr.width-tip.offsetWidth-6) left=ev.clientX-wr.left-tip.offsetWidth-14;
    tip.style.left=Math.max(4,left)+'px'; tip.style.top=Math.max(4,ev.clientY-wr.top-12)+'px';
  });
  svg.addEventListener('mouseleave',hide);
}
function trBadge(cur,prev,rise){      // rise: 増えたときの色('good'/'bad')
  if(cur===0&&prev===0) return {t:'±0',c:'flat'};
  if(prev===0) return {t:'新規',c:rise};
  if(cur===prev) return {t:'±0',c:'flat'};
  const up=cur>prev, pct=Math.round(100*(cur-prev)/prev);
  const fall=rise==='bad'?'good':'flat';
  return {t:(up?'▲ +':'▼ ')+pct+'%', c:up?rise:fall};
}
function trTipRow(color,label,v){ return `<div class="li"><i style="background:${color}"></i>${esc(label)}<b>${v}</b></div>`; }
function renderTraffic(){
  const d=tstats(), tr=(d.trend||{})[trafRange];
  if(!tr) return;
  const cur=tr.cur||[], prev=tr.prev||[], pl=PREV_LABEL[trafRange];
  const sub=document.getElementById('trSub'); if(sub) sub.textContent='('+RANGE_LABEL[trafRange]+')';
  const note=document.getElementById('trNote');
  if(note) note.textContent='3段とも目盛りは別です(フラッドの件数で攻撃の増減が埋もれないように)。点線は1つ前の期間('+PREV_NOTE[trafRange]+')。点にカーソルを合わせると内訳を表示します。';
  const lanes=[
    {id:'allow',key:'ALLOW',color:'var(--pass)',name:'通常アクセス',rise:'good'},
    {id:'atk',key:'ATTACK',color:'var(--block)',name:'攻撃',rise:'bad'},
    {id:'lim',key:'LIMIT',color:'var(--lim)',name:'制限',rise:'bad'}];
  lanes.forEach(L=>{
    const total=sumKey(cur,L.key), ptotal=sumKey(prev,L.key);
    const t=document.getElementById('trt-'+L.id); if(t) t.textContent='合計 '+total.toLocaleString()+'件';
    const bd=trBadge(total,ptotal,L.rise), b=document.getElementById('trb-'+L.id);
    if(b){ b.textContent=bd.t; b.className='tr-badge '+bd.c; b.title=pl+'との比較(前の期間 '+ptotal.toLocaleString()+'件)'; }
    trLine(document.getElementById('trs-'+L.id),{
      W:1000,H:170,rows:cur,prev:prev,prevVal:r=>r[L.key],
      series:[{color:L.color,val:r=>r[L.key],fill:true}],
      tip:i=>{
        const r=cur[i], p=prev[i]||{};
        let h=`<b>${esc(r.t)}</b>`+trTipRow(L.color,L.name,(r[L.key]||0).toLocaleString());
        if(L.key==='ATTACK'){
          h+=JUDGE.filter(j=>r[j.k]).map(j=>trTipRow(j.color,'└ '+j.ja,r[j.k])).join('');
          h+=Object.entries(r.cats||{}).sort((a,b)=>b[1]-a[1]).slice(0,4)
             .map(([c,v])=>trTipRow(CAT_COLOR[c]||'#888','└ '+(CAT_LABEL[c]||c),v)).join('');
        }
        return h+`<div class="sub">${pl}: ${(p[L.key]||0).toLocaleString()}件</div>`;
      }});
  });
  // 攻撃の判定別(積み上げ面)
  const js=JUDGE.filter(j=>sumKey(cur,j.k)>0);
  const jUse=js.length?js:[JUDGE[0]];
  trLine(document.getElementById('trs-judge'),{
    W:480,H:200,rows:cur,stacked:true,lw:1.6,
    series:jUse.map(j=>({color:j.color,val:r=>r[j.k],fill:true,fillOpacity:.5})),
    tip:i=>{ const r=cur[i];
      return `<b>${esc(r.t)}</b>`+jUse.map(j=>trTipRow(j.color,j.label+'('+j.ja+')',r[j.k]||0)).join(''); }});
  document.getElementById('trLegJudge').innerHTML=
    (js.length?js:JUDGE).map(j=>`<span title="${j.ja}"><i style="background:${j.color}"></i>${j.label}</span>`).join('')
    +(js.length?'':'<span class="seemore">この期間の攻撃はありません</span>');
  // カテゴリ別(上位5本の折れ線)
  const tot={}; cur.forEach(r=>Object.entries(r.cats||{}).forEach(([c,v])=>{ tot[c]=(tot[c]||0)+v; }));
  const top=Object.entries(tot).sort((a,b)=>b[1]-a[1]).slice(0,5).map(x=>x[0]);
  const cs=top.map(c=>({c,color:CAT_COLOR[c]||'#888',val:r=>(r.cats||{})[c]||0}));
  if(cs.length){
    trLine(document.getElementById('trs-cat'),{
      W:480,H:200,rows:cur,series:cs,lw:1.8,
      tip:i=>{ const r=cur[i];
        return `<b>${esc(r.t)}</b>`+cs.map(s=>trTipRow(s.color,CAT_LABEL[s.c]||s.c,s.val(r))).join(''); }});
  } else {
    trLine(document.getElementById('trs-cat'),{W:480,H:200,rows:cur,series:[{color:'var(--block)',val:()=>0}],tip:i=>`<b>${esc(cur[i].t)}</b>`});
  }
  document.getElementById('trLegCat').innerHTML=
    cs.map(s=>`<span><i style="background:${s.color}"></i>${esc(CAT_LABEL[s.c]||s.c)}</span>`).join('')
    || '<span class="seemore">この期間の攻撃はありません</span>';
}

/* ホーム画面 */
function isAtkEvent(e){
  if(e.action!=='BLOCK' && e.action!=='DETECT') return false;
  const dp=String(e.disposition||'');
  return !(dp.indexOf('country:')===0 || dp.indexOf('autoban_')===0 || dp==='slow_conn');
}
function homeSpark(d){
  const tr=((d.trend||{}).month)||{cur:[],prev:[]}, cur=tr.cur||[], prev=tr.prev||[];
  [['allow','ALLOW','var(--pass)'],['atk','ATTACK','var(--block)'],['lim','LIMIT','var(--lim)']].forEach(([id,key,color])=>{
    const t=sumKey(cur,key), el=document.getElementById('hs-'+id+'-t'); if(el) el.textContent='合計 '+t.toLocaleString()+'件';
    trLine(document.getElementById('hsp-'+id),{W:620,H:58,rows:cur,mini:true,prev:prev,prevVal:r=>r[key],
      series:[{color:color,val:r=>r[key],fill:true}],
      tip:i=>{ const r=cur[i], p=prev[i]||{};
        return `<b>${esc(r.t)}</b>`+trTipRow(color,{ALLOW:'通常アクセス',ATTACK:'攻撃',LIMIT:'制限'}[key],(r[key]||0).toLocaleString())
          +`<div class="sub">1つ前の期間: ${(p[key]||0).toLocaleString()}件</div>`; }});
  });
}
function homeDonut(d){
  const svg=document.getElementById('hdonutSvg'), lg=document.getElementById('hDonutLg'); if(!svg) return;
  const data=(d.categories||[]).filter(c=>c.count>0).sort((a,b)=>b.count-a.count);
  const total=data.reduce((s,c)=>s+c.count,0);
  const cx=95,cy=95,r=68,w=26;
  let g='';
  if(!total){
    g=`<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="var(--border)" stroke-width="${w}"/>`;
    lg.innerHTML='<div class="hempty">攻撃はまだありません</div>';
  } else {
    let a0=-Math.PI/2;
    data.forEach(c=>{
      const col=CAT_COLOR[c.name]||'#888', frac=c.count/total;
      if(frac>=0.9999){ g+=`<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="${col}" stroke-width="${w}"><title>${esc(c.label||c.name)}: ${c.count}</title></circle>`; return; }
      const a1=a0+frac*2*Math.PI, large=frac>0.5?1:0;
      g+=`<path d="M ${cx+r*Math.cos(a0)} ${cy+r*Math.sin(a0)} A ${r} ${r} 0 ${large} 1 ${cx+r*Math.cos(a1)} ${cy+r*Math.sin(a1)}" fill="none" stroke="${col}" stroke-width="${w}"><title>${esc(c.label||c.name)}: ${c.count} (${Math.round(frac*100)}%)</title></path>`;
      a0=a1;
    });
    lg.innerHTML=data.slice(0,8).map(c=>`<div class="li"><i style="background:${CAT_COLOR[c.name]||'#888'}"></i><span class="nm" title="${esc(c.label||c.name)}">${esc(c.label||c.name)}</span><b>${c.count}</b><span class="pc">${Math.round(100*c.count/total)}%</span></div>`).join('');
  }
  g+=`<text x="${cx}" y="${cy+4}" text-anchor="middle" fill="var(--ink)" font-size="28" font-weight="700">${total}</text>`;
  g+=`<text x="${cx}" y="${cy+22}" text-anchor="middle" fill="var(--ink-muted)" font-size="11">攻撃(件)</text>`;
  svg.innerHTML=g;
}
let homeMapMode='all';
function homeLoadWorld(){
  if(window.__hWorld!==undefined) return;
  window.__hWorld=null;
  fetch('/assets/world').then(r=>r.text()).then(s=>{
    if(s && s.indexOf('<path')>=0){ window.__hWorld=s; const el=document.getElementById('hland'); if(el) el.innerHTML=s; }
  }).catch(()=>{});
}
function homeMap(d){
  homeLoadWorld();
  const land=document.getElementById('hland'); if(land && window.__hWorld && !land.firstChild) land.innerHTML=window.__hWorld;
  const m=d.map||{}, K=['PASS','BLOCK','DETECT','RATELIMIT'];
  const pts=(m.nodes||[]).map(n=>({lat:n.lat,lon:n.lon,ip:n.ip,country:n.country,c:Object.assign({},n.counts||{})}));
  const ic=m.internal_counts||{}, icTot=K.reduce((s,k)=>s+(ic[k]||0),0);
  let unplaced=0;
  if(icTot>0){
    if(m.server && m.server.lat!=null){
      const ex=pts.find(p=>p.ip===m.server.ip);
      if(ex){ K.forEach(k=>{ ex.c[k]=(ex.c[k]||0)+(ic[k]||0); }); }
      else pts.push({lat:m.server.lat,lon:m.server.lon,ip:m.server.ip+'(防御サーバ/LAN内アクセス)',country:m.server.country,c:Object.assign({},ic)});
    } else unplaced=icTot;
  }
  const tot=p=>K.reduce((s,k)=>s+(p.c[k]||0),0), atk=p=>(p.c.BLOCK||0)+(p.c.DETECT||0);
  const sumT=pts.reduce((s,p)=>s+tot(p),0)+unplaced, sumA=pts.reduce((s,p)=>s+atk(p),0);
  const meta=document.getElementById('hmapMeta');
  if(meta) meta.textContent=`(${pts.length}地点 / 合計${sumT.toLocaleString()}件 うち攻撃${sumA.toLocaleString()}件)`;
  const note=document.getElementById('hmapNote');
  if(note) note.textContent=unplaced?`位置を特定できないLAN内アクセス ${unplaced}件は地図に出ません`:'';
  const g=document.getElementById('hnodes'); if(!g) return;
  const shown=(homeMapMode==='atk'?pts.filter(p=>atk(p)>0):pts).slice().sort((a,b)=>tot(b)-tot(a));
  const rad=()=>7;       // 件数に関係なく固定サイズ。件数は吹き出しで見る
  let h='';
  shown.forEach(p=>{
    const x=(p.lon+180)/360*MAP_W, y=(90-p.lat)/180*MAP_H;
    const tip=`${p.ip} ${p.country||''}\n通常 ${p.c.PASS||0} / 遮断 ${p.c.BLOCK||0} / 検知 ${p.c.DETECT||0} / 制限 ${p.c.RATELIMIT||0}`;
    if(homeMapMode==='atk'){
      h+=`<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="${rad(atk(p)).toFixed(1)}" fill="var(--block)" fill-opacity=".85" stroke="#fff" stroke-width="1.5"><title>${esc(tip)}</title></circle>`;
    } else {
      h+=`<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="${rad(tot(p)).toFixed(1)}" fill="var(--pass)" fill-opacity=".85" stroke="#fff" stroke-width="1.5"><title>${esc(tip)}</title></circle>`;
      if(atk(p)>0) h+=`<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="4.2" fill="var(--block)" stroke="#fff" stroke-width="1"><title>${esc(tip)}</title></circle>`;
    }
  });
  g.innerHTML=h;
}
function homeRecent(){
  const tb=document.querySelector('#hrecent tbody'); if(!tb) return;
  const rows=(window.__recent||[]).filter(e=>isAtkEvent(e)&&scIn('home',e.backend||'')).slice(0,8);
  tb.innerHTML=rows.map(e=>{
    const tag=String(e.disposition||'')==='response_sanitize'?'SANITIZE':e.action;
    const tagTxt=tag==='SANITIZE'?'無害化':tag;
    const cats=[...new Set((e.hits||[]).map(h=>h.category).filter(Boolean))];
    const c0=cats[0], lab=c0?(CAT_LABEL[c0]||c0):'-';
    return `<tr><td>${esc((e.ts||'').replace('T',' ').slice(5,19))}</td><td><span class="htag ${tag}">${esc(tagTxt)}</span></td>
      <td>${esc(e.ip||e.client_ip||'')}</td><td class="cat" title="${esc(lab)}" style="color:${CAT_COLOR[c0]||'var(--ink)'}">${esc(lab)}${cats.length>1?` <span class="seemore">+${cats.length-1}</span>`:''}</td></tr>`;
  }).join('') || '<tr><td colspan="4" class="empty">攻撃はまだありません</td></tr>';
}
function homeScale(d){
  const L=d.limit_scale||{}, el=document.getElementById('hScale'); if(!el) return;
  const t=(v,l)=>`<div class="t"><b>${v}</b><small>${l}</small></div>`;
  el.innerHTML=t((L.ips||0).toLocaleString(),'制限した送信元IP')+t(fmtNum(L.requests||0),'制限したリクエスト')
    +t((L.peak_rps||0).toLocaleString(),'ピーク(毎秒・10秒平均)')+t((L.bans||0).toLocaleString(),'BANした回数');
  const top=L.top||[], tp=document.getElementById('hScaleTop');
  if(!top.length){ tp.innerHTML='<div class="hempty">この期間の制限はありません。</div>'; return; }
  const max=Math.max(1,...top.map(x=>x.count));
  tp.innerHTML='<ul class="hlist">'+top.map(x=>`<li><span class="ip">${esc(x.ip)}</span><div class="bar"><div style="width:${Math.max(3,Math.round(100*x.count/max))}%"></div></div><span class="n">${x.count.toLocaleString()} 件</span></li>`).join('')+'</ul>';
}
function homeWatch(){
  const el=document.getElementById('hWatch'), ov=window.__ov; if(!el) return;
  if(!ov){ el.innerHTML='<div class="hempty">読み込み中…</div>'; return; }
  const w=ov.watch||[];
  if(!w.length){ el.innerHTML='<div class="hempty">しきい値に近いIPはありません。</div>'; return; }
  el.innerHTML='<ul class="hlist warn">'+w.map(x=>{
    const p=Math.min(100,Math.round(100*x.count/Math.max(1,x.threshold)));
    return `<li class="${p>=80?'hot':''}"><span class="ip">${esc(x.ip)}</span><span class="why">${esc(x.label)}</span><div class="bar"><div style="width:${p}%"></div></div><span class="n">${x.count} / ${x.threshold}</span></li>`;
  }).join('')+'</ul><div class="seemore" style="margin-top:6px">しきい値に達するとBANされます(窓内の回数 / しきい値)。</div>';
}
function homeStatus(){
  const el=document.getElementById('hStatus'), ov=window.__ov; if(!el||!ov) return;
  const row=(l,v,c)=>`<div class="r"><span>${l}</span><b${c?` class="${c}"`:''}>${v}</b></div>`;
  const ab=ov.autoban||{}, sl=ov.slow||{}, slb=sl.ban||{}, rl=ov.rate_limit||{}, cn=ov.connections||{}, gi=ov.global_ip||{}, au=ov.auth||{}, wh=ov.webhook||{};
  const RI={sanitize:'無害化',block:'遮断(403)',monitor:'記録のみ',off:'無効'};
  const geoTxt = ov.geoip ? (ov.geoip.ready?'GeoIP DBあり(オフライン判定)':(ov.geoip.online?'DBなし(外部APIで判定)':'DBなし')) : '不明';
  const left=[
    row('動作モード', ov.mode==='block'?'🛡 遮断モード':'👁 検知モード(通すだけ)', ov.mode==='block'?'':'warn'),
    row('WAFルール', `${ov.rules_on} / ${ov.rules_total}`, ov.rules_on<ov.rules_total?'warn':''),
    row('BAN中のIP', ov.bans_known?`${ov.bans} 件`:'—(単体起動では不明)'),
    row('自動BAN', ab.enabled===false?'無効':`${ab.threshold}回/${ab.window_seconds}秒`, ab.enabled===false?'warn':''),
    row('国判定(GeoIP)', geoTxt+(ov.country_rules?`/国制限 ${ov.country_rules}件`:'')),
    row('管理画面の認証', au.enabled?'あり(パスワード)':(au.local_only?'なし(このPCのみ)':'なし(外部から接続可)'), au.enabled?'good':(au.local_only?'':'warn'))];
  const right=[
    row('レスポンス検査', RI[ov.response_inspection]||esc(ov.response_inspection)),
    row('同時接続', cn.known===false?'—':`${cn.total} / 上限 ${cn.max_total||'なし'}(IPごと ${cn.max_per_ip||'なし'})`),
    row('レート制限', rl.enabled?`${rl.max_requests}回/${rl.window_seconds}秒`:'無効', rl.enabled?'':'warn'),
    row('低速攻撃対策', (sl.header||sl.body)?`ヘッダー${sl.header}秒・ボディ${sl.body}秒`+(slb.enabled===false?'':`・${slb.threshold}回でBAN`):'無効'),
    row('グローバルIP解決', gi.enabled?('有効'+(gi.ip?`(出口IP ${esc(gi.ip)})`:'')):'無効'),
    row('Webhook送信待ち', wh.enabled?`${wh.pending} 件`+(wh.dropped?`(破棄 ${wh.dropped})`:''):'未設定')];
  el.innerHTML='<div>'+left.join('')+'</div><div>'+right.join('')+'</div>';
}

/* 確認ダイアログ */
function askChoice(title, html, buttons){
  return new Promise(res=>{
    const ov=document.createElement('div'); ov.className='dlg-ov';
    ov.innerHTML=`<div class="dlg" role="dialog" aria-modal="true"><h3>${esc(title)}</h3><div class="dlg-b">${html}</div><div class="dlg-f"></div></div>`;
    const f=ov.querySelector('.dlg-f');
    const kd=ev=>{ if(ev.key==='Escape') done(null); };
    const done=v=>{ ov.remove(); document.removeEventListener('keydown',kd); res(v); };
    buttons.forEach(b=>{ const x=document.createElement('button'); x.type='button'; x.textContent=b.label; x.className=b.cls||''; x.onclick=()=>done(b.value); f.appendChild(x); });
    document.addEventListener('keydown',kd);
    ov.addEventListener('click',ev=>{ if(ev.target===ov) done(null); });
    document.body.appendChild(ov);
    const first=f.querySelector('button:not(.danger)'); if(first) first.focus();
  });
}
function fmtCount(n){ return (n==null)?'':Number(n).toLocaleString(); }
async function beDeleteChoice(name,id){
  if(AUTH.limited) return askChoice('バックエンドを削除',
    `<p>「<b>${esc(name)}</b>」を一覧から外します。</p><p class="seemore">ログは残ります(ログの削除は管理者が行います)。</p>`,
    [{label:'削除する',value:'keep',cls:'danger'},{label:'キャンセル',value:null,cls:'ghost'}]);
  let n=null;
  try{ const s=await (await fetch('/api/logs/summary',{cache:'no-store'})).json(); const r=(s.backends||[]).find(x=>x.id===id); n=r?r.count:0; }catch(e){}
  return askChoice('バックエンドを削除',
    `<p>「<b>${esc(name)}</b>」を削除します。</p>
     <p>このバックエンドのログ${n==null?'':`(<b>${fmtCount(n)}</b> 件)`}も一緒に削除しますか?</p>
     <p class="seemore">「ログは残す」を選んでも、あとから <b>設定 → ログ・通知 → ログの管理</b> で削除できます。</p>`,
    [{label:'ログも削除する',value:'with',cls:'danger'},{label:'ログは残す',value:'keep'},{label:'キャンセル',value:null,cls:'ghost'}]);
}
function postJSON(url,obj){ return fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(obj)}).then(r=>r.json()); }
function reloadAfterLogDelete(){   // KPI・ライブ表示・集計を作り直すため再読み込み。設定のログ管理に戻る
  try{ sessionStorage.setItem('waf-open','settings|log'); }catch(e){}
  location.reload();
}

/* ログの管理(設定のログ・通知) */
async function loadLogMgr(){
  const box=document.getElementById('logMgr'); if(!box) return;
  let s;
  try{ s=await (await fetch('/api/logs/summary',{cache:'no-store'})).json(); }
  catch(e){ box.innerHTML='<div class="empty">ログの情報を取得できませんでした。</div>'; return; }
  const alive=new Set(((typeof BE!=='undefined'&&BE&&BE.profiles)||[]).map(p=>p.id));
  const rows=(s.backends||[]).slice().sort((a,b)=>b.count-a.count).map(r=>
    `<tr><td>${esc(r.name||r.id)}${alive.size&&!alive.has(r.id)?'<span class="gone">削除済みのバックエンド</span>':''}</td>
     <td class="n">${fmtCount(r.count)} 件</td>
     <td style="text-align:right"><button type="button" class="danger" data-lg="${esc(r.id)}" data-nm="${esc(r.name||r.id)}" data-n="${r.count}">このログを削除</button></td></tr>`).join('');
  const none=s.none>0?`<tr><td>バックエンド不明(接続段階の遮断など)</td><td class="n">${fmtCount(s.none)} 件</td>
     <td style="text-align:right"><button type="button" class="danger" data-lg="__none" data-nm="バックエンド不明のログ" data-n="${s.none}">このログを削除</button></td></tr>`:'';
  box.className='logmgr';
  box.innerHTML=`<div class="set-note" style="margin-bottom:6px">バックエンドごとにログ(waf.log の該当行)を削除できます。削除したバックエンドのログもここに残ります。削除すると元に戻せません。</div>
    <table><thead><tr><th>バックエンド</th><th style="text-align:right">ログ件数</th><th></th></tr></thead><tbody>${rows+none||'<tr><td colspan="3" class="empty">ログはありません</td></tr>'}</tbody></table>
    <div style="margin-top:10px;display:flex;align-items:center;gap:10px"><button type="button" class="danger" data-lg="__all" data-nm="すべてのログ" data-n="${s.total}" ${s.total?'':'disabled'}>すべてのログを削除</button>
    <span class="seemore">ログファイル ${(s.size/1024).toFixed(1)} KB / 合計 ${fmtCount(s.total)} 件</span></div>`;
  box.onclick=async ev=>{
    const b=ev.target.closest('button[data-lg]'); if(!b||b.disabled) return;
    const c=await askChoice('ログを削除',
      `<p><b>${esc(b.dataset.nm)}</b>(${fmtCount(+b.dataset.n)} 件)を削除します。</p><p>この操作は元に戻せません。よろしいですか?</p>`,
      [{label:'削除する',value:'yes',cls:'danger'},{label:'キャンセル',value:null,cls:'ghost'}]);
    if(c!=='yes') return;
    const r=await postJSON('/api/logs/delete',{backend:b.dataset.lg}).catch(()=>({ok:false,error:'通信エラー'}));
    if(!r.ok){ await askChoice('削除できませんでした',`<p>${esc(r.error||'失敗')}</p>`,[{label:'閉じる',value:null}]); return; }
    await askChoice('ログを削除しました',`<p>${fmtCount(r.removed)} 件のログを削除しました。画面を更新します。</p>`,[{label:'OK',value:'ok'}]);
    reloadAfterLogDelete();
  };
}

/* 設定画面のタブ */
const AUTH={enabled:false,user:null,limited:false,users:[]};
const SET_TABS=[['basic','基本'],['backend','バックエンド'],['defense','防御・制限'],['log','ログ・通知'],['system','システム'],['account','アカウント'],['org','組織登録編集']];
let sTab='basic';
function setTabOf(t){
  if(/^(動作モード|検知ルール)/.test(t)) return 'basic';
  if(/^防御するバックエンド/.test(t)) return 'backend';
  if(/^(防御オプション|追加の防御)/.test(t)) return 'defense';
  if(/^再起動が必要/.test(t)) return 'system';
  if(/^アカウント/.test(t)) return 'account';
  if(/^組織/.test(t)) return 'org';
  return 'log';
}
function fitSettings(){
  const b=document.getElementById('sBody'); if(!b||curPage!=='settings') return;
  const top=b.getBoundingClientRect().top+window.scrollY;
  b.style.height=Math.max(380,window.innerHeight-top-44)+'px';
}
window.addEventListener('resize',fitSettings);
function showSetTab(k){
  sTab=k; if(curPage==='settings') navHashSave();
  const sc=document.querySelector('#sBody>.set-scroll'); if(sc) sc.scrollTop=0;
  document.querySelectorAll('#sBody .set-tabs button').forEach(b=>b.classList.toggle('on',b.dataset.t===k));
  document.querySelectorAll('#sBody .set-pane').forEach(p=>p.classList.toggle('on',p.dataset.t===k));
}
function tabifySettings(){
  const body=document.getElementById('sBody');
  const groups=[...body.querySelectorAll(':scope>.set-group')];
  const note=body.querySelector(':scope>.set-note'), foot=(body.querySelector('#s-save')||{closest:()=>null}).closest('.set-foot');
  const bar=document.createElement('div'); bar.className='set-tabs';
  const panes={};
  SET_TABS.forEach(([k,l])=>{
    const b=document.createElement('button'); b.type='button'; b.dataset.t=k; b.textContent=(k==='account'&&AUTH.limited)?'アカウント・通知':l; b.onclick=()=>showSetTab(k); bar.appendChild(b);   // 一般・アナリストは警報バナーの個人設定もここにあるので「アカウント・通知」にする
    const p=document.createElement('div'); p.className='set-pane'; p.dataset.t=k; panes[k]=p;
  });
  groups.forEach(g=>{ panes[setTabOf((g.querySelector('h4')||{}).textContent||'')].appendChild(g); });
  body.innerHTML='';
  if(note&&note.textContent.trim()) body.appendChild(note);
  body.appendChild(bar);
  const scr=document.createElement('div'); scr.className='set-scroll'; body.appendChild(scr);
  SET_TABS.forEach(([k])=>scr.appendChild(panes[k]));
  SET_TABS.forEach(([k])=>{ if(!panes[k].children.length){ panes[k].remove(); const bb=bar.querySelector(`button[data-t="${k}"]`); if(bb) bb.remove(); } });
  if(foot) body.appendChild(foot);
  fitSettings();
  showSetTab(bar.querySelector(`button[data-t="${sTab}"]`)?sTab:(bar.querySelector('button')||{dataset:{t:'basic'}}).dataset.t);
}

/* ホーム: 監視中のアプリ(接続先) */
function extLink(url,text){ return `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer" title="新しいタブで開く">${esc(text!==undefined?text:url)}</a>`; }
function homeListenCell(l){
  const m=/^(https?):\/\/([^:/]+):(\d+)(\/.*)?$/.exec(l||'');
  if(!m) return esc(l);                                   // 「ホスト名: …」などURLでない表記はそのまま
  const wild=['0.0.0.0','::','','[::]'].includes(m[2]);
  const host=wild?location.hostname:m[2];                  // 0.0.0.0 ではアクセスできないので、今開いているホスト名にする
  const path=(m[4]||'').replace(/\/?…$/,'');
  const url=m[1]+'://'+host+':'+m[3]+path;
  return extLink(url+(path?'':'/'),url);
}
function homeBackends(){
  const tb=document.querySelector('#hBe tbody'), ov=window.__ov; if(!tb||!ov) return;
  const list=(ov.backends||[]).filter(b=>scIn('home',b.id));
  const c=document.getElementById('hBeCount'); if(c) c.textContent=`(${list.length}件)`;
  tb.innerHTML=list.map((b,i)=>`<tr>
    <td>${i+1}<span class="nm">${esc(b.name)}</span></td>
    <td>${b.listen?homeListenCell(b.listen):'<span class="seemore">専用の待ち受けなし</span>'}</td>
    <td>${b.origin?extLink(b.origin+'/',b.origin):''}</td>
    <td><span class="st ${esc(b.state)}">${esc(HEALTH_LABEL[b.state]||b.state)}</span>${(AUTH.user&&AUTH.user.role==='admin')?`<div class="seemore" style="margin-top:3px">組織: ${esc(beOrgLabel(b.org))}</div>`:''}</td>
    <td class="ops"><button type="button" class="hbtn" data-be="stop" data-id="${esc(b.id)}">${b.stopped?'稼働再開':'稼働停止'}</button><button type="button" class="hbtn" data-be="edit" data-id="${esc(b.id)}">接続先変更</button><button type="button" class="hbtn" data-be="del" data-id="${esc(b.id)}" ${list.length<2?'disabled title="最後の1件は削除できません"':''}>削除</button></td></tr>`).join('')
    || '<tr><td colspan="5" class="empty">登録されたアプリはありません</td></tr>';
}
async function homeBeStop(id){
  const b=((window.__ov||{}).backends||[]).find(x=>x.id===id); if(!b) return;
  const to=!b.stopped;
  const c=await askChoice(to?'稼働を停止しますか?':'稼働を再開しますか?',
    to?`<p>「${esc(b.name)}」宛のアクセスに、503(メンテナンス中)を返すようになります。設定とログは残ります。</p>`:`<p>「${esc(b.name)}」宛のアクセスを再び転送します。</p>`,
    [{label:'キャンセル',value:null},{label:to?'稼働停止にする':'稼働を再開する',value:'ok'}]);
  if(!c) return;
  try{
    const cfg=await (await fetch('/api/config',{cache:'no-store'})).json();
    const be=cfg.editable.backend;
    const profiles=be.profiles.map(p=>p.id===id?Object.assign({},p,{stopped:to}):p);
    const res=await postJSON('/api/config',{backend:{active:be.active,host_routing:be.host_routing,rewrite_links:be.rewrite_links,profiles}});
    if(!res.ok) throw new Error(res.error||'失敗');
  }catch(e){ await askChoice('変更できませんでした',`<p>${esc(e.message||e)}</p>`,[{label:'閉じる',value:null}]); return; }
  loadOverview(); pollHealth();
}
async function homeBeDelete(id){
  const b=((window.__ov||{}).backends||[]).find(x=>x.id===id); if(!b) return;
  const choice=await beDeleteChoice(b.name,id); if(!choice) return;
  try{
    const cfg=await (await fetch('/api/config',{cache:'no-store'})).json();
    const be=cfg.editable.backend;
    const profiles=be.profiles.filter(p=>p.id!==id);
    if(!profiles.length){ await askChoice('削除できません','<p>最後の1件は削除できません。</p>',[{label:'閉じる',value:null}]); return; }
    const res=await postJSON('/api/config',{backend:{active:be.active===id?profiles[0].id:be.active,host_routing:be.host_routing,rewrite_links:be.rewrite_links,profiles}});
    if(!res.ok) throw new Error(res.error||'失敗');
    if(choice==='with') await postJSON('/api/logs/delete',{backend:id});
  }catch(e){ await askChoice('削除できませんでした',`<p>${esc(e.message||e)}</p>`,[{label:'閉じる',value:null}]); return; }
  if(choice==='with'){ reloadAfterLogDelete(); try{ sessionStorage.setItem('waf-open','home|'); }catch(e){} return; }
  loadOverview(); load();
}
function loadOverview(){
  fetch('/api/overview',{cache:'no-store'}).then(r=>r.json()).then(o=>{ window.__ov=o; homeStatus(); homeWatch(); homeBackends(); }).catch(()=>{});
}
/* ホーム: 組織と接続先 */
let HOME_BE='';
function hstats(){ return HOME_BE?(window.__hstats||null):(window.__stats||null); }
function homeBeSync(){
  const sel=document.getElementById('homeBe'); if(!sel) return;
  scOrgFill('home','homeOrg');
  const base=beBase();
  scBeFill('home',sel,base,'すべての接続先');
  HOME_BE=scStr('home');
  scPickShow(sel,base.length);
  const n=document.getElementById('homeBeNote'); if(n) n.textContent=HOME_BE?'選んだ組織・接続先だけの集計を表示しています':'';
}
function loadHomeBe(){
  const q=HOME_BE; if(!q) return;
  fetch('/api/stats?map_period='+encodeURIComponent(mapRange)+'&backend='+encodeURIComponent(q)).then(r=>r.json()).then(d=>{
    if(q!==HOME_BE||!d||!d.categories) return;
    window.__hstats=d; renderHome();
  }).catch(()=>{});
}
function homeScopeChanged(){
  window.__hstats=null; homeBeSync();
  const bd=document.querySelector('#hmapNote'); if(bd) bd.textContent='';
  if(HOME_BE) loadHomeBe(); else renderHome();
  homeBackends();
}
function changeHomeBe(v){ SC.home.be=v||''; homeScopeChanged(); }
function changeHomeOrg(v){ SC.home.org=v||''; SC.home.be=''; homeScopeChanged(); }
function renderHome(){
  const d=hstats(); if(!d) return;
  homeSpark(d); homeDonut(d); homeMap(d); homeScale(d); homeRecent();
}
function renderTable(id,rows){
  document.querySelector('#'+id+' tbody').innerHTML = rows || '<tr><td colspan="6" class="empty">データなし</td></tr>';
}

/* ライブ攻撃マップ(同梱の世界地図、等間隔投影、arcアニメ) */
const MAP_W=960, MAP_H=480;
let worldReady=false, worldFailed=false;
const SVGNS='http://www.w3.org/2000/svg';
let mapData={server:null, nodes:[]};
let activeActions={PASS:true,BLOCK:true,DETECT:true,RATELIMIT:true};
let projectiles=[];           // {sx,sy,cx,cy,tx,ty,t,speed,color}
let arcGeo=[];                // 表示中ノードのarc幾何
let rafStarted=false;

function project(lon,lat){ return [ (lon+180)/360*MAP_W, (90-lat)/180*MAP_H ]; }

function initWorld(){
  if(worldReady||worldFailed) return;
  fetch('/assets/world').then(r=>r.text()).then(svg=>{
    if(!svg || svg.indexOf('<path')<0){ worldFailed=true; drawMapFallback(); return; }
    const land=document.getElementById('land');
    land.innerHTML=svg;
    land.querySelectorAll('path').forEach(p=>{
      p.setAttribute('fill','var(--land)');
      p.setAttribute('stroke','var(--land-stroke)');
      p.setAttribute('stroke-width','0.5');
    });
    worldReady=true; drawMap();
    if(!rafStarted){ rafStarted=true; requestAnimationFrame(animate); }
  }).catch(()=>{ worldFailed=true; drawMapFallback(); });
}
function drawMapFallback(){
  const land=document.getElementById('land');
  if(land) land.innerHTML=`<text x="${MAP_W/2}" y="${MAP_H/2}" fill="var(--ink-muted)"
     text-anchor="middle" font-size="14">世界地図を読み込めませんでした。下の国別/IP一覧をご覧ください。</text>`;
}
function nodeActiveTotal(n){
  let s=0; for(const a in activeActions) if(activeActions[a]) s+=(n.counts[a]||0); return s;
}
function nodeDominantAction(n){
  let best='PASS', bv=-1;
  for(const a in activeActions){ if(activeActions[a] && (n.counts[a]||0)>bv){ bv=n.counts[a]||0; best=a; } }
  return best;
}
function drawMap(){
  if(!worldReady) return;
  const srv=mapData.server;
  const arcsG=document.getElementById('arcs'), nodesG=document.getElementById('nodes'), srvG=document.getElementById('srv'), hitsG=document.getElementById('hits');
  arcsG.innerHTML=''; nodesG.innerHTML=''; srvG.innerHTML=''; hitsG.innerHTML=''; arcGeo=[];
  const z=zoomOf('map');            // ズーム倍率。描画サイズを /z して画面上で一定にする
  let T=null;
  if(srv){ T=project(srv.lon,srv.lat);
    const sr=(5/z).toFixed(2), sr2=(20/z).toFixed(2);
    // 防御サーバ(ターゲット)
    srvG.innerHTML=`<circle cx="${T[0]}" cy="${T[1]}" r="${sr}" fill="var(--ink)"/>
      <circle cx="${T[0]}" cy="${T[1]}" r="${sr}" class="srv-ring" vector-effect="non-scaling-stroke">
        <animate attributeName="r" from="${sr}" to="${sr2}" dur="2s" repeatCount="indefinite"/>
        <animate attributeName="opacity" from=".8" to="0" dur="2s" repeatCount="indefinite"/></circle>
      <title>防御サーバ ${esc(srv.ip)} (${esc(srv.country||'')})</title>`;
    // サーバ印の当たり判定(ツールチップはtitle)。大きめにして狙いやすくする
    const sh=document.createElementNS(SVGNS,'circle');
    sh.setAttribute('cx',T[0]); sh.setAttribute('cy',T[1]); sh.setAttribute('r',(12/z).toFixed(2));
    const st=document.createElementNS(SVGNS,'title'); st.textContent=`防御サーバ ${srv.ip} (${srv.country||''})`; sh.appendChild(st);
    hitsG.appendChild(sh);
  }
  const hitList=[];
  const nodes=(mapData.nodes||[]).slice(0,80);
  const maxT=Math.max(1,...nodes.map(nodeActiveTotal));
  nodes.forEach(n=>{
    const at=nodeActiveTotal(n); if(at<=0) return;
    const S=project(n.lon,n.lat);
    // 半径は件数の対数で決めて上限を小さくする。大量件数でも地図を覆わない
    const r=(2.6+3.4*Math.min(1,Math.log10(at+1)/5))/z;
    const dom=nodeDominantAction(n), col=ACT_COLOR[dom];
    const isSelf = srv && n.ip===srv.ip;
    if(T && !isSelf){
      // 曲線arc(制御点は中点から法線方向)
      const mx=(S[0]+T[0])/2, my=(S[1]+T[1])/2;
      const dx=T[0]-S[0], dy=T[1]-S[1], len=Math.hypot(dx,dy)||1;
      const cx=mx - dy/len*len*0.18, cy=my + dx/len*len*0.18;
      arcsG.innerHTML+=`<path class="arc" vector-effect="non-scaling-stroke" d="M ${S[0]} ${S[1]} Q ${cx} ${cy} ${T[0]} ${T[1]}" stroke="${col}"/>`;
      arcGeo.push({n, sx:S[0], sy:S[1], cx, cy, tx:T[0], ty:T[1]});
    } else if(isSelf){
      // 自ホスト(ローカル/内部)はサーバ位置でパルス
      arcGeo.push({n, sx:S[0], sy:S[1], cx:S[0], cy:S[1], tx:S[0], ty:S[1], self:true});
    }
    const dot=document.createElementNS(SVGNS,'circle');
    dot.setAttribute('cx',S[0]); dot.setAttribute('cy',S[1]); dot.setAttribute('r',r);
    dot.setAttribute('fill',col); dot.setAttribute('fill-opacity','.85'); dot.setAttribute('class','node');
    nodesG.appendChild(dot);
    // 見た目より大きい透明な当たり判定(画面上で半径14px以上)。ズームしても一定
    const hit=document.createElementNS(SVGNS,'circle');
    hit.setAttribute('cx',S[0]); hit.setAttribute('cy',S[1]);
    hit.setAttribute('r',Math.max(r,14/z).toFixed(2));
    hit.addEventListener('mouseenter',()=>{ hoverIp=n.ip; dot.classList.add('hov'); });
    hit.addEventListener('mousemove',ev=>{ hoverIp=n.ip; showTip(ev,n); });
    hit.addEventListener('mouseleave',()=>{ hoverIp=null; dot.classList.remove('hov'); hideTip(); });
    if(n.ip===hoverIp) dot.classList.add('hov');     // 再描画(約4秒ごと)しても強調を維持する
    hitList.push({hit,r});
  });
  // 小さい点を手前に置く(重なっても狙える)
  hitList.sort((a,b)=>b.r-a.r).forEach(h=>hitsG.appendChild(h.hit));
  if(hoverIp && !nodes.some(n=>n.ip===hoverIp)){ hoverIp=null; hideTip(); }
}
function spawnProjectiles(){
  // 各arcから、アクティブな件数に比例してプロジェクタイルを出す
  arcGeo.forEach(a=>{
    if(a.self) return;
    const n=a.n;
    for(const act in activeActions){
      if(!activeActions[act]) continue;
      const c=n.counts[act]||0; if(c<=0) continue;
      // 1フレームあたりの発生確率。件数で増やし、上限あり
      const p=Math.min(0.14, 0.015*Math.log2(c+1));
      if(Math.random()<p && projectiles.length<220){
        projectiles.push({sx:a.sx,sy:a.sy,cx:a.cx,cy:a.cy,tx:a.tx,ty:a.ty,
                          t:0, speed:0.012+Math.random()*0.01, color:ACT_COLOR[act]});
      }
    }
  });
}
function bez(a,b,c,t){ const u=1-t; return u*u*a+2*u*t*b+t*t*c; }
let lastSpawn=0;
function animate(ts){
  if(worldReady){
    const projG=document.getElementById('proj');
    const z=zoomOf('map'), pr=(2.4/z).toFixed(2), fr=(3/z).toFixed(2);
    if(ts-lastSpawn>60){ spawnProjectiles(); lastSpawn=ts; }
    let s='';
    projectiles.forEach(p=>{
      p.t+=p.speed;
      const x=bez(p.sx,p.cx,p.tx,p.t), y=bez(p.sy,p.cy,p.ty,p.t);
      s+=`<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="${pr}" fill="${p.color}"/>`;
      if(p.t>=1){ // 着弾フラッシュ
        s+=`<circle cx="${p.tx}" cy="${p.ty}" r="${fr}" fill="none" stroke="${p.color}" stroke-width="1.5" opacity="0.8" vector-effect="non-scaling-stroke"/>`;
      }
    });
    projectiles=projectiles.filter(p=>p.t<1);
    projG.innerHTML=s;
  }
  requestAnimationFrame(animate);
}
function showTip(ev,n){
  const tip=document.getElementById('maptip'), wrap=document.getElementById('mapWrap');
  const rc=wrap.getBoundingClientRect();
  const c=n.counts;
  const parts=['PASS','BLOCK','DETECT','RATELIMIT'].filter(a=>c[a]).map(a=>`${ACT_LABEL[a]} ${c[a]}`);
  const conns = (n.conns&&n.conns.length) ? `<br><span style="color:var(--ink-muted)">接続元: ${n.conns.map(esc).join(', ')}</span>` : '';
  const self = (mapData.server && n.ip===mapData.server.ip) ? ' · 自ホスト/内部' : '';
  tip.innerHTML=`<b>${esc(n.country||'?')}</b> (${esc(n.cc||'')})${self}<br>${esc(n.ip)}<br>${parts.join(' / ')}${conns}`;
  tip.style.display='block';
  tip.style.left=Math.min(ev.clientX-rc.left+12, rc.width-170)+'px';
  tip.style.top=(ev.clientY-rc.top+12)+'px';
}
let hoverIp=null;
function hideTip(){document.getElementById('maptip').style.display='none';}

function renderMapFilter(){
  const el=document.getElementById('mapFilter');
  el.innerHTML=['PASS','BLOCK','DETECT','RATELIMIT'].map(a=>
    `<span class="f ${activeActions[a]?'on':''}" data-a="${a}">
       <i style="background:${ACT_COLOR[a]}"></i>${ACT_LABEL[a]}</span>`).join('');
  el.querySelectorAll('.f').forEach(f=>{
    f.onclick=()=>{ activeActions[f.dataset.a]=!activeActions[f.dataset.a];
      f.classList.toggle('on'); drawMap(); };
  });
}

function renderInsights(){
  const d=tstats(); const el=document.getElementById('insights'); if(!el) return;
  const a=d.actions||{}; const atkTotal=(a.BLOCK||0)+(a.DETECT||0);
  // 最も狙われたパス(攻撃を受けたパス優先、無ければフィールド)
  const topPath=(d.top_paths&&d.top_paths[0])||(d.top_fields&&d.top_fields[0]&&{path:d.top_fields[0].field,count:d.top_fields[0].count});
  // 最多の攻撃カテゴリ
  const cats=(d.categories||[]).filter(c=>c.count>0).sort((x,y)=>y.count-x.count);
  const topCat=cats[0];
  // 最多の攻撃元IP(遮断数順)
  const topIp=(d.top_ips||[]).slice().sort((x,y)=>(y.blocked||0)-(x.blocked||0))[0];
  // 攻撃元トップ国(map.nodes から BLOCK+DETECT で集計)
  const nodes=(d.map&&d.map.nodes)||[]; const byC={};
  nodes.forEach(n=>{ const atk=((n.counts&&n.counts.BLOCK)||0)+((n.counts&&n.counts.DETECT)||0);
    if(atk>0){ const k=n.country||'(不明)'; byC[k]=(byC[k]||0)+atk; } });
  const topCountry=Object.entries(byC).sort((x,y)=>y[1]-x[1])[0];
  // ピーク時間(直近24h)
  const hrs=(d.traffic&&d.traffic.hour)||[]; let peak=null;
  hrs.forEach(x=>{ const tot=(x.PASS||0)+(x.BLOCK||0)+(x.DETECT||0)+(x.RATELIMIT||0); if(!peak||tot>peak.tot) peak={t:x.t,tot}; });
  const card=(label,val,sub,tone)=>`<div class="ins ${tone||''}"><div class="ins-l">${label}</div>
    <div class="ins-v">${val}</div><div class="ins-s">${sub||'&nbsp;'}</div></div>`;
  el.innerHTML =
    card('🎯 最も狙われたパス', topPath?esc(topPath.path||'—'):'—', topPath?topPath.count+' 件の攻撃':'攻撃なし','k-red')
    + card('🧬 最多の攻撃タイプ', topCat?esc(topCat.label||topCat.name):'—', topCat?topCat.count+' 件':'—','k-amber')
    + card('📍 最大の攻撃元IP', topIp?esc(topIp.ip):'—', topIp?(topIp.blocked||0)+' 件遮断':'—','k-red')
    + card('🌐 攻撃元トップ国', topCountry?esc(topCountry[0]):'—', topCountry?topCountry[1]+' 件の攻撃':'攻撃なし','k-purple')
    + card('🔥 攻撃の多い時間', peak?esc(peak.t):'—', peak?'総'+peak.tot+' リクエスト':'—','k-neutral')
    + card('🛡 攻撃総数(BLOCK+DETECT)', atkTotal, '遮断率 '+(d.block_rate||0)+'%','k-red');
  // 深刻度バー
  const sb=document.getElementById('sevbar'); if(sb){
    const sev=d.severity||{}; const order=[['critical','危険'],['high','高'],['medium','中'],['low','低']];
    const tot=order.reduce((s,o)=>s+(sev[o[0]]||0),0);
    if(!tot){ sb.innerHTML='<span class="seemore">検知された攻撃はまだありません</span>'; }
    else{
      sb.innerHTML='<div class="sevrow">'+order.map(o=>{ const v=sev[o[0]]||0; const w=100*v/tot;
        // 幅が十分ある区間は、色だけに頼らず名前と件数を書く
        const lab=w>=14?`${o[1]} ${v}`:(w>=6?o[1]:'');
        return v>0?`<div class="sevseg sev-${o[0]}" style="flex:${v} 1 0" title="${o[1]}: ${v} 件(${w.toFixed(1)}%)">${lab}</div>`:''; }).join('')+'</div>'
        +'<div class="sevleg">'+order.map(o=>{ const v=sev[o[0]]||0;
          return `<span class="sev-${o[0]}"><i></i>${o[1]} <b>${v}</b>${tot?`(${Math.round(100*v/tot)}%)`:''}</span>`; }).join('')+'</div>';
    }
  }
}
function renderCountries(){
  const el=document.getElementById('countryTable'); if(!el) return;
  const m=tstats().map||{};
  const nodes=m.nodes||[];
  const agg={};
  nodes.forEach(n=>{
    const key=n.country||'(不明)', cc=n.cc||'';
    const a=agg[key]||(agg[key]={country:key, cc:cc, PASS:0,BLOCK:0,DETECT:0,RATELIMIT:0, total:0});
    ['PASS','BLOCK','DETECT','RATELIMIT'].forEach(k=>{ a[k]+=(n.counts&&n.counts[k])||0; });
    a.total+=n.total||0;
  });
  const rows=Object.values(agg).sort((x,y)=>y.total-x.total);
  if(!rows.length){ el.innerHTML='<div class="empty">この期間の送信元データがありません(ジオ解決済みの公開IPのみ集計)。</div>'; return; }
  const maxT=Math.max(1,...rows.map(r=>r.total));
  let h='<table class="ctbl"><thead><tr><th>国</th><th>総数</th><th>構成</th>'
    +'<th>通過</th><th>検知</th><th>遮断</th><th>制限</th></tr></thead><tbody>';
  rows.forEach(r=>{
    const w=Math.round(100*r.total/maxT);
    const atk=r.BLOCK+r.DETECT;
    const bar=`<div class="ctrack"><div class="cfill" style="width:${w}%;background:${atk>0?'var(--block)':'var(--pass)'}"></div></div>`;
    h+=`<tr>
      <td><b>${esc(r.country)}</b> <span class="seemore">${esc(r.cc)}</span></td>
      <td>${r.total}</td><td style="width:140px">${bar}</td>
      <td style="color:var(--pass)">${r.PASS}</td>
      <td style="color:var(--detect)">${r.DETECT}</td>
      <td style="color:var(--block)">${r.BLOCK}</td>
      <td style="color:var(--rate)">${r.RATELIMIT}</td>
    </tr>`;
  });
  h+='</tbody></table>';
  el.innerHTML=h;
}
function renderMap(m){
  mapData=m;
  document.getElementById('m-pub').textContent=(m.nodes||[]).length;
  const intPill=document.getElementById('m-int');
  if(m.server){
    intPill.innerHTML=`${m.internal_count} <span style="color:var(--ink-muted)">(防御サーバ ${esc(m.server.ip)} / ${esc(m.server.country||'?')})</span>`;
  }else{ intPill.textContent=m.internal_count; }
  document.getElementById('m-top').textContent=
    (m.countries&&m.countries.length) ? m.countries.map(c=>c.country+'('+c.count+')').slice(0,3).join(' / ') : '—';
  const notes=[];
  notes.push('送信元ノード(色=主要アクション)から防御サーバへ、リクエストがアニメ表示されます。右上のフィルタで種類を切替。スクロールでズーム / ドラッグで移動 / ダブルクリックで戻す。');
  if(m.internal_count>0 && m.server)
    notes.push(`内部/LANからのアクセス ${m.internal_count}件は、各自のIPではなく「WAFホスト自身の出口IP(${m.server.ip})」に集約されます。この出口IPはWAFを動かしているPCのVPN/回線でのみ変わり、LAN内の訪問者(友人)のVPNでは変わりません(LANの通信には各自の公開IPが含まれないため)。友人の実IP/VPN出口を見るには、友人がインターネット経由で接続する必要があります。`);
  if(m.public_unresolved>0)
    notes.push(`ジオ未解決IP: ${m.public_unresolved}件。`);
  document.getElementById('mapNote').innerHTML = notes.map(esc).join('<br>');
  if(worldFailed){drawMapFallback();} else {initWorld(); drawMap();}
}

/* リアルタイム攻撃マップ(SSE) */
let rtWorldReady=false, rtServer=null, rtRafStarted=false;
let rtActive={PASS:true,BLOCK:true,DETECT:true,RATELIMIT:true,ERROR:true};
let rtProj=[], rtPings=[], rtRate=[], rtLastBig={}, rtLastTs=0;
const RT_MAX_PROJ=160, RT_MAX_PING=90;
let rtWorldLoading=false;
function rtLoadWorld(n){
  // 世界地図の読み込み。1回の失敗(起動直後、瞬断、ログイン前の401)で止めず、成功するまで再試行する
  if(rtWorldReady||rtWorldLoading) return; rtWorldLoading=true;
  const retry=()=>{ rtWorldLoading=false; const land=document.getElementById('rtland');
    if(land && !land.children.length) land.innerHTML=`<text x="480" y="240" fill="var(--ink-muted)" text-anchor="middle" font-size="14">世界地図を読み込み中…</text>`;
    setTimeout(()=>rtLoadWorld((n||0)+1), Math.min(15000,1000*((n||0)+1))); };
  fetch('/assets/world',{cache:'no-store'}).then(r=>r.ok?r.text():Promise.reject()).then(svg=>{
    if(!svg || svg.indexOf('<path')<0) return Promise.reject();
    const land=document.getElementById('rtland'); land.innerHTML=svg;
    land.querySelectorAll('path').forEach(p=>{ p.setAttribute('fill','var(--land)');
      p.setAttribute('stroke','var(--land-stroke)'); p.setAttribute('stroke-width','0.5'); });
    rtWorldReady=true; rtWorldLoading=false; rtDrawServer();
  }).catch(retry);
}
function rtInit(){
  rtLoadWorld(0);
  rtRenderFilter();
  rtConnect();
  if(!rtRafStarted){ rtRafStarted=true; requestAnimationFrame(rtAnimate); }
}
function rtRenderFilter(){
  const el=document.getElementById('rtFilter');
  el.innerHTML=['PASS','BLOCK','DETECT','RATELIMIT','ERROR'].map(a=>
    `<span class="f ${rtActive[a]?'on':''}" data-a="${a}"><i style="background:${ACT_COLOR[a]}"></i>${ACT_LABEL[a]}</span>`).join('');
  el.querySelectorAll('.f').forEach(f=>{ f.onclick=()=>{ rtActive[f.dataset.a]=!rtActive[f.dataset.a]; f.classList.toggle('on'); }; });
}
function setRtStatus(on){
  document.getElementById('rtLive').classList.toggle('on',on);
  document.getElementById('rtStatus').textContent = on?'ライブ接続中':'切断 — 再接続中…';
}
function rtConnect(){
  try{
    const es=new EventSource('/api/stream');
    es.addEventListener('server',ev=>{ try{ rtServer=JSON.parse(ev.data).server; rtDrawServer(); }catch(e){} });
    // KPIの絶対カウント(ストリーム開始位置と一致)。以降はSSEイベントで加算するだけ
    es.addEventListener('counts',ev=>{ try{ const c=JSON.parse(ev.data);
      window.__live=Object.assign({PASS:0,BLOCK:0,DETECT:0,RATELIMIT:0,ERROR:0}, c.actions||{});
      window.__liveTotal=c.total; window.__liveSeeded=true; renderKpisLive(); }catch(e){} });
    es.onmessage=ev=>{ let e; try{e=JSON.parse(ev.data);}catch(_){return;} if(e&&e.heartbeat)return; rtOnEvent(e); };
    es.onopen=()=>setRtStatus(true);
    es.onerror=()=>{ setRtStatus(false); };
  }catch(e){ setRtStatus(false); }
}
function rtDrawServer(){
  const g=document.getElementById('rtsrv'); if(!rtServer||!rtWorldReady){ if(g)g.innerHTML=''; return; }
  const [x,y]=project(rtServer.lon,rtServer.lat);
  const z=zoomOf('rtmap'), sr=(5/z).toFixed(2), sr2=(20/z).toFixed(2);
  g.innerHTML=`<circle cx="${x}" cy="${y}" r="${sr}" fill="var(--ink)"/>
    <circle cx="${x}" cy="${y}" r="${sr}" class="srv-ring" vector-effect="non-scaling-stroke">
      <animate attributeName="r" from="${sr}" to="${sr2}" dur="2s" repeatCount="indefinite"/>
      <animate attributeName="opacity" from=".8" to="0" dur="2s" repeatCount="indefinite"/></circle>
    <title>防御サーバ ${esc(rtServer.ip||'')}</title>`;
}
let rtSkip={};
function rtSkipText(){ const t=Object.keys(rtSkip).map(k=>k+' '+rtSkip[k]+'件').join(' / '); return t?'  ※地図に描けず: '+t:''; }
function rtSkipShow(){ const el=document.getElementById('rtLast'); if(el){ el.textContent=el.textContent.replace(/  ※地図に描けず:.*$/,'')+rtSkipText(); } }
function rtOnEvent(e){
  const now=performance.now();
  // 集約されたdrop(×N)はN件として数える(req/s と点の数に反映)
  const cnt=Math.max(1, parseInt(e.count,10)||1);
  // マップの接続先絞り込み。対象外のイベントはマップの件数・表示に入れない(イベントログとアラートは全体のまま)
  const mapOk = !MAP_BE || scIn('map',e.backend||'');
  if(mapOk){
    rtRate.push([now,cnt]);
    document.getElementById('rtLast').textContent =
      `最新: ${esc(e.action||'')}${cnt>1?' ×'+cnt:''} ${esc(e.method||e.disposition||'')} ${esc(e.path||'')} ← ${esc(e.country||e.client_ip||'')}`+rtSkipText();
  }
  // イベントログにもリアルタイムで反映(先頭に追加)
  logOnEvent(e);
  try{ alertOnEvent(e); }catch(_){}
  if(!mapOk) return;
  if(!rtActive[e.action]) return;
  // 防御サーバ位置が未取得(出口IPを解決できなかった等)でも、内部/LANイベントがサーバ位置を持つので、それで描き始める
  if(!rtServer && e.kind==='egress' && e.lat!=null){ rtServer={ip:e.client_ip||'',lat:e.lat,lon:e.lon,country:e.country,cc:e.cc}; rtDrawServer(); }
  if(e.lat==null || !rtWorldReady){
    // 描けない理由を画面に出す(切り分け用)。位置不明か地図未読込
    const k=!rtWorldReady?'地図未読込':'送信元の位置が不明';
    rtSkip[k]=(rtSkip[k]||0)+1; rtSkipShow(); return;
  }
  // 別タブ/最小化中は描かない。戻ったときに溜まった弾が一斉に出るのを防ぐ
  if(document.hidden || curPage!=='map') return;
  const S=project(e.lon,e.lat), T=rtServer?project(rtServer.lon,rtServer.lat):S;
  const col=ACT_COLOR[e.action]||'#888';
  // 送信元が防御サーバと同じ位置(LAN内/同一ホスト/同じ出口IP)なら、マーカーに隠れないようサーバ位置に大きな波紋を重ねる。
  // サーバ位置が不明なとき(出口IPを取得できない環境)は線を引けないので、送信元の位置に波紋だけ出す
  const local = (e.kind==='egress') || !rtServer;
  if(local){
    // 内部/LAN(サーバ位置)の波紋は種類ごとに最短120ms間隔に間引く。多発時も1つずつ見える
    const lb=rtLastBig[e.action]||0;
    if(now-lb<120){ const q=rtPings[rtPings.length-1]; if(q&&q.big&&q.color===col) q.n=(q.n||1)+cnt; return; }
    rtLastBig[e.action]=now;
  }
  if(rtPings.length>=RT_MAX_PING) rtPings.splice(0, rtPings.length-RT_MAX_PING+1);
  rtPings.push({x:S[0],y:S[1],born:now,color:col,big:local,n:cnt});
  if(!local){
    // 集約件数が多いほど弾数を増やす(最大8発、1件=1発)。混雑時は上限まで間引く
    const room=RT_MAX_PROJ-rtProj.length; if(room<=0) return;
    const shots=Math.min(8, cnt, room);
    for(let k=0;k<shots;k++){
      const mx=(S[0]+T[0])/2,my=(S[1]+T[1])/2,dx=T[0]-S[0],dy=T[1]-S[1],len=Math.hypot(dx,dy)||1;
      const bend=0.18*(1+(k?(Math.random()-0.5)*0.6:0));
      const cx=mx-dy/len*len*bend, cy=my+dx/len*len*bend;
      rtProj.push({sx:S[0],sy:S[1],cx,cy,tx:T[0],ty:T[1],t:-k*0.06,speed:0.016+Math.random()*0.008,color:col});
    }
  }
}
function rtAnimate(ts){
  const now=performance.now(); rtRate=rtRate.filter(r=>now-r[0]<3000);
  const dt=Math.min(3, rtLastTs? (now-rtLastTs)/16.67 : 1); rtLastTs=now;   // 60fps換算の経過。フレームが落ちても同じ速さで進む
  const rr=document.getElementById('rtRate'); if(rr){ const tot=rtRate.reduce((a,r)=>a+r[1],0)/3; rr.textContent=(tot>=100?Math.round(tot).toLocaleString():tot.toFixed(1))+' req/s'; }
  if(rtWorldReady && (document.hidden || curPage!=='map')){ rtProj.length=0; rtPings.length=0; }
  else if(rtWorldReady){
    const z=zoomOf('rtmap');
    let s='';
    rtProj.forEach(p=>{ p.t+=p.speed*dt;
      if(p.t<0) return;
      const u=1-p.t, x=u*u*p.sx+2*u*p.t*p.cx+p.t*p.t*p.tx, y=u*u*p.sy+2*u*p.t*p.cy+p.t*p.t*p.ty;
      const op=Math.max(0.15,1-p.t);
      s+=`<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="${(2.6/z).toFixed(2)}" fill="${p.color}" opacity="${op.toFixed(2)}"/>`;
      if(p.t>=1) s+=`<circle cx="${p.tx}" cy="${p.ty}" r="${(4/z).toFixed(2)}" fill="none" stroke="${p.color}" stroke-width="1.5" opacity="0.7" vector-effect="non-scaling-stroke"/>`;
    });
    rtProj=rtProj.filter(p=>p.t<1.05);
    document.getElementById('rtproj').innerHTML=s;
    let ns='';
    rtPings.forEach(p=>{ const age=(now-p.born)/2600; if(age>1) return;
      if(p.big){   // サーバ位置に重なる送信元は大きく太い波紋(件数が多いほど濃く)
        const R=(8+34*age)/z, dens=Math.min(1,0.45+Math.log10(p.n||1)*0.2);
        ns+=`<circle cx="${p.x}" cy="${p.y}" r="${R.toFixed(2)}" fill="${p.color}" opacity="${((1-age)*0.22*dens).toFixed(2)}"/>`;
        ns+=`<circle cx="${p.x}" cy="${p.y}" r="${R.toFixed(2)}" fill="none" stroke="${p.color}" stroke-width="2.4" opacity="${((1-age)*dens).toFixed(2)}" vector-effect="non-scaling-stroke"/>`;
        ns+=`<circle cx="${p.x}" cy="${p.y}" r="${(R*0.6).toFixed(2)}" fill="none" stroke="${p.color}" stroke-width="1.2" opacity="${((1-age)*0.7*dens).toFixed(2)}" vector-effect="non-scaling-stroke"/>`;
        return;
      }
      const r=(3+10*age)/z;
      ns+=`<circle cx="${p.x}" cy="${p.y}" r="${((3+2*(1-age))/z).toFixed(2)}" fill="${p.color}" opacity="${((1-age)*0.9).toFixed(2)}"/>`;
      ns+=`<circle cx="${p.x}" cy="${p.y}" r="${r.toFixed(2)}" fill="none" stroke="${p.color}" stroke-width="1" opacity="${((1-age)*0.8).toFixed(2)}" vector-effect="non-scaling-stroke"/>`;
    });
    rtPings=rtPings.filter(p=>(now-p.born)/2600<=1);
    document.getElementById('rtnodes').innerHTML=ns;
  }
  requestAnimationFrame(rtAnimate);
}

/* 地図のズーム/パン(両マップ共通) */
// ズーム倍率(960/viewBox幅)。マーカーとアニメはこの値で割り、画面上のサイズを一定にする
window.__zoom={map:1, rtmap:1};
function zoomOf(which){ return (window.__zoom&&window.__zoom[which])||1; }
function attachZoom(svgId, onZoom){
  const svg=document.getElementById(svgId); if(!svg) return;
  const key = svgId==='rtmap' ? 'rtmap' : 'map';
  const vb={x:0,y:0,w:960,h:480};
  const apply=()=>{
    svg.setAttribute('viewBox',`${vb.x.toFixed(1)} ${vb.y.toFixed(1)} ${vb.w.toFixed(1)} ${vb.h.toFixed(1)}`);
    window.__zoom[key]=960/vb.w;
    if(onZoom) onZoom();
  };
  const clamp=()=>{ vb.w=Math.min(960,vb.w); vb.h=vb.w*480/960;
    vb.x=Math.max(0,Math.min(960-vb.w,vb.x)); vb.y=Math.max(0,Math.min(480-vb.h,vb.y)); };
  svg.addEventListener('wheel',ev=>{ ev.preventDefault();
    const r=svg.getBoundingClientRect();
    const mx=vb.x+(ev.clientX-r.left)/r.width*vb.w, my=vb.y+(ev.clientY-r.top)/r.height*vb.h;
    const f=ev.deltaY<0?0.82:1.22; let nw=Math.max(80,Math.min(960,vb.w*f));
    vb.x=mx-(mx-vb.x)*(nw/vb.w); vb.y=my-(my-vb.y)*(nw*480/960/vb.h); vb.w=nw; vb.h=nw*480/960; clamp(); apply();
  },{passive:false});
  let drag=null;
  svg.addEventListener('pointerdown',ev=>{ drag={x:ev.clientX,y:ev.clientY,vx:vb.x,vy:vb.y};
    try{svg.setPointerCapture(ev.pointerId);}catch(e){} svg.style.cursor='grabbing'; });
  svg.addEventListener('pointermove',ev=>{ if(!drag)return; const r=svg.getBoundingClientRect();
    vb.x=drag.vx-(ev.clientX-drag.x)/r.width*vb.w; vb.y=drag.vy-(ev.clientY-drag.y)/r.height*vb.h; clamp(); apply(); });
  const end=()=>{ drag=null; svg.style.cursor='grab'; };
  svg.addEventListener('pointerup',end); svg.addEventListener('pointerleave',end);
  svg.addEventListener('dblclick',()=>{ vb.x=0;vb.y=0;vb.w=960;vb.h=480; apply(); });
  svg.style.cursor='grab';
}

/* 攻撃マップの全画面表示 */
let mapFsCard=null;
function mapFsSet(card,on){
  if(on){
    if(mapFsCard&&mapFsCard!==card) mapFsSet(mapFsCard,false);
    mapFsCard=card; card.classList.add('mapfull'); document.body.classList.add('mapfs-lock');
    const b=card.querySelector('.mapfs'); if(b) b.textContent='✕ 全画面を終了(Esc)';
    try{ if(!document.fullscreenElement && document.documentElement.requestFullscreen)
           document.documentElement.requestFullscreen().catch(()=>{}); }catch(e){}
  } else {
    card.classList.remove('mapfull'); document.body.classList.remove('mapfs-lock'); mapFsCard=null;
    const b=card.querySelector('.mapfs'); if(b) b.textContent='⛶ 全画面';
    try{ if(document.fullscreenElement) document.exitFullscreen().catch(()=>{}); }catch(e){}
  }
  alSyncH();
}
document.querySelectorAll('.mapfs').forEach(b=>{
  b.onclick=()=>{ const card=b.closest('.card'); mapFsSet(card,!card.classList.contains('mapfull')); };
});
document.addEventListener('fullscreenchange',()=>{ if(!document.fullscreenElement && mapFsCard) mapFsSet(mapFsCard,false); });
document.addEventListener('keydown',ev=>{ if(ev.key==='Escape' && mapFsCard && !document.getElementById('modal').classList.contains('open')) mapFsSet(mapFsCard,false); });

/* 攻撃アラート(警報バナー) */
const AL={cfg:{enabled:true,sound:false,immediate:'critical',threshold:5,window:10,critical:100,hold:2,bg:true},
  win:[],kind:'intrusion',tkind:'intrusion',shown:false,hideT:0,enterT:0,on:false,lv:'warn',last:0,dismissed:false,min:false,test:false,testUntil:0,audio:null,blink:0,title0:document.title,builtLv:''};
// 攻撃の性質で文言を変える。intrusion=不正リクエスト(XSS/SQLi等の検知・遮断)、flood=大量アクセス(レート制限・接続フラッド・BAN)
const AL_TXT={
  warn:{word:'警戒',lv:'警戒',
    intrusion:{title:'攻撃を検知しました',t1:['不正アクセス検知','Intrusion Detected'],t2:['防御システム稼働中','Defense Active']},
    flood:{title:'大量アクセスを検知しました',t1:['大量アクセス検知','Flood Detected'],t2:['防御システム稼働中','Defense Active']}},
  crit:{word:'緊急',lv:'緊急',
    intrusion:{title:'大規模な攻撃を受けています',t1:['大規模攻撃 発生中','Large-scale Attack'],t2:['防御中','Defending']},
    flood:{title:'DoS攻撃を受けています',t1:['DoS攻撃 発生中','DoS Attack in Progress'],t2:['防御中','Defending']}}};
// レート制限系(カテゴリを持たないイベント)の理由を日本語にする
const AL_DISP={ban_triggered:'BAN発動(レート超過)',ban:'BAN中IPの接続',blocklist:'ブロックリストIP',drop:'レート超過(drop)','429':'レート超過(429)',
  global_shed:'全体上限超過',conn_limit:'同時接続数の超過',overload:'全体の同時接続数が上限',conn_flood:'接続フラッド',
  allowlist:'許可リスト外のIP',slow_conn:'低速接続(Slowloris)',autoban_attack:'自動BAN(攻撃の繰り返し)',autoban_slow:'自動BAN(低速接続)',
  autoban_connlimit:'自動BAN(同時接続上限)',autoban_would_attack:'自動BAN相当(detect)',autoban_would_slow:'自動BAN相当(detect)',
  autoban_would_connlimit:'自動BAN相当(detect)',response_sanitized:'応答のXSSを無害化',response_blocked:'応答のXSSを遮断',response_monitor:'応答のXSSを検知'};
const AL_SEV={low:1,medium:2,high:3,critical:4};
function alCatLabel(key){   // key: 'c:xss'(ルールのカテゴリ) か 'd:ban'(レート制限などの理由)
  const k=key.slice(2);
  if(key[0]==='d') return k.indexOf('country:')===0 ? '国ブロック('+k.slice(8)+')' : (AL_DISP[k]||k);
  return (typeof CAT_LABEL!=='undefined'&&CAT_LABEL[k])||({geo:'国ブロック'})[k]||k;
}
function alLoadCfg(){
  fetch('/api/config').then(r=>r.json()).then(c=>{
    const be=(c.editable||{}).backend;
    if(be){ const ap=(be.profiles||[]).find(x=>x.id===be.active); window.__beName=ap?ap.name:null;
      beSetColors(be.profiles); try{ beChipsRender(); renderRecent(); }catch(e){}
      if((be.profiles||[]).length>1){ let ch=false; be.profiles.forEach(x=>{ if(beKnow(x.id,x.name)) ch=true; }); if(ch) beChipsRender(); } }
    const a=(c.editable||{}).alert; if(a) AL.gcfg=Object.assign({},AL_DEF,a);
    alMerge();
  }).catch(()=>{});
}
const AL_DEF={enabled:true,sound:false,immediate:'critical',threshold:5,window:10,critical:100,hold:2,position:'top',bg:true};
/* 警報バナーの設定。全体の既定(管理者が設定)をユーザー個人の設定で上書きしたもの */
function alMerge(){
  const g=AL.gcfg||AL_DEF, mine=(AUTH.user&&AUTH.user.alert)||{};
  AL.cfg=Object.assign({},g,mine);
  // 「攻撃アラートを表示」は管理者の全体設定(ログ・通知)が優先。全体がオフなら全員オフ、オンのときだけ個人でオフにできる
  AL.cfg.enabled=!!g.enabled && (mine.enabled===undefined||!!mine.enabled);
  if(!AL.cfg.enabled && AL.on && !AL.test) alEnd();
  try{ alBgSync(); }catch(e){}
  const p=['top','both'].includes(AL.cfg.position)?AL.cfg.position:'top';
  if(document.body.dataset.abpos!==p){ document.body.dataset.abpos=p; alSyncH(); }
}
// 上のバナー(#alertBar)と下のバナー(#alertBarB)。下は上の複製で、表示/最小化などの状態を両方に反映する
function alBars(){ return [document.getElementById('alertBar'),document.getElementById('alertBarB')].filter(Boolean); }
function alSyncH(){
  const b=document.getElementById('alertBar'), c=document.getElementById('alertBarB'), p=document.body.dataset.abpos||'top';
  const st=document.documentElement.style;
  st.setProperty('--ab-h',(b&&!b.hidden&&p!=='bottom'?b.offsetHeight:0)+'px');
  const w=c&&c.firstElementChild;   // 展開アニメの途中でも完成時の高さで余白を確保する
  st.setProperty('--abb-h',(c&&!c.hidden&&p!=='top'&&AL.shown!==false?w.scrollHeight:0)+'px');
}
// 上バナーの文字(件数・IP数など)を下バナーへ写す。流れる帯(abTrack)は中身が変わったときだけ写す
function alMirror(){
  const c=document.getElementById('alertBarB'); if(!c) return;
  c.querySelectorAll('[data-mid]').forEach(e=>{
    const s=document.getElementById(e.dataset.mid); if(!s) return;
    if(e.dataset.mid==='abTrack'){ if(e.dataset.src!==(s.dataset.v||'')){ e.dataset.src=s.dataset.v||''; e.innerHTML=s.innerHTML; alSyncAnim(); } }
    else{
      if(!s.children.length && e.textContent!==s.textContent) e.textContent=s.textContent;   // 子要素を持つ枠(攻撃元IPなど)は文字ごと写さない
      if(s.style.display!==e.style.display) e.style.display=s.style.display;
    }
  });
}
// 上下の流れる帯の位置をそろえる
function alSyncAnim(){
  try{
    const a=document.querySelector('#abTrack').getAnimations()[0], b=document.querySelector('#alertBarB [data-mid="abTrack"]').getAnimations()[0];
    if(a&&b&&a.currentTime!=null) b.currentTime=a.currentTime;
  }catch(e){}
}
// 警報中の背景。六角形がランダムに裏返る。canvas1枚に描き、回転中の六角形の周りだけ描き直す
const ALBG={cv:null,cx:null,cells:[],act:[],sp:[null,null],spW:0,spBack:'',w:0,h:0,dpr:1,raf:0,key:'',ra:.62};
const ALBG_DUR=1250;   // 1枚が裏返るまでの時間(ms)
function alHexSvg(fill,stroke,txt,col,tl){
  const t=txt?`<text x="50" y="62" text-anchor="middle" font-family="Arial,Helvetica,sans-serif" font-weight="800" font-size="11" textLength="${tl}" lengthAdjust="spacingAndGlyphs" fill="${col}">${txt}</text>`:'';
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 115.47"><polygon points="50,2 98,29.7 98,85.8 50,113.5 2,85.8 2,29.7" fill="${fill}" stroke="${stroke}" stroke-width="3.5" stroke-linejoin="round"/>${t}</svg>`;
}
// 裏面(文字なし)の色。ダークモードは黒(#000000)、ライトモードは画面の背景と同じ
function alBgLine(back){   // 平常時の六角形の枠。六角形と同じ色
  return back;
}
function alBgBack(){
  const c=getComputedStyle(document.body).backgroundColor, m=(c.match(/[\d.]+/g)||[0,0,0]).map(Number);
  return (0.2126*m[0]+0.7152*m[1]+0.0722*m[2])/255<.5?'#000000':c;
}
// 表(赤・EMERGENCY)と裏(背景ふう)の絵を実寸で作る。大きさかテーマが変わったときだけ作り直す
function alBgSprites(cb){
  const back=alBgBack();
  if(ALBG.spW===ALBG.w && ALBG.spBack===back && ALBG.sp[0] && ALBG.sp[1]) return cb();
  const pw=Math.ceil(ALBG.w*ALBG.dpr), ph=Math.ceil(ALBG.h*ALBG.dpr), w=ALBG.w; let n=0;
  [['#e91507',back==='#000000'?'#000000':back,'EMERGENCY','#000000',66],[back,alBgLine(back),'','',0]]   // 赤の枠はダークが黒、ライトは背景と同じ色。平常時の六角形は薄い輪郭
  .forEach((a,i)=>{
    const img=new Image();
    img.onload=()=>{ const c=document.createElement('canvas'); c.width=pw; c.height=ph; c.getContext('2d').drawImage(img,0,0,pw,ph); ALBG.sp[i]=c; if(++n===2 && ALBG.w===w){ ALBG.spW=w; ALBG.spBack=back; cb(); } };
    img.src='data:image/svg+xml,'+encodeURIComponent(alHexSvg(a[0],a[1],a[2],a[3],a[4]));
  });
}
function alBgCell(c){   // 止まっている六角形を描く
  const f=c.show;
  ALBG.cx.globalAlpha=f===0?ALBG.ra:1;   // 赤は警戒/緊急で濃さを変える
  ALBG.cx.drawImage(ALBG.sp[f],c.x,c.y,ALBG.w,ALBG.h);
  ALBG.cx.globalAlpha=1;
}
// 回転中の六角形は横幅を縮めて裏返す(1枚につき画像1回の描画、影・帯の分割なし)。真横のときは少し縦に大きくして手前に浮かせる
function alBgCellMoving(c){
  const w=ALBG.w, h=ALBG.h, phi=c.th<Math.PI/2?c.th:c.th-Math.PI, k=Math.max(.02,Math.cos(phi)), lift=1+.1*Math.sin(Math.abs(phi)), hh=h*lift;
  ALBG.cx.globalAlpha=c.show===0?ALBG.ra:1;
  ALBG.cx.drawImage(ALBG.sp[c.show],c.x+w*(1-k)/2,c.y+(h-hh)/2,w*k,hh);
  ALBG.cx.globalAlpha=1;
}
function alBgPaintAll(){
  const cx=ALBG.cx; if(!cx||!ALBG.sp[0]) return;
  cx.clearRect(0,0,ALBG.cv.width,ALBG.cv.height);
  ALBG.cells.forEach(alBgCell);
}
function alBgBuild(){
  let cv=ALBG.cv;
  if(!cv){ cv=ALBG.cv=document.createElement('canvas'); cv.id='alertBg'; document.body.insertBefore(cv,document.body.firstChild); ALBG.cx=cv.getContext('2d');
    new MutationObserver(()=>{ if(ALBG.cells.length) alBgSprites(alBgPaintAll); }).observe(document.documentElement,{attributes:true,attributeFilter:['data-theme']}); }   // ダーク/ライト切替で絵を作り直す
  const vw=innerWidth, vh=innerHeight, dpr=Math.min(2,window.devicePixelRatio||1);
  const w=Math.max(84,Math.sqrt(vw*vh/280/0.866)), h=w*1.1547, rh=h*0.75;   // 六角形の幅は最小84px。枚数は約280枚まで
  const cols=Math.ceil(vw/w)+2, rows=Math.ceil(vh/rh)+2, key=cols+'x'+rows+'x'+Math.round(w)+'@'+dpr+'/'+vw+'x'+vh;
  if(ALBG.key===key) return cv;
  ALBG.key=key; ALBG.w=w; ALBG.h=h; ALBG.dpr=dpr; ALBG.act=[]; cancelAnimationFrame(ALBG.raf); ALBG.raf=0;
  cv.width=Math.ceil(vw*dpr); cv.height=Math.ceil(vh*dpr); ALBG.cx.setTransform(dpr,0,0,dpr,0,0);
  ALBG.cells=[]; ALBG.cols=cols; ALBG.rows=rows;
  for(let r=0;r<rows;r++) for(let c=0;c<cols;c++)
    ALBG.cells.push({x:c*w-w+(r%2?w/2:0),y:r*rh-h/2,r,c,show:1,th:0,mv:0,from:0,to:0,t0:0});
  alBgSprites(alBgPaintAll);
  return cv;
}
function alBgFlip(c,now){
  if(c.t0) return;                                    // 回転中は触らない
  c.from=c.show; c.to=1-c.show; c.t0=now||1; ALBG.act.push(c);   // now は開始時刻。未来にするとその時刻から捲り始める
  if(!ALBG.raf) ALBG.raf=requestAnimationFrame(alBgFrame);
}
function alBgFrame(now){
  ALBG.raf=0; const act=ALBG.act; if(!act.length||!ALBG.sp[1]) return;
  const w=ALBG.w, h=ALBG.h, cx=ALBG.cx, cells=ALBG.cells, cols=ALBG.cols, rows=ALBG.rows;
  const dirty=[];                                    // 今回、描き直す六角形(回転中のもの+いま止まったもの)
  act.forEach(c=>{
    if(now<c.t0){ c.mv=0; return; }                  // まだ捲り始めていない
    const p=Math.min(1,(now-c.t0)/ALBG_DUR), e=p<.5?4*p*p*p:1-Math.pow(-2*p+2,3)/2;   // ゆっくり動き出し、ゆっくり止まる
    c.th=e*Math.PI; c.show=c.th<Math.PI/2?c.from:c.to; c.mv=1;
    if(p>=1){ c.th=0; c.show=c.to; c.t0=0; c.mv=0; }
    dirty.push(c);
  });
  if(dirty.length){
    // 回転中の六角形は遠近ではみ出すので、広めの範囲をまとめて1回で消して描き直す
    const mx=Math.ceil(w*.06), my=Math.ceil(h*.1), idx=new Set();
    let x0=1e9,y0=1e9,x1=-1e9,y1=-1e9;
    cx.save(); cx.beginPath();
    dirty.forEach(a=>{
      const X=Math.floor(a.x)-mx, Y=Math.floor(a.y)-my, W=Math.ceil(w)+2*mx, H=Math.ceil(h)+2*my;
      cx.rect(X,Y,W,H); x0=Math.min(x0,X); y0=Math.min(y0,Y); x1=Math.max(x1,X+W); y1=Math.max(y1,Y+H);
      for(let r=a.r-1;r<=a.r+1;r++) for(let c=a.c-1;c<=a.c+1;c++) if(r>=0&&c>=0&&r<rows&&c<cols) idx.add(r*cols+c);
    });
    cx.clip(); cx.clearRect(x0,y0,x1-x0,y1-y0);
    const mv=[]; idx.forEach(i=>{ const c=cells[i]; if(c.mv) mv.push(c); else alBgCell(c); });   // 止まっているものを先に、回転中のものを手前に
    mv.forEach(alBgCellMoving);
    cx.restore();
  }
  ALBG.act=act.filter(c=>c.t0);
  if(ALBG.act.length) ALBG.raf=requestAnimationFrame(alBgFrame);
}
function alBgSync(noIntro){
  const bgOn=!!(AL.cfg&&AL.cfg.bg);
  document.body.classList.toggle('hexbg',bgOn);
  if(!bgOn){                                           // 「背景の六角形」オフのときは点の背景にする
    if(ALBG.cv) ALBG.cv.style.display='none';
    if(AL.bgT){ clearInterval(AL.bgT); AL.bgT=0; }
    return;
  }
  const l=alBgBuild(); l.style.display='';             // 平常時から六角形を敷いておく
  const want=!!(AL.shown && AL.on);
  const still=window.matchMedia&&matchMedia('(prefers-reduced-motion:reduce)').matches;
  if(want){
    clearTimeout(AL.bgOutT); clearTimeout(AL.bgOutT2);
    const ra=AL.lv==='crit'?.88:.62; if(ra!==ALBG.ra){ ALBG.ra=ra; alBgPaintAll(); }
    if(!AL.bgT){
      // 出だし: 敷いてある六角形を順に赤へ捲る
      if(!noIntro){
        const now=performance.now();
        ALBG.cells.forEach(c=>{ if(c.show===1&&!c.t0&&Math.random()<.7){ if(still) c.show=0; else alBgFlip(c,now+Math.random()*1200); } });
        if(still) alBgPaintAll();
      }
      AL.bgT=setInterval(()=>{
        if(document.hidden||!ALBG.cells.length) return;                     // 別タブのときは回さない
        const n=AL.lv==='crit'?6:3, now=performance.now();
        for(let i=0;i<n;i++){
          const c=ALBG.cells[Math.random()*ALBG.cells.length|0];
          if(still){ c.show=1-c.show; } else alBgFlip(c,now);
        }
        if(still) alBgPaintAll();
      },AL.lv==='crit'?260:420); AL.bgLv=AL.lv;
    }
    else if(AL.bgLv!==AL.lv){ clearInterval(AL.bgT); AL.bgT=0; alBgSync(true); }
  } else if(AL.bgT){
    // 終わり: 赤い六角形を元に捲って戻す
    clearInterval(AL.bgT); AL.bgT=0;
    const now=performance.now(), back=()=>ALBG.cells.forEach(c=>{ if(c.show===0&&!c.t0){ if(still){ c.show=1; } else alBgFlip(c,performance.now()+Math.random()*300); } });
    if(still){ back(); alBgPaintAll(); }
    else{
      ALBG.cells.forEach(c=>{ if(c.show===0&&!c.t0&&Math.random()<.9) alBgFlip(c,now+Math.random()*700); });
      clearTimeout(AL.bgOutT); AL.bgOutT=setTimeout(back,1400);                       // 回転の途中で取り残されたものも戻す
      clearTimeout(AL.bgOutT2); AL.bgOutT2=setTimeout(()=>{ ALBG.act=[]; ALBG.cells.forEach(c=>{ c.show=1; c.mv=0; c.th=0; c.t0=0; }); alBgPaintAll(); },3200);
    }
  }
}
let alRsT=0;
window.addEventListener('resize',()=>{ clearTimeout(alRsT); alRsT=setTimeout(()=>{ if(AL.cfg&&AL.cfg.bg) alBgBuild(); },250); });
function alBuildBottom(){
  const src=document.getElementById('alertBar'); if(!src||document.getElementById('alertBarB')) return;
  const c=src.cloneNode(true); c.id='alertBarB'; c.hidden=true; c.className='alertbar';
  c.querySelectorAll('[id]').forEach(e=>{ e.dataset.mid=e.id; e.removeAttribute('id'); });
  c.querySelector('[data-mid="abTrack"]').innerHTML='';
  c.querySelector('[data-mid="abMin"]').onclick=()=>document.getElementById('abMin').click();
  c.querySelector('[data-mid="abClose"]').onclick=()=>document.getElementById('abClose').click();
  document.body.appendChild(c);
  new MutationObserver(alMirror).observe(src,{subtree:true,childList:true,characterData:true,attributes:true,attributeFilter:['style']});
}
// 展開/収納のアニメ中は、下のナビがバナーに追従するよう毎フレーム高さを反映する
function alTrackH(ms){
  const t0=performance.now();
  (function f(){ alSyncH(); if(performance.now()-t0<ms) requestAnimationFrame(f); })();
}
function alReplay(cls,ms){
  const bars=alBars();
  bars.forEach(bar=>{ bar.classList.remove(cls); void bar.offsetWidth; bar.classList.add(cls); });
  if(cls==='enter'){ clearTimeout(AL.enterT); AL.enterT=setTimeout(()=>bars.forEach(b=>b.classList.remove('enter')),ms||1300); }
  else setTimeout(()=>bars.forEach(b=>b.classList.remove(cls)),ms||600);
}
function alReveal(show){
  const bars=alBars();
  if(show===AL.shown) return;
  AL.shown=show; clearTimeout(AL.hideT); alBgSync();
  if(show){
    alMirror();
    bars.forEach(bar=>{ if(bar.hidden){ bar.classList.add('collapsed'); bar.hidden=false; } void bar.offsetHeight; });   // 畳んだ状態を一度描画してから展開する(アニメーションのため)
    bars.forEach(bar=>bar.classList.remove('collapsed')); alReplay('enter'); alSyncAnim();
  } else {
    bars.forEach(bar=>{ bar.classList.remove('enter'); bar.classList.add('collapsed'); });
    AL.hideT=setTimeout(()=>{ if(!AL.shown){ bars.forEach(bar=>{ bar.hidden=true; bar.classList.remove('collapsed'); }); } alSyncH(); },620);
  }
  alSyncH(); alTrackH(750);
}
function alBuild(lv,kind){
  if(AL.builtLv===lv+kind) return; AL.builtLv=lv+kind;
  const w=AL_TXT[lv].word, t=AL_TXT[lv][kind];
  const cell=`<div class="ab-cell"><span class="ab-word">${w}</span><div class="ab-tags">
    <div class="ab-tag"><b>${t.t1[0]}</b><small>${t.t1[1]}</small></div>
    <div class="ab-tag"><b>${t.t2[0]}</b><small>${t.t2[1]}</small></div></div></div>`;
  const set=cell.repeat(10);
  const tk=document.getElementById('abTrack'); tk.innerHTML=set+set; tk.dataset.v=String((+tk.dataset.v||0)+1);   // 同じものを2セット並べて -50% でループ
}
function alBeep(lv){
  if(!AL.cfg.sound) return;
  try{
    const C=window.AudioContext||window.webkitAudioContext; if(!C) return;
    const ac=AL.audio||(AL.audio=new C()); if(ac.state==='suspended') ac.resume();
    let t=ac.currentTime; const n=lv==='crit'?6:3;
    for(let i=0;i<n;i++){
      const o=ac.createOscillator(), g=ac.createGain();
      o.type='square'; o.frequency.value=i%2?660:880;
      g.gain.setValueAtTime(0.0001,t); g.gain.exponentialRampToValueAtTime(0.07,t+0.02);
      g.gain.exponentialRampToValueAtTime(0.0001,t+0.22);
      o.connect(g); g.connect(ac.destination); o.start(t); o.stop(t+0.24); t+=0.26;
    }
  }catch(e){}
}
function alShow(lv){
  const bars=alBars();
  const kind=AL.test?AL.tkind:alStats().kind;
  const escalate = AL.on && AL.lv!==lv && lv==='crit';
  AL.lv=lv; AL.kind=kind; alBuild(lv,kind);
  bars.forEach(b=>b.classList.toggle('crit',lv==='crit')); alBgSync();
  document.getElementById('abLv').textContent=AL_TXT[lv].lv;
  document.getElementById('abTitle').textContent=AL_TXT[lv][kind].title+(AL.test?'(テスト表示)':'');
  if(escalate){ AL.dismissed=false; if(AL.shown) alReplay('shake',560); }   // 格上げしたら、閉じていても出し直す
  bars.forEach(b=>b.classList.toggle('min',AL.min));
  alMirror();
  document.getElementById('alertChip').classList.toggle('on',AL.on&&AL.dismissed);
  alReveal(!AL.dismissed);
  if(escalate && AL.shown) alReplay('enter');
  alSyncH();
}
function alStart(lv){
  const fresh=!AL.on; AL.on=true;
  if(fresh){ AL.dismissed=false; }
  const up = fresh || (lv==='crit'&&AL.lv!=='crit');
  alShow(lv); if(up) alBeep(lv); alRender();
}
function alEnd(){
  AL.on=false; AL.test=false; AL.dismissed=false;
  AL.win=[];          // 次の攻撃は件数が溜まってから表示する(消えた直後の再表示を防ぐ)
  alReveal(false);
  document.getElementById('alertChip').classList.remove('on');
  document.title=AL.title0;
}
// 国コードを日本語の国名にする(ブラウザ内蔵、オフラインでも動く)。取れなければ英語名かコード
let AL_RN=null;
function alCountryName(cc,cn){
  if(cc){
    try{ AL_RN=AL_RN||new Intl.DisplayNames(['ja'],{type:'region'}); const n=AL_RN.of(cc); if(n&&n!==cc) return n; }catch(e){}
  }
  return cn||cc||'不明';
}
function alTop(map,k,unit){   // 件数の多い順に上位k件を「名前 件数」でつなぐ(1種類だけなら件数なし)
  const arr=[...map.entries()].sort((a,b)=>b[1].n-a[1].n);
  const top=arr.slice(0,k).map(([,v])=>arr.length>1?`${v.name} ${v.n.toLocaleString()}`:v.name);
  return top.join(' / ')+(arr.length>k?` ほか${arr.length-k}${unit||''}`:'');
}
function alStats(){
  const now=Date.now(), w=AL.cfg.window*1000;
  AL.win=AL.win.filter(x=>now-x.t<=w);
  let n=0, fl=0, last=null, crit=false; const ips=new Set(), ipn=new Map(), cats=new Map(), ctys=new Map();
  const add=(m,key,name,c)=>{ const o=m.get(key)||{name:name,n:0}; o.n+=c; m.set(key,o); };
  AL.win.forEach(x=>{
    n+=x.n; if(x.act==='RATELIMIT') fl+=x.n; ips.add(x.ip); ipn.set(x.ip,(ipn.get(x.ip)||0)+x.n); last=x; if(x.crit) crit=true;
    add(cats,x.cat,alCatLabel(x.cat),x.n);
    // 内部(LAN/同一ホスト)からの接続は防御サーバの出口IPの国で表示されるので、印を付ける
    const cname=alCountryName(x.cc,x.cn)+(x.inner?'(内部IP)':'');
    add(ctys,(x.cc||x.cn||'?')+(x.inner?'|in':''),cname,x.n);
  });
  const iptip=[...ipn.entries()].sort((a,b)=>b[1]-a[1]).slice(0,8).map(([ip,c])=>ip+'  '+c.toLocaleString()+'件').join('\n');
  return {n,ips:ips.size,iptip,kind:(fl*2>n?'flood':'intrusion'),top:alTop(cats,2,'種'),cty:alTop(ctys,4,'か国'),
          last:last?last.ip+' ('+(last.inner?'内部IP':alCountryName(last.cc,last.cn))+')':'-',crit};
}
function alRender(){
  if(!AL.on) return;
  let s;
  if(AL.test){
    const F={ 'crit|intrusion':{n:234,ips:6,top:'SQLインジェクション 150 / XSS 84',cty:'ロシア 150 / 中国 60 / アメリカ合衆国 24'},
              'crit|flood':{n:5200,ips:3,top:'接続フラッド 3,100 / レート超過(drop) 2,100',cty:'ロシア 3,800 / 中国 1,400'},
              'warn|intrusion':{n:12,ips:2,top:'XSS 8 / SQLインジェクション 4',cty:'ロシア 8 / 中国 4'},
              'warn|flood':{n:40,ips:1,top:'BAN発動(レート超過) 25 / レート超過(drop) 15',cty:'ロシア 40'} };
    s=Object.assign({iptip:''},F[AL.lv+'|'+AL.tkind]);
  }
  else s=alStats();
  document.getElementById('abN').textContent=s.n.toLocaleString();
  document.getElementById('abNl').textContent='件 / 直近'+AL.cfg.window+'秒';
  document.getElementById('abIps').textContent=s.ips.toLocaleString();
  document.getElementById('abTop').textContent=s.top;
  document.getElementById('abCty').textContent=s.cty;
  document.getElementById('abIpsWrap').title=s.iptip||'';   // 攻撃元IPの内訳(マウスを乗せると表示)
  return s;
}
function alTick(){
  if(!AL.on) return;
  const now=Date.now();
  if(AL.test){ if(now>AL.testUntil) alEnd(); else { alRender(); } return; }
  if(now-AL.last>AL.cfg.hold*1000){ alEnd(); return; }
  const s=alRender();
  const c=AL.cfg.critical;
  if(AL.lv==='crit' && c>0 && s.n<c*0.5) alShow('warn');     // 勢いが落ちたら「警戒」に戻す
  else if(s.kind!==AL.kind) alShow(AL.lv);                  // 攻撃の性質が変わったら文言を差し替える
  alSyncH();
  // タブが裏にあっても気づけるよう、タイトルを点滅させる
  AL.blink++; document.title=(AL.blink%2? '⚠ '+AL_TXT[AL.lv].lv+' | ':'')+AL.title0;
}
function alertOnEvent(e){
  if(!AL.cfg.enabled) return;
  const a=e.action; if(a!=='BLOCK'&&a!=='RATELIMIT'&&a!=='DETECT') return;
  const hits=e.hits||[];
  // 複数のルールに当たったら、一番重いルールのカテゴリを攻撃方法とする。ルールが無ければ(レート制限など)理由で表す
  let best=null; hits.forEach(h=>{ if(!best||(AL_SEV[h.severity]||0)>(AL_SEV[best.severity]||0)) best=h; });
  const cat=(best&&best.category)?'c:'+best.category:'d:'+(e.disposition||a.toLowerCase());
  const now=Date.now();
  AL.win.push({t:now,n:Math.max(1,parseInt(e.count,10)||1),ip:e.client_ip||e.ip||'?',cc:e.cc||'',cn:e.country||'',
               inner:e.kind==='egress',act:a,cat:cat,crit:hits.some(h=>h.severity==='critical')});
  const s=alStats(), c=AL.cfg.critical;
  AL.last=now;
  if(AL.test) return;
  const wantCrit = c>0 && s.n>=c;
  // 設定した深刻度以上のルールに当たったら、件数に関係なく1件で表示(UNION SELECT 1回でも出す)
  const sevMax=hits.reduce((m,h)=>Math.max(m,AL_SEV[h.severity]||0),0);
  const imm=({critical:4,high:3,medium:2})[AL.cfg.immediate]||0;
  if(!AL.on){
    if(s.n>=AL.cfg.threshold || (imm>0 && sevMax>=imm)) alStart(wantCrit?'crit':'warn');
  } else if(wantCrit && AL.lv!=='crit'){ alStart('crit'); }
}
function alPreview(lv,kind){
  AL.tkind=kind||'intrusion'; AL.test=true; AL.testUntil=Date.now()+9000; AL.on=true; AL.dismissed=false; AL.last=Date.now();
  alShow(lv); alBeep(lv); alRender();
}
(function alInit(){
  const $=id=>document.getElementById(id);
  alBuildBottom(); alMerge();
  $('abMin').onclick=()=>{ AL.min=!AL.min; alBars().forEach(b=>b.classList.toggle('min',AL.min)); alMirror(); $('abMin').textContent=AL.min?'拡大':'最小化'; alSyncH(); if(!AL.min) alReplay('enter',900); };
  $('abClose').onclick=()=>{ AL.dismissed=true; alReveal(false); $('alertChip').classList.toggle('on',AL.on&&!AL.test); };
  $('alertChip').onclick=()=>{ AL.dismissed=false; alShow(AL.lv); };
  document.addEventListener('click',()=>{ try{ if(AL.audio&&AL.audio.state==='suspended') AL.audio.resume(); }catch(e){} },{once:true});
  window.addEventListener('resize',alSyncH);
  alLoadCfg(); setInterval(alLoadCfg,30000); setInterval(alTick,250);
})();

/* 組織とバックエンドの2段階選択(マップ/トラフィック/イベントログ/IP管理/状態ログ/ホーム共通) */
const SCOPE={orgs:[],backends:[],loaded:false};
const SC={map:{org:'',be:''},traf:{org:'',be:''},ev:{org:'',be:''},ip:{org:'',be:''},sl:{org:'',be:''},home:{org:'',be:''}};
function scopeLoad(){
  return fetch('/api/scope',{cache:'no-store'}).then(r=>r.json()).then(d=>{
    SCOPE.orgs=d.orgs||[]; SCOPE.backends=d.backends||[]; SCOPE.loaded=true;
    Object.keys(SC).forEach(k=>{ const o=SC[k].org; if(o&&!SCOPE.orgs.some(x=>x.id===o)){ SC[k].org=''; SC[k].be=''; } });
    scAllSync();
  }).catch(()=>{});
}
function scAllSync(){ try{ mapBeSync(); trafBeSync(); homeBeSync(); beLfSync(true); if(window.__lastSec) ipSelSync(window.__lastSec); if(slData) slRender(); }catch(e){} }
function scOrgSet(org){
  const out=new Set([org]); let ch=true;
  while(ch){ ch=false; SCOPE.orgs.forEach(o=>{ if(o.parent&&out.has(o.parent)&&!out.has(o.id)){ out.add(o.id); ch=true; } }); }
  return out;
}
function scOrgOf(id){ const b=SCOPE.backends.find(x=>x.id===id); return b?b.org:''; }
function scInOrg(k,id){ const o=SC[k].org; if(!o) return true; return scOrgSet(o).has(scOrgOf(id)); }
function scIn(k,id){ const be=SC[k].be; if(be) return id===be; return scInOrg(k,id); }
// API用: 単一ID またはカンマ区切りID('' = 絞り込みなし, '-' = 該当バックエンドなし)
function scStr(k){
  const s=SC[k]; if(s.be) return s.be; if(!s.org) return '';
  const set=scOrgSet(s.org), ids=SCOPE.backends.filter(b=>set.has(b.org)).map(b=>b.id);
  return ids.length?ids.join(','):'-';
}
function scOrgOn(){ return SCOPE.orgs.length>0 && !AUTH.guser; }   // 一般ユーザーは組織の選択なし
function scOrgFill(k,selId){
  const sel=document.getElementById(selId); if(!sel) return;
  const depth=o=>{ let d=0,p=o.parent,g=0; while(p&&g++<20){ d++; const q=SCOPE.orgs.find(x=>x.id===p); p=q?q.parent:''; } return d; };
  const kids={}; SCOPE.orgs.forEach(o=>{ (kids[o.parent||'']=kids[o.parent||'']||[]).push(o); });
  const ordered=[]; const walk=(pid,seen)=>{ (kids[pid]||[]).forEach(o=>{ if(seen.has(o.id)) return; seen.add(o.id); ordered.push(o); walk(o.id,seen); }); };
  const seen=new Set(); walk('',seen); SCOPE.orgs.forEach(o=>{ if(!seen.has(o.id)){ ordered.push(o); } });
  const sig=ordered.map(o=>o.id+':'+o.name+':'+o.parent).join('|');
  if(sel.dataset.sig!==sig){
    sel.dataset.sig=sig;
    sel.innerHTML='<option value="">'+(selId==='lf-org'?'全組織':'すべての組織')+'</option>'+ordered.map(o=>`<option value="${esc(o.id)}">${'\u3000'.repeat(depth(o))}${esc(o.name)}</option>`).join('');
  }
  sel.value=SC[k].org;
  sel.style.display=scOrgOn()?'':'none';
  const lb=document.querySelector('label[for="'+selId+'"]'); if(lb) lb.style.display=scOrgOn()?'':'none';
}
// base=[{id,name}] を組織で絞って選択肢にする。選択中の接続先が範囲外なら解除
function scBeFill(k,sel,base,allLabel,pre,post){
  if(!sel) return [];
  const list=base.filter(b=>scInOrg(k,b.id));
  const sig=k+'|'+SC[k].org+'|'+list.map(b=>b.id+':'+b.name).join('|')+'|'+(pre||'')+(post||'');
  if(sel.dataset.sig!==sig){
    sel.dataset.sig=sig;
    sel.innerHTML=(pre!==undefined?pre:'<option value="">'+allLabel+'('+list.length+'件)</option>')+list.map(b=>`<option value="${esc(b.id)}">${esc(b.name)}</option>`).join('')+(post||'');
  }
  if(SC[k].be && SC[k].be!=='__none' && !list.some(b=>b.id===SC[k].be)) SC[k].be='';
  sel.value=SC[k].be;
  if(sel.value!==SC[k].be) sel.value='';
  return list;
}
function beBase(){ return Object.keys(BE_KNOWN).map(id=>({id:id,name:BE_KNOWN[id]})); }
function scPickShow(sel,n){ const p=sel&&sel.parentNode; if(p) p.style.display=(n>1||scOrgOn())?'':'none'; }
/* トラフィックページ: 接続先の選択(空=すべて) */
let TRAF_BE='';
// マップ(リアルタイム/集計とも)を接続先ごとに絞り込む。'' = すべて
let MAP_BE='';
function mapBeSync(){
  const sel=document.getElementById('mapBe'); if(!sel) return;
  scOrgFill('map','mapOrg');
  const base=beBase();
  scBeFill('map',sel,base,'すべての接続先');
  MAP_BE=scStr('map');
  scPickShow(sel,base.length);
  const n=document.getElementById('mapBeNote'); if(n) n.textContent=MAP_BE?'選んだ組織・接続先の通信だけを、リアルタイムマップと集計マップに表示しています':'';
}
function loadMapBe(){
  const q=MAP_BE; if(!q) return;
  fetch('/api/stats?map_period='+encodeURIComponent(mapRange)+'&backend='+encodeURIComponent(q)).then(r=>r.json()).then(d=>{
    if(q!==MAP_BE||!d||!d.map) return;
    renderMap(d.map);
  }).catch(()=>{});
}
function mapScopeChanged(){
  mapBeSync();
  rtProj.length=0; rtPings.length=0; rtSkip={};          // リアルタイム側は表示中の弾・波紋を消し、以降は選んだ範囲のイベントだけ描く
  const rl=document.getElementById('rtLast'); if(rl) rl.textContent='';
  if(MAP_BE) loadMapBe(); else if(window.__stats&&window.__stats.map) renderMap(window.__stats.map);
}
function changeMapBe(v){ SC.map.be=v||''; mapScopeChanged(); }
function changeMapOrg(v){ SC.map.org=v||''; SC.map.be=''; mapScopeChanged(); }
function tstats(){ return TRAF_BE?(window.__tstats||{}):(window.__stats||{}); }
function renderTrafficExtras(d){
  if(!d||!d.categories) return;
  renderDonut(d.categories);
    renderBars(document.getElementById('categories'),
      d.categories.filter(c=>c.count>0).sort((a,b)=>b.count-a.count)
        .map(c=>({label:c.label||c.name,count:c.count,color:CAT_COLOR[c.name]})));
    renderTable('rules', d.top_rules.map(r=>`<tr><td><code>${esc(r.id)}</code></td><td>${r.count}</td></tr>`).join(''));
    renderTable('ips', d.top_ips.map(r=>`<tr><td>${esc(r.ip)}</td><td>${r.total}</td><td style="color:var(--block)">${r.blocked}</td></tr>`).join(''));
    const fields=d.top_fields.map(r=>`<tr><td class="path">${esc(r.field)}</td><td>${r.count}</td></tr>`).join('')
      + d.top_paths.map(r=>`<tr><td class="path" title="${esc(r.path)}">${esc(r.path)}</td><td>${r.count}</td></tr>`).join('');
    renderTable('fields', fields);
    window.__heat = d.heatmap||{}; renderHeatmap();
}
function loadTrafficBe(){
  const q=TRAF_BE; if(!q) return;
  fetch('/api/stats?map_period='+encodeURIComponent(mapRange)+'&backend='+encodeURIComponent(q)).then(r=>r.json()).then(d=>{
    if(q!==TRAF_BE||!d||!d.categories) return;
    window.__tstats=d;
    renderCountries(); renderInsights(); renderTraffic(); renderTrafficExtras(d);
  }).catch(()=>{});
}
function trafBeSync(){
  const sel=document.getElementById('trafBe'); if(!sel) return;
  scOrgFill('traf','trafOrg');
  const base=beBase();
  scBeFill('traf',sel,base,'すべての接続先');
  TRAF_BE=scStr('traf');
  scPickShow(sel,base.length);
  const n=document.getElementById('trafBeNote'); if(n) n.textContent=TRAF_BE?'選んだ組織・接続先だけの集計を表示しています':'';
}
function trafScopeChanged(){
  window.__tstats=null; trafBeSync();
  if(TRAF_BE) loadTrafficBe(); else { renderCountries(); renderInsights(); renderTraffic(); renderTrafficExtras(window.__stats); }
}
function changeTrafBe(v){ SC.traf.be=v||''; trafScopeChanged(); }
function changeTrafOrg(v){ SC.traf.org=v||''; SC.traf.be=''; trafScopeChanged(); }
let lastBans=0;
let mapRange='all';
function load(){
  loadSecurity();
  fetch('/api/stats?map_period='+encodeURIComponent(mapRange)).then(r=>r.json()).then(d=>{
    document.getElementById('meta').textContent='最終更新 '+d.generated_at;
    // カテゴリ色/ラベルを確定(初回のみ割当)
    d.categories.forEach((c,i)=>{ if(!CAT_COLOR[c.name]) CAT_COLOR[c.name]=CAT_PALETTE[i%CAT_PALETTE.length];
      CAT_LABEL[c.name]=c.label||c.name; });
    window.__stats=d;
    // KPIのリアルタイム用。SSEが種(counts)を配信するまではポーリング値で代用し、受け取った後はポーリングで上書きしない(二重計上防止)
    if(!window.__liveSeeded){
      window.__live=Object.assign({PASS:0,BLOCK:0,DETECT:0,RATELIMIT:0,ERROR:0}, d.actions||{});
      window.__liveTotal=d.total;
    }
    renderKpisLive();
    beChipsRender();
    renderMapFilter();
    if(MAP_BE) loadMapBe(); else renderMap(d.map);
    renderCountries();
    renderInsights();
    renderTraffic();
    renderHome();
    if(curPage==='home') loadOverview();
    if(!TRAF_BE) renderTrafficExtras(d); else loadTrafficBe();
    if(HOME_BE) loadHomeBe();
    window.__total_events = d.total_events;
    // 初回のみテーブルを種データで初期化。以降はSSEが追加するので上書きしない
    if(!window.__seeded){
      window.__recent = d.recent || [];
      window.__seeded = true;
      renderRecent();
    }
  }).catch(()=>{document.getElementById('meta').textContent='ログ取得に失敗';});
}
// 現在のライブカウントからKPIを描画(SSEの種とSSE加算)
function renderKpisLive(){
  const L=window.__live||{PASS:0,BLOCK:0,DETECT:0,RATELIMIT:0,ERROR:0};
  const tot=window.__liveTotal||0, bl=L.BLOCK||0;
  const br=tot?Math.round(1000*bl/tot)/10:0;
  renderKpis({actions:L, total:tot, block_rate:br}, lastBans);
}
// KPIをSSEイベントで即時加算する(ポーリング待ちなし)。種と加算だけなので二重計上しない
let _kpiPending=false;
function bumpKpiFromEvent(e){
  const a=e.action; if(!window.__live) return;
  const n=Math.max(1, parseInt(e.count||1,10)||1);   // 集約イベントは n 件を表す
  if(a in window.__live){ window.__live[a]+=n; window.__liveTotal=(window.__liveTotal||0)+n; }
  if(!_kpiPending){ _kpiPending=true;
    setTimeout(()=>{ _kpiPending=false; renderKpisLive(); }, 150); }
}
let _logRenderPending=false, _logLastRender=0;
function logOnEvent(e){
  if(e.ip==null) e.ip=e.client_ip||'';   // テーブルは e.ip を参照するため正規化
  if(e.backend){ if(beKnow(e.backend,e.backend_name)) beChipsRender(); } else if(!window.__beHasNone){ window.__beHasNone=true; beLfSync(); }
  bumpKpiFromEvent(e);
  const arr=window.__recent||(window.__recent=[]);
  const n=Math.max(1, parseInt(e.count||1,10)||1);
  // drop系(RATELIMIT)は先頭行が同じ(IP×種別)ならまとめて ×N を伸ばす。毎回新規行は作らない
  const mk = e.action==='RATELIMIT' ? (e.ip||e.client_ip||'')+'|'+(e.conn_ip||'')+'|'+(e.disposition||'')+'|'+(e.backend||'') : null;
  const top = arr[0];
  const topMk = (top && top.action==='RATELIMIT') ? (top.ip||'')+'|'+(top.conn_ip||'')+'|'+(top.disposition||'')+'|'+(top.backend||'') : null;
  if(mk!==null && topMk===mk){
    top.count=(parseInt(top.count||1,10)||1)+n;
    top.ts_from = top.ts_from||top.ts;
    top.ts = e.ts||top.ts;
  } else {
    if(e.ts_from==null) e.ts_from=e.ts;
    arr.unshift(e);
    if(!_allLoaded && arr.length>8000) arr.length=8000;     // 全件読込後は、読み込んだ行を切り捨てない
  }
  window.__total_events=(window.__total_events||0)+n;
  // 高頻度でも重くならないよう描画は最大5回/秒に間引く
  const now=performance.now();
  if(now-_logLastRender>200){ _logLastRender=now; renderRecent(); }
  else if(!_logRenderPending){ _logRenderPending=true;
    setTimeout(()=>{ _logRenderPending=false; _logLastRender=performance.now(); renderRecent(); }, 200); }
}

/* リクエスト/レスポンス詳細(Burp風) */
function buildRawRequest(e){
  const req=e.req||{}, hdrs=req.headers||{};
  const target=(e.path||'')+(req.query?('?'+req.query):'');
  let s=`${e.method||'GET'} ${target} HTTP/1.1\n`;
  // Host を先頭付近に出す(記録ヘッダになければ省略)
  Object.keys(hdrs).forEach(k=>{ s+=`${k}: ${hdrs[k]}\n`; });
  s+='\n';
  if(req.body) s+=req.body+(req.body_truncated?'\n…(truncated)':'');
  return s;
}
function buildRawResponse(e){
  const r=e.resp;
  if(!r) return null;
  let s=`HTTP/1.1 ${r.status||''} ${r.reason||''}\n`;
  const h=r.headers||{};
  Object.keys(h).forEach(k=>{ s+=`${k}: ${h[k]}\n`; });
  s+='\n';
  if(r.body) s+=r.body+(r.body_truncated?'\n…(truncated)':'');
  else if(r.body_len===0) s+='(本文なし)';
  else s+='(本文はバイナリ/未記録)';
  return s;
}
/* ログ詳細の暗号化。復号はキー・オフィサーが暗号ログページで行う。秘密鍵はこのブラウザに読み込むだけで、送信も保存もしない */
const DEC={keys:{},timer:null,tick:null,until:0,rows:null,mask:true,info:null};
function encOk(){ return !!(window.crypto&&crypto.subtle); }
const ENC_NEED_SECURE='このページが https または localhost で開かれていないため、ブラウザ内の暗号機能が使えません。https で開いてください。';
function b64buf(s){ const bin=atob(s), u=new Uint8Array(bin.length); for(let i=0;i<bin.length;i++) u[i]=bin.charCodeAt(i); return u.buffer; }
function bufB64(b){ let s=''; const u=new Uint8Array(b); for(let i=0;i<u.length;i++) s+=String.fromCharCode(u[i]); return btoa(s); }
function toPem(b,label){ const t=bufB64(b).match(/.{1,64}/g).join('\n'); return `-----BEGIN ${label}-----\n${t}\n-----END ${label}-----\n`; }
/* 復号結果のマスク(ブラウザ内)。調査に不要な認証情報・カード番号・マイナンバー等を既定で伏せる */
const MASK_TXT='●●●●●(マスク)';
const MASK_HDR=/^(cookie|set-cookie|authorization|proxy-authorization|x-api-key|x-auth-token|x-csrf-token|x-xsrf-token)$/i;
const MASK_KEY='[A-Za-z0-9_.\\[\\]-]*(?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|apikey|auth|session|sid|cvv|cvc|otp|credit|card(?:[_-]?(?:number|no|num))?)[A-Za-z0-9_.\\[\\]-]*';
const MASK_RE_FORM=new RegExp('((?:^|[?&;,\\s])'+MASK_KEY+'=)([^&\\s;,]*)','gi');
const MASK_RE_JSON=new RegExp('("'+MASK_KEY+'"\\s*:\\s*)"([^"]*)"','gi');
function luhnOk(d){ let s=0,alt=false; for(let i=d.length-1;i>=0;i--){ let n=d.charCodeAt(i)-48; if(alt){ n*=2; if(n>9) n-=9; } s+=n; alt=!alt; } return s%10===0; }
function maskText(t){
  if(typeof t!=='string'||!t) return t;
  let o=t.replace(MASK_RE_JSON,(m,k)=>k+'"'+MASK_TXT+'"').replace(MASK_RE_FORM,(m,k)=>k+MASK_TXT);
  o=o.replace(/(?<![\d])(?:\d[ -]?){12,18}\d(?![\d])/g,m=>{ const d=m.replace(/\D/g,''); return (d.length>=13&&d.length<=19&&luhnOk(d))?'●●●●●●●●●●●●'+d.slice(-4):m; });       // カード番号(桁数とLuhnで判定。下4桁だけ残す)
  o=o.replace(/(?<![\d])\d{4}[ -]?\d{4}[ -]?\d{4}(?![\d])/g,'●●●●-●●●●-●●●●');                                                                 // マイナンバー(12桁の形式で判定)
  return o;
}
function maskDeep(v,key){
  if(v==null) return v;
  if(typeof v==='string') return (key&&MASK_HDR.test(key))?MASK_TXT:maskText(v);
  if(Array.isArray(v)) return v.map(x=>maskDeep(x,key));
  if(typeof v==='object'){ const o={}; for(const k of Object.keys(v)) o[k]=(MASK_HDR.test(k)&&(typeof v[k]==='string'||Array.isArray(v[k])))?MASK_TXT:maskDeep(v[k],k); return o; }
  return v;
}
function encApplyMask(e){
  const r=e.__raw; if(!r) return;
  e.req=DEC.mask?maskDeep(r.req):r.req; e.resp=DEC.mask?maskDeep(r.resp):r.resp; e.query=DEC.mask?maskText(r.query):r.query;
}
function encMaskStatus(){
  const el=document.getElementById('encMaskSt'); if(!el) return;
  el.innerHTML=DEC.mask?`<span class="eb ok">マスク ON</span> <span class="seemore">認証情報(Cookie・Authorization・パスワード欄など)・カード番号・マイナンバーを伏せて表示します。</span> <button type="button" class="cp" onclick="encUnmask()">マスクを外す</button>`
    :`<span class="eb warn">マスク OFF</span> <span class="seemore">すべて表示しています(外した操作は記録されています)。</span> <button type="button" class="cp" onclick="encRemask()">マスクをかける</button>`;
}
async function encUnmask(){
  if(!confirm('復号した結果のマスクを外します。調査に必要な範囲だけにしてください。この操作は記録に残ります。よろしいですか?')) return;
  const r=await postJSON('/api/enc/unmask_log',{action:'unmask',count:(DEC.rows||[]).length});
  if(!r.ok){ alert(r.error||'失敗'); return; }
  DEC.mask=false; encMaskReapply();
}
function encRemask(){ DEC.mask=true; encMaskReapply(); postJSON('/api/enc/unmask_log',{action:'mask'}); }
function encMaskReapply(){
  (DEC.rows||[]).forEach(encApplyMask); encMaskStatus(); closeModal();      // 開いている詳細は閉じて表示を揃える
  if(DEC.rows) encDSearch(DEC.q||'');
}
async function encDecrypt(e){
  const en=e.enc, key=DEC.keys[en.kid||''];
  if(!key){ const er=new Error('この鍵では復号できません'); er.kid=en.kid||''; throw er; }
  const dek=await crypto.subtle.decrypt({name:'RSA-OAEP'},key,b64buf(en.ek));
  const k=await crypto.subtle.importKey('raw',dek,'AES-GCM',false,['decrypt']);
  const pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:b64buf(en.iv),additionalData:new TextEncoder().encode(en.kid||'')},k,b64buf(en.ct));
  const o=JSON.parse(new TextDecoder().decode(pt));
  e.__raw={req:o.req||null,resp:o.resp||null,query:o.query||''}; e.__dec=true; e.enc=null; encApplyMask(e);
}
function encHasKeys(){ return Object.keys(DEC.keys).length>0; }
// 鍵が消える条件: 最後の操作からの無操作時間、読み込みからの最大保持時間、「鍵を忘れる」、ページを離れる、再読み込み。消える1分前に警告し、延長できる(最大保持時間は超えない)
function encIdleOpts(){ const mx=(ENC&&ENC.idle_max)||60; return [5,15,30,60].filter(m=>m<=mx).concat([5,15,30,60].some(m=>m===mx)?[]:[mx]); }
function encIdleMin(){
  let v=30; try{ v=parseInt(localStorage.getItem('enc_idle')||'30',10)||30; }catch(e){}
  const o=encIdleOpts(); if(o.indexOf(v)<0) v=o.filter(m=>m<=v).pop()||o[o.length-1]; return v;
}
function encIdleSet(v){ try{ localStorage.setItem('enc_idle',String(v)); }catch(e){} if(encHasKeys()) encArm(); else encKeyStatus(); }
function encForgetKey(){ DEC.keys={}; DEC.mask=true; DEC.until=0; DEC.start=0; DEC.hardUntil=0; if(DEC.timer){ clearTimeout(DEC.timer); DEC.timer=null; } if(DEC.tick){ clearInterval(DEC.tick); DEC.tick=null; } encWipeBulk(); encKeyStatus(); }
function encArm(){
  const now=Date.now(), holdMs=(((ENC&&ENC.hold_max)||120)*60*1000);
  if(!DEC.start){ DEC.start=now; DEC.hardUntil=now+holdMs; }
  if(DEC.timer) clearTimeout(DEC.timer);
  DEC.until=Math.min(now+encIdleMin()*60*1000, DEC.hardUntil);
  DEC.timer=setTimeout(()=>{ encForgetKey(); closeModal(); },Math.max(0,DEC.until-now));
  if(!DEC.tick) DEC.tick=setInterval(encKeyStatus,1000);
}
function encExtend(){ if(encHasKeys()) { encArm(); encKeyStatus(); } }
function encRemain(){ const t=Math.max(0,Math.round((DEC.until-Date.now())/1000)); return Math.floor(t/60)+':'+String(t%60).padStart(2,'0'); }
function encWipeBulk(){ DEC.rows=null; const b=document.getElementById('encDecBox'); if(b) b.innerHTML=''; }
function encWipe(){
  if(curDetail&&curDetail.__dec){ curDetail.req=null; curDetail.resp=null; curDetail.query=''; curDetail.__raw=null; curDetail.__dec=false; }
  if(curDetail&&curDetail.__encview){ const b=document.getElementById('mBody'); if(b) b.innerHTML=''; curDetail=null; }
}
function encPanel(e){
  if(e.enc_error&&!e.enc_locked) return '<div class="hit" style="margin-top:10px">🔒 暗号化に失敗したため、このログの詳細は保存していません(公開鍵の設定を確認してください)。</div>';
  return `<div class="hit" style="margin-top:10px"><b>🔒 このログの詳細(ヘッダ・Cookie・ボディ・クエリ)は暗号化されています</b>
    <div class="seemore" style="margin:4px 0">鍵ID: <code>${esc(e.kid||'')}</code> ／ 内容を確認する必要があるときは、キー・オフィサーに復号を依頼してください(復号は、組織側の承認を受けた申請があるときだけできます)。</div></div>`;
}
/* 暗号ログページ(キー・オフィサー: 調べる/申請/鍵の管理/操作記録、管理者: 鍵の状態と操作記録) */
let ENC_ORG={req:'',flt:''}, ENC_LOGOPEN=null;
let ENC=null, ENC_TAB='', ENC_SEL={}, ENC_W={org:'',pub:'',verified:false,msg:''}, ENC_F={backend:'',days:7,from:'',to:'',method:'',action:'',status:'',ip:'',path:'',granted:false,sort:'ts',dir:'desc',page:1,per:50}, ENC_AUTO=true;
const ENC_ACT={key_set:'鍵を登録',key_remove:'鍵を外す',enable:'暗号化をON',disable:'暗号化をOFF',request:'復号を申請',grant:'復号を承認',grant_reject:'復号を却下',decrypt:'復号した',unmask:'マスクを外した',mask:'マスクをかけ直した',denied:'拒否'};
function encKeyStatus(){
  encMaskStatus(); encCardKey();
  const el=document.getElementById('encKeySt'); if(!el) return;
  const ks=Object.keys(DEC.keys);
  const kb=document.getElementById('encKeyBox'); if(kb){ kb.classList.toggle('loaded',ks.length>0); if(!ks.length) kb.classList.remove('more'); }
  if(!ks.length){ el.innerHTML='<span class="eb mute">未読み込み</span>'; return; }
  if(document.activeElement&&document.activeElement.id==='encIdle'){ const r=document.getElementById('encRemain'); if(r) r.textContent=encRemain(); return; }
  const orgOf=k=>{ const o=((ENC&&ENC.orgs)||[]).find(x=>x.kid===k); return o?o.name:'以前の鍵または他の組織'; };
  el.innerHTML=`<span class="eb ok">${ks.length}個の鍵を読み込み済み</span> <span class="seemore">あと <b id="encRemain">${encRemain()}</b> で自動的に忘れます(操作すると延びます。読み込みから最大${Math.round(((ENC&&ENC.hold_max)||120))}分)</span> <button type="button" class="cp" onclick="encForgetKey()">鍵を忘れる</button> <button type="button" class="cp" onclick="document.getElementById('encKeyBox').classList.toggle('more')">鍵を追加・説明</button>
    <span class="seemore">無操作 <select id="encIdle" onchange="encIdleSet(+this.value)">${encIdleOpts().map(m=>`<option value="${m}"${m===encIdleMin()?' selected':''}>${m}分</option>`).join('')}</select></span>
    ${(DEC.until-Date.now())<=60000&&(DEC.until-Date.now())>0?`<div class="hit" style="margin-top:4px">⏳ まもなく鍵を忘れます。${DEC.until>=DEC.hardUntil?'最大保持時間に達したため、延長できません。':'<button type="button" class="cp" onclick="encExtend()">延長する</button>'}</div>`:''}
    <div class="seemore" style="margin-top:3px">${ks.map(k=>`<code>${esc(k)}</code> ${esc(orgOf(k))}`).join(' ／ ')}</div>`;
}
async function loadEnc(){
  const body=document.getElementById('encBody'); if(!body) return;
  try{
    const ov=await (await fetch('/api/enc/overview',{cache:'no-store'})).json();
    if(ov.error){ body.innerHTML='<div class="hempty">'+esc(ov.error)+'</div>'; return; }
    ENC=ov; ENC_SIG=encSig(ov);
    const au=await (await fetch('/api/enc/audit',{cache:'no-store'})).json();
    renderEnc(ov,au);
    if(ov.is_officer) encEvLoad();
  }catch(e){ body.innerHTML='<div class="hempty">読み込めませんでした</div>'; }
}
function encRvHtml(ov){
  const L=ov.reviews||[], ST={open:['受付中','warn'],in_progress:['対応中','warn'],done:['完了','ok'],rejected:['却下','ng']};
  if(!L.length) return '<div class="seemore">アナリストからのログの確認依頼はありません。</div>';
  return L.map(t=>{ const s=ST[t.status]||[t.status,'mute'], open_=t.status!=='done'&&t.status!=='rejected';
    const cm=(t.comments||[]).map(c=>`<div class="snip">${esc(c.by)} ${esc((c.at||'').replace('T',' '))}: ${esc(c.text)}</div>`).join('');
    return `<details class="keybox" ${open_?'open':''}><summary><b>${esc(t.id)}</b> <span class="eb ${s[1]}">${s[0]}</span> ${esc(t.subject)} <span class="seemore">${esc(encOrgName(ov,t.org))} / ${esc(t.backend)} / 依頼: ${esc(t.by)} / ${esc((t.created||'').replace('T',' '))}</span></summary>
      ${t.body?`<p style="white-space:pre-wrap;margin:6px 0">${esc(t.body)}</p>`:''}${cm}
      ${open_?`<div style="display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin-top:6px">
        <button type="button" class="cp" onclick="encRvUse('${esc(t.id)}')">この依頼で復号を申請する</button>
        <button type="button" class="cp" onclick="encRvSt('${esc(t.id)}','in_progress')">対応中にする</button>
        <button type="button" class="cp" onclick="encRvSt('${esc(t.id)}','done')">完了にする</button>
        <button type="button" class="cp" onclick="encRvSt('${esc(t.id)}','rejected')">却下する</button></div>`:''}
      <div style="display:flex;gap:6px;margin-top:6px"><input type="text" id="encRvC-${esc(t.id)}" size="44" placeholder="アナリストへのコメント"><button type="button" class="cp" onclick="encRvCm('${esc(t.id)}')">送信</button></div></details>`; }).join('');
}
function encRvUse(id){
  const t=((ENC&&ENC.reviews)||[]).find(x=>x.id===id); if(!t) return;
  const now=new Date(); encFillReq(t.backend,new Date(now.getTime()-24*3600e3),now);
  const w=document.getElementById('encReqWhy'); if(w){ w.value='【ログ確認依頼 '+t.id+'】'+t.subject; w.focus(); }
}
function encRvSt(id,status){ postJSON('/api/tickets/status',{id,status}).then(r=>{ if(r.ok) loadEnc(); else alert('エラー: '+(r.error||'失敗')); }); }
function encRvCm(id){ const v=(document.getElementById('encRvC-'+id)||{}).value||''; postJSON('/api/tickets/comment',{id,text:v}).then(r=>{ if(r.ok) loadEnc(); else alert('エラー: '+(r.error||'失敗')); }); }
function encSig(ov){
  return JSON.stringify([(ov.tickets||[]).map(t=>[t.id,t.status,(t.grant||{}).approved_by||'',(t.grant||{}).until||'',(t.comments||[]).length]),
    (ov.reviews||[]).map(t=>[t.id,t.status,(t.comments||[]).length]), ov.enabled, (ov.orgs||[]).map(o=>[o.id,o.kid||'']), encActiveGrants(ov).length]);
}
let ENC_SIG='';
async function encRvPoll(){
  const body=document.getElementById('encBody'); if(!body||!ENC||!ENC.is_officer||curPage!=='enc'||document.hidden) return;
  try{
    const ov=await (await fetch('/api/enc/overview',{cache:'no-store'})).json(); if(ov.error) return;
    const sig=encSig(ov); if(!ENC_SIG) ENC_SIG=encSig(ENC);
    if(sig===ENC_SIG) return;                                     // 変化がなければ何もしない
    const a=document.activeElement;
    if(a&&body.contains(a)&&/^(INPUT|TEXTAREA|SELECT)$/.test(a.tagName)) return;     // 入力中は次の確認まで待つ(入力を壊さない)
    const au=await (await fetch('/api/enc/audit',{cache:'no-store'})).json();
    const keep={}; body.querySelectorAll('input[id],select[id],textarea[id]').forEach(e=>{ if(e.type!=='file') keep[e.id]=e.type==='checkbox'?e.checked:e.value; });
    const sy=window.scrollY; ENC=ov; ENC_SIG=sig;
    renderEnc(ov,au); if(ov.is_officer) encEvLoad();
    Object.keys(keep).forEach(k=>{ const e=document.getElementById(k); if(!e) return; if(e.type==='checkbox') e.checked=keep[k]; else e.value=keep[k]; });
    window.scrollTo(0,sy);
  }catch(e){}
}
setInterval(encRvPoll,8000);
function encDepth(o,all){ let d=0,p=o.parent,g=0; while(p&&g++<20){ d++; const q=all.find(x=>x.id===p); p=q?q.parent:''; } return d; }
function encTkState(t){
  const g=t.grant||{};
  if(t.status==='rejected') return '<span class="eb ng">却下</span>';
  if(t.status==='done'){
    const left=(new Date(String(g.until||'').replace(' ','T'))-Date.now())/1000;
    if(!(left>0)) return '<span class="eb mute">期限切れ</span>';
    const h=Math.floor(left/3600), m=Math.floor(left%3600/60);
    return `<span class="eb ok">承認済み</span> <span class="seemore">あと ${h}時間${m}分(${esc((g.approved_by||''))})</span>`;
  }
  return '<span class="eb warn">承認待ち</span>';
}
function encActiveGrants(ov){ return (ov.tickets||[]).filter(t=>t.status==='done'&&String(((t.grant||{}).until)||'')>new Date(Date.now()-new Date().getTimezoneOffset()*60000).toISOString().slice(0,19)); }
function encTab(t){ ENC_TAB=t; document.querySelectorAll('#encBody .enc-tabs button').forEach(b=>b.classList.toggle('on',b.dataset.t===t)); document.querySelectorAll('#encBody .enc-pn').forEach(p=>p.style.display=(p.dataset.t===t)?'':'none'); }
function renderEnc(ov,au){
  const body=document.getElementById('encBody'); if(!body) return;
  const off=ov.is_officer, can=ov.can_manage;
  const tabs=off?[['inv','調べる(復号)'],['req','申請'],['keys','鍵の管理'],['audit','操作記録']]:[['keys','鍵の状態'],['audit','操作記録']];
  if(!tabs.some(t=>t[0]===ENC_TAB)) ENC_TAB=tabs[0][0];
  const act=encActiveGrants(ov), waiting=(ov.tickets||[]).filter(t=>t.status!=='done'&&t.status!=='rejected').length, rvOpen=(ov.reviews||[]).filter(t=>t.status==='open'||t.status==='in_progress').length, tabN=waiting+rvOpen;
  const nKeyed=(ov.orgs||[]).filter(o=>o.kid).length;
  // 上の要約
  let h=`<div class="enc-cards">
    <div class="enc-card"><div class="k">暗号化</div><div class="v"><b class="${ov.enabled?'ok':'ng'}">${ov.enabled?'ON':'OFF'}</b></div>
      <div>${can?`<button type="button" class="cp" onclick="encToggle(${!ov.enabled})">${ov.enabled?'OFFにする':'ONにする'}</button>`:''}</div></div>
    <div class="enc-card"><div class="k">鍵を登録した組織</div><div class="v">${nKeyed} <small>/ ${(ov.orgs||[]).length}</small></div><div class="seemore">鍵がない組織のログは暗号化されません</div></div>
    ${off?`<div class="enc-card"><div class="k">承認待ちの申請</div><div class="v ${waiting?'warn':''}">${waiting}</div><div class="seemore">組織側の承認を待っています</div></div>
    <div class="enc-card"><div class="k">いま復号できる範囲</div><div class="v ${act.length?'ok':''}">${act.length}</div><div class="seemore">承認済みで期限内の申請</div></div>
    <div class="enc-card"><div class="k">秘密鍵</div><div class="v" id="encCardKey"></div><div class="seemore">ブラウザ内だけ・自動で消えます</div></div>`:''}
  </div>
  <div class="seemore" style="margin:4px 0 8px">${ov.officers?'暗号鍵と暗号化のON/OFFは、キー・オフィサーだけが変更できます(管理者は設定を変えられません)。':'キー・オフィサーがまだいないため、管理者が初期設定できます。設定後に「キー・オフィサー」のアカウントを作ってください。'}${ov.available===false?' <b class="ng">⚠ サーバーに cryptography パッケージがありません(pip install cryptography)</b>':''}</div>
  <div class="enc-tabs">${tabs.map(t=>`<button type="button" data-t="${t[0]}" class="${t[0]===ENC_TAB?'on':''}" onclick="encTab('${t[0]}')">${t[1]}${t[0]==='req'&&tabN?` <span class="eb warn">${tabN}</span>`:''}</button>`).join('')}</div>`;
  // 調べる(復号)
  if(off){
    const F=ENC_F, selO=(id,key,opts)=>`<select id="${id}" onchange="encFApply()">${opts.map(o=>`<option value="${esc(o[0])}" ${String(F[key])===String(o[0])?'selected':''}>${esc(o[1])}</option>`).join('')}</select>`;
    h+=`<div class="enc-pn" data-t="inv" style="${ENC_TAB==='inv'?'':'display:none'}">
      <div class="enc-sec"><h3>承認済みの範囲(いま復号できます)</h3>${act.length?`<table><thead><tr><th>申請</th><th>接続先</th><th>対象の期間</th><th>期限</th><th></th></tr></thead><tbody>`+act.map(t=>{ const g=t.grant||{}; return `<tr><td>${esc(t.id)}</td><td>${esc(t.backend)}</td><td>${esc((g.from||'').replace('T',' '))} 〜 ${esc((g.to||'').replace('T',' '))}</td><td>${encTkState(t)}</td>
        <td><button type="button" class="cp" onclick="encGrantGo('${esc(t.id)}')">この範囲を復号して一覧にする</button></td></tr>`; }).join('')+'</tbody></table>':'<div class="seemore">承認済みの申請はありません。「② 申請」から復号を申請してください。</div>'}</div>
      <div class="keybox" id="encKeyBox" ondragover="event.preventDefault();this.classList.add('drag')" ondragleave="this.classList.remove('drag')" ondrop="encDropKey(event)">
        <b>秘密鍵</b> <span id="encKeySt"></span>
        <div id="encMaskSt" style="margin:4px 0"></div>
        <div class="kb-more">
        <span class="seemore">鍵ファイル(.pem)をここへドラッグ&ドロップ(複数可)。鍵を入れ替えたあとは、古い鍵と新しい鍵を両方読み込むと、ログごとに合う鍵が自動で選ばれます。</span><br>
        <input type="file" id="encPrivFile" accept=".pem,.key,.txt" multiple onchange="encReadPriv(this)">
        <details style="margin-top:4px"><summary class="seemore" style="cursor:pointer">貼り付けて読み込む</summary>
          <textarea id="encPriv" rows="3" spellcheck="false" style="width:100%;font-family:monospace;font-size:11px;margin-top:4px" placeholder="-----BEGIN PRIVATE KEY-----"></textarea>
          <button type="button" class="cp" onclick="encLoadPriv()">鍵を読み込む</button></details>
        <label style="display:flex;gap:6px;align-items:center;margin-top:4px"><input type="checkbox" id="encAuto" ${ENC_AUTO?'checked':''} onchange="ENC_AUTO=this.checked">鍵を読み込んだら、承認済みのログを自動で復号して一覧にする</label>
        <div class="seemore" id="encPrivMsg">秘密鍵はこのブラウザの中だけで使い、サーバーには送りません。最後の操作から一定時間(既定30分)・読み込みから最大2時間・「鍵を忘れる」・画面を離れる・再読み込みで消えます。</div></div></div>
      <div id="encDecBox"></div>
      <details class="enc-sec" id="encLogDet" ${(ENC_LOGOPEN===null?!act.length:ENC_LOGOPEN)?'open':''} ontoggle="ENC_LOGOPEN=this.open"><summary><b>暗号化されたログ</b> <span class="seemore">検索して、個別に選んで申請するとき</span></summary>
      <div style="display:flex;flex-wrap:wrap;gap:6px;align-items:center">
        <select id="encFOrg" onchange="encFOrg(this.value)">${encOrgOpts(ov,ENC_ORG.flt)}</select>
        <select id="encFBe" onchange="encFApply()">${encBeOpts(ov,ENC_ORG.flt,F.backend,'すべての接続先')}</select>
        ${selO('encFDays','days',[[1,'直近1日'],[3,'直近3日'],[7,'直近7日'],[14,'直近14日'],[30,'直近30日'],[60,'直近60日'],[93,'直近93日']])}
        ${selO('encFMethod','method',[['','メソッド: すべて'],['GET','GET'],['POST','POST'],['PUT','PUT'],['DELETE','DELETE'],['PATCH','PATCH'],['HEAD','HEAD'],['OPTIONS','OPTIONS']])}
        ${selO('encFAction','action',[['','アクション: すべて'],['BLOCK','BLOCK'],['DETECT','DETECT'],['PASS','PASS'],['DROP','DROP']])}
        <input id="encFIp" placeholder="IP(一部でも可)" size="14" value="${esc(F.ip)}" onkeydown="if(event.key==='Enter')encFApply()">
        <input id="encFPath" placeholder="パス(一部でも可)" size="18" value="${esc(F.path)}" onkeydown="if(event.key==='Enter')encFApply()">
        <input id="encFStatus" placeholder="ステータス" size="7" value="${esc(F.status)}" onkeydown="if(event.key==='Enter')encFApply()">
        <label style="display:flex;gap:4px;align-items:center"><input type="checkbox" id="encFGr" ${F.granted?'checked':''} onchange="encFApply()">承認済みだけ</label>
        ${selO('encFPer','per',[[50,'50件ずつ'],[100,'100件ずつ'],[200,'200件ずつ']])}
        <button type="button" class="cp" onclick="encFApply()">検索</button>
        <button type="button" class="cp" onclick="encFReset()">条件をクリア</button></div>
      ${(F.from||F.to)?`<div style="margin-top:4px"><span class="eb warn">期間指定: ${esc((F.from||'').replace('T',' '))} 〜 ${esc((F.to||'').replace('T',' '))}</span> <button type="button" class="cp" onclick="ENC_F.from='';ENC_F.to='';encFApply()">期間指定を外す</button></div>`:''}
      <div id="encEvBox"><div class="seemore">読み込み中…</div></div>
      <div style="margin-top:8px"><button type="button" class="cp" onclick="encBulk()">絞り込み結果のうち承認済みのものを、まとめて復号して一覧にする(最大500件)</button>
        <span class="seemore">復号はこのブラウザの中だけ。復号した件数は操作記録に残ります。</span></div>
      </details></div>`;
    // 申請
    const now=new Date(), pad=n=>String(n).padStart(2,'0'), loc=d=>d.getFullYear()+'-'+pad(d.getMonth()+1)+'-'+pad(d.getDate())+'T'+pad(d.getHours())+':'+pad(d.getMinutes());
    h+=`<div class="enc-pn" data-t="req" style="${ENC_TAB==='req'?'':'display:none'}">
      <div class="enc-sec"><h3>アナリストからのログの確認依頼</h3><div id="encRvBox">${encRvHtml(ov)}</div></div>
      <div class="enc-sec"><h3>復号の申請(組織側の承認が必要です)</h3>
      <div id="encSelInfo" class="seemore"></div>
      <div class="keybox" style="margin-top:4px"><div style="display:flex;flex-wrap:wrap;gap:6px;align-items:center">
        <label>申請先の組織</label><select id="encReqOrg" onchange="encReqOrg(this.value)">${encOrgOpts(ov,ENC_ORG.req)}</select>
        <label>接続先</label><select id="encReqBe" onchange="encReqPreview();encReqWho()">${encBeOpts(ov,ENC_ORG.req,'')}</select>
        <label>期間</label><input type="datetime-local" id="encReqFrom" value="${loc(new Date(now.getTime()-24*3600e3))}" onchange="encReqPreview()"> 〜 <input type="datetime-local" id="encReqTo" value="${loc(now)}" onchange="encReqPreview()"></div>
        <div style="margin-top:4px"><span class="seemore">すばやく選ぶ:</span>
          <button type="button" class="cp" onclick="encPreset('1h')">直近1時間</button><button type="button" class="cp" onclick="encPreset('24h')">直近24時間</button><button type="button" class="cp" onclick="encPreset('today')">今日</button><button type="button" class="cp" onclick="encPreset('yday')">昨日</button><button type="button" class="cp" onclick="encPreset('7d')">直近7日</button></div>
        <div style="display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin-top:6px">
          <label>理由</label><select id="encReqTpl" onchange="encReason(this.value)"><option value="">テンプレートから選ぶ</option><option>インシデントの調査</option><option>お客様からの問い合わせ対応</option><option>誤検知かどうかの確認</option><option>監査・法的要請への対応</option><option>その他</option></select>
          <input type="text" id="encReqWhy" size="46" placeholder="復号が必要な理由(必須・5文字以上)">
          <button type="button" class="cp" onclick="encRequest()">申請する</button></div>
        <div class="seemore" id="encReqWho" style="margin-top:4px"></div>
        <div class="seemore" id="encReqPrev" style="margin-top:4px"></div>
        <div class="seemore" id="encReqMsg" style="margin-top:4px">期間は93日以内。その組織側の担当者が承認すると、承認から指定時間(最大7日)だけ、その期間のログを復号できます。</div></div>
      <h3 style="margin-top:12px">申請の一覧</h3>
      <table><thead><tr><th>申請</th><th>組織 / 接続先</th><th>対象の期間</th><th>状態</th></tr></thead><tbody>`+
      ((ov.tickets||[]).map(t=>{ const g=t.grant||{};
        return `<tr><td>${esc(t.id)} <span class="seemore">${esc(t.body||t.subject||'')}</span></td><td>${esc(encOrgName(ov,t.org))}<br><span class="seemore">${esc(t.backend)}</span></td><td>${esc((g.from||'').replace('T',' '))} 〜 ${esc((g.to||'').replace('T',' '))}</td><td>${encTkState(t)}</td></tr>`; }).join('')||'<tr><td colspan="4" class="seemore">申請はまだありません</td></tr>')+`</tbody></table></div></div>`;
  }
  // 鍵の管理(ウィザードと組織ごとの状態)
  const W=ENC_W, editable=(ov.orgs||[]).filter(o=>o.editable);
  h+=`<div class="enc-pn" data-t="keys" style="${ENC_TAB==='keys'?'':'display:none'}">`;
  if(can&&editable.length){
    h+=`<div class="enc-sec"><h3>鍵を登録する(3ステップ)</h3><div class="keybox">
      <div class="enc-steps"><span class="${W.pub?'done':'now'}">① 鍵を用意する</span><span class="${W.verified?'done':(W.pub?'now':'')}">② 秘密鍵の保管を確認</span><span class="${W.verified?'now':''}">③ 登録して ON</span></div>
      <div style="display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin-top:6px"><label>組織</label>
        <select id="encWOrg" onchange="ENC_W.org=this.value">${editable.map(o=>`<option value="${esc(o.id)}" ${o.id===W.org?'selected':''}>${esc(o.name)}${o.kid?'(鍵の入れ替え)':''}</option>`).join('')}</select>
        <button type="button" class="cp" onclick="encWGen()">鍵ペアを作成(ブラウザ内)</button><span class="seemore">または、別の場所で作った公開鍵を貼り付け:</span></div>
      <textarea id="encWPub" rows="3" spellcheck="false" style="width:100%;font-family:monospace;font-size:11px;margin-top:4px" placeholder="-----BEGIN PUBLIC KEY-----" oninput="ENC_W.pub=this.value.trim();ENC_W.verified=false;encWSteps()">${esc(W.pub||'')}</textarea>
      <div style="margin-top:6px"><b>② 保管の確認</b> <span class="seemore">ダウンロードした秘密鍵のファイルを選ぶと、この公開鍵で暗号化したテストデータを復号できるか確認します。鍵をなくす事故を防ぎます。</span><br>
        <input type="file" id="encWFile" accept=".pem,.key,.txt" onchange="encWVerify(this)"></div>
      <div class="seemore" id="encWMsg" style="margin-top:4px">${esc(W.msg||'')}</div>
      <div style="margin-top:6px"><label style="display:flex;gap:6px;align-items:center"><input type="checkbox" id="encWSkip" onchange="encWSteps()">確認せずに登録する(別の鍵管理の仕組みで、秘密鍵の保管を確認済み)</label></div>
      <div style="margin-top:6px"><button type="button" class="cp" id="encWReg" onclick="encWRegister()" disabled>③ 登録して、暗号化をONにする</button></div></div></div>`;
  }
  h+=`<div class="enc-sec"><h3>組織ごとの暗号鍵</h3><table><thead><tr><th>組織</th><th>状態</th><th></th></tr></thead><tbody>`+
    ((ov.orgs||[]).length?ov.orgs.map(o=>`<tr><td style="padding-left:${8+14*encDepth(o,ov.orgs)}px">${esc(o.name)} <span class="seemore">(${esc(o.id)})</span></td>
      <td>${o.kid?`<span class="eb ok">暗号化あり</span><br><span class="seemore">鍵ID: ${esc(o.kid)}${o.key_at?'<br>登録: '+esc(o.key_at.replace('T',' ')):''}</span>`:'<span class="eb ng">鍵なし(暗号化されません)</span>'}</td>
      <td>${o.editable?`${o.kid?`<button type="button" class="cp" onclick="encSetKey('${esc(o.id)}',true)">鍵を外す</button>`:'<span class="seemore">上のステップで登録します</span>'}
        <div class="seemore" id="encKeyMsg-${esc(o.id)}"></div>${ov.demo_keys?encGenBox(o.id):''}`:'<span class="seemore">変更できません</span>'}</td></tr>`).join(''):'<tr><td colspan="3" class="seemore">担当する組織がありません(管理者に担当範囲の設定を依頼してください)</td></tr>')+
    `</tbody></table><div class="seemore" style="margin-top:4px">秘密鍵はこの画面で作ると自動でダウンロードされ、サーバーには保存されません。なくすと、その鍵で暗号化したログは復号できません。</div></div></div>`;
  // 操作記録
  h+=`<div class="enc-pn" data-t="audit" style="${ENC_TAB==='audit'?'':'display:none'}"><div class="enc-sec"><h3>操作記録 <span class="seemore ${au.chain_ok===false?'ng':'ok'}">${au.chain_ok===false?'⚠ 記録が改ざんされた可能性があります(つながりが一致しません)':'✓ 記録のつながりを確認済み'}</span></h3>
    <table><thead><tr><th>時刻</th><th>ユーザー</th><th>操作</th><th>内容</th></tr></thead><tbody>`+
    ((au.rows||[]).slice(0,100).map(r=>`<tr><td>${esc((r.ts||'').replace('T',' '))}</td><td>${esc(r.user)} <span class="seemore">${esc(r.role||'')}</span></td><td>${esc(ENC_ACT[r.action]||r.action)}</td>
      <td class="seemore">${esc([r.org&&('組織 '+r.org),r.backend&&('接続先 '+r.backend),r.ticket,r.kid&&('鍵ID '+r.kid),r.detail].filter(Boolean).join(' / '))}</td></tr>`).join('')||'<tr><td colspan="4" class="seemore">記録はまだありません</td></tr>')+`</tbody></table></div></div>`;
  body.innerHTML=h; encKeyStatus(); encCardKey(); encSelInfo(); if(off){ encReqPreview(); encReqWho(); if(DEC.rows) encDecShow(); }
}
function encOrgOpts(ov,sel){ return '<option value="">すべての組織</option>'+(ov.orgs||[]).filter(o=>(ov.backends||[]).some(b=>b.org===o.id)).map(o=>`<option value="${esc(o.id)}" ${o.id===sel?'selected':''}>${'\u3000'.repeat(encDepth(o,ov.orgs))}${esc(o.name)}</option>`).join(''); }
function encBeOpts(ov,org,sel,all){ const l=(ov.backends||[]).filter(b=>!org||b.org===org); return (all?'<option value="">'+all+'('+l.length+'件)</option>':'')+l.map(b=>`<option value="${esc(b.id)}" ${b.id===sel?'selected':''}>${esc(b.name)}</option>`).join(''); }
function encOrgName(ov,id){ const o=(ov.orgs||[]).find(x=>x.id===id); return o?o.name:(id||''); }
function encReqOrg(v){ ENC_ORG.req=v; const sel=document.getElementById('encReqBe'); if(sel) sel.innerHTML=encBeOpts(ENC,v,''); encReqPreview(); encReqWho(); }
function encFOrg(v){ ENC_ORG.flt=v; ENC_F.backend=''; const sel=document.getElementById('encFBe'); if(sel) sel.innerHTML=encBeOpts(ENC,v,'','すべての接続先'); encFApply(); }
function encReqWho(){
  const el=document.getElementById('encReqWho'); if(!el||!ENC) return;
  const id=(document.getElementById('encReqBe')||{}).value, b=(ENC.backends||[]).find(x=>x.id===id);
  el.innerHTML=b?`申請先: <b>${esc(encOrgName(ENC,b.org))}</b> の担当者が承認します(申請者本人は承認できません)。`:'';
}
function encCardKey(){ const el=document.getElementById('encCardKey'); if(el) el.innerHTML=encHasKeys()?`<b class="ok">${Object.keys(DEC.keys).length}個 読込中</b>`:'<span class="seemore">未読み込み</span>'; }
function encFQuery(F,extra){
  const qs=new URLSearchParams(Object.assign({days:F.days,sort:F.sort,dir:F.dir},extra||{}));
  ['backend','method','action','status','ip','path','from','to'].forEach(k=>{ if(F[k]) qs.set(k,F[k]); }); if(F.granted) qs.set('granted','1');
  if(ENC_ORG.flt&&!F.backend) qs.set('org',ENC_ORG.flt);
  return qs;
}
function encFApply(){
  const v=id=>{ const e=document.getElementById(id); return e?e.value.trim():''; };
  Object.assign(ENC_F,{backend:v('encFBe'),days:v('encFDays')||7,method:v('encFMethod'),action:v('encFAction'),ip:v('encFIp'),path:v('encFPath'),status:v('encFStatus'),per:v('encFPer')||50,granted:!!(document.getElementById('encFGr')||{}).checked,page:1});
  ENC_SEL={}; encEvLoad();
}
function encFReset(){ Object.assign(ENC_F,{backend:'',from:'',to:'',method:'',action:'',status:'',ip:'',path:'',granted:false,page:1,sort:'ts',dir:'desc'}); loadEnc(); }
function encSort(k){ if(ENC_F.sort===k) ENC_F.dir=ENC_F.dir==='asc'?'desc':'asc'; else { ENC_F.sort=k; ENC_F.dir=(k==='ts')?'desc':'asc'; } ENC_F.page=1; encEvLoad(); }
function encPage(n){ ENC_F.page=n; encEvLoad(); }
async function encEvLoad(){
  const box=document.getElementById('encEvBox'); if(!box) return;
  const F=ENC_F, qs=encFQuery(F,{per:F.per,page:F.page});
  let ev; try{ ev=await (await fetch('/api/enc/events?'+qs,{cache:'no-store'})).json(); }catch(e){ box.innerHTML='<div class="seemore">読み込めませんでした</div>'; return; }
  if(ev.error){ box.innerHTML='<div class="seemore">'+esc(ev.error)+'</div>'; return; }
  F.page=ev.page; ENC_LAST=ev;
  const th=(k,t)=>`<th style="cursor:pointer;white-space:nowrap" onclick="encSort('${k}')">${t}${F.sort===k?(F.dir==='asc'?' ▲':' ▼'):''}</th>`;
  const rows=(ev.events||[]).map(r=>`<tr><td>${r.granted?'':`<input type="checkbox" ${ENC_SEL[r.eid]?'checked':''} onchange="encSelToggle('${esc(r.eid)}','${esc(r.backend)}','${esc(r.ts)}',this.checked)">`}</td><td>${esc((r.ts||'').replace('T',' '))}</td><td>${esc(r.backend_name)}</td><td>${esc(r.method)} ${esc(r.path)}</td><td>${esc(r.client_ip)}</td><td>${esc(r.action)} ${esc(r.status)}</td>
    <td>${r.granted?`<button type="button" class="cp" onclick="encOpen('${esc(r.eid)}','${esc(r.backend)}')">復号して表示</button><div class="seemore">${esc(r.ticket)}</div>`:`<span class="seemore">承認が必要</span><br><button type="button" class="cp" onclick="encReqFor('${esc(r.backend)}','${esc(r.ts)}')">この日時で申請</button>`}</td></tr>`).join('');
  const pg=ev.pages>1?`<button type="button" class="cp" ${ev.page<=1?'disabled':''} onclick="encPage(${ev.page-1})">‹ 前へ</button> <span class="seemore">${ev.page} / ${ev.pages} ページ</span> <button type="button" class="cp" ${ev.page>=ev.pages?'disabled':''} onclick="encPage(${ev.page+1})">次へ ›</button>`:'';
  box.innerHTML=`<div class="seemore" style="margin:6px 0">${ev.total} 件(うち承認済み ${ev.granted} 件)${pg?' ／ ':''}${pg}
    <span id="encSelBar"></span></div>
    <table><thead><tr><th></th>${th('ts','時刻')}${th('backend_name','接続先')}${th('path','リクエスト')}${th('client_ip','IP')}${th('action','結果')}<th></th></tr></thead><tbody>${rows||'<tr><td colspan="7" class="seemore">条件に合う暗号化ログはありません</td></tr>'}</tbody></table>
    ${pg?`<div style="margin-top:6px">${pg}</div>`:''}`;
  encSelBar();
}
let ENC_LAST=null;
function encSelToggle(eid,backend,ts,on){ if(on) ENC_SEL[eid]={backend,ts}; else delete ENC_SEL[eid]; encSelBar(); }
function encSelBar(){
  const el=document.getElementById('encSelBar'); if(!el) return; const n=Object.keys(ENC_SEL).length;
  el.innerHTML=n?`<span class="eb warn">${n}件を選択中</span> <button type="button" class="cp" onclick="encReqFromSel()">選んだログで申請する</button> <button type="button" class="cp" onclick="ENC_SEL={};encEvLoad()">選択を解除</button>`:'<span class="seemore">(承認が必要なログにチェックを入れると、まとめて申請できます)</span>';
}
function encSelInfo(){
  const el=document.getElementById('encSelInfo'); if(!el) return; const n=Object.keys(ENC_SEL).length;
  el.innerHTML=n?`<span class="eb warn">選んだログ ${n}件</span> を含む期間が入力されています。期間内のほかのログも、承認されると復号の対象になります。`:'';
}
function encReqFromSel(){
  const sel=Object.values(ENC_SEL); if(!sel.length) return;
  const bes=[...new Set(sel.map(x=>x.backend))];
  if(bes.length>1){ alert('接続先が異なるログが選ばれています。1つの接続先ごとに申請してください。'); return; }
  const ts=sel.map(x=>new Date(String(x.ts).replace(' ','T')).getTime()).filter(x=>!isNaN(x)); if(!ts.length) return;
  encFillReq(bes[0],new Date(Math.min(...ts)-5*60e3),new Date(Math.max(...ts)+5*60e3));
}
function encFillReq(backend,from,to){
  const pad=n=>String(n).padStart(2,'0'), loc=d=>d.getFullYear()+'-'+pad(d.getMonth()+1)+'-'+pad(d.getDate())+'T'+pad(d.getHours())+':'+pad(d.getMinutes());
  encTab('req');
  const bo=((ENC&&ENC.backends)||[]).find(x=>x.id===backend); ENC_ORG.req=bo?bo.org:'';
  const so=document.getElementById('encReqOrg'); if(so) so.value=ENC_ORG.req;
  const sel=document.getElementById('encReqBe'); if(sel){ sel.innerHTML=encBeOpts(ENC,ENC_ORG.req,backend); sel.value=backend; }
  encReqWho();
  document.getElementById('encReqFrom').value=loc(from); document.getElementById('encReqTo').value=loc(to);
  encSelInfo(); encReqPreview();
  const why=document.getElementById('encReqWhy'); if(why){ why.scrollIntoView({block:'center',behavior:'smooth'}); why.focus(); }
}
function encReqFor(backend,ts){
  const t=new Date(String(ts).replace(' ','T')); if(isNaN(t)) return;
  encFillReq(backend,new Date(t.getTime()-3600e3),new Date(t.getTime()+3600e3));
  const m=document.getElementById('encReqMsg'); if(m){ m.style.color=''; m.textContent='このログの前後1時間を入力しました。理由を書いて「申請する」を押してください(期間は変更できます)。'; }
}
function encPreset(k){
  const now=new Date(), d0=new Date(now.getFullYear(),now.getMonth(),now.getDate());
  const m={'1h':[new Date(now-3600e3),now],'24h':[new Date(now-24*3600e3),now],'today':[d0,now],'yday':[new Date(d0-24*3600e3),new Date(d0-60e3)],'7d':[new Date(now-7*24*3600e3),now]}[k];
  const pad=n=>String(n).padStart(2,'0'), loc=d=>d.getFullYear()+'-'+pad(d.getMonth()+1)+'-'+pad(d.getDate())+'T'+pad(d.getHours())+':'+pad(d.getMinutes());
  document.getElementById('encReqFrom').value=loc(m[0]); document.getElementById('encReqTo').value=loc(m[1]); encReqPreview();
}
function encReason(t){ const w=document.getElementById('encReqWhy'); if(!w||!t) return; const cur=w.value.replace(/^【[^】]*】\s*/,''); w.value='【'+t+'】'+(cur?' '+cur:' '); w.focus(); }
let ENC_PV=null;
function encReqPreview(){
  clearTimeout(ENC_PV); ENC_PV=setTimeout(async()=>{
    const el=document.getElementById('encReqPrev'); if(!el) return;
    const be=(document.getElementById('encReqBe')||{}).value, f=(document.getElementById('encReqFrom')||{}).value, t=(document.getElementById('encReqTo')||{}).value;
    if(!be||!f||!t){ el.textContent=''; return; }
    try{ const r=await (await fetch('/api/enc/count?'+new URLSearchParams({backend:be,from:f,to:t}),{cache:'no-store'})).json();
      el.innerHTML=(r.count!=null)?`この期間の暗号化ログ: <b>${r.count}</b> 件(承認されると、この件数すべてが復号の対象になります)`:''; }catch(e){ el.textContent=''; }
  },300);
}
async function encRequest(){
  const g=id=>document.getElementById(id).value, m=document.getElementById('encReqMsg');
  const r=await postJSON('/api/enc/request',{backend:g('encReqBe'),from:g('encReqFrom'),to:g('encReqTo'),reason:g('encReqWhy')});
  if(!r.ok){ m.textContent='エラー: '+(r.error||'失敗'); m.style.color='var(--e-ng)'; return; }
  ENC_SEL={}; loadEnc();
}
// 秘密鍵の読み込み(複数可)。ログの鍵ID(kid)に合う鍵を自動で選ぶ
async function encKidOf(pem){
  const der=b64buf(pem.replace(/-----[^-]+-----/g,'').replace(/\s+/g,''));
  const ex=await crypto.subtle.importKey('pkcs8',der,{name:'RSA-OAEP',hash:'SHA-256'},true,['decrypt']);       // 鍵IDの計算のためだけに、取り出せる形で読む
  const jwk=await crypto.subtle.exportKey('jwk',ex);
  const pub=await crypto.subtle.importKey('jwk',{kty:'RSA',n:jwk.n,e:jwk.e,alg:'RSA-OAEP-256',ext:true},{name:'RSA-OAEP',hash:'SHA-256'},true,['encrypt']);
  const h=new Uint8Array(await crypto.subtle.digest('SHA-256',await crypto.subtle.exportKey('spki',pub)));
  const kid=[...h].slice(0,8).map(x=>x.toString(16).padStart(2,'0')).join('');
  const key=await crypto.subtle.importKey('pkcs8',der,{name:'RSA-OAEP',hash:'SHA-256'},false,['decrypt']);      // 保持するのは取り出せない形だけ
  return {kid,key};
}
async function encAddKeys(text){
  if(!encOk()) throw new Error(ENC_NEED_SECURE);
  if(/ENCRYPTED/.test(text)) throw new Error('パスフレーズ付きの鍵には未対応です');
  if(/BEGIN RSA PRIVATE KEY/.test(text)) throw new Error('PKCS#8形式(BEGIN PRIVATE KEY)の秘密鍵を指定してください');
  const blocks=text.match(/-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----/g)||[];
  if(!blocks.length) throw new Error('秘密鍵(PEM形式)として読めません');
  const added=[]; for(const b of blocks){ const r=await encImportKey(b); DEC.keys[r.kid]=r.key; added.push(r.kid); }
  return added;
}
async function encImportKey(pem){ return encKidOf(pem); }
async function encKeysLoaded(text){
  const m=document.getElementById('encPrivMsg');
  try{
    const ids=await encAddKeys(text); encArm(); encKeyStatus(); encCardKey();
    if(m){ m.style.color=''; m.textContent='鍵を読み込みました(鍵ID: '+ids.join(', ')+')。'; }
    const p=document.getElementById('encPriv'); if(p) p.value=''; const f=document.getElementById('encPrivFile'); if(f) f.value='';
    if(ENC_AUTO&&ENC&&ENC.is_officer&&encActiveGrants(ENC).length) encBulk();
  }catch(err){ if(m){ m.textContent='✗ '+(err&&err.message||'読み込めません'); m.style.color='var(--e-ng)'; } }
}
function encReadFiles(files){
  const arr=[...(files||[])]; if(!arr.length) return;
  Promise.all(arr.map(f=>new Promise(res=>{ const r=new FileReader(); r.onload=()=>res(String(r.result||'')); r.readAsText(f); }))).then(t=>encKeysLoaded(t.join('\n')));
}
function encReadPriv(inp){ encReadFiles(inp.files); }
function encDropKey(ev){ ev.preventDefault(); const bx=document.getElementById('encKeyBox'); if(bx) bx.classList.remove('drag'); encReadFiles(ev.dataTransfer&&ev.dataTransfer.files); }
function encLoadPriv(){ encKeysLoaded((document.getElementById('encPriv').value||'').trim()); }
// 復号
function encGrantGo(tid){
  const t=((ENC&&ENC.tickets)||[]).find(x=>x.id===tid); if(!t) return; const g=t.grant||{};
  Object.assign(ENC_F,{backend:t.backend,from:g.from||'',to:g.to||'',granted:true,page:1,days:93});
  loadEnc().then(()=>{ if(encHasKeys()) encBulk(); else { const m=document.getElementById('encPrivMsg'); if(m){ m.style.color='var(--e-warn)'; m.textContent='秘密鍵を読み込むと、この範囲を復号できます。'; } } });
}
async function encBulk(){
  const m=document.getElementById('encPrivMsg'), box=document.getElementById('encDecBox'); if(!box) return;
  if(!encHasKeys()){ m.textContent='先に秘密鍵を読み込んでください'; m.style.color='var(--e-ng)'; return; }
  box.innerHTML='<div class="seemore">復号しています…</div>';
  const F=ENC_F, body={days:F.days,sort:F.sort,dir:F.dir}; ['backend','method','action','status','ip','path','from','to'].forEach(k=>{ if(F[k]) body[k]=F[k]; }); if(ENC_ORG.flt&&!F.backend) body.org=ENC_ORG.flt;
  const r=await postJSON('/api/enc/fetch_many',body);
  if(!r.ok){ box.innerHTML=''; m.textContent='エラー: '+(r.error||'失敗'); m.style.color='var(--e-ng)'; return; }
  const rows=[], missing={}; let fail=0;
  for(const it of r.items){
    const e=Object.assign({},it.meta,{enc:it.enc,hits:it.meta.hits||[]});
    try{ await encDecrypt(e); rows.push(e); }catch(err){ fail++; if(err&&err.kid!==undefined) missing[err.kid]=(missing[err.kid]||0)+1; }
  }
  DEC.rows=rows; DEC.q=''; DEC.info={total:r.total,n:r.items.length,fail,miss:Object.keys(missing)}; encArm(); m.style.color='';
  encDecShow();
  box.scrollIntoView({block:'nearest',behavior:'smooth'});
}
function encDecShow(){
  const box=document.getElementById('encDecBox'); if(!box||!DEC.rows) return; const i=DEC.info||{}, miss=i.miss||[];
  box.innerHTML=`<div class="decbox"><div class="dh"><b>復号した結果 ${DEC.rows.length}件</b>${i.total>i.n?`<span class="eb warn">条件に合う承認済み ${i.total}件のうち先頭 ${i.n}件</span>`:''}${miss.length?`<span class="eb ng">${i.fail}件は鍵が足りません(鍵ID: ${miss.map(esc).join(', ')} の秘密鍵を読み込むと、続けて復号します)</span>`:(i.fail?`<span class="eb ng">${i.fail}件は復号できませんでした</span>`:'')}
    <input type="text" id="encDQ" size="30" placeholder="中身で検索(Cookie・ボディ・クエリ・パス・IP)" value="${esc(DEC.q||'')}" oninput="encDSearch(this.value)">
    <span class="seemore" id="encDCnt"></span><button type="button" class="cp" onclick="encWipeBulk()">一覧を閉じる(消去)</button></div>
    <div id="encDList"></div></div>`;
  encDSearch(DEC.q||'');
}
function encDText(e){ try{ return JSON.stringify([e.path,e.client_ip,e.query,e.req,e.resp]).toLowerCase(); }catch(x){ return ''; } }
function encDSearch(q){
  if(!DEC.rows) return; DEC.q=q; encArm();
  const t=String(q||'').toLowerCase().trim(), list=document.getElementById('encDList'); if(!list) return;
  const hit=t?DEC.rows.filter(e=>encDText(e).includes(t)):DEC.rows;
  const hl=(txt)=>{ if(!t) return esc(txt); const low=txt.toLowerCase(); let out='', i=0, j;
    while((j=low.indexOf(t,i))>=0){ out+=esc(txt.slice(i,j))+'<mark>'+esc(txt.slice(j,j+t.length))+'</mark>'; i=j+t.length; }
    return out+esc(txt.slice(i)); };
  const snip=e=>{
    const b=(e.req&&e.req.body)||'', base=[e.query&&('query: '+e.query),b&&('body: '+String(b).slice(0,120))].filter(Boolean).join('  ').slice(0,200);
    if(!t||base.toLowerCase().includes(t)) return hl(base);
    let full=''; try{ full=JSON.stringify([e.req,e.resp]); }catch(x){}      // 検索に一致した箇所(ヘッダ・Cookie・レスポンスなど)の前後を見せる
    const k=full.toLowerCase().indexOf(t); if(k<0) return hl(base);
    return '<span class="seemore">一致: </span>'+hl((k>40?'…':'')+full.slice(Math.max(0,k-40),k+t.length+60)+'…');
  };
  document.getElementById('encDCnt').textContent=t?`${hit.length} / ${DEC.rows.length} 件`:'';
  list.innerHTML=`<table><thead><tr><th>時刻</th><th>リクエスト</th><th>IP</th><th>結果</th><th>中身(抜粋)</th><th></th></tr></thead><tbody>`+
    (hit.slice(0,300).map((e,i)=>`<tr><td>${esc((e.ts||'').replace('T',' '))}</td><td>${esc(e.method)} ${esc(e.path)}</td><td>${esc(e.client_ip)}</td><td>${esc(e.action)} ${esc(e.status)}</td><td class="snip">${snip(e)}</td>
      <td><button type="button" class="cp" onclick="encDOpen(${DEC.rows.indexOf(e)})">詳細</button></td></tr>`).join('')||'<tr><td colspan="6" class="seemore">条件に合うログはありません</td></tr>')+
    `</tbody></table>${hit.length>300?'<div class="seemore">先頭300件を表示しています。検索で絞り込んでください。</div>':''}`;
}
function encDOpen(i){ const e=DEC.rows&&DEC.rows[i]; if(!e) return; encArm(); showDetail(-1,Object.assign({},e,{__encview:true,__dec:true})); }
async function encOpen(eid,backend){
  const m=document.getElementById('encPrivMsg');
  if(!encHasKeys()){ m.textContent='先に秘密鍵を読み込んでください'; m.style.color='var(--e-ng)'; return; }
  const r=await postJSON('/api/enc/fetch',{eid,backend});
  if(!r.ok){ m.textContent='エラー: '+(r.error||'失敗'); m.style.color='var(--e-ng)'; loadEnc(); return; }
  const e=Object.assign({},r.meta,{enc:r.enc,__encview:true,hits:r.meta.hits||[]});
  try{ await encDecrypt(e); encArm(); m.style.color=''; showDetail(-1,e); }
  catch(err){ m.textContent=(err&&err.kid!==undefined)?`✗ 鍵ID ${err.kid} の秘密鍵が必要です(その鍵のファイルを読み込んでください)`:'✗ この鍵では復号できません'; m.style.color='var(--e-ng)'; }
}
async function encToggle(on){
  if(!confirm(on?'ログ詳細の暗号化をONにします。鍵を登録した組織の、これから保存するログが暗号化されます。よろしいですか?':'ログ詳細の暗号化をOFFにします。以後のログは暗号化されません(すでに暗号化したログは、そのままです)。よろしいですか?')) return;
  const r=await postJSON('/api/enc/config',{enabled:on}); if(!r.ok) alert(r.error||'失敗'); loadEnc();
}
// 鍵の登録ウィザード: 鍵を用意、秘密鍵の保管を確認、登録してON
let ENC_GEN={};      // デモ用(enc_demo_keys): 作成した鍵ペアを、画面を離れるか再読み込みするまでメモリに保持
function encWSteps(){
  const reg=document.getElementById('encWReg'); if(!reg) return;
  const skip=!!(document.getElementById('encWSkip')||{}).checked;
  reg.disabled=!(ENC_W.pub&&(ENC_W.verified||skip));
  document.querySelectorAll('#encBody .keybox .enc-steps span').forEach((s,i)=>{ s.className=(i===0?(ENC_W.pub?'done':'now'):i===1?(ENC_W.verified?'done':(ENC_W.pub?'now':'')):(ENC_W.verified||skip?'now':'')); });
}
function encWOrg(){ const s=document.getElementById('encWOrg'); ENC_W.org=s?s.value:ENC_W.org; return ENC_W.org; }
async function encWGen(){
  const org=encWOrg(), m=document.getElementById('encWMsg');
  if(!encOk()){ m.textContent='⚠ '+ENC_NEED_SECURE; return; }
  m.textContent='鍵ペアを作成しています…';
  const kp=await crypto.subtle.generateKey({name:'RSA-OAEP',modulusLength:3072,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['encrypt','decrypt']);
  const pub=toPem(await crypto.subtle.exportKey('spki',kp.publicKey),'PUBLIC KEY'), priv=toPem(await crypto.subtle.exportKey('pkcs8',kp.privateKey),'PRIVATE KEY');
  ENC_W.pub=pub; ENC_W.verified=false; document.getElementById('encWPub').value=pub;
  if(ENC&&ENC.demo_keys) ENC_GEN[org]={pub,priv,at:new Date().toLocaleString()};
  encSaveFile(priv,'waf-log-private-key-'+org+'.pem');
  m.style.color=''; m.textContent='✓ 鍵ペアを作成し、秘密鍵(waf-log-private-key-'+org+'.pem)をダウンロードしました。② ダウンロードしたファイルを選んで、保管を確認してください。';
  encWSteps();
}
async function encWVerify(inp){
  const m=document.getElementById('encWMsg'), f=inp.files&&inp.files[0]; if(!f) return;
  if(!ENC_W.pub){ m.textContent='先に ① で公開鍵を用意してください'; m.style.color='var(--e-ng)'; return; }
  try{
    const text=await new Promise(res=>{ const r=new FileReader(); r.onload=()=>res(String(r.result||'')); r.readAsText(f); });
    const blocks=text.match(/-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----/g); if(!blocks) throw new Error('秘密鍵(BEGIN PRIVATE KEY)として読めません');
    const pub=await crypto.subtle.importKey('spki',b64buf(ENC_W.pub.replace(/-----[^-]+-----/g,'').replace(/\s+/g,'')),{name:'RSA-OAEP',hash:'SHA-256'},false,['encrypt']);
    const probe=crypto.getRandomValues(new Uint8Array(32)), ct=await crypto.subtle.encrypt({name:'RSA-OAEP'},pub,probe);
    let okk=false;
    for(const b of blocks){ try{ const k=await encKidOf(b); const back=new Uint8Array(await crypto.subtle.decrypt({name:'RSA-OAEP'},k.key,ct)); if(back.length===32&&back.every((x,i)=>x===probe[i])){ okk=true; break; } }catch(e){} }
    if(!okk) throw new Error('この秘密鍵では、上の公開鍵で暗号化したデータを復号できません(別の鍵のファイルです)');
    ENC_W.verified=true; m.style.color=''; m.textContent='✓ 確認できました。この秘密鍵で復号できます。③ 登録してください。';
  }catch(err){ ENC_W.verified=false; m.textContent='✗ '+(err&&err.message||'確認できません'); m.style.color='var(--e-ng)'; }
  encWSteps();
}
async function encWRegister(){
  const org=encWOrg(), m=document.getElementById('encWMsg'), pem=(ENC_W.pub||'').trim(); if(!org||!pem) return;
  if(!confirm('この組織の公開鍵を登録して、暗号化をONにします。以後のログは、この鍵で暗号化されます。(以前の鍵で暗号化したログは、以前の秘密鍵が必要です)よろしいですか?')) return;
  let r=await postJSON('/api/enc/config',{org_keys:{[org]:pem}}); if(!r.ok){ m.textContent='エラー: '+(r.error||'失敗'); m.style.color='var(--e-ng)'; return; }
  if(!(ENC&&ENC.enabled)){ r=await postJSON('/api/enc/config',{enabled:true}); if(!r.ok){ m.textContent='鍵は登録しましたが、ONにできませんでした: '+(r.error||''); return; } }
  ENC_W={org,pub:'',verified:false,msg:'✓ 登録しました。以後のログはこの鍵で暗号化されます。'};
  loadEnc();
}
function encSaveFile(text,name){ const a=document.createElement('a'); a.href=URL.createObjectURL(new Blob([text],{type:'application/x-pem-file'})); a.download=name; document.body.appendChild(a); a.click(); a.remove(); }
function encGenDl(org,which){ const g=ENC_GEN[org]; if(g) encSaveFile(which==='pub'?g.pub:g.priv,'waf-log-'+(which==='pub'?'public':'private')+'-key-'+org+'.pem'); }
async function encGenCopy(org,which,btn){
  const g=ENC_GEN[org]; if(!g) return;
  try{ await navigator.clipboard.writeText(which==='pub'?g.pub:g.priv); const t=btn.textContent; btn.textContent='✓ コピーしました'; setTimeout(()=>{ btn.textContent=t; },1500); }
  catch(e){ alert('コピーできませんでした(ブラウザの許可が必要です)。ダウンロードを使ってください。'); }
}
function encGenBox(org){
  const g=ENC_GEN[org]; if(!g) return '';
  const q=esc(org);
  return `<div class="keybox" style="margin-top:6px"><b>デモ用: この画面で作成した鍵(${esc(g.at)})</b>
    <div style="margin-top:4px"><button type="button" class="cp" onclick="encGenDl('${q}','priv')">秘密鍵をダウンロード</button>
    <button type="button" class="cp" onclick="encGenCopy('${q}','priv',this)">秘密鍵をコピー</button>
    <button type="button" class="cp" onclick="encGenDl('${q}','pub')">公開鍵をダウンロード</button>
    <button type="button" class="cp" onclick="encGenCopy('${q}','pub',this)">公開鍵をコピー</button>
    <button type="button" class="cp" onclick="delete ENC_GEN['${q}'];loadEnc()">この画面から消す</button></div>
    <div class="seemore warn">デモ用の機能です。秘密鍵はこの画面を離れる・再読み込みするまでブラウザのメモリに残ります。本番では設定 <code>enc_demo_keys</code> を false にしてください。</div></div>`;
}
async function encSetKey(org,remove){
  const m=document.getElementById('encKeyMsg-'+org);
  if(!confirm('この組織の暗号鍵を外します。以後のログは暗号化されません(すでに暗号化したログは、その鍵の秘密鍵があれば復号できます)。よろしいですか?')) return;
  const r=await postJSON('/api/enc/config',{org_keys:{[org]:''}}); if(!r.ok){ if(m){ m.textContent='エラー: '+(r.error||'失敗'); m.style.color='var(--e-ng)'; } return; }
  delete ENC_GEN[org]; loadEnc();
}

let curDetail=null;
function showDetail(i,ev){
  const e=ev||(window.__filtered||window.__recent||[])[i]; if(!e) return;
  window.__detailEv=e;      // 申請に添付するのは、いま開いているイベント。自動更新で一覧が変わっても影響しない
  curDetail=e;
  const t=(e.ts||'').replace('T',' ').slice(0,19);
  let ov='<div class="kv">';
  ov+=`<div class="k">時刻</div><div class="v">${esc(t)}</div>`;
  ov+=`<div class="k">アクション</div><div class="v"><span class="tag ${esc(e.action)}">${esc(e.action)}</span>${e.disposition?` <span class="seemore">${esc(e.disposition)}</span>`:''}</div>`;
  if(parseInt(e.count||1,10)>1)
    ov+=`<div class="k">集約件数</div><div class="v"><b>${parseInt(e.count,10)} 件</b> <span class="seemore">— 大量の同種dropを1行に集約</span></div>`;
  const srcLabel={remote:'接続元の公開IP(本人)',reported:'ブラウザが申告した公開IP(VPN出口など・自己申告)',egress:'WAFホストの出口IP(内部アクセス共通)',xff:'X-Forwarded-For',local:'接続元IP(オフライン時)'}[e.ip_src]||e.ip_src;
  const gipLabel = e.ip_src==='egress' ? 'グローバルIP(WAF出口)' : (e.ip_src==='reported' ? 'グローバルIP(申告)' : 'グローバルIP');
  ov+=`<div class="k">${gipLabel}</div><div class="v">${esc(e.ip)}${e.ip_src?` <span class="seemore">(${esc(srcLabel)})</span>`:''}</div>`;
  if(e.ip_src==='egress')
    ov+=`<div class="k"></div><div class="v"><span class="seemore">※ この端末からの公開IPの申告がまだ無いため、WAFホスト自身の出口IPで代用しています(ブラウザでページを開くと申告されます。curl等は申告されません。下の「接続元」が実際の識別子)。</span></div>`;
  if(e.ip_src==='reported')
    ov+=`<div class="k"></div><div class="v"><span class="seemore">※ 端末自身が申告した値で、偽装できます。レート制限・BANは下の「接続元」で判定しています。</span></div>`;
  if(e.conn_ip && e.conn_ip!==e.ip)
    ov+=`<div class="k">接続元(実際の送信元)</div><div class="v"><b>${esc(e.conn_ip)}</b>${(e.ip_src==='egress'||e.ip_src==='reported')?' <span class="seemore">— 内部クライアントはこれで区別</span>':''}</div>`;
  if(e.backend) ov+=`<div class="k">防御したバックエンド</div><div class="v"><span class="be-tag" style="--c:${beColor(e.backend)}">${esc(e.backend_name||e.backend)}</span></div>`;
  ov+=`<div class="k">メソッド / パス</div><div class="v">${esc(e.method)} ${esc(e.path)}</div>`;
  if(e.status!=='' && e.status!=null) ov+=`<div class="k">応答ステータス</div><div class="v">${esc(e.status)}</div>`;
  ov+='</div>';
  if(e.hits && e.hits.length){
    ov+='<div class="sec-title">検知ルール</div>';
    e.hits.forEach(h=>{ ov+=`<div class="hit"><b>${esc(h.id)}</b> [${esc(h.category)}/${esc(h.severity)}] ${esc(h.description)}<br>`
        +`場所: <code>${esc(h.field||'')}</code> / 一致: <code>${esc(h.matched||'')}</code></div>`; });
  }

  if(e.hits && e.hits.length && e.backend && (e.action==='BLOCK'||e.action==='DETECT') && !e.disposition){
    ov+=`<div style="margin:8px 0"><button type="button" class="cp" onclick="tkDraftFrom()">📨 これを誤検知として申請</button></div>`;
  }

  if((e.enc_locked&&!e.__dec)||e.enc_error){
    document.getElementById('mTitle').textContent=`${e.method} ${e.path}`;
    document.getElementById('mBody').innerHTML=ov+encPanel(e);
    document.getElementById('modal').classList.add('open'); return;
  }
  // 生リクエスト(攻撃一致箇所をハイライト)
  const rawReq=buildRawRequest(e);
  const matches=(e.hits||[]).map(h=>h.matched).filter(Boolean);
  const reqHtml=highlightRaw(rawReq, matches);
  const resp=e.resp;
  const respRaw=buildRawResponse(e);
  const reqSz=(e.req&&e.req.body_len!=null)?`body ${e.req.body_len}B`:'';
  const respSz=(resp&&resp.body_len!=null)?`body ${resp.body_len}B`:'';
  const stc = resp ? ('stc-'+String(resp.status||'').charAt(0)) : '';

  let html=ov;
  html+='<div class="rr-cols">';
  html+=`<div class="rr-pane">
    <div class="rr-head"><span>リクエスト</span><span class="sz">${reqSz}</span>
      <button class="cp" onclick="copyRaw('rawReq')">コピー</button></div>
    <pre class="raw" id="rawReq">${reqHtml}</pre></div>`;
  html+=`<div class="rr-pane">
    <div class="rr-head"><span>レスポンス</span>${resp?`<span class="st ${stc}">${esc((resp.status||'')+' '+(resp.reason||''))}</span>`:''}
      <span class="sz">${respSz}</span>
      ${respRaw?`<button class="cp" onclick="copyRaw('rawResp')">コピー</button>`:''}</div>
    <pre class="raw" id="rawResp">${respRaw?esc(respRaw):'<span class="seemore">レスポンス未記録(log_response が無効、または遮断で転送なし)。</span>'}</pre></div>`;
  html+='</div>';

  document.getElementById('mTitle').textContent = `${e.method} ${e.path}`;
  document.getElementById('mBody').innerHTML = html;
  document.getElementById('modal').classList.add('open');
}
function highlightRaw(raw, matches){
  // 1行目(リクエストライン)を強調し、攻撃一致箇所をハイライト
  let h=esc(raw);
  // ヘッダ名を薄く色付け(行頭の Name:)
  h=h.replace(/^([A-Za-z0-9-]+):/gm,'<span class="hk">$1</span>:');
  // 1行目
  h=h.replace(/^(.*?)\n/,'<span class="ln1">$1</span>\n');
  // 一致箇所(重複排除、長い順)
  const uniq=[...new Set(matches)].filter(m=>m&&m.length>=3).sort((a,b)=>b.length-a.length);
  uniq.forEach(m=>{
    const em=esc(m).replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
    try{ h=h.replace(new RegExp(em,'g'),'<span class="hl">$&</span>'); }catch(_){}
  });
  return h;
}
function copyRaw(id){
  const el=document.getElementById(id); if(!el) return;
  const txt=el.innerText;
  try{ navigator.clipboard.writeText(txt); }catch(e){}
}
function closeModal(){ document.getElementById('modal').classList.remove('open'); encWipe(); }

/* バックエンド別の表示(絞り込み・件数チップ) */
const BE_COLORS={};     // idごとの色(#rrggbb。設定で選ぶ)
function beColor(id){ if(BE_COLORS[id]) return BE_COLORS[id]; let h=0; const t=String(id||''); for(let i=0;i<t.length;i++) h=(h*31+t.charCodeAt(i))%360; return `hsl(${h} 62% 55%)`; }
function beColorHex(id){
  const c=beColor(id); if(c[0]==='#') return c;
  const m=/hsl\((\d+)\s+(\d+)%\s+(\d+)%\)/.exec(c); if(!m) return '#3987e5';
  const h=+m[1], s=+m[2]/100, l=+m[3]/100, k=n=>(n+h/30)%12, a=s*Math.min(l,1-l), f=n=>l-a*Math.max(-1,Math.min(k(n)-3,Math.min(9-k(n),1)));
  return '#'+[f(0),f(8),f(4)].map(x=>Math.round(x*255).toString(16).padStart(2,'0')).join('');
}
function beSetColors(profiles){ (profiles||[]).forEach(p=>{ if(p&&p.id){ if(/^#[0-9a-f]{6}$/i.test(p.color||'')) BE_COLORS[p.id]=p.color; else delete BE_COLORS[p.id]; } }); }
const BE_KNOWN={};      // idごとの表示名(設定・集計・ログに出てきたもの)
function beKnow(id,name){ if(!id) return false; const was=BE_KNOWN[id]; if(was===undefined||(name&&was!==name)){ BE_KNOWN[id]=name||was||id; return was===undefined; } return false; }
function beLfSync(force){
  const sel=document.getElementById('lf-backend'); if(!sel) return;
  scOrgFill('ev','lf-org');
  const ids=Object.keys(BE_KNOWN);
  const list=scBeFill('ev',sel,beBase(),'全バックエンド',
    '<option value="">全バックエンド</option>',
    (window.__beHasNone&&ids.length&&!SC.ev.org?'<option value="__none">(判定前に遮断)</option>':''));
  if(SC.ev.be==='__none'&&SC.ev.org){ SC.ev.be=''; sel.value=''; }
  sel.style.display = (ids.length>1||scOrgOn()) ? '' : 'none';
  trafBeSync(); mapBeSync(); homeBeSync();
}
function beChipsRender(){
  // 接続先ごとの件数(表示のみ)。ログ表の横に縦に並べる。絞り込みはドロップダウン(lf-backend)
  const box=document.getElementById('lf-bechips'); if(!box) return;
  const st=(window.__stats&&window.__stats.backends)||[];
  const by={}; st.forEach(b=>{ by[b.id]=b; if(b.id) beKnow(b.id,b.name); });
  window.__beHasNone=!!(by['']&&by[''].total);
  const ids=Object.keys(BE_KNOWN).filter(id=>scInOrg('ev',id));
  if(Object.keys(BE_KNOWN).length<2){ box.hidden=true; beLfSync(); return; }
  const cur=document.getElementById('lf-backend').value;
  const chip=(id,name,c,col)=>{ const a=(c&&c.counts)||{};
    return `<div class="bechip ${cur===id?'on':''}" style="--c:${col}"><i></i><span style="flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis" title="${esc(name)}">${esc(name)}</span> <b>${((c&&c.total)||0).toLocaleString()}</b>`
      +`<small>BLOCK ${(a.BLOCK||0).toLocaleString()} / DETECT ${(a.DETECT||0).toLocaleString()}</small></div>`; };
  box.innerHTML='<div class="be-side-h">接続先ごとの件数</div>'
    +`<div class="bechip ${cur===''?'on':''}"><i></i>すべて</div>`
    +ids.map(id=>chip(id,BE_KNOWN[id],by[id],beColor(id))).join('')
    +(window.__beHasNone?chip('__none','(判定前に遮断)',by[''],'var(--ink-muted)'):'');
  box.hidden=false; beLfSync();
}

/* イベントログの描画とフィルタ */
const ATTACK_ACTIONS={BLOCK:1,DETECT:1};
let LOG_SHOW_MAX=1000;      // 一度に表示する行数(「さらに表示」で増やす)
const LOG_SHOW_STEP=1000;
function _tsMs(v){ if(!v) return null; const d=new Date(v); const t=d.getTime(); return isNaN(t)?null:t; }
function renderRecent(){
  const all=window.__recent||[];
  homeRecent();
  const fa=document.getElementById('lf-action').value;
  const fm=document.getElementById('lf-method').value;
  const ftRaw=document.getElementById('lf-text').value.trim().toLowerCase();
  const terms=ftRaw?ftRaw.split(/\s+/):[];
  const onlyAtk=document.getElementById('lf-attack').checked;
  const fb=document.getElementById('lf-backend').value;
  const fromMs=_tsMs(document.getElementById('lf-from').value);
  const toMs=_tsMs(document.getElementById('lf-to').value);
  const filtered=all.filter(e=>{
    if(fa && e.action!==fa) return false;
    if(fm && e.method!==fm) return false;
    if(onlyAtk && !(e.hits&&e.hits.length)) return false;
    if(fb){ if(fb==='__none'){ if(e.backend) return false; } else if(e.backend!==fb) return false; }
    else if(SC.ev.org && !scInOrg('ev',e.backend||'')) return false;
    if(fromMs!=null || toMs!=null){ const em=_tsMs(e.ts);
      if(em==null) return false;
      if(fromMs!=null && em<fromMs) return false;
      if(toMs!=null && em>toMs) return false; }
    if(terms.length){
      const hay=((e.ts||'')+' '+(e.ip||e.client_ip||'')+' '+(e.conn_ip||'')+' '+(e.method||'')+' '+
                 (e.action||'')+' '+(e.path||'')+' '+(e.rules||'')+' '+(e.disposition||'')+' '+(e.status||'')+' '+(e.backend_name||e.backend||'')).toLowerCase();
      for(const t of terms){ if(hay.indexOf(t)<0) return false; }
    }
    return true;
  });
  window.__filtered=filtered;
  const shown=filtered.slice(0,LOG_SHOW_MAX);
  const meta=window.__logMeta;
  document.getElementById('lf-count').textContent=
    `${filtered.length.toLocaleString()} 行該当${filtered.length>LOG_SHOW_MAX?`(先頭${LOG_SHOW_MAX.toLocaleString()}行を表示)`:''}`
    +` / 読込 ${all.length.toLocaleString()} 行`
    +(meta?(meta.truncated?`(ログ全${meta.lines_in_file.toLocaleString()}行のうち新しい方)`:'(ログ全行)'):'')
    +` / 累計 ${(window.__total_events||all.length).toLocaleString()} リクエスト`;
  const rc=document.getElementById('recentCount');
  if(rc) rc.textContent=`— 累計 ${(window.__total_events||all.length).toLocaleString()} リクエスト / 行クリックで詳細`;
  renderTable('recent', shown.map((e,i)=>{
    const t=(e.ts||'').replace('T',' ').slice(0,19);
    const n=parseInt(e.count||1,10)||1;
    const tf=(e.ts_from||'').replace('T',' ').slice(11,19);
    const tcell = (n>1 && tf && tf!==t.slice(11)) ? `${t}<br><small>〜${tf}</small>` : esc(t);
    const cntBadge = n>1 ? ` <span class="cnt-badge">×${n}</span>` : '';
    const dispTxt = (n>1 && e.disposition) ? ` <span class="seemore">${esc(e.disposition)}</span>` : '';
    const detail=e.rules?`<code>${esc(e.rules)}</code>`:(esc(e.status)+dispTxt);
    const ipc = (e.conn_ip && e.conn_ip!==e.ip)
      ? `<div class="ipcell">${esc(e.ip)}<br><small>接続元 ${esc(e.conn_ip)}</small></div>`
      : esc(e.ip);
    const bcell = e.backend ? `<span class="be-tag" style="--c:${beColor(e.backend)}" title="${esc(e.backend_name||e.backend)}">${esc(e.backend_name||e.backend)}</span>`
                            : '<span class="seemore" title="どのバックエンド宛てか判定できる前に遮断した接続">—</span>';
    return `<tr onclick="showDetail(${i})"><td>${tcell}</td>
      <td><span class="tag ${esc(e.action)}">${esc(e.action)}</span>${cntBadge}</td>
      <td>${bcell}</td>
      <td>${ipc}</td><td>${esc(e.method)}</td>
      <td class="path" title="${esc(e.path)}">${esc(e.path)}</td><td>${detail}</td></tr>`;
  }).join('') + (filtered.length>shown.length
    ? `<tr><td colspan="7" class="empty"><button class="lf-clr" onclick="logMore(${LOG_SHOW_STEP})">さらに${LOG_SHOW_STEP.toLocaleString()}行表示</button>
        <button class="lf-clr" onclick="logMore(1e9)">すべて表示(${filtered.length.toLocaleString()}行・重い場合があります)</button>
        <span class="seemore">残り ${(filtered.length-shown.length).toLocaleString()} 行</span></td></tr>` : ''));
}
function logMore(n){ LOG_SHOW_MAX = (n>=1e9) ? 1e9 : LOG_SHOW_MAX+n; renderRecent(); }

/* 防御するバックエンド(転送先) */
let BE=null, BE_N=0, BE_OPEN=null;
function beScope(h){
  h=String(h||'').toLowerCase();
  if(h==='localhost'||h==='::1'||/^127\./.test(h)) return ['ローカル',false];
  if(/^10\./.test(h)||/^192\.168\./.test(h)||/^172\.(1[6-9]|2\d|3[01])\./.test(h)||/^169\.254\./.test(h)||/^f[cd]/.test(h)||/\.(local|lan|internal)$/.test(h)||(h.indexOf('.')<0&&!/^[0-9a-f:]+$/.test(h)))
    return ['LAN内',false];
  return ['インターネット',true];
}
function beOrigin(p){
  const h=String(p.host).indexOf(':')>=0?'['+p.host+']':p.host, def=p.scheme==='https'?443:80;
  return p.scheme+'://'+h+(+p.port===def?'':':'+p.port);
}
let BE_RO={};
function beInit(be,ro){ BE=JSON.parse(JSON.stringify(be)); BE_OPEN=null; if(ro) BE_RO=ro; beSetColors(BE.profiles); setTimeout(()=>{ try{ beChipsRender(); renderRecent(); }catch(e){} },0);
  // メインの待受ポートの転送先は、一覧の先頭に置く
  const k=BE.profiles.findIndex(p=>p.id===BE.active); if(k>0) BE.profiles.unshift(BE.profiles.splice(k,1)[0]);
  if(BE.profiles.length&&!AUTH.limited) BE.active=BE.profiles[0].id; }
// 専用ポートのアクセス先(開いているダッシュボードのホスト名で組み立てる)
function beMainUrl(){ return beLpUrl(BE_RO.main_port); }
function beLpUrl(lp){ const sch=(BE_RO.tls===false)?'http':'https'; return sch+'://'+location.hostname+':'+lp; }
function beParse(text){
  let s=String(text||'').trim(); if(!s) throw new Error('URLを入力してください');
  if(!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s='http://'+s;
  const u=new URL(s);
  if(u.protocol!=='http:'&&u.protocol!=='https:') throw new Error('http:// か https:// のURLだけ指定できます');
  const scheme=u.protocol.replace(':','');
  return {scheme, host:u.hostname.replace(/^\[|\]$/g,''), port:u.port?+u.port:(scheme==='https'?443:80),
          path:(u.pathname&&u.pathname!=='/')?u.pathname:''};
}
function beRender(){
  const box=document.getElementById('beList'); if(!box||!BE) return;
  box.innerHTML=BE.profiles.map((p,i)=>{
    const act=p.id===BE.active, [sc,g]=beScope(p.host);
    let ed='';
    if(BE_OPEN===i){
      ed=`<div class="be-edit">
        <label>名前</label><input type="text" id="be-e-name" value="${esc(p.name)}" maxlength="40">
        <label>URL<small>例: https://example.com / http://192.168.1.10:8080</small></label>
        <input type="text" id="be-e-url" value="${esc(beOrigin(p))}" placeholder="https://example.com">
        <label>TLS証明書を検証<small>https のとき。自己署名や社内CAならOFF</small></label>
        <span>${sw('be-e-tls', !!p.verify_tls)}</span>
        <label>稼働チェックのパス<small>状態の監視・接続テストで開くパス</small></label>
        <input type="text" id="be-e-hp" value="${esc(p.health_path||'/')}">
        <label>振り分けホスト名<small>「ホスト名で振り分ける」ON時、このホスト名でアクセスされたらこのバックエンドへ。カンマ区切り</small></label>
        <input type="text" id="be-e-mh" value="${esc((p.match_hosts||[]).join(', '))}" placeholder="例: board.example.com, www.example.com">
        <label>専用の待受ポート<small>空欄=専用ポートなし。入れると、そのポートに来たアクセスは常にこのバックエンドへ転送されます(他のバックエンドと同時に防御できます)</small></label>
        <input type="text" id="be-e-lp" inputmode="numeric" value="${p.listen_port?esc(p.listen_port):''}" placeholder="例: 8081">
        <label>パス振り分け<small>空欄=なし。例: /shop と入れると、メインの待受ポートの /shop/... はこのバックエンドへ転送(最長一致。専用ポートと併用不可)</small></label>
        <input type="text" id="be-e-pp" value="${esc(p.path_prefix||'')}" placeholder="例: /shop">
        <label>プレフィックスを外して転送<small>ON: /shop/a → バックエンドの /a。OFF: /shop/a のまま転送(絶対パスを返すアプリ向け)</small></label>
        <span>${sw('be-e-sp', p.strip_prefix!==false)}</span>
        <label>表示カラー<small>イベントログなどの色。ここで選んだ色がログの表示と連動します</small></label>
        <span><input type="color" id="be-e-color" value="${esc(/^#[0-9a-f]{6}$/i.test(p.color||'')?p.color:beColorHex(p.id))}" style="width:56px;height:30px;padding:0;border:1px solid var(--border);border-radius:6px;background:none;cursor:pointer"></span>
        <label>稼働停止<small>ON: このバックエンド宛のアクセスに503(メンテナンス中)を返す。ログ・設定はそのまま残ります</small></label>
        <span>${sw('be-e-stop', !!p.stopped)}</span>
        ${(AUTH.user&&(AUTH.user.role==='admin'||AUTH.analyst))?`<label>所属組織<small>この接続先のログを見られるのは、この組織(と上位の担当アナリスト)です。${p._new?'':'変更は管理者が「組織登録編集」タブで行います'}</small></label>
        ${p._new?`<select id="be-e-org">${AUTH.analyst?'':'<option value="">未割り当て</option>'}${beOrgList().map(o=>`<option value="${esc(o.id)}" ${o.id===p.org?'selected':''}>${esc(o.name)} (${esc(o.id)})</option>`).join('')}</select>`:`<span>${esc(beOrgLabel(p.org))}</span>`}`:''}
        <label>転送ヘッダ<small>外部サイトを表示するときに、リダイレクトを繰り返す場合はOFFに(接続テストで原因を特定できます)</small></label>
        <div class="be-xf"><label><input type="checkbox" id="be-e-xfh" ${p.xf_host!==false?'checked':''}> X-Forwarded-Host</label>
          <label><input type="checkbox" id="be-e-xfp" ${p.xf_proto!==false?'checked':''}> X-Forwarded-Proto</label>
          <label><input type="checkbox" id="be-e-xff" ${p.xf_for!==false?'checked':''}> X-Forwarded-For</label></div>
        <label>Hostヘッダ<small>通常は「転送先」のままでOK</small></label>
        <select id="be-e-hh"><option value="target" ${p.host_header!=='client'?'selected':''}>転送先のホスト名にする(通常)</option>
          <option value="client" ${p.host_header==='client'?'selected':''}>アクセスされたホスト名のまま渡す</option></select>
        <div class="be-ed-foot"><button type="button" data-do="cancel">キャンセル</button><button type="button" data-do="ok">決定</button></div>
      </div>`;
    }
    return `<div class="be-item" data-i="${i}">
      <div class="be-row ${p.stopped?'stopped':''}">
        <div class="be-main">
          <div><span class="be-dot" style="background:${esc(/^#[0-9a-f]{6}$/i.test(p.color||'')?p.color:beColor(p.id))}"></span><span class="nm">${esc(p.name)}</span>${p.stopped?'<span class="be-badge stp" title="このバックエンド宛のアクセスには503(メンテナンス中)を返します">稼働停止中</span>':''}<span class="be-scope ${g?'g':''}">${sc}</span>${(AUTH.user&&(AUTH.user.role==='admin'||AUTH.analyst))?`<span class="be-owner">組織:${esc(beOrgLabel(p.org))}</span>`:''}${p.listen_port?`<span class="be-lp">:${esc(p.listen_port)}</span>`:''}</div>
          <div class="url">転送先: ${extLink(beOrigin(p)+'/',beOrigin(p))}${esc(p.health_path&&p.health_path!=='/'?p.health_path:'')}${p.scheme==='https'&&!p.verify_tls?'  (TLS検証なし)':''}</div>
          ${(!p.listen_port&&!p.path_prefix&&BE.profiles[0]===p&&BE_RO.main_port)?`<div class="url">待ち受け: ${extLink(beMainUrl()+'/',beMainUrl())} (メインの待受ポート)</div>`:''}
          ${(p.match_hosts||[]).length?`<div class="url">振り分け: ${esc(p.match_hosts.join(', '))}</div>`:''}
          ${p.path_prefix?`<div class="url">パス振り分け: ${BE_RO.main_port?extLink(beMainUrl()+p.path_prefix+'/',beMainUrl()+p.path_prefix+'/…'):esc(p.path_prefix)+'/…'} → このバックエンド${p.strip_prefix===false?'(プレフィックスを付けたまま転送)':''}</div>`:''}
          ${p.listen_port?`<div class="url">専用ポート(待ち受け): ${extLink(beLpUrl(p.listen_port)+'/',beLpUrl(p.listen_port))} → このバックエンド${(()=>{ const l=(BE_RO.listeners||[]).find(x=>x.port===+p.listen_port); return l&&!l.listening?` <span class="be-lp bad">待受できていません: ${esc(l.error||'')}</span>`:''; })()}</div>`:''}
        </div>
        <div class="be-btns">${AUTH.guser?'':`<button type="button" class="${p.stopped?'warn':''}" data-do="stop" title="${p.stopped?'このバックエンドの稼働を再開します':'このバックエンド宛のアクセスを止めます(503を返します)'}">${p.stopped?'稼働を再開':'稼働停止'}</button>`}<button type="button" data-do="test">接続テスト</button>${AUTH.guser?'':`<button type="button" data-do="edit">編集</button>
          <button type="button" data-do="del" ${(BE.profiles.length<2&&!AUTH.limited)?'disabled':''}>削除</button>`}</div>
      </div>
      <div class="be-res" id="beres-${i}"></div>${ed}</div>`;
  }).join('');
  beStagedNote();
}
function beStagedNote(){
  const el=document.getElementById('beStaged'); if(!el) return;
  el.textContent=BE_LOGDEL.length?`※「保存して適用」を押すと、削除したバックエンドのログも削除されます(${BE_LOGDEL.length}件)`:'';
}
function beMsg(i,cls,html){ const el=document.getElementById('beres-'+i); if(el){ el.className='be-res '+cls; el.innerHTML=html; } }
function beLoopNote(l){
  if(!l) return '';
  if(l.error) return `<br><small>転送ヘッダの診断: 実行できませんでした(${esc(l.error)})</small>`;
  const w=l.with_headers||{};
  if(!w.self) return `<br><small>✓ 転送ヘッダの診断: WAF 経由でもリダイレクトの繰り返しは起きません(「${esc(l.path||'/')}」→ HTTP ${esc(w.status)})</small>`;
  return `<br><span class="hint" style="color:var(--block)">⚠ リダイレクトの繰り返しになります(「${esc(l.path||'/')}」→ ${esc(w.location)})。</span>`
    +(l.hint?`<br><span class="hint">${esc(l.hint)}</span>`:'');
}
function beTest(i){
  const p=BE.profiles[i]; beMsg(i,'','テスト中…(DNS → TCP → TLS → HTTP)');
  fetch('/api/backend-test',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({profile:p})})
    .then(r=>r.json()).then(d=>{
      if(!d.ok){ beMsg(i,'ng','✗ '+esc(d.error||'テストできません')); return; }
      const r=d.result, st={dns:'名前解決(DNS)',tcp:'TCP接続',tls:'TLS(証明書)',http:'HTTPリクエスト'}[r.stage]||r.stage;
      let tls='';
      if(r.tls){ tls=r.tls.verified===true?`<br><small>証明書: 検証OK(${esc(r.tls.subject)} / 発行: ${esc(r.tls.issuer)} / 期限 ${esc(r.tls.not_after)})</small>`
                 :r.tls.verified===false?`<br><small>証明書: 検証NG(${esc(r.tls.error)})${p.verify_tls?'':' → 検証OFFなので接続は可能'}</small>`:''; }
      if(r.ok){
        beMsg(i,'ok',`✓ 接続OK — HTTP ${r.status}${r.location?'(→ '+esc(r.location)+')':''} / ${r.ms} ms / ${esc(r.ip||'')}${tls}`
          +(r.status>=500?'<br><span class="hint">応答は5xxです。バックエンド側の異常かもしれません</span>':'')
          +beLoopNote(r.loop));
      } else {
        beMsg(i,'ng',`✗ 失敗(${st}) — ${esc(r.error)}${r.hint?`<br><span class="hint">${esc(r.hint)}</span>`:''}${tls}`);
      }
    }).catch(()=>beMsg(i,'ng','✗ 通信エラー'));
}
function beClick(ev){
  const b=ev.target.closest('[data-do]'); if(!b) return;
  const item=b.closest('.be-item'); const i=item?+item.dataset.i:-1, act=b.dataset.do;
  if(act==='use'){ BE.active=BE.profiles[i].id; beRender(); }
  else if(act==='stop'){ BE.profiles[i].stopped=!BE.profiles[i].stopped; beRender();
    beMsg(i,'','※「保存して適用」を押すと'+(BE.profiles[i].stopped?'停止':'再開')+'が反映されます'); }
  else if(act==='edit'){ BE_OPEN=(BE_OPEN===i)?null:i; beRender(); if(BE_OPEN!==null) beFocusEditor(); }
  else if(act==='cancel'){ if(BE.profiles[i]._new) BE.profiles.splice(i,1); BE_OPEN=null; beRender(); }
  else if(act==='del'){
    const p=BE.profiles[i];
    if(BE.profiles.length<2&&!AUTH.limited) return;
    const doDel=()=>{ const k=BE.profiles.indexOf(p); if(k<0) return; const was=p.id===BE.active; BE.profiles.splice(k,1);
      if(BE.profiles.length&&!AUTH.limited) BE.active=BE.profiles[0].id; BE_OPEN=null; beRender(); };
    if(p._new || String(p.id).indexOf('tmp-')===0){ doDel(); return; }     // 未保存の新規分はそのまま消す
    beDeleteChoice(p.name,p.id).then(c=>{ if(!c) return; if(c==='with') BE_LOGDEL.push(p.id); doDel(); });
  }
  else if(act==='test'){ beTest(i); }
  else if(act==='ok'){
    const p=BE.profiles[i], v=id=>document.getElementById(id);
    try{
      const u=beParse(v('be-e-url').value);
      p.name=(v('be-e-name').value.trim()||u.host).slice(0,40);
      p.scheme=u.scheme; p.host=u.host; p.port=u.port;
      p.verify_tls=v('be-e-tls').checked;
      p.health_path=(v('be-e-hp').value.trim()||u.path||'/');
      p.match_hosts=v('be-e-mh').value.split(/[,\s]+/).map(x=>x.trim().toLowerCase()).filter(Boolean);
      const lpv=v('be-e-lp').value.trim();
      if(lpv && (!/^\d+$/.test(lpv) || +lpv<1 || +lpv>65535)) throw new Error('専用の待受ポートは 1〜65535 の数字で指定してください(空欄=専用ポートなし)');
      p.listen_port=lpv?+lpv:0;
      const ppv=v('be-e-pp').value.trim();
      if(ppv && !ppv.startsWith('/')) throw new Error('パス振り分けは / から始めて指定してください(例: /shop)');
      p.path_prefix=(ppv==='/'?'':ppv.replace(/\/+$/,'')); p.strip_prefix=v('be-e-sp').checked;
      if(p.path_prefix && p.listen_port) throw new Error('パス振り分けと専用の待受ポートは同時に指定できません');
      p.stopped=v('be-e-stop').checked; p.color=v('be-e-color').value;
      if(v('be-e-org')) p.org=v('be-e-org').value;
      p.xf_host=v('be-e-xfh').checked; p.xf_proto=v('be-e-xfp').checked; p.xf_for=v('be-e-xff').checked;
      p.host_header=v('be-e-hh').value; delete p._new; BE_OPEN=null; beRender();
      beMsg(i,'','※「保存して適用」を押すと反映されます');
    }catch(e){ beMsg(i,'ng','✗ '+esc(e.message)); }
  }
}
function beOrgList(){ return (AUTH.user&&AUTH.user.role==='admin')?(AUTH.orgs||[]):(AUTH.scopeOrgs||[]); }
function beOrgLabel(id){ const o=beOrgList().find(x=>x.id===id); return o?o.name:(id||'未割り当て'); }
function beAdd(){
  BE.profiles.push({id:'tmp-'+(++BE_N),org:(AUTH.analyst?((AUTH.scopeOrgs||[])[0]||{}).id:(AUTH.user&&AUTH.user.role!=='admin'&&AUTH.user.org))||'',stopped:false,name:'新しいバックエンド',scheme:'https',host:'example.com',port:443,verify_tls:true,
                    health_path:'/',match_hosts:[],host_header:'target',listen_port:0,_new:true});
  BE_OPEN=BE.profiles.length-1; beRender(); beFocusEditor();
}
function beFocusEditor(){ setTimeout(()=>{ const e=document.querySelector('.be-edit'); if(e) e.scrollIntoView({block:'start',behavior:'smooth'}); },30); }

/* 設定モーダル */
const RULE_LABEL={xss:'XSS',sqli:'SQLi',traversal:'パストラバーサル',cmdi:'コマンドインジェクション'};
function sw(id, on){ return `<label class="sw"><input type="checkbox" id="${id}" ${on?'checked':''}><span class="track"><span class="knob"></span></span></label>`; }
function row(label, sub, control){ return `<div class="set-row"><div class="lbl">${label}${sub?`<small>${sub}</small>`:''}</div>${control}</div>`; }

let BE_LOGDEL=[];
function openSettings(){
  BE_LOGDEL=[];
  const body=document.getElementById('sBody');
  body.innerHTML='<div class="empty">読み込み中…</div>';
  fetch('/api/config').then(r=>r.json()).then(cfg=>{ buildSettings(cfg); })
    .catch(()=>{ body.innerHTML='<div class="empty">設定の取得に失敗しました。</div>'; });
}
function buildSettings(cfg){
  const e=cfg.editable, ro=cfg.readonly||{}, LIM=!!cfg.limited||!!cfg.analyst, ANA=!!cfg.analyst;
  if(ANA) AUTH.scopeOrgs=cfg.scope_orgs||[];
  let h='';
  h+=`<div class="set-note">${ANA?'担当範囲の組織のバックエンドを追加・編集できます。防御ルール・通知・ユーザーや組織の管理は管理者のみの設定です。':LIM?'所属組織のバックエンドの状態を確認できます(稼働停止・編集・削除・防御モードやIPブロックの変更は、管理者・アナリストに依頼してください)。':esc(cfg.note||'')}</div>`;

  // 動作モード
  if(!LIM){
  h+='<div class="set-group"><h4>動作モード</h4>';
  h+=row('モード','block=遮断 / detect=監視のみ',
    `<div class="seg" id="seg-mode">
       <button data-v="block" class="${e.mode==='block'?'on block':''}">block</button>
       <button data-v="detect" class="${e.mode==='detect'?'on detect':''}">detect</button>
     </div>`);
  h+='</div>';
  }

  // 防御するバックエンド(転送先)
  if(e.backend){
    h+='<div class="set-group"><h4>防御するバックエンド(転送先)</h4>';
    h+=`<div class="set-note" style="margin:0 0 4px">WAFが守る相手(Webサイト/アプリ)を登録します。専用ポートやホスト名の指定がないアクセス(メインの待受ポート)は、一覧の一番上のバックエンドへ転送されます。ローカル(127.0.0.1)・LAN内(192.168.x.x など)・インターネット上のサイト(https://example.com)のどれも指定できます。「保存して適用」で即時に切り替わります(再起動は不要)。</div>`;
    h+=`<div class="set-note" style="margin:0 0 6px"><b>複数を同時に防御するには</b>: (1) バックエンドごとに「専用の待受ポート」を決める(例: 本番アプリ=8080、社内Wiki=8081、外部サイト=8082)。(2) または「ホスト名で振り分ける」をONにして、1つのポートでホスト名ごとに分ける。両方の併用もできます。ログはバックエンドごとに「イベントログ」で絞り込めます。</div>`;
    h+='<div id="beList"></div><div class="set-note" id="beStaged" style="margin:6px 0 0;color:var(--detect)"></div>';
    if(!LIM||(ANA&&(AUTH.scopeOrgs||[]).length)) h+='<div class="set-foot" style="margin-top:8px"><button type="button" id="beAdd">＋ バックエンドを追加</button></div>';
    if(!LIM) h+=row('ホスト名で振り分ける','ON: アクセスされたホスト名(各バックエンドの「振り分けホスト名」)ごとに別のバックエンドへ転送。一致しなければ一覧の先頭のバックエンドへ。ホスト名をこのPCに向けるDNS/hostsの設定は別途必要', sw('s-berout', e.backend.host_routing));
    if(!LIM) h+=row('リンクをWAF経由に書き換える','別ドメインのサイトを守るとき、リダイレクト・Cookie・ページ内の元サイトURLをWAFのアドレスに書き換えて、リンクをたどってもWAFを通るようにします', sw('s-berw', e.backend.rewrite_links!==false));
    h+='</div>';
  }

  // ルール
  if(!LIM){
  h+='<div class="set-group"><h4>検知ルール(カテゴリ別)</h4>';
  Object.keys(e.rules||{}).forEach(k=>{
    h+=row(CAT_LABEL[k]||k, null, sw('r-'+k, !!(e.rules||{})[k]));
  });
  h+=`<div class="set-foot" style="margin-top:4px"><button id="openRules" style="background:var(--surface-2);color:var(--ink)">ルール単位の詳細設定を開く…</button></div>`;
  h+='</div>';

  // レスポンス/レート
  h+='<div class="set-group"><h4>防御オプション</h4>';
  h+=row('セキュリティヘッダ付与','CSP / X-Frame-Options 等', sw('s-sec', e.security_headers_enabled));
  h+=row('レート制限', null, sw('s-rl', e.rate_limit.enabled));
  h+=row('　上限リクエスト数','window 秒あたり',
    `<input type="number" id="s-rlmax" min="1" max="100000" value="${e.rate_limit.max_requests}">`);
  h+=row('　ウィンドウ(秒)', null,
    `<input type="number" id="s-rlwin" min="1" max="86400" value="${e.rate_limit.window_seconds}">`);
  h+=row('　超過時の動作','drop=無応答で切断(DDoS対策) / 429=応答',
    `<div class="seg" id="seg-rlact">
       <button data-v="drop" class="${e.rate_limit.action==='drop'?'on block':''}">drop</button>
       <button data-v="429" class="${e.rate_limit.action!=='drop'?'on':''}">429</button>
     </div>`);
  h+=row('　自動BAN発動回数','window内の違反がこの回数で自動BAN(0=無効)',
    `<input type="number" id="s-banth" min="0" max="100000" value="${e.rate_limit.ban_threshold}">`);
  h+=row('　BAN継続(秒)', null,
    `<input type="number" id="s-bansec" min="1" max="86400" value="${e.rate_limit.ban_seconds}">`);
  h+=row('　バースト上限','短時間(下記秒)でこの数を超えたら即BAN(0=無効)',
    `<input type="number" id="s-burst" min="0" max="100000" value="${e.rate_limit.burst_max||0}">`);
  h+=row('　バースト判定窓(秒)', null,
    `<input type="number" id="s-burstsec" min="1" max="60" value="${e.rate_limit.burst_seconds||3}">`);
  h+=row('　全体上限(req/s)','全IP合計がこれを超えたら超過分をdrop(0=無効)',
    `<input type="number" id="s-grps" min="0" max="1000000" value="${e.rate_limit.global_max_rps||0}">`);
  h+=row('　再犯でBAN延長','違反を繰り返すほどBANを自動的に長く', sw('s-escal', e.rate_limit.ban_escalate!==false));
  h+=row('　IPごと同時接続数上限','Slowloris等の接続枯渇対策。accept段階で拒否(0=無効)',
    `<input type="number" id="s-maxconn" min="0" max="100000" value="${e.rate_limit.max_conn_per_ip||0}">`);
  h+=row('　全体同時接続数上限','スレッド枯渇対策。全接続合計がこれを超えたらaccept段階で拒否(0=無効)',
    `<input type="number" id="s-maxtotal" min="0" max="1000000" value="${e.rate_limit.max_total_conn||0}">`);
  h+=row('　接続頻度の上限(回)','窓の秒数内の接続試行がこれを超えたら握手の前にBAN。TLS握手/接続だけのフラッド対策(0=無効)',
    `<input type="number" id="s-cburst" min="0" max="1000000" value="${e.rate_limit.conn_burst_max||0}">`);
  h+=row('　接続頻度の判定窓(秒)', null,
    `<input type="number" id="s-cburstsec" min="1" max="600" value="${e.rate_limit.conn_burst_seconds||5}">`);
  h+=row('　接続タイムアウト(秒)','低速/アイドル接続を打ち切る。Slowlorisの遅延送信対策(0=無効)',
    `<input type="number" id="s-ctimeout" min="0" max="600" value="${e.conn_timeout_seconds!=null?e.conn_timeout_seconds:20}">`);
  h+='</div>';

  // ログ/IP
  h+='<div class="set-group"><h4>ログ / 送信元IP</h4>';
  h+=row('通過(PASS)も記録','access_log', sw('s-acc', e.access_log));
  h+=row('リクエスト詳細を記録','クエリ・ヘッダ・ボディ', sw('s-det', e.log_request_detail));
  h+=row('PASSのボディも記録','GET/POST。資格情報に注意', sw('s-pb', e.log_pass_body));
  h+=row('レスポンスも記録','status/ヘッダ/ボディ(Burp風)', sw('s-rsp', e.log_response));
  h+=row('ログ詳細の暗号化','ヘッダ・Cookie・ボディ・クエリを、組織ごとの公開鍵で暗号化して保存します。鍵の登録・ON/OFF・復号は「🔐 暗号ログ」タブ(キー・オフィサー)で管理します', `<button type="button" class="cp" onclick="showPage('enc')">暗号ログを開く</button>`);
  h+=row('送信元を必ずグローバルIPに','ON=LAN/内部も「WAFホストの出口IP」で地図化(内部は全員同じIPに集約)。OFF=内部は各自のLAN IPで区別(外部クライアントは常に実IPでジオ表示)', sw('s-gip', e.log_global_ip));
  h+=row('X-Forwarded-For を信頼','信頼プロキシ背後のみON(偽装注意)', sw('s-xff', e.trust_xforwarded_for));
  h+=row('出口IP更新間隔(秒)','WAFホスト自身のVPN/回線切替への追従(訪問者のVPNではなくWAF機の出口IP)',
    `<input type="number" id="s-ttl" min="5" max="3600" value="${e.self_ip_ttl}">`);
  h+='</div>';

  // 攻撃アラート
  const al=e.alert||{enabled:true,sound:false,immediate:'critical',threshold:5,window:10,critical:100,hold:2,position:'top',bg:true};
  h+='<div class="set-group"><h4>攻撃アラート(警報バナー)・全体の既定</h4>';
  h+='<div class="set-note" style="margin:0 0 6px">ここは全ユーザー共通の既定値です。各ユーザーは「アカウント」タブで自分用に変更できます(変更した人だけ、この既定より優先されます)。</div>';
  h+=row('攻撃アラートを表示','全ユーザーの大元のスイッチです。オフにすると、各ユーザーの個人設定にかかわらず、誰の画面にも警報バナーを出しません(オンのときだけ、各ユーザーが自分用にオフにできます)', sw('s-alon', al.enabled));
  h+=row('　表示する位置','警報バナーを画面の上だけに出すか、上下の両方に出すか', `<select id="s-alpos">${[['top','上部のみ'],['both','上部と下部の両方']].map(([v,l])=>`<option value="${v}" ${(al.position||'top')===v?'selected':''}>${l}</option>`).join('')}</select>`);
  h+=row('　背景の六角形','警報中、画面の背景に六角形(EMERGENCY)をランダムに回転させて表示', sw('s-albg', al.bg!==false));
  h+=row('　警報音','画面を一度クリックした後から鳴ります(ブラウザの制限)', sw('s-alsnd', al.sound));
  h+=row('　1件でも表示する深刻度','この深刻度以上のルール(SQLi/XSS等)に当たった攻撃は、1回でもすぐ表示。それ未満は下の件数に達したら表示',
    `<select id="s-alimm">
       <option value="critical" ${(al.immediate||'critical')==='critical'?'selected':''}>危険(critical)のみ</option>
       <option value="high" ${al.immediate==='high'?'selected':''}>高(high)以上</option>
       <option value="medium" ${al.immediate==='medium'?'selected':''}>中(medium)以上</option>
       <option value="off" ${al.immediate==='off'?'selected':''}>使わない(件数だけで判定)</option>
     </select>`);
  h+=row('　「警戒」を出す件数','上の深刻度に満たない攻撃や、レート制限系は、判定秒数のあいだにこの件数に達したら表示',
    `<input type="number" id="s-althr" min="1" max="100000" value="${al.threshold}">`);
  h+=row('　判定する秒数', null, `<input type="number" id="s-alwin" min="1" max="300" value="${al.window}">`);
  h+=row('　「緊急」に格上げする件数','この件数に達したら「緊急」表示(0=格上げしない)',
    `<input type="number" id="s-alcrit" min="0" max="1000000" value="${al.critical}">`);
  h+=row('　攻撃が止んでから消すまで(秒)','この秒数のあいだ攻撃が来なければバナーを自動で消す',
    `<input type="number" id="s-alhold" min="1" max="3600" value="${al.hold}">`);
  h+=row('　見た目の確認','保存しなくても試せます(9秒で消えます)',
    `<span><button type="button" class="lf-clr" data-alt="warn|intrusion">警戒(不正アクセス)</button> <button type="button" class="lf-clr" data-alt="warn|flood">警戒(大量アクセス)</button> <button type="button" class="lf-clr" data-alt="crit|intrusion">緊急(大規模攻撃)</button> <button type="button" class="lf-clr" data-alt="crit|flood">緊急(DoS)</button></span>`);
  h+='</div>';

  // 追加の防御(self_made_waf 由来)
  const x=e.extra||{};
  if(e.extra){
    const ab=x.autoban||{}, sb=x.slow_ban||{}, cb=x.connlimit_ban||{}, ri=x.response_inspection||{}, wh=x.webhook||{};
    h+='<div class="set-group"><h4>追加の防御(自動BAN / Slowloris / 応答検査 / Webhook)</h4>';
    h+=row('攻撃の繰り返しで自動BAN','検知(BLOCK/DETECT)が窓の秒数内にこの回数に達した送信元をBAN。detectモードではBANせず記録のみ', sw('x-ab', ab.enabled!==false));
    h+=row('　しきい値(回)', null, `<input type="number" id="x-abth" min="1" max="100000" value="${ab.threshold||10}">`);
    h+=row('　判定窓(秒)', null, `<input type="number" id="x-abwin" min="1" max="86400" value="${ab.window_seconds||60}">`);
    h+=row('　BAN継続(秒)','低速接続/同時接続上限によるBANもこの秒数(再犯で延長)', `<input type="number" id="x-absec" min="1" max="2592000" value="${ab.ban_seconds||300}">`);
    h+=row('低速接続の繰り返しでBAN','ヘッダ/ボディの締め切り超過(Slowloris・Slow POST)', sw('x-sb', sb.enabled!==false));
    h+=row('　しきい値(回) / 判定窓(秒)', null, `<span><input type="number" id="x-sbth" min="1" max="100000" value="${sb.threshold||10}" style="width:70px"> / <input type="number" id="x-sbwin" min="1" max="86400" value="${sb.window_seconds||60}" style="width:70px"></span>`);
    h+=row('同時接続上限の超過を繰り返したらBAN', null, sw('x-cb', cb.enabled!==false));
    h+=row('　しきい値(回) / 判定窓(秒)', null, `<span><input type="number" id="x-cbth" min="1" max="100000" value="${cb.threshold||5}" style="width:70px"> / <input type="number" id="x-cbwin" min="1" max="86400" value="${cb.window_seconds||60}" style="width:70px"></span>`);
    h+=row('ヘッダ受信の締め切り(秒)','1バイト目からこの秒数でヘッダが揃わなければ低速接続として切断(0=無効)', `<input type="number" id="x-ht" min="0" max="600" value="${x.header_timeout_seconds!=null?x.header_timeout_seconds:10}">`);
    h+=row('ボディ受信の締め切り(秒)','Slow POST 対策(0=無効)', `<input type="number" id="x-bt" min="0" max="3600" value="${x.body_timeout_seconds!=null?x.body_timeout_seconds:30}">`);
    h+=row('ボディの上限(MB)','超えたら 413(0=無制限)', `<input type="number" id="x-mb" min="0" max="16384" step="0.5" value="${x.max_body_bytes!=null?Math.round(x.max_body_bytes/104857.6)/10:10}">`);
    h+=row('応答の Stored XSS 検査','バックエンドが返すHTMLに埋め込まれた攻撃スクリプトを、sanitize=無害化 / block=403 / monitor=記録のみ。detectモードでは常に記録のみ',
      `<select id="x-ri">${['sanitize','block','monitor','off'].map(v=>`<option value="${v}" ${(ri.action||'sanitize')===v?'selected':''}>${{sanitize:'無害化(sanitize)',block:'遮断(block)',monitor:'記録のみ(monitor)',off:'無効(off)'}[v]}</option>`).join('')}</select>`);
    h+=row('Webhook URL','BLOCK/DETECT/RATELIMIT のイベントを JSON で POST(空=無効)', `<input type="text" id="x-wh" value="${esc(wh.url||'')}" placeholder="https://example.com/waf-events" style="width:260px">`);
    h+=row('　通過(PASS)も送る', null, sw('x-whp', !!wh.send_pass));
    h+=row('信頼する逆プロキシ','ここからの接続は X-Forwarded-For を右からたどって送信元を判定(カンマ区切り。nginx 等の背後に置くとき)', `<input type="text" id="x-tp" value="${esc((x.trusted_proxies||[]).join(', '))}" placeholder="例: 127.0.0.1, 10.0.0.0/8" style="width:260px">`);
    if(ro.webhook){ h+=`<div class="set-note">Webhook 送信: 成功 ${ro.webhook.sent} / 失敗 ${ro.webhook.failed}${ro.webhook.last_error?' (直近のエラー: '+esc(ro.webhook.last_error)+')':''}</div>`; }
    h+='</div>';
  }

  // 攻撃マップ
  h+='<div class="set-group"><h4>攻撃マップ</h4>';
  h+=row('ジオロケーション', null, sw('s-geo', e.geo));
  h+=row('内部IPを出口IPで地図化', null, sw('s-egr', e.egress));
  h+='</div>';

  }

  // ログの管理(バックエンド別に削除)
  if(!LIM) h+='<div class="set-group"><h4>ログの管理(バックエンド別に削除)</h4><div id="logMgr" class="empty">読み込み中…</div></div>';

  // 読み取り専用(再起動が必要)
  if(!LIM){
  h+='<div class="set-group"><h4>再起動が必要な項目(変更不可)</h4>';
  h+=`<div class="set-ro"><span>待受</span><code>${esc(ro.listen||'')}</code></div>`;
  h+=`<div class="set-ro"><span>転送先</span><code>${esc(ro.backend||'')}</code></div>`;
  h+=`<div class="set-ro"><span>ダッシュボード</span><code>${esc(ro.dashboard||'')}</code></div>`;
  h+=`<div class="set-ro"><span>管理画面の認証</span><code>${ro.admin_auth?'パスワードあり':'なし(dashboard.password / --admin-password / WAF_ADMIN_PASSWORD で設定)'}</code></div>`;
  if(ro.geoip_offline!=null) h+=`<div class="set-ro"><span>国判定(GeoIP)</span><code>${ro.geoip_offline?'オフラインDB(GeoLite2)':'外部API(ipinfo.io / ip-api.com)'}</code></div>`;
  h+='</div>';
  }

  // 自分の警報バナー設定(全員)
  if(AUTH.user&&AUTH.user.username) h+=alertMineHtml();
  // アカウント
  if(AUTH.user) h+=accountHtml();
  if(AUTH.user&&AUTH.user.role==='admin') h+='<div class="set-group"><h4>組織の登録・編集</h4><div class="set-note" style="margin:0 0 8px">提供元 / 直接契約 / 中間企業 / エンドユーザー企業の登録・編集、接続先の所属、ログの保存期間と書き出しをここで行います(この画面の操作は、その場で保存されます)。</div><div id="orgBody"><div class="hempty">読み込み中…</div></div></div>';

  h+=`<div class="set-foot"><button id="s-save">保存して適用</button>
      <span class="msg" id="s-msg">${cfg.hot_reload?'':'※単体起動のため反映にはWAF再起動が必要です'}</span></div>`;
  document.getElementById('sBody').innerHTML=h;
  tabifySettings();
  if(document.getElementById('orgBody')) loadOrgs();

  // モード切替セグメント
  document.querySelectorAll('#seg-mode button').forEach(b=>{
    b.onclick=()=>{ document.querySelectorAll('#seg-mode button').forEach(x=>x.className='');
      b.className='on '+b.dataset.v; };
  });
  document.querySelectorAll('#seg-rlact button').forEach(b=>{
    b.onclick=()=>{ document.querySelectorAll('#seg-rlact button').forEach(x=>x.className='');
      b.className='on '+(b.dataset.v==='drop'?'block':''); };
  });
  document.getElementById('s-save').onclick=saveSettings;
  if(e.backend){ beInit(e.backend, ro); beRender(); document.getElementById('beList').onclick=beClick; if(document.getElementById('beAdd')) document.getElementById('beAdd').onclick=beAdd;
    if(window.__beEditId){ const k=BE.profiles.findIndex(p=>p.id===window.__beEditId); window.__beEditId=null;
      if(k>=0){ BE_OPEN=k; beRender(); const it=document.querySelector(`.be-item[data-i="${k}"]`); if(it&&it.scrollIntoView) it.scrollIntoView({block:'center'}); } } }
  loadLogMgr();
  alertMineBind();
  document.querySelectorAll('[data-alt]').forEach(b=>{ b.onclick=()=>{ const [lv,kind]=b.dataset.alt.split('|'); alPreview(lv,kind); }; });
  { const orl=document.getElementById('openRules'); if(orl) orl.onclick=()=>showPage('rules'); }
  if(AUTH.user) accountInit();
}
function readExtra(){
  const v=id=>document.getElementById(id);
  if(!v('x-ab')) return undefined;
  const n=(id,d)=>{ const x=parseFloat(v(id).value); return isNaN(x)?d:x; };
  return {
    autoban:{enabled:v('x-ab').checked, threshold:n('x-abth',10), window_seconds:n('x-abwin',60), ban_seconds:n('x-absec',300)},
    slow_ban:{enabled:v('x-sb').checked, threshold:n('x-sbth',10), window_seconds:n('x-sbwin',60)},
    connlimit_ban:{enabled:v('x-cb').checked, threshold:n('x-cbth',5), window_seconds:n('x-cbwin',60)},
    header_timeout_seconds:n('x-ht',10), body_timeout_seconds:n('x-bt',30),
    max_body_bytes:Math.round(n('x-mb',10)*1048576),
    response_inspection:{action:v('x-ri').value},
    webhook:{url:v('x-wh').value.trim(), send_pass:v('x-whp').checked},
    trusted_proxies:v('x-tp').value,
  };
}
/* アカウント(パスワード変更、管理者はユーザー管理) */
function alertMineHtml(){
  const al=Object.assign({},AL.gcfg||AL_DEF,(AUTH.user&&AUTH.user.alert)||{}), mine=!!(AUTH.user.alert&&Object.keys(AUTH.user.alert).length);
  const num=(id,v,mn,mx)=>`<input type="number" id="${id}" min="${mn}" max="${mx}" value="${v}">`;
  let h='<div class="set-group"><h4>アカウントの表示設定(攻撃アラートの警報バナー)</h4><div class="acc-box" style="max-width:none">';
  h+=`<div class="set-note" style="margin:0 0 6px">この警報バナーの設定は<b>あなたの画面だけ</b>に効きます(他のユーザーには影響しません)。${mine?'いまは自分用の設定を使っています。':'いまは全体の既定の設定を使っています。'}変更するとすぐ保存されます。</div></div>`;
  h+=row('攻撃アラートを表示','攻撃を検知したら警報バナーを出す(管理者が全体でオフにしているときは使えません)', sw('m-alon', al.enabled));
  h+=row('　表示する位置','警報バナーを画面の上だけに出すか、上下の両方に出すか(全体の既定: '+((AL.gcfg||AL_DEF).position==='both'?'上部と下部の両方':'上部のみ')+')', `<select id="m-alpos">${[['top','上部のみ'],['both','上部と下部の両方']].map(([v,l])=>`<option value="${v}" ${(al.position||'top')===v?'selected':''}>${l}</option>`).join('')}</select>`);
  h+=row('　背景の六角形','警報中、画面の背景に六角形(EMERGENCY)をランダムに回転させて表示', sw('m-albg', al.bg!==false));
  h+=row('　警報音','画面を一度クリックした後から鳴ります(ブラウザの制限)', sw('m-alsnd', al.sound));
  h+=row('　1件でも表示する深刻度','この深刻度以上のルールに当たった攻撃は、1回でもすぐ表示。それ未満は下の件数に達したら表示',
    `<select id="m-alimm">${[['critical','危険(critical)のみ'],['high','高(high)以上'],['medium','中(medium)以上'],['off','使わない(件数だけで判定)']].map(([v,l])=>`<option value="${v}" ${(al.immediate||'critical')===v?'selected':''}>${l}</option>`).join('')}</select>`);
  h+=row('　「警戒」を出す件数','判定秒数のあいだにこの件数に達したら表示', num('m-althr',al.threshold,1,100000));
  h+=row('　判定する秒数', null, num('m-alwin',al.window,1,300));
  h+=row('　「緊急」に格上げする件数','この件数に達したら「緊急」表示(0=格上げしない)', num('m-alcrit',al.critical,0,1000000));
  h+=row('　攻撃が止んでから消すまで(秒)','この秒数のあいだ攻撃が来なければバナーを自動で消す', num('m-alhold',al.hold,1,3600));
  h+=row('　見た目の確認','保存しなくても試せます(9秒で消えます)',
    `<span><button type="button" class="lf-clr" data-alt="warn|intrusion">警戒(不正アクセス)</button> <button type="button" class="lf-clr" data-alt="warn|flood">警戒(大量アクセス)</button> <button type="button" class="lf-clr" data-alt="crit|intrusion">緊急(大規模攻撃)</button> <button type="button" class="lf-clr" data-alt="crit|flood">緊急(DoS)</button></span>`);
  h+=row('　','<span class="seemore" id="m-almsg"></span>',`<span><button type="button" class="lf-clr" id="m-alreset">全体の既定に戻す</button></span>`);
  return h+'</div>';
}
function alertMineBind(){
  const g=i=>document.getElementById(i); if(!g('m-alon')) return;
  if(!(AL.gcfg||AL_DEF).enabled){ g('m-alon').checked=false; g('m-alon').disabled=true; g('m-almsg').textContent='管理者が全体で攻撃アラートをオフにしているため、いまは表示されません(この項目は変更できません)'; }
  const save=()=>{
    const all={enabled:!!g('m-alon').checked,sound:!!g('m-alsnd').checked,immediate:g('m-alimm').value,position:g('m-alpos').value,bg:!!g('m-albg').checked,threshold:g('m-althr').value,window:g('m-alwin').value,critical:g('m-alcrit').value,hold:g('m-alhold').value};
    // 全体の既定と同じ値の項目は保存しない。その項目は全体の既定に従い、管理者が既定を変えると一緒に変わる
    const gc=AL.gcfg||AL_DEF, a={}; Object.keys(all).forEach(k=>{ if(String(all[k])!==String(gc[k])) a[k]=all[k]; });
    postJSON('/api/users',{action:'set_alert',alert:a}).then(r=>{
      if(!r.ok){ g('m-almsg').textContent='エラー: '+(r.error||'失敗'); return; }
      return fetch('/api/auth').then(x=>x.json()).then(x=>{ AUTH.user=x.user||AUTH.user; alMerge(); g('m-almsg').textContent='✓ 保存しました'; });
    }).catch(()=>{ g('m-almsg').textContent='通信エラー'; });
  };
  ['m-alon','m-alsnd','m-albg','m-alpos','m-alimm','m-althr','m-alwin','m-alcrit','m-alhold'].forEach(i=>g(i).addEventListener('change',save));
  g('m-alreset').onclick=()=>{ postJSON('/api/users',{action:'set_alert',reset:true}).then(r=>{
    if(!r.ok){ g('m-almsg').textContent='エラー: '+(r.error||'失敗'); return; }
    return fetch('/api/auth').then(x=>x.json()).then(x=>{ AUTH.user=x.user||AUTH.user; alMerge(); const c=AL.cfg; g('m-alon').checked=!!c.enabled; g('m-alsnd').checked=!!c.sound; g('m-alimm').value=c.immediate; g('m-alpos').value=c.position||'top'; g('m-albg').checked=c.bg!==false; g('m-althr').value=c.threshold; g('m-alwin').value=c.window; g('m-alcrit').value=c.critical; g('m-alhold').value=c.hold; g('m-almsg').textContent='✓ 全体の既定に戻しました'; }); }); };
}
function accountHtml(){
  const u=AUTH.user, adm=u.role==='admin';
  let h='<div class="set-group"><h4>アカウント</h4><div class="acc-box">';
  h+=`<div class="set-note" style="margin:0 0 6px">ログイン中: <b>${esc(u.display||u.username)}</b>(${esc(u.username)} / ${adm?'管理者':(u.role==='analyst'?'アナリスト':(u.role==='key_officer'?'キー・オフィサー':'一般ユーザー'))})</div>`;
  h+=`<div class="hsub-title" style="margin-top:4px">パスワードを変更</div><div class="acc-grid">
    <label>現在のパスワード</label><input type="password" id="ac-old" autocomplete="current-password">
    <label>新しいパスワード<small style="display:block;color:var(--ink-muted)">6文字以上</small></label><input type="password" id="ac-new" autocomplete="new-password">
    <label>新しいパスワード(確認)</label><input type="password" id="ac-new2" autocomplete="new-password"></div>
    <button type="button" id="ac-pw" class="lf-clr">パスワードを変更</button><div class="acc-msg" id="ac-pwmsg"></div>`;
  if(adm){
    h+=`<div class="hsub-title" style="margin-top:14px">ユーザー管理</div><div id="ac-users"></div>
    <div class="acc-grid"><label>ユーザー名</label><input type="text" id="ac-nu" maxlength="32" placeholder="英数字 _ . -(2〜32文字)">
    <label>表示名</label><input type="text" id="ac-nd" maxlength="40">
    <label>パスワード</label><input type="password" id="ac-np" autocomplete="new-password">
    <label>権限</label><select id="ac-nr"><option value="user">一般(所属組織のログの閲覧・申請)</option><option value="analyst">アナリスト(担当範囲の閲覧・設定変更・申請の対応)</option><option value="key_officer">キー・オフィサー(設定には触れず、暗号化ログの復号だけ)</option><option value="admin">管理者(提供元・すべて)</option></select>
    <label>所属組織<small style="display:block;color:var(--ink-muted)">一般は必須に近い設定。ベンダー側は「ベンダー」</small></label><select id="ac-no">${'<option value="">(なし)</option>'+(AUTH.orgs||[]).map(o=>`<option value="${esc(o.id)}">${esc(o.name)}</option>`).join('')}</select>
    <label>担当範囲<small style="display:block;color:var(--ink-muted)">アナリスト用。組織IDをカンマ区切り(その下も含む)</small></label><input type="text" id="ac-ns" placeholder="例: x,a">
    <div class="seemore" style="grid-column:1/-1">ベンダー側(提供元のアナリスト・キー・オフィサー)にするときは、所属組織で「ベンダー」を選びます。ベンダー所属のアナリストは担当アナリストのいない組織も担当し、キー・オフィサーは全組織を担当します。</div>
    <button type="button" id="ac-add" class="lf-clr">ユーザーを追加</button><div class="acc-msg" id="ac-umsg"></div>`;
  }
  return h+'</div></div>';
}
function accMsg(id,ok,t){ const el=document.getElementById(id); if(el){ el.className='acc-msg '+(ok?'ok':'ng'); el.textContent=t; } }
function accUsersRender(){
  const el=document.getElementById('ac-users'); if(!el) return;
  el.innerHTML='<table class="acc-tbl"><thead><tr><th>ユーザー</th><th>権限</th><th>所属 / 担当範囲</th><th></th></tr></thead><tbody>'+AUTH.users.map(x=>
    `<tr><td>${esc(x.display)}<small style="color:var(--ink-muted)"> (${esc(x.username)})</small></td><td>${x.role==='admin'?'管理者':(x.role==='analyst'?'アナリスト':(x.role==='key_officer'?'キー・オフィサー':'一般'))}</td>
    <td>${(x.role==='analyst'||x.role==='key_officer')?esc((x.scope||[]).join(', ')||(x.provider?'':'(未割り当て: 何も見えません)'))+(x.provider?(x.role==='key_officer'?'<br><small style="color:var(--accent)">ベンダー側: 全組織を担当</small>':'<br><small style="color:var(--accent)">提供元アナリスト: 担当アナリストのいない組織も担当</small>'):''):esc(x.org||'-')}</td>
    <td><button type="button" data-ac="org" data-u="${esc(x.username)}">所属・範囲</button>${(x.role==='analyst'||x.role==='key_officer')?`<button type="button" data-ac="prov" data-u="${esc(x.username)}">${x.provider?(x.role==='key_officer'?'ベンダー所属を解除':'ベンダー所属を解除'):(x.role==='key_officer'?'ベンダー所属にする(全組織)':'ベンダー所属にする')}</button>`:''}<button type="button" data-ac="pw" data-u="${esc(x.username)}">パスワード再設定</button>${x.username===AUTH.user.username?'':`<button type="button" data-ac="del" data-u="${esc(x.username)}">削除</button>`}</td></tr>`).join('')+'</tbody></table>';
}
function accPost(body){ return postJSON('/api/users',body); }
function accountInit(){
  const v=id=>document.getElementById(id);
  if(v('ac-pw')) v('ac-pw').onclick=async()=>{
    if(v('ac-new').value!==v('ac-new2').value){ accMsg('ac-pwmsg',false,'新しいパスワードが一致しません'); return; }
    try{ const r=await accPost({action:'set_password',old_password:v('ac-old').value,password:v('ac-new').value});
      if(!r.ok) throw new Error(r.error||'失敗'); accMsg('ac-pwmsg',true,'✓ パスワードを変更しました'); v('ac-old').value=v('ac-new').value=v('ac-new2').value=''; }
    catch(e){ accMsg('ac-pwmsg',false,e.message||String(e)); } };
  if(AUTH.user.role!=='admin') return;
  accUsersRender();
  const sync=r=>{ if(r&&r.users){ AUTH.users=r.users; accUsersRender(); } };
  v('ac-add').onclick=async()=>{
    try{ const r=await accPost({action:'add',username:v('ac-nu').value.trim(),display:v('ac-nd').value.trim(),password:v('ac-np').value,role:v('ac-nr').value,org:v('ac-no').value,scope:v('ac-ns').value.split(',').map(x=>x.trim()).filter(Boolean)});
      if(!r.ok) throw new Error(r.error||'失敗'); sync(r); accMsg('ac-umsg',true,'✓ 追加しました'); v('ac-nu').value=v('ac-nd').value=v('ac-np').value=''; }
    catch(e){ accMsg('ac-umsg',false,e.message||String(e)); } };
  v('ac-users').onclick=async ev=>{
    const b=ev.target.closest('button[data-ac]'); if(!b) return; const name=b.dataset.u;
    try{
      if(b.dataset.ac==='del'){
        const c=await askChoice('ユーザーを削除しますか?',`<p>「${esc(name)}」を削除します。このユーザーのバックエンドは、あなたの登録になります。</p>`,[{label:'キャンセル',value:null},{label:'削除する',value:'ok'}]);
        if(!c) return; const r=await accPost({action:'delete',username:name}); if(!r.ok) throw new Error(r.error||'失敗'); sync(r); accMsg('ac-umsg',true,'✓ 削除しました'); }
      else if(b.dataset.ac==='prov'){
        const u=AUTH.users.find(z=>z.username===name)||{};
        const r=await accPost({action:'update',username:name,org:u.provider?'':'vendor'}); if(!r.ok) throw new Error(r.error||'失敗'); sync(r); accMsg('ac-umsg',true,u.provider?'✓ ベンダー所属を解除しました':(u.role==='key_officer'?'✓ ベンダー側(全組織担当)にしました':'✓ 提供元アナリストにしました')); }
      else if(b.dataset.ac==='org'){
        const u=AUTH.users.find(z=>z.username===name)||{};
        if(u.role==='analyst'||u.role==='key_officer'){ const t=prompt(name+' の担当範囲(組織IDをカンマ区切り。空=何も見えない)',(u.scope||[]).join(',')); if(t===null) return;
          const r=await accPost({action:'update',username:name,scope:t.split(',').map(x=>x.trim()).filter(Boolean)}); if(!r.ok) throw new Error(r.error||'失敗'); sync(r); }
        else { const t=prompt(name+' の所属組織ID(空=なし)',u.org||''); if(t===null) return;
          const r=await accPost({action:'update',username:name,org:t.trim()}); if(!r.ok) throw new Error(r.error||'失敗'); sync(r); }
        accMsg('ac-umsg',true,'✓ 更新しました'); }
      else{
        const pw=prompt(name+' の新しいパスワード(6文字以上)'); if(!pw) return;
        const r=await accPost({action:'set_password',username:name,password:pw,force:true}); if(!r.ok) throw new Error(r.error||'失敗'); accMsg('ac-umsg',true,'✓ パスワードを再設定しました'); }
    }catch(e){ accMsg('ac-umsg',false,e.message||String(e)); } };
}
function saveSettings(){
  if(AUTH.limited){
    const msg=document.getElementById('s-msg'); msg.textContent='保存中…';
    const payload={backend:{profiles:BE.profiles.map(p=>({id:p.id,name:p.name,scheme:p.scheme,host:p.host,port:p.port,verify_tls:p.verify_tls,
      org:p.org||'',health_path:p.health_path,match_hosts:p.match_hosts,host_header:p.host_header,listen_port:p.listen_port||0,
      path_prefix:p.path_prefix||'',strip_prefix:p.strip_prefix!==false,stopped:!!p.stopped,color:p.color||'',ip_policy:p.ip_policy,xf_host:p.xf_host!==false,xf_proto:p.xf_proto!==false,xf_for:p.xf_for!==false}))}};
    fetch('/api/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)})
      .then(r=>r.json()).then(res=>{
        if(res.ok){ msg.textContent='✓ 適用しました'; load();
          if(BE_LOGDEL.length){ const ids=BE_LOGDEL.splice(0);
            Promise.all(ids.map(id=>postJSON('/api/logs/delete',{backend:id}))).then(()=>{ reloadAfterLogDelete(); }); }
          if(res.config&&res.config.editable&&res.config.editable.backend){ beInit(res.config.editable.backend, res.config.readonly||{}); beRender(); }
          setTimeout(()=>msg.textContent='',2500); }
        else msg.textContent='エラー: '+(res.error||'失敗');
      }).catch(()=>{ msg.textContent='通信エラー'; });
    return;
  }
  const modeBtn=document.querySelector('#seg-mode button.on');
  const val=id=>document.getElementById(id);
  const rules={};
  document.querySelectorAll('[id^="r-"]').forEach(x=>{ rules[x.id.slice(2)]=x.checked; });
  const payload={
    mode: modeBtn?modeBtn.dataset.v:'block',
    rules,
    security_headers_enabled: val('s-sec').checked,
    rate_limit:{ enabled:val('s-rl').checked,
                 max_requests:parseInt(val('s-rlmax').value||'120',10),
                 window_seconds:parseInt(val('s-rlwin').value||'60',10),
                 action:(document.querySelector('#seg-rlact button.on')||{}).dataset?
                        document.querySelector('#seg-rlact button.on').dataset.v:'drop',
                 ban_threshold:parseInt(val('s-banth').value||'0',10),
                 ban_seconds:parseInt(val('s-bansec').value||'300',10),
                 burst_max:parseInt(val('s-burst').value||'0',10),
                 burst_seconds:parseInt(val('s-burstsec').value||'3',10),
                 global_max_rps:parseInt(val('s-grps').value||'0',10),
                 ban_escalate:val('s-escal').checked,
                 max_conn_per_ip:parseInt(val('s-maxconn').value||'0',10),
                 max_total_conn:parseInt(val('s-maxtotal').value||'0',10),
                 conn_burst_max:parseInt(val('s-cburst').value||'0',10),
                 conn_burst_seconds:parseInt(val('s-cburstsec').value||'5',10) },
    conn_timeout_seconds: parseInt(val('s-ctimeout').value||'20',10),
    access_log: val('s-acc').checked,
    log_request_detail: val('s-det').checked,
    log_pass_body: val('s-pb').checked,
    log_response: val('s-rsp').checked,
    log_global_ip: val('s-gip').checked,
    trust_xforwarded_for: val('s-xff').checked,
    self_ip_ttl: parseInt(val('s-ttl').value||'60',10),
    geo: val('s-geo').checked,
    egress: val('s-egr').checked,
    backend: BE?{ active:(BE.profiles[0]||{}).id||BE.active, host_routing:val('s-berout').checked, rewrite_links:val('s-berw').checked,
                  profiles:BE.profiles.map(p=>({id:p.id,name:p.name,scheme:p.scheme,host:p.host,port:p.port,verify_tls:p.verify_tls,
                    health_path:p.health_path,match_hosts:p.match_hosts,host_header:p.host_header,listen_port:p.listen_port||0,
                    path_prefix:p.path_prefix||'',strip_prefix:p.strip_prefix!==false,stopped:!!p.stopped,owner:p.owner||'',org:p.org||'',color:p.color||'',ip_policy:p.ip_policy,xf_host:p.xf_host!==false,xf_proto:p.xf_proto!==false,xf_for:p.xf_for!==false})) }:undefined,
    extra: readExtra(),
    alert:{ enabled:val('s-alon').checked, sound:val('s-alsnd').checked, immediate:val('s-alimm').value, position:val('s-alpos').value, bg:val('s-albg').checked,
            threshold:parseInt(val('s-althr').value||'5',10), window:parseInt(val('s-alwin').value||'10',10),
            critical:parseInt(val('s-alcrit').value||'0',10), hold:parseInt(val('s-alhold').value||'2',10) },
  };
  const msg=document.getElementById('s-msg');
  msg.textContent='保存中…';
  fetch('/api/config',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify(payload)})
    .then(r=>r.json()).then(res=>{
      if(res.ok){ msg.textContent='✓ 適用しました'; alLoadCfg(); load();
        if(BE_LOGDEL.length){ const ids=BE_LOGDEL.splice(0);
          Promise.all(ids.map(id=>postJSON('/api/logs/delete',{backend:id}))).then(()=>{ reloadAfterLogDelete(); }); }
        if(BE&&res.config&&res.config.editable&&res.config.editable.backend){ beInit(res.config.editable.backend, res.config.readonly); beRender(); } setTimeout(()=>msg.textContent='',2500); }
      else { msg.textContent='エラー: '+(res.error||'失敗'); }
    }).catch(()=>{ msg.textContent='通信エラー'; });
}
/* 検知ルール管理 */
let rulesData=null;
function openRules(){
  loadRulesExtra();
  if(AUTH.analyst) return;
  document.getElementById('rBody').innerHTML='<div class="empty">読み込み中…</div>';
  fetch('/api/rules').then(r=>r.json()).then(d=>{ rulesData=d; initRulesFilters(); renderRules(); })
    .catch(()=>{ document.getElementById('rBody').innerHTML='<div class="empty">取得に失敗</div>'; });
}

function loadRulesExtra(light){
  if(!light){
    fetch('/api/backend-rules',{cache:'no-store'}).then(r=>r.json()).then(renderBeRules).catch(()=>{});
    fetch('/api/rules/catalog',{cache:'no-store'}).then(r=>r.ok?r.json():null).then(c=>{ if(c){ BER.cat=c; berRulesRender(); } }).catch(()=>{});
  }
  fetch('/api/rule-history',{cache:'no-store'}).then(r=>r.ok?r.json():null).then(d=>{ if(d) renderRuleHist(d); }).catch(()=>{});
  if(AUTH.analyst) return;
  fetch('/api/custom-rules',{cache:'no-store'}).then(r=>r.json()).then(renderCustom).catch(()=>{});
}
/* 組織・保存期間(管理者) */
let ORGS={orgs:[],backends:[],types:{},users:[]};
function loadOrgs(){ return fetch('/api/orgs',{cache:'no-store'}).then(r=>r.ok?r.json():null).then(d=>{ if(d&&d.orgs){ ORGS=d; AUTH.orgs=d.orgs; renderOrgs(); } }).catch(()=>{}); }
function orgOp(o,done){ postJSON('/api/orgs',o).then(r=>{ if(r.ok){ ORGS=r; AUTH.orgs=r.orgs; renderOrgs(); if(done) done(r); } else alert('エラー: '+(r.error||'失敗')); }); }
function orgName(id){ const o=(ORGS.orgs||[]).find(x=>x.id===id); return o?o.name+' ('+o.id+')':(id||'未割り当て'); }
function renderOrgs(){
  const el=document.getElementById('orgBody'); if(!el) return;
  const T=ORGS.types||{}; const os=ORGS.orgs||[];
  const parentOpts='<option value="">(最上位)</option>'+os.filter(o=>o.type==='intermediary').map(o=>`<option value="${esc(o.id)}">${esc(o.name)}</option>`).join('');
  const orgOpts=sel=>'<option value="">未割り当て</option>'+os.map(o=>`<option value="${esc(o.id)}" ${o.id===sel?'selected':''}>${esc(o.name)} (${esc(T[o.type]||o.type)})</option>`).join('');
  el.innerHTML=`<table class="org-tbl"><thead><tr><th>組織(表示名)</th><th>種類</th><th>親(中間企業)</th><th>通過を含む個別ログの保存(日)</th><th>攻撃のまとめの保存(日)</th><th></th></tr></thead><tbody>`+
    (os.map(o=>`<tr><td><input size="16" id="org-nm-${esc(o.id)}" value="${esc(o.name)}" maxlength="60"> <small class="seemore">${esc(o.id)}</small></td>
      <td><select id="org-ty-${esc(o.id)}" ${o.type==='vendor'?'disabled':''}>${(o.type==='vendor'?['vendor']:['direct','intermediary','enduser']).map(t=>`<option value="${t}" ${t===o.type?'selected':''}>${esc(T[t]||t)}</option>`).join('')}</select></td>
      <td><select id="org-pa-${esc(o.id)}"><option value="">-</option>${os.filter(x=>x.type==='intermediary'&&x.id!==o.id).map(x=>`<option value="${esc(x.id)}" ${x.id===o.parent?'selected':''}>${esc(x.name)}</option>`).join('')}</select></td>
      <td><input size="5" id="org-ret-${esc(o.id)}" value="${o.retention_days||''}" placeholder="${ORGS.default_retention_days||30}"></td>
      <td><input size="5" id="org-reta-${esc(o.id)}" value="${o.retention_attack_days||''}" placeholder="${ORGS.default_attack_retention_days||180}"> <button onclick="orgSaveRet('${esc(o.id)}')">保存</button></td>
      <td><button onclick="orgEdit('${esc(o.id)}')">名前・種類を保存</button> <button onclick="orgExport('${esc(o.id)}')">ログを書き出す</button> ${o.type==='vendor'?'':`<button onclick="orgDel('${esc(o.id)}')">削除</button>`}</td></tr>`).join('')||'<tr><td colspan="7" class="seemore">まだ組織がありません</td></tr>')+`</tbody></table>
    <div class="org-form"><b>組織を追加</b><input id="oa-id" placeholder="ID(英小文字・数字・-)" maxlength="32"><input id="oa-name" placeholder="表示名">
      <select id="oa-type"><option value="direct">直接契約</option><option value="intermediary">中間企業</option><option value="enduser">エンドユーザー企業</option></select>
      <select id="oa-parent">${parentOpts}</select><button onclick="orgAdd()">追加</button></div>
    <div class="hsub-title">接続先(バックエンド)の所属と保存期間 <span class="seemore">接続先は組織に紐づきます。組織に属さないものは管理者だけが見られ、ログも自動削除しません</span></div>
    <table class="org-tbl"><thead><tr><th>バックエンド</th><th>所属組織</th><th>通過を含む個別ログの保存(日・空=組織に従う)</th></tr></thead><tbody>`+
    (ORGS.backends||[]).map(b=>`<tr><td>${esc(b.name)}</td>
      <td><select onchange="orgOp({op:'assign_backend',backend:'${esc(b.id)}',org:this.value})">${orgOpts(b.org)}</select></td>
      <td><input size="5" id="bret-${esc(b.id)}" value="${b.retention_days||''}"> <button onclick="orgBeRet('${esc(b.id)}')">保存</button>
        <small class="seemore">${b.retention_effective?('実際: 通過を含む'+b.retention_effective+'日 / 攻撃のまとめ'+(b.attack_retention_effective||'-')+'日'):'自動削除なし'}</small></td></tr>`).join('')+`</tbody></table>
    <div class="org-form"><button onclick="orgPrune()">期限切れのログを今すぐ削除</button><span class="seemore" id="orgMsg">(1日1回、自動でも実行します)</span></div>`;
}
function orgAdd(){ const g=i=>document.getElementById(i).value.trim();
  orgOp({op:'add_org',id:g('oa-id'),name:g('oa-name'),type:g('oa-type'),parent:g('oa-parent')}); }
function orgEdit(id){ const g=k=>document.getElementById('org-'+k+'-'+id).value.trim(); const ty=g('ty');
  orgOp({op:'update_org',id:id,name:g('nm'),type:ty,parent:ty==='enduser'?g('pa'):''}); }
function orgSaveRet(id){ orgOp({op:'update_org',id:id,retention_days:document.getElementById('org-ret-'+id).value.trim(),retention_attack_days:document.getElementById('org-reta-'+id).value.trim()}); }
function orgBeRet(id){ orgOp({op:'set_backend_retention',backend:id,retention_days:document.getElementById('bret-'+id).value.trim()}); }
function orgDel(id){ if(confirm('組織「'+orgName(id)+'」を削除しますか?')) orgOp({op:'delete_org',id:id}); }
function orgExport(id){ postJSON('/api/orgs/export',{org:id}).then(r=>{ const m=document.getElementById('orgMsg');
  if(r.ok){ const n=Object.values(r.counts||{}).reduce((a,b)=>a+b,0); if(m) m.textContent='✓ '+n+' 行を '+r.dir+' に書き出しました(WAFのフォルダ内)'; }
  else alert('エラー: '+(r.error||'失敗')); }); }
function orgPrune(){ postJSON('/api/orgs/prune',{}).then(r=>{ const m=document.getElementById('orgMsg'); if(m) m.textContent=r.ok?('✓ 期限切れのログ '+r.removed+' 件を削除しました'):('エラー: '+(r.error||'失敗')); }); }
function renderCustom(d){
  const el=document.getElementById('cusBody'); if(!el) return;
  const s=d.status; if(!s){ el.innerHTML='<div class="hempty">追加ルールは使えません</div>'; return; }
  const rs=d.rules||[];
  el.innerHTML=`<div class="seemore" style="margin-bottom:6px">版 v${esc(s.version||0)} / ${esc(s.count||0)}件${s.active!=null?`(有効 ${esc(s.active)}件)`:''}${s.loaded_at?` / 反映 ${esc(s.loaded_at.replace('T',' '))}`:''}
      <button type="button" onclick="cusReload()" ${s.standalone?'disabled':''}>今すぐ再読み込み</button></div>
    ${s.error?`<div class="mode-warn">⚠ 読み込みエラー(今のルールのまま稼働中): ${esc(s.error)}</div>`:''}
    ${rs.length?rs.map(r=>`<div class="rrow"><span class="rid">${esc(r.id)}</span><span class="rsev ${esc(r.severity)}">${esc(r.severity)}</span>
        <span class="rdesc">${esc(r.name||r.description||'')} <span class="seemore">${esc(r.target)} / ${esc(r.cve||'')}</span></span>
        <span class="mode-badge ${r.mode==='block'?'block':'detect'}">${r.mode==='block'?'遮断':'検知のみ'}</span></div>`).join(''):'<div class="hempty">追加ルールはまだありません(専用ツールで追加します)</div>'}`;
}
function cusReload(){ postJSON('/api/custom-rules/reload',{}).then(r=>{ if(r.ok) renderCustom(r); else alert('エラー: '+(r.error||'失敗')); }); }
let BER={sub:'all',backends:[],orgs:[],cat:null,org:'__',be:'',q:'',cq:'',oq:'',req:null,msg:''};
let HR={data:null,org:'',be:''};
function berClosure(id){ const out=new Set([id]); let ch=true; while(ch){ ch=false; (BER.orgs||[]).forEach(o=>{ if(o.parent&&out.has(o.parent)&&!out.has(o.id)){ out.add(o.id); ch=true; } }); } return out; }
function berBeList(){
  if(BER.org==='__') return [];
  if(BER.org==='') return (BER.backends||[]).filter(b=>!b.org);
  const cl=berClosure(BER.org); return (BER.backends||[]).filter(b=>cl.has(b.org));
}
function berState(b,r){
  if(b.eff_off) return b.eff_off.includes(r)?'off':(b.eff_detect.includes(r)?'det':'ok');
  return (b.rule_disabled||[]).includes(r)?'off':((b.rule_detect||[]).includes(r)?'det':'ok'); }
const BER_CRIT=['XSS-001','XSS-002','XXE-001','PROTO-001','PROTO-002','RESP-001'];
function renderBeRules(d){
  if(d){ BER.backends=d.backends||BER.backends; if(d.orgs) BER.orgs=d.orgs; if(d.presets) BER.presets=d.presets; if(d.backends){ BER.impact=null; BER.reimp=null; } }
  const el=document.getElementById('berBody'); if(!el) return;
  const hasUn=(BER.backends||[]).some(b=>!b.org);
  const oq=(BER.oq||'').toLowerCase();
  const orgs=(BER.orgs||[]).filter(o=>!oq||(o.name+' '+o.id).toLowerCase().includes(oq)||o.id===BER.org);
  const orgOpts='<option value="__">組織を選択…</option>'+(hasUn&&AUTH.user&&AUTH.user.role==='admin'?`<option value="" ${BER.org===''?'selected':''}>未割り当て</option>`:'')+
    orgs.map(o=>`<option value="${esc(o.id)}" ${o.id===BER.org?'selected':''}>${esc(o.name)} (${esc(o.id)})</option>`).join('');
  const bl=berBeList();
  if(bl.length===1&&!BER.be) BER.be=bl[0].id;
  if(BER.be&&!bl.some(b=>b.id===BER.be)) BER.be='';
  const beOpts=`<option value="">${BER.org==='__'?'先に組織を選んでください':(bl.length?'バックエンドを選択…':'この組織にバックエンドはありません')}</option>`+
    bl.map(b=>`<option value="${esc(b.id)}" ${b.id===BER.be?'selected':''}>${esc(b.name)}</option>`).join('');
  const tRow='';
  el.innerHTML=`<div class="ber-pick"><label>組織</label><input id="ber-oq" placeholder="組織名で検索" size="14" value="${esc(BER.oq)}">
    <select id="ber-org">${orgOpts}</select><label>バックエンド</label><select id="ber-be">${beOpts}</select></div>
    <div id="berSel"></div>`;
  document.getElementById('ber-oq').oninput=ev=>{ BER.oq=ev.target.value; const pos=ev.target.selectionStart; renderBeRules(); const i=document.getElementById('ber-oq'); i.focus(); try{ i.setSelectionRange(pos,pos); }catch(e){} };
  document.getElementById('ber-org').onchange=ev=>{ BER.org=ev.target.value; BER.be=''; renderBeRules(); };
  document.getElementById('ber-be').onchange=ev=>{ BER.be=ev.target.value; renderBeRules(); };
  const sel=document.getElementById('berSel'), b=(BER.backends||[]).find(x=>x.id===BER.be);
  if(!b){ sel.innerHTML=`<div class="hempty">${BER.org==='__'?'組織を選ぶと、その配下のバックエンドを選べます。':'バックエンドを選ぶと、ルールの設定が表示されます。'}</div>`; return; }
  const cat=BER.cat, ids=(cat?cat.rules:[]).map(r=>`<option value="${esc(r.id)}">`).join('');
  const rq=BER.req;
  const reqRow=rq?`<div class="mode-warn" style="margin-bottom:8px">${rq.kind==='exclude'
      ?`パス <b>${esc(rq.path_prefix)}</b> でルール <b>${esc(rq.rule)}</b> を「使わない」設定にするには、管理者の承認が必要です。`
      :`ルール <b>${esc(rq.rule)}</b> を「使わない」設定にするには、管理者の承認が必要です。`}理由を書いて申請してください。<br>
    <textarea id="berReqBody" rows="2" style="width:min(520px,100%);margin:6px 0" maxlength="500" placeholder="例: 記事投稿で誤検知が続いており、検知のみでは運用できないため"></textarea><br>
    <button type="button" onclick="berReqSend()">申請する</button> <button type="button" onclick="BER.req=null;renderBeRules()">やめる</button></div>`:'';
  const msgRow=BER.msg?`<div class="seemore" style="margin:0 0 8px;color:${BER.msg.startsWith('エラー')?'var(--block)':'var(--pass,#1f9d55)'};font-weight:600">${esc(BER.msg)}</div>`:'';
  const exl=b.exclusions||[], sub=BER.sub||'all';
  let inner='';
  if(sub==='all'){
    inner=`<div class="ber-flt"><select id="ber-cq"><option value="">全カテゴリ</option>${cat?cat.categories.map(c=>`<option value="${esc(c.key)}" ${c.key===BER.cq?'selected':''}>${esc(c.label)}</option>`).join(''):''}</select>
      <select id="ber-sq"><option value="">状態: すべて</option><option value="ok" ${BER.sq==='ok'?'selected':''}>遮断</option><option value="det" ${BER.sq==='det'?'selected':''}>検知のみ</option><option value="off" ${BER.sq==='off'?'selected':''}>使わない</option></select>
      <input id="ber-q" placeholder="ID / 説明で絞り込み" size="26" value="${esc(BER.q)}"></div>
    <div id="berRules"></div>`;
  } else {
    const rows=exl.map(e=>`<tr class="${e.expired?'exp':''}"><td><code>${esc(e.path_prefix||'全パス')}</code></td><td><code>${esc(e.rule==='*'?'すべてのルール':e.rule)}</code></td>
      <td><span class="ber-chip ${e.mode==='detect'?'det':''}">${e.mode==='detect'?'検知のみ':'使わない'}</span></td>
      <td>${e.until?(e.expired?'期限切れ ':'〜')+esc(new Date(e.until*1000).toLocaleString()):'無期限'}</td><td>${esc(e.ticket||'')}</td><td>${esc(e.by||'')}</td>
      <td><a href="#" onclick="beRuleOp('${esc(b.id)}',{op:'remove_exclusion',exclusion:'${esc(e.id)}'});return false" title="この設定を削除(元の動作に戻る)">削除</a></td></tr>`).join('');
    inner=`<div class="seemore" style="margin:8px 0">特定のパス(前方一致)だけ、ルールの扱いを変えます。それ以外のパスは「バックエンド全体」の設定のままです。期限を付けると、切れたあと自動で元に戻ります。</div>
      <table class="sl-table"><thead><tr><th>パス</th><th>ルール</th><th>このパスでは</th><th>期限</th><th>申請</th><th>設定した人</th><th></th></tr></thead>
      <tbody>${rows||'<tr><td colspan="7" class="seemore">パス別の設定はありません</td></tr>'}</tbody></table>
      <div class="tk-act" style="margin-top:10px"><input id="bex-p" size="16" placeholder="パス(例 /editor)">
        <input id="bex-r" size="20" list="ber-ids" placeholder="ルールID(* で全て)"><datalist id="ber-ids">${ids}</datalist>
        <select id="bex-mode"><option value="detect">検知のみ</option><option value="off">${AUTH.analyst?'使わない(申請して承認)':'使わない'}</option></select>
        <select id="bex-m"><option value="1440">1日</option><option value="10080">7日</option><option value="43200" selected>30日</option><option value="0">無期限</option></select>
        <button type="button" onclick="beExAdd('${esc(b.id)}')">追加</button></div>`;
  }
  sel.innerHTML=msgRow+reqRow+`<div class="ber-be"><b>${esc(b.name)}</b> <span class="seemore">組織: ${esc(beOrgLabelAny(b.org))}</span></div>
    <div id="berPresets"></div>
    <details class="ber-adv" id="berAdv" ${BER.adv?'open':''}><summary>詳細設定(ルール別・パス別) <span class="seemore">使わない ${(b.rule_disabled||[]).length}件・検知のみ ${(b.rule_detect||[]).length}件・遮断に上げた ${(b.rule_block||[]).length}件・パス別 ${exl.length}件</span></summary>
    <div class="set-tabs" style="margin-top:6px"><button type="button" class="${sub==='all'?'on':''}" onclick="BER.sub='all';renderBeRules()">バックエンド全体</button>
      <button type="button" class="${sub==='path'?'on':''}" onclick="BER.sub='path';renderBeRules()">パス別(${exl.length})</button></div>`+inner+`</details>`;
  document.getElementById('berAdv').ontoggle=function(){ BER.adv=this.open; };
  berPresetRender(); berLoadImpact(b.id);
  if(sub==='all'){
    document.getElementById('ber-cq').onchange=ev=>{ BER.cq=ev.target.value; berRulesRender(); };
    document.getElementById('ber-sq').onchange=ev=>{ BER.sq=ev.target.value; berRulesRender(); };
    document.getElementById('ber-q').oninput=ev=>{ BER.q=ev.target.value; berRulesRender(); };
    berRulesRender();
  }
  if(HR.data) renderRuleHist();
}
/* ルールのモードプリセット */
function berPresetRender(){
  const el=document.getElementById('berPresets'); if(!el) return;
  const b=(BER.backends||[]).find(x=>x.id===BER.be); if(!b) { el.innerHTML=''; return; }
  const P=BER.presets||{}, pl=P.presets||[]; if(!pl.length){ el.innerHTML=''; return; }
  const cur=b.rule_preset||'', allowed=b.preset_allowed||[], adm=AUTH.user&&AUTH.user.role==='admin';
  const diff=(b.preset_diff||[]).length, m=b.modes||{};
  const curName=cur?((pl.find(x=>x.id===cur)||{}).name||cur):'従来(全ルール遮断)';
  const imp=(BER.impact&&BER.impact.backend===b.id)?BER.impact:null, rim=(BER.reimp&&BER.reimp.backend===b.id)?BER.reimp:null;
  const u=b.undo;
  let h=`<div class="pset-head"><span>現在: <b>${esc(curName)}${diff?`(+${diff}件変更)`:''}</b> <span class="seemore">遮断 ${m.block||0}・検知のみ ${m.detect||0}${m.off?`・使わない ${m.off}`:''}</span></span>
    ${u?`<button type="button" class="lf-clr" onclick="berUndo('${esc(b.id)}')" title="${esc((u.time||'').replace('T',' '))} ${esc(u.by||'')}">直前の変更を1つ戻す(${esc(u.op||'')} ${esc(u.rule||'')})</button>`:''}
    <button type="button" class="lf-clr" onclick="berReinspect('${esc(b.id)}')" title="ログに残っているリクエストの内容を、いまのルールで検査し直して試算します(手動・件数を絞って実行)">過去ログを再検査して試算</button>
    ${imp?`<span class="seemore">試算の対象: 直近${imp.days}日のヒットあり ${imp.with_hits}件</span>`:'<span class="seemore">影響を計算中…</span>'}</div>`;
  if(!cur) h+=`<div class="seemore" style="margin:0 0 8px">この接続先は従来の設定(全ルール遮断)のままです。下のプリセットを選ぶと切り替わります。</div>`;
  h+='<div class="pset-grid">'+pl.map(p=>{
    const on=p.id===cur, ok=adm||!allowed.length||allowed.includes(p.id);
    const i1=imp&&imp.impact?imp.impact[p.id]:null, i2=rim&&rim.impact?rim.impact[p.id]:null;
    const chg=(p.to_detect.length||p.to_block.length)&&p.id!=='standard'&&p.id!=='strict'?`<div class="pi" title="${esc('検知のみに下げる: '+p.to_detect.join(', ')+'\n遮断に上げる: '+p.to_block.join(', '))}">標準から: 検知のみに下げる ${p.to_detect.length}件 / 遮断に上げる ${p.to_block.length}件</div>`:'';
    let info='';
    if(on) info='<div class="pi">いまの設定です'+(diff?'(個別の変更を含む)':'')+'</div>';
    else if(i1) info=`<div class="pi">過去ログの記録から: <b>遮断に変わる ${i1.to_block}件</b> / <b>通るようになる ${i1.to_pass}件</b>${i1.top&&i1.top.length?`<br><span class="seemore">主なルール: ${i1.top.slice(0,3).map(t=>esc(t.rule)+'×'+t.n).join(', ')}</span>`:''}</div>`;
    if(!on&&i2) info+=`<div class="pi">再検査(${rim.scanned}件): <b>新たに遮断 ${i2.to_block}件</b> / <b>通るように ${i2.to_pass}件</b></div>`;
    return `<div class="pset ${on?'on':''}"><h5>${esc(p.name)}${on?' <span class="ber-chip">選択中</span>':''}</h5>
      <div class="pc"><span class="b">遮断 ${p.block}</span> / <span class="d">検知のみ ${p.detect}</span></div>
      <div class="pd">${esc(p.desc)}</div>${chg}${info}
      <button type="button" ${(on&&!diff)||!ok?'disabled':''} onclick="berPresetSet('${esc(b.id)}','${esc(p.id)}')">${on?(diff?'個別の変更をリセット':'選択中'):(ok?'このプリセットにする':'管理者が許可していません')}</button></div>`;
  }).join('')+'</div>';
  h+=`<div class="seemore" style="margin:8px 0 0">critical の6件(${BER_CRIT.join('・')})は、どのプリセットでも遮断です。${AUTH.limited?'検知のみ・使わないにできるのは管理者だけです(必要なときは申請してください)。':'この6件も、管理者は「詳細設定」で検知のみ・使わないに変えられます(アナリスト・一般は変更できません)。'}</div>`;
  if(adm){
    h+=`<div class="pset-allow"><b>アナリストが選べるプリセット:</b>${pl.map(p=>`<label><input type="checkbox" ${(!allowed.length||allowed.includes(p.id))?'checked':''} onchange="berAllowSet('${esc(b.id)}')" data-pa="${esc(p.id)}"> ${esc(p.name)}</label>`).join('')}<span class="seemore">(すべてチェック=制限なし)</span></div>`;
  }
  el.innerHTML=h;
}
function berLoadImpact(bid){
  if(BER.impactBusy===bid||(BER.impact&&BER.impact.backend===bid)) return;
  BER.impactBusy=bid;
  fetch('/api/rule-presets/impact?backend='+encodeURIComponent(bid)+'&days=30',{cache:'no-store'}).then(r=>r.json()).then(d=>{
    BER.impactBusy=''; if(d&&d.impact){ BER.impact=d; if(BER.be===bid) berPresetRender(); }
  }).catch(()=>{ BER.impactBusy=''; });
}
async function berPresetSet(bid,pid){
  const b=(BER.backends||[]).find(x=>x.id===bid); if(!b) return;
  const diff=(b.preset_diff||[]).length, pl=(BER.presets||{}).presets||[], p=pl.find(x=>x.id===pid)||{};
  let keep=true;
  if(diff>0){
    const c=await askChoice('プリセットを「'+(p.name||pid)+'」にします',`<p>この接続先には、プリセットから個別に変更したルールが <b>${diff}件</b> あります。</p><p>残すと「${esc(p.name||pid)}(+${diff}件変更)」、リセットすると「${esc(p.name||pid)}」そのままになります。</p>`,
      [{label:'キャンセル',value:null},{label:'個別の変更を残す',value:'keep'},{label:'リセットして切り替える',value:'reset'}]);
    if(!c) return; keep=(c==='keep');
  } else {
    const c=await askChoice('プリセットを「'+(p.name||pid)+'」にします',`<p>遮断 ${p.block}・検知のみ ${p.detect} になります。変更は履歴に残り、直後なら1つ前に戻せます。</p>`,[{label:'キャンセル',value:null},{label:'切り替える',value:'ok'}]);
    if(!c) return;
  }
  const r=await postJSON('/api/backend-rules',{backend:bid,op:'set_preset',preset:pid,keep_overrides:keep});
  if(!r.ok){ BER.msg='エラー: '+(r.error||'失敗'); renderBeRules(); return; }
  BER.msg='✓ プリセットを「'+(p.name||pid)+'」にしました'; renderBeRules(r); loadRulesExtra(true);
}
async function berUndo(bid){
  const b=(BER.backends||[]).find(x=>x.id===bid); if(!b||!b.undo) return;
  const c=await askChoice('直前の変更を戻します',`<p>${esc((b.undo.time||'').replace('T',' '))} の「${esc(b.undo.op||'')} ${esc(b.undo.rule||'')}」(${esc(b.undo.by||'')})をする前の状態に戻します。戻した記録も履歴に残ります。</p>`,[{label:'キャンセル',value:null},{label:'戻す',value:'ok'}]);
  if(!c) return;
  const r=await postJSON('/api/backend-rules',{backend:bid,op:'undo'});
  if(!r.ok){ BER.msg='エラー: '+(r.error||'失敗'); renderBeRules(); return; }
  BER.msg='✓ 直前の変更を戻しました'; renderBeRules(r); loadRulesExtra(true);
}
async function berAllowSet(bid){
  const ids=[...document.querySelectorAll('#berPresets [data-pa]')].filter(x=>x.checked).map(x=>x.dataset.pa);
  if(!ids.length){ alert('少なくとも1つは選べるようにしてください'); berPresetRender(); return; }
  const all=document.querySelectorAll('#berPresets [data-pa]').length;
  const r=await postJSON('/api/backend-rules',{backend:bid,op:'set_preset_allowed',allowed:ids.length===all?[]:ids});
  if(!r.ok){ BER.msg='エラー: '+(r.error||'失敗'); renderBeRules(); return; }
  renderBeRules(r);
}
async function berReinspect(bid){
  const c=await askChoice('過去ログを再検査します',`<p>ログに残っているリクエスト(直近30日・最大500件。本文は先頭4KBまで)を、いまのルールで検査し直して、各プリセットにしたときの影響を試算します。設定は変わりません。</p><p class="seemore">記録されたヒットだけの試算と違い、これまで何にも当たらなかった通常のリクエストが新たに遮断されるかも分かります。時間がかかることがあります。</p>`,[{label:'キャンセル',value:null},{label:'再検査する',value:'ok'}]);
  if(!c) return;
  BER.msg='再検査中…'; renderBeRules();
  const r=await postJSON('/api/rule-presets/reinspect',{backend:bid,days:30,limit:500}).catch(()=>({ok:false,error:'通信エラー'}));
  if(!r.ok){ BER.msg='エラー: '+(r.error||'失敗'); renderBeRules(); return; }
  BER.reimp=r; BER.msg='✓ 再検査しました(対象 '+r.scanned+'件'+(r.no_detail?'、内容が残っていない '+r.no_detail+'件は対象外':'')+')'; renderBeRules();
}
function beOrgLabelAny(id){ const o=(BER.orgs||[]).find(x=>x.id===id); return o?o.name:(id||'未割り当て'); }
function berRulesRender(){
  const el=document.getElementById('berRules'); if(!el) return;
  const b=(BER.backends||[]).find(x=>x.id===BER.be), cat=BER.cat;
  if(!b) return;
  if(!cat){ el.innerHTML='<div class="hempty">ルール一覧を読み込み中…</div>'; return; }
  const q=(BER.q||'').toLowerCase(); const cl={}; cat.categories.forEach(c=>cl[c.key]=c.label);
  const by={};
  cat.rules.forEach(r=>{
    if(BER.cq&&r.category!==BER.cq) return;
    if(BER.sq&&berState(b,r.id)!==BER.sq) return;
    if(q&&((r.id+' '+(r.description||'')).toLowerCase().indexOf(q)<0)) return;
    (by[r.category]=by[r.category]||[]).push(r);
  });
  let h='';
  cat.categories.forEach(c=>{ const rs=by[c.key]; if(!rs||!rs.length) return;
    h+=`<div class="rcat"><div class="rcat-head"><span class="nm">${esc(c.label)}</span><span class="ct">${rs.length}ルール</span></div>`;
    rs.forEach(r=>{ const st=berState(b,r.id);
      h+=`<div class="rrow ${st==='off'?'off':''}"><span class="rid">${esc(r.id)}</span><span class="rsev ${esc(r.severity)}">${esc(r.severity)}</span><span class="rdesc">${esc(r.description||'')}</span>
        <span class="ber-st">${[['ok','遮断'],['det','検知のみ'],['off',AUTH.analyst?'使わない(申請)':'使わない']].map(([k,l])=>{ const lock=BER_CRIT.includes(r.id)&&k!=='ok'&&AUTH.limited; return `<button type="button" class="${k} ${st===k?'on':''}" ${lock?'disabled title="critical のため、検知のみ・使わないにできるのは管理者だけです"':''} onclick="beRuleSet('${esc(b.id)}','${esc(r.id)}','${k}')">${l}${lock?' 🔒':''}</button>`; }).join('')}</span></div>`; });
    h+='</div>'; });
  el.innerHTML=h||'<div class="hempty">該当するルールはありません</div>';
}
async function berReqSend(){
  const rq=BER.req; if(!rq) return; const b=(BER.backends||[]).find(x=>x.id===rq.bid); if(!b) return;
  const body=(document.getElementById('berReqBody')||{}).value||'';
  const ex=rq.kind==='exclude';
  const r=await postJSON('/api/tickets',{kind:'rule_proposal',backend:rq.bid,
    subject:(ex?'パス '+rq.path_prefix+' でルールを使わない設定の申請: ':'ルールを使わない設定の申請: ')+rq.rule+'('+b.name+')',body:body,
    proposal:ex?{op:'exclude',rule:rq.rule,path_prefix:rq.path_prefix,minutes:rq.minutes}:{op:'disable',rule:rq.rule}}).catch(()=>({ok:false,error:'通信エラー'}));
  if(r.ok){ BER.req=null; BER.msg='✓ 申請しました('+((r.ticket||{}).id||'')+')。管理者が承認すると反映されます(「申請」タブで状況を確認できます)'; }
  else BER.msg='エラー: '+(r.error||'失敗');
  renderBeRules();
}
function beExAdd(bid){
  const g=id=>(document.getElementById(id)||{}).value||'';
  const o={op:'add_exclusion',rule:g('bex-r').trim(),path_prefix:g('bex-p').trim(),minutes:g('bex-m'),mode:g('bex-mode')};
  if(!o.rule||!o.path_prefix){ BER.msg='エラー: パスとルールIDを入れてください'; renderBeRules(); return; }
  if(AUTH.analyst&&o.mode==='off'){ BER.req={kind:'exclude',bid,rule:o.rule,path_prefix:o.path_prefix,minutes:parseInt(o.minutes,10)||0}; BER.msg=''; renderBeRules(); const t=document.getElementById('berReqBody'); if(t) t.focus(); return; }
  BER.msg=''; beRuleOp(bid,o);
}
async function beRuleSet(bid,rule,want){
  const b=(BER.backends||[]).find(x=>x.id===bid); if(!b) return;
  const cur=berState(b,rule); if(cur===want) return;
  if(AUTH.analyst&&want==='off'){ BER.req={bid,rule}; BER.msg=''; renderBeRules(); const t=document.getElementById('berReqBody'); if(t) t.focus(); return; }
  const ops=[];
  if(cur==='off') ops.push('enable');
  if(want==='off') ops.push('disable'); else if(want==='det') ops.push('detect'); else ops.push('block');
  for(const op of ops){
    const o={backend:bid,op,rule};
    const r=await postJSON('/api/backend-rules',o);
    if(!r.ok){ alert('エラー: '+(r.error||'失敗')); break; }
    BER.backends=r.backends||BER.backends;
  }
  renderBeRules(); loadRulesExtra(true);
}
function beRuleOp(id,o){
  return postJSON('/api/backend-rules',Object.assign({backend:id},o)).then(r=>{ if(r.ok){ renderBeRules(r); loadRulesExtra(true); } else alert('エラー: '+(r.error||'失敗')); }); }
function ruleTab(k){
  const g=document.getElementById('ruleGrid'); if(!g) return; g.dataset.rt=k;
  document.querySelectorAll('#ruleTabs button').forEach(b=>b.classList.toggle('on',b.dataset.rt===k));
}
document.querySelectorAll('#ruleTabs button').forEach(b=>{ b.onclick=()=>ruleTab(b.dataset.rt); });
function renderRuleHist(d){
  const el=document.getElementById('rhBody'); if(!el) return;
  if(d) HR.data=d.history||[];
  const hs=HR.data||[];
  const isAdm=AUTH.user&&AUTH.user.role==='admin';
  const bes=BER.backends||[], orgs=BER.orgs||[];
  const hasUn=bes.some(b=>!b.org);
  const orgOpts='<option value="">すべての組織</option>'+(hasUn&&isAdm?`<option value="__none" ${HR.org==='__none'?'selected':''}>未割り当て</option>`:'')+orgs.map(o=>`<option value="${esc(o.id)}" ${o.id===HR.org?'selected':''}>${esc(o.name)} (${esc(o.id)})</option>`).join('');
  let pool=bes;
  if(HR.org==='__none') pool=bes.filter(b=>!b.org); else if(HR.org){ const cl=berClosure(HR.org); pool=bes.filter(b=>cl.has(b.org)); }
  if(HR.be&&!pool.some(b=>b.id===HR.be)) HR.be='';
  const beOpts='<option value="">すべてのバックエンド</option>'+pool.map(b=>`<option value="${esc(b.id)}" ${b.id===HR.be?'selected':''}>${esc(b.name)}</option>`).join('');
  const ids=new Set(pool.map(b=>b.id));
  const rows=hs.filter(h=>{
    if(HR.be) return h.backend===HR.be;
    if(HR.org) return !!h.backend&&ids.has(h.backend);
    return true;
  });
  el.innerHTML=`<div class="ber-pick"><label>組織</label><select id="hr-org">${orgOpts}</select><label>バックエンド</label><select id="hr-be">${beOpts}</select><span class="seemore">${rows.length}件</span></div>`+
    (rows.length?`<table class="sl-table"><thead><tr><th>時刻</th><th>操作者</th><th>対象</th><th>内容</th></tr></thead><tbody>`+
    rows.slice(0,200).map(h=>`<tr><td>${esc((h.time||'').replace('T',' '))}</td><td>${esc(h.by||'')}</td><td>${esc(h.backend_name||(h.kind==='global_rule'||h.kind==='global_category'?'全体':''))}</td>
      <td>${esc(({set_preset:'プリセット変更',set_preset_allowed:'選べるプリセット変更',undo:'元に戻す'})[h.op]||h.op||'')} ${esc(h.rule||'')}${h.op==='set_preset'?(h.keep_overrides?' (個別の変更は残す)':' (個別の変更はリセット)'):''}${h.path_prefix?' @ '+esc(h.path_prefix):''}${h.mode?(h.mode==='detect'?' (検知のみ)':' (使わない)'):''}${h.ticket?' <span class="seemore">'+esc(h.ticket)+'</span>':''}${h.reason?' <span class="seemore">'+esc(h.reason)+'</span>':''}</td></tr>`).join('')+'</tbody></table>':'<div class="hempty">該当する変更はありません</div>');
  document.getElementById('hr-org').onchange=ev=>{ HR.org=ev.target.value; HR.be=''; renderRuleHist(); };
  document.getElementById('hr-be').onchange=ev=>{ HR.be=ev.target.value; renderRuleHist(); };
}
function initRulesFilters(){
  const sel=document.getElementById('rf-cat');
  if(sel.options.length<=1){
    rulesData.categories.forEach(c=>{
      const o=document.createElement('option'); o.value=c.key; o.textContent=c.label; sel.appendChild(o);
    });
  }
  document.getElementById('rTotal').textContent=`— 全 ${rulesData.total} ルール`;
}
function renderRules(){
  const fc=document.getElementById('rf-cat').value;
  const fs=document.getElementById('rf-sev').value;
  const ft=document.getElementById('rf-text').value.trim().toLowerCase();
  const catOf={}; rulesData.categories.forEach(c=>catOf[c.key]=c);
  const byCat={};
  rulesData.rules.forEach(r=>{
    if(fc && r.category!==fc) return;
    if(fs && r.severity!==fs) return;
    if(ft && ((r.id+' '+r.description).toLowerCase().indexOf(ft)<0)) return;
    (byCat[r.category]=byCat[r.category]||[]).push(r);
  });
  let h='';
  rulesData.categories.forEach(c=>{
    const rs=byCat[c.key]; if(!rs||!rs.length) return;
    h+=`<div class="rcat"><div class="rcat-head">
      <span class="nm">${esc(c.label)}</span>
      <span class="ct">${rs.length}ルール</span>
      <label class="sw" style="margin-left:auto" title="カテゴリ一括">
        <input type="checkbox" ${c.enabled?'checked':''} onchange="toggleCategory('${c.key}',this.checked)">
        <span class="track"><span class="knob"></span></span></label></div>`;
    rs.forEach(r=>{
      const dbtn = r.enabled
        ? `<button class="rdet ${r.detect_only?'on':''}" title="検知のみ=一致しても遮断せず記録だけ(遮断運用での誤検知対策)"
             onclick="toggleDetect('${r.id}',${r.detect_only?'false':'true'})">${r.detect_only?'検知のみ':'遮断'}</button>`
        : '';
      h+=`<div class="rrow ${r.enabled?'':'off'}">
        <span class="rid">${esc(r.id)}</span>
        <span class="rsev ${esc(r.severity)}">${esc(r.severity)}</span>
        <span class="rdesc">${esc(r.description)}</span>
        ${dbtn}
        <label class="sw" title="ルール単体(オフ=無効化)"><input type="checkbox" ${r.enabled?'checked':''}
          ${r.category_enabled?'':'disabled'} onchange="toggleRule('${r.id}',this.checked)">
          <span class="track"><span class="knob"></span></span></label></div>`;
    });
    h+='</div>';
  });
  document.getElementById('rBody').innerHTML=h||'<div class="empty">該当ルールなし</div>';
}
function toggleRule(id,enabled){
  fetch('/api/rules/rule',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({id,enabled})}).then(r=>r.json()).then(res=>{
      if(res.rules){ rulesData=res.rules; renderRules(); }});
}
function toggleDetect(id,detect){
  fetch('/api/rules/detect',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({id,detect})}).then(r=>r.json()).then(res=>{
      if(res.rules){ rulesData=res.rules; renderRules(); } else if(res.error){ alert('エラー: '+res.error); }});
}
function toggleCategory(cat,enabled){
  fetch('/api/rules/category',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({category:cat,enabled})}).then(r=>r.json()).then(res=>{
      if(res.rules){ rulesData=res.rules; renderRules(); }});
}
/* IPブロック / BAN 管理 */

/* 稼働モニター(接続先アプリ / WAF待受)。3秒ごとに確認する。ダッシュボードに繋がらない場合はプロセス停止の可能性 */
const HEALTH_LABEL={paused:'稼働停止中',up:'稼働中',slow:'遅い',error:'異常応答(5xx)',down:'ダウン',unknown:'未確認'};
let healthFails=0, healthLast=null;
function sparkSvg(samples,slowMs,interval){
  const v=(samples||[]); if(!v.length) return '<svg class="spark"></svg>';
  const W=420,H=34, vals=v.filter(x=>x!=null); const mx=Math.max(slowMs||1000, ...(vals.length?vals:[1]));
  const n=v.length, dx=n>1?W/(n-1):W; let d='', pen=false, dots='';
  v.forEach((x,i)=>{ const px=(i*dx).toFixed(1);
    if(x==null){ pen=false; dots+=`<rect x="${(+px-2).toFixed(1)}" y="0" width="4" height="${H}" fill="var(--block)" opacity=".35"/>`; return; }
    const py=(H-2-(H-6)*Math.min(1,x/mx)).toFixed(1); d+=(pen?'L':'M')+px+' '+py+' '; pen=true; });
  const slowY=(H-2-(H-6)*Math.min(1,(slowMs||1000)/mx)).toFixed(1);
  const meta=esc(JSON.stringify({s:v,iv:interval||5,slow:slowMs||1000}));
  return `<div class="tr-wrap spk-wrap" data-spk="${meta}"><svg class="spark" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">
    <line x1="0" y1="${slowY}" x2="${W}" y2="${slowY}" stroke="var(--detect)" stroke-dasharray="3 3" opacity=".5"/>
    ${dots}<path d="${d}" fill="none" stroke="var(--accent,#3987e5)" stroke-width="1.6" vector-effect="non-scaling-stroke"/>
    <line class="sx" y1="0" y2="${H}" stroke="var(--ink-muted)" stroke-dasharray="3 3" vector-effect="non-scaling-stroke" style="display:none"/></svg>
    <div class="maptip tr-tip"></div></div>`;
}
/* 稼働グラフ: カーソルを合わせると、その時点の応答時間を表示。3秒ごとの再描画に影響されないよう親で拾う */
function sparkHover(root){
  const hide=w=>{ const t=w.querySelector('.tr-tip'), x=w.querySelector('.sx'); if(t) t.style.display='none'; if(x) x.style.display='none'; };
  root.addEventListener('mousemove',ev=>{
    const w=ev.target.closest('.spk-wrap'); if(!w) return;
    let m; try{ m=JSON.parse(w.dataset.spk); }catch(e){ return; }
    const svg=w.querySelector('svg'), tip=w.querySelector('.tr-tip'), rc=svg.getBoundingClientRect(); if(!rc.width) return;
    const n=m.s.length, W=420;
    let i=n===1?0:Math.round((ev.clientX-rc.left)/rc.width*(n-1)); i=Math.max(0,Math.min(n-1,i));
    const x=n===1?0:i*W/(n-1), sx=w.querySelector('.sx'); sx.setAttribute('x1',x); sx.setAttribute('x2',x); sx.style.display='';
    const ago=(n-1-i)*m.iv, val=m.s[i];
    const when=new Date(Date.now()-ago*1000), hh=[when.getHours(),when.getMinutes(),when.getSeconds()].map(z=>String(z).padStart(2,'0')).join(':');
    const col=val==null?'var(--block)':(val>m.slow?'var(--detect)':'var(--pass)');
    tip.innerHTML=`<div class="li"><i style="background:${col}"></i>${val==null?'応答なし(ダウン)':'応答時間'}<b>${val==null?'—':Math.round(val)+' ms'}</b></div>
      <div class="sub">${hh}${ago?'(約'+ago+'秒前)':'(最新)'}</div>`;
    tip.style.display='block';
    const wr=w.getBoundingClientRect(); let left=ev.clientX-wr.left+14; if(left>wr.width-tip.offsetWidth-6) left=ev.clientX-wr.left-tip.offsetWidth-14;
    tip.style.left=Math.max(4,left)+'px'; tip.style.top=Math.max(0,ev.clientY-wr.top-tip.offsetHeight-8)+'px';
  });
  root.addEventListener('mouseout',ev=>{ const w=ev.target.closest('.spk-wrap'); if(w&&!w.contains(ev.relatedTarget)) hide(w); });
}
function renderHealth(h, unreachable){
  const rank={up:0,paused:0,unknown:1,slow:2,error:3,down:4};
  let worst='up';
  // 接続先アプリ(登録した全件の集計)
  const bl=(h&&h.backends)||[];
  const be=document.getElementById('hp-backend'), wf=document.getElementById('hp-waf');
  if(be){
    let st='unknown', txt='確認中…';
    if(unreachable){ st='down'; txt='応答なし'; }
    else if(h===null){ txt='未接続'; }
    else if(bl.length){
      bl.forEach(b=>{ if((rank[b.state]||0)>(rank[st==='unknown'?'up':st]||0)||st==='unknown') st=b.state; });
      const nb=bl.filter(b=>b.state==='down'||b.state==='error').length, ns=bl.filter(b=>b.state==='slow').length;
      txt=nb?`${nb}件 ダウン/異常 (全${bl.length}件)`:(ns?`${ns}件 遅い (全${bl.length}件)`:`全${bl.length}件 `+(st==='paused'?'稼働停止中':'稼働中'));
      if(!nb&&!ns&&bl.every(b=>b.state==='paused')) st='paused';
      else if(!nb&&!ns) st=bl.some(b=>b.state==='unknown')?'unknown':'up';
    }
    if((rank[st]||0)>(rank[worst]||0)) worst=st;
    be.className='seg '+st; be.querySelector('b').textContent=txt;
  }
  if(wf){
    let st='unknown', txt='確認中…';
    if(unreachable){ st='down'; txt='応答なし'; }
    else if(h&&h.targets&&h.targets.waf){ const t=h.targets.waf; st=t.state; txt=(HEALTH_LABEL[st]||st)+(t.latency_ms!=null?` ${Math.round(t.latency_ms)}ms`:''); }
    else if(h===null){ txt='未接続'; }
    if((rank[st]||0)>(rank[worst]||0)) worst=st;
    wf.className='seg '+st; wf.querySelector('b').textContent=txt;
  }
  const pill=document.getElementById('hpill'); if(pill) pill.className='hp '+worst;
  slLiveRender(h, unreachable);
}
/* 状態ログタブ内の「稼働の詳細」(接続先ドロップダウンに連動) */
function slLiveRender(h, unreachable){
  const el=document.getElementById('slLive'); if(!el) return;
  if(curPage!=='status') return;
  if(el.querySelector('.spk-wrap:hover')) return;      // グラフを見ている間は、数値が動かないよう再描画しない
  if(unreachable){ el.innerHTML='<div class="hempty">ダッシュボードに接続できません。WAFプロセスが停止している、またはネットワークが切れている可能性があります。</div>'; return; }
  if(!h){ el.innerHTML='<div class="hempty">この画面はWAFと別プロセスで動いているため、リアルタイムの稼働情報がありません(python waf.py で一緒に起動したときに表示されます)。下の「状態の変化の履歴」は保存済みの記録から表示しています。</div>'; return; }
  if(h.limited){
    const ls=h.backends||[], pick=ls.filter(x=>scIn('sl',x.id));
    const one=b=>`<h3>${esc(b.name)}</h3>
      <div class="row"><span>状態</span><b>${HEALTH_LABEL[b.state]||b.state}${b.since?'('+esc((b.since||'').replace('T',' '))+' から)':''}</b></div>
      <div class="row"><span>応答時間</span><b>${b.latency_ms!=null?Math.round(b.latency_ms)+' ms':'—'}</b></div>
      <div class="row"><span>最後に正常だった時刻</span><b>${esc((b.last_ok||'—').replace('T',' '))}</b></div>
      ${sparkSvg(b.samples,h.slow_ms,h.interval)}`;
    el.innerHTML=(pick.map(one).join('')||'<div class="hempty">登録したバックエンドの稼働情報はまだありません</div>')
      +`<h3>WAF</h3><div class="row"><span>WAF全体の稼働</span><b>${(h.waf&&h.waf.state==='up')?'稼働中':(h.waf&&h.waf.state==='unknown'?'未確認':'停止/異常')}</b></div>
      <div class="row" style="margin-top:6px;color:var(--ink-muted)"><span>${h.interval||5}秒ごとに確認 / 青い線=応答時間(点線=「遅い」の基準) / 赤い帯=応答なし</span></div>`;
    return;
  }
  const bl=h.backends||[], secs=h.interval||5;
  const rowsOf=(b)=>`
      <div class="row"><span>状態</span><b>${HEALTH_LABEL[b.state]||b.state}${b.since?'('+esc((b.since||'').replace('T',' '))+' から)':''}</b></div>
      <div class="row"><span>応答時間</span><b>${b.latency_ms!=null?Math.round(b.latency_ms)+' ms':'—'}</b></div>
      <div class="row"><span>詳細</span><b>${esc(b.detail||'')}</b></div>
      <div class="row"><span>最後に正常だった時刻</span><b>${esc((b.last_ok||'—').replace('T',' '))}</b></div>
      ${sparkSvg(b.samples,h.slow_ms,h.interval)}`;
  let out='';
  if(slSel){
    const b=bl.find(x=>x.id===slSel);
    out+=b?`<h3>${esc(b.name)}${b.listen_port?' :'+b.listen_port:''}(接続先アプリ)</h3>`+rowsOf(b):'<div class="hempty">この接続先の稼働情報はまだありません</div>';
  } else {
    const bl3=bl.filter(b=>scIn('sl',b.id));
    out+=`<h3>接続先アプリ(全${bl3.length}件。行をクリックするとその接続先に絞り込みます)</h3>`+(bl3.map(b=>
      `<div class="row sel" data-sel="${esc(b.id)}"><span>${esc(b.name)}${b.listen_port?' :'+b.listen_port:''}</span><b>${HEALTH_LABEL[b.state]||b.state}${b.latency_ms!=null?' '+Math.round(b.latency_ms)+'ms':''}</b></div>`).join('')||'<div class="hempty">登録なし</div>');
  }
  const w=h.targets&&h.targets.waf;
  if(w) out+=`<h3>WAF(待受ポート)</h3>`+rowsOf(w);
  if(h.lag_ms!=null){
    const hot=h.lag_ms>200;
    out+=`<h3>処理の渋滞(WAF内部)</h3>
      <div class="row"><span>スレッド起床遅れ(直近約10秒の最大 / 平均)</span><b style="${hot?'color:var(--danger,#c0392b)':''}">${h.lag_ms} ms / ${h.lag_avg_ms} ms</b></div>
      <div class="row"><span>正規の接続: 受付→処理開始の待ち(直近10秒 最大 / 平均)</span><b>${h.queue_ms_max!=null?h.queue_ms_max+' ms / '+h.queue_ms_avg+' ms':'—'}</b></div>
      <div class="row"><span>正規の接続: TLS握手の時間(最大 / 平均)</span><b>${h.tls_ms_max!=null?h.tls_ms_max+' ms / '+h.tls_ms_avg+' ms':'—'}</b></div>
      <div class="row"><span>直近10秒に処理を始めた正規の接続数</span><b>${h.conns_10s!=null?h.conns_10s+' 件':'—'}</b></div>
      <div class="row"><span>受付(accept)エラー累計</span><b style="${h.accept_errors>0?'color:var(--danger,#c0392b)':''}">${h.accept_errors||0} 件</b></div>
      ${h.accept_last_error?`<div class="row"><span>直近の受付エラー</span><b>${esc(h.accept_last_error)}</b></div>`:''}
      <div class="row" style="color:var(--ink-muted)"><span>起床遅れが数百ms以上=CPU/GILが飽和して全スレッドが待たされている状態。受付エラー増加=新規接続が受け付けきれていない状態。</span></div>`;
  }
  const hist=(h.history||[]).filter(x=>x.target!=='backend'||scIn('sl',x.backend));
  out+=`<h3>直近の状態の変化(新しい順)</h3><ul>`+(hist.map(x=>
      `<li>${esc((x.ts||'').replace('T',' '))} ${x.target==='backend'?esc(x.backend_name||'接続先アプリ'):'WAF'}: ${HEALTH_LABEL[x.from]||x.from} → <b>${HEALTH_LABEL[x.to]||x.to}</b> <span style="color:var(--ink-muted)">${esc(x.detail||'')}</span></li>`).join('')
      ||'<li>まだありません</li>')+`</ul>
    <div class="row" style="margin-top:6px;color:var(--ink-muted)"><span>${secs}秒ごとに確認 / 青い線=応答時間(点線=「遅い」の基準) / 赤い帯=応答なし</span></div>`;
  el.innerHTML=out;
}
function pollHealth(){
  if(AUTH.limited&&curPage!=='status') return;      // 一般ユーザーは状態ログを開いている間だけ取得する
  fetch('/api/health',{cache:'no-store'}).then(r=>{ if(r.status===403){ AUTH.limited=true; throw new Error('forbidden'); } return r.json(); }).then(d=>{
    healthFails=0; healthLast=d.health; if(AUTH.limited){ slLiveRender(healthLast,false); return; } renderHealth(d.health,false);
  }).catch(()=>{ if(AUTH.limited) return; healthFails++; if(healthFails>=2) renderHealth(healthLast,true); });
}
document.getElementById('hpill').addEventListener('click',()=>showPage('status'));
document.getElementById('slLive').addEventListener('click',ev=>{
  const r=ev.target.closest('[data-sel]'); if(!r) return;
  slSel=r.dataset.sel; SC.sl.be=slSel; slRender(); if(window.__lastSec) renderMode(window.__lastSec); slLiveRender(healthLast, healthFails>=2);
});
pollHealth(); setInterval(pollHealth, 3000);
function loadSecurity(){
  fetch('/api/security').then(r=>r.ok?r.json():null)
    .then(s=>{ if(s) renderSecurity(s); })
    .catch(()=>{});
}
let IP_BE='';
function ipPolicyOf(s){
  if(!IP_BE) return s;
  const p=((s.backend_policies||{})[IP_BE])||{};
  return {blocklist:p.blocklist||[], ip_allowlist:p.ip_allowlist||[], country_blocklist:p.country_blocklist||[], country_allowlist:p.country_allowlist||[]};
}
function ipSelSync(s){
  const sel=document.getElementById('ipSel'), pick=document.getElementById('ipPick'); if(!sel) return;
  const bl=s.backends||[];
  pick.style.display=(bl.length||AUTH.limited)?'':'none';
  scOrgFill('ip','ipOrg');
  const org=SC.ip.org;
  const bl2=org?bl.filter(b=>scInOrg('ip',b.id)):bl;
  const noCommon=AUTH.limited||!!org;
  const sig=org+'|'+noCommon+'|'+bl2.map(b=>b.id+':'+b.name).join('|');
  if(sel.dataset.sig!==sig){
    sel.dataset.sig=sig;
    sel.innerHTML=(noCommon?'':'<option value="">共通(すべてのバックエンド)</option>')+bl2.map(b=>`<option value="${esc(b.id)}">${esc(b.name)} だけ</option>`).join('');
  }
  if(IP_BE&&!bl2.some(b=>b.id===IP_BE)) IP_BE='';
  if(noCommon&&!IP_BE&&bl2.length) IP_BE=bl2[0].id;      // 一般ユーザー/組織を選んだときはバックエンドごとの設定だけ。共通設定は組織未選択の管理者のみ
  SC.ip.be=IP_BE;
  sel.value=IP_BE;
  const pg=document.getElementById('page-ip'); if(pg) pg.classList.toggle('be-sel',!!IP_BE||!!AUTH.limited);
  const n=document.getElementById('ipSelNote');
  if(n) n.textContent=AUTH.limited?(bl.length?'自分のバックエンド宛のアクセスにだけ効く設定です':'登録したバックエンドがありません(設定画面で登録すると、ここで設定できます)'):(org&&!bl2.length?'この組織にはバックエンドがありません':(IP_BE?'このバックエンド宛のアクセスにだけ効く設定です(BAN・除外IP・同時接続は接続の段階で判定するため「共通」でのみ設定します)':'全バックエンド共通の設定です'));
}
function renderSecurity(s0){
  window.__lastSec=s0;
  ipSelSync(s0);
  const s=Object.assign({}, s0, ipPolicyOf(s0));
  lastBans=(s.bans||[]).length;
  const bl=document.getElementById('blocklist');
  bl.innerHTML=(s.blocklist||[]).map(ip=>
    `<li><span class="ip">${esc(ip)}</span>
      <button onclick="unblockIP('${esc(ip)}')">解除</button></li>`).join('')
    || '<li class="empty">なし</li>';
  const bn=document.getElementById('banlist');
  bn.innerHTML=(s.bans||[]).map(b=>{
    const m=Math.floor(b.expires_in/60), sec=b.expires_in%60;
    return `<li><span class="ip">${esc(b.ip)}</span>
      <span class="exp">残り ${m}分${sec}秒 <span class="seemore">${esc(BAN_REASON[b.reason]||b.reason||'')}</span></span>
      ${AUTH.limited?'':`<button onclick="extendBan('${esc(b.ip)}')" title="10分延長">+10分</button>
      <button onclick="unbanIP('${esc(b.ip)}')">解除</button>`}</li>`;
  }).join('') || `<li class="empty">${s.online===false?'単体起動では表示できません':'なし'}</li>`;
  const li=(arr,fn,lab)=>(arr||[]).map(v=>`<li><span class="ip">${esc(lab?lab(v):v)}</span>
      <button onclick="${fn}('${esc(v)}')">解除</button></li>`).join('') || '<li class="empty">なし</li>';
  const cl=document.getElementById('countrylist');
  if(cl) cl.innerHTML=li(s.country_blocklist,'unblockCountry',ccName);
  const cal=document.getElementById('countryallowlist');
  if(cal) cal.innerHTML=li(s.country_allowlist,'unallowCountry',ccName);
  const cu=document.getElementById('countryUnknown'); if(cu) cu.checked=!!s.country_block_unknown;
  const al=document.getElementById('allowlist'); if(al) al.innerHTML=li(s.ip_allowlist,'unallowIP');
  const aw=document.getElementById('allowWarn');
  if(aw) aw.textContent=(s.ip_allowlist||[]).length?'⚠ 有効: 登録したIP/CIDR以外からのアクセスは全て拒否されます(このダッシュボードは対象外)':'';
  const ex=document.getElementById('exemptlist'); if(ex) ex.innerHTML=li(s.exempt_ips,'unexemptIP');
  // BAN履歴
  const bh=document.querySelector('#banhist tbody');
  if(bh){
    const hist=s.ban_history||[];
    bh.innerHTML = hist.length ? hist.map(h=>{
      const t=(h.at||'').replace('T',' ').slice(0,19);
      const m=Math.floor((h.duration||0)/60), sc=(h.duration||0)%60;
      const dur=m>0?`${m}分${sc?sc+'秒':''}`:`${sc}秒`;
      const reason=BAN_REASON[h.reason]||h.reason||'-';
      return `<tr><td>${esc(t)}</td><td>${esc(h.ip)}</td><td>${dur}</td>
        <td>${h.offense||1}回目</td><td>${esc(reason)}</td></tr>`;
    }).join('') : '<tr><td colspan="5" class="empty">BAN履歴はありません</td></tr>';
  }
  // 接続の流れ(累計カウンター。上の「接続先」に連動)
  window.__lastConn=s.connections||{}; renderConnFlow();
  // IPごとの現在の同時接続数(ライブ)
  const cn=s.connections||{}; const clist=document.getElementById('connlist'); const csum=document.getElementById('connSum');
  if(csum){
    if(cn.offline){ csum.textContent='(単体起動のため非表示)'; }
    else{
      const mt=cn.max_total?(' / 上限 '+cn.max_total):''; const mi=cn.max_per_ip?('、IP上限 '+cn.max_per_ip):'';
      csum.innerHTML=`合計 <b>${cn.total||0}</b>${mt}${mi}`;
    }
  }
  if(clist){
    const rows=cn.per_ip||[];
    clist.innerHTML = cn.offline ? '<li class="empty">単体起動では表示できません</li>'
      : (rows.length ? rows.map(r=>{
          const near = cn.max_per_ip>0 && r.count>=cn.max_per_ip;
          return `<li><span class="ip">${esc(r.ip)}</span>
            <span class="conn-n ${near?'hot':''}">${r.count} 接続</span>
            <button onclick="addBlockIP('${esc(r.ip)}')">ブロック</button></li>`;
        }).join('') : '<li class="empty">現在アクティブな接続はありません</li>');
  }
}
function connFlowFor(cn){
  /* 選んだ接続先の分だけ返す {stats, note}。未選択なら全体 */
  const cs=cn.stats; if(!cs||!slSel) return {stats:cs, note:''};
  const pm=cn.port_map||{}, bp=cn.by_port||{}, bb=cn.by_backend||{};
  const ports=Object.keys(pm).filter(p=>pm[p]===slSel);
  const out={}; Object.keys(cs).forEach(k=>{ if(typeof cs[k]==='number') out[k]=0; });
  ports.forEach(p=>{ const d=bp[p]||{}; Object.keys(d).forEach(k=>{ out[k]=(out[k]||0)+d[k]; }); });
  out.gate_total=['gate_blocklist','gate_ban','gate_conn_limit','gate_overload','gate_conn_flood'].reduce((a,k)=>a+(out[k]||0),0);
  out.since=cs.since;
  const rq=(bb[slSel]||{}).requests; if(rq!==undefined) out.requests=rq;
  let note='';
  if(!ports.length) note='この接続先は共有の待受ポート(ホスト名/パスで振り分け)を通るため、受理・TLS握手などの接続段階の項目は接続先ごとに分けられません(リクエスト数だけ接続先別に出ます)。専用の待受ポートを設定すると、これらも接続先別に出ます。';
  return {stats:out, note, noConn:!ports.length};
}
function renderConnFlow(){
  const cn=window.__lastConn||{}; const cst=document.getElementById('connStats'); const csince=document.getElementById('connStatsSince');
  if(!cst) return;
  const f=connFlowFor(cn), cs=f.stats;
  if(!cs){ cst.innerHTML='<tbody><tr><td class="empty">単体起動では表示できません(統合起動 python waf.py で表示)</td></tr></tbody>'; if(csince) csince.textContent=''; return; }
  if(csince) csince.textContent=(cs.since?('(開始 '+String(cs.since).replace('T',' ')+')'):'')+(slSel?' ・ 選択した接続先の分':'');
  const n=v=>(v||0).toLocaleString();
  const R=(label,val,note,hot)=>`<tr><td>${label}</td><td style="text-align:right"><b class="${hot?'conn-n hot':''}">${n(val)}</b></td><td class="seemore">${note||''}</td></tr>`;
  const dash=(label,note)=>`<tr><td>${label}</td><td style="text-align:right"><b>-</b></td><td class="seemore">${note||''}</td></tr>`;
  const C=(label,key,note,hot)=>f.noConn?dash(label,'共有ポートのため分けられません'):R(label,cs[key],note,hot&&cs[key]>0);
  cst.innerHTML='<tbody>'
    +(f.note?`<tr><td colspan="3" class="seemore">${esc(f.note)}</td></tr>`:'')
    +C('受理した接続','accepted','ゲートを通過した接続')
    +(f.noConn?dash('ゲートで遮断した接続(計)','共有ポートのため分けられません'):R('ゲートで遮断した接続(計)',cs.gate_total,'TLS握手より前に切った分(暗号計算なし)',cs.gate_total>0))
    +C('　BAN中の送信元','gate_ban','')
    +C('　接続頻度で新規BAN','gate_conn_flood','握手/接続フラッド対策が発動した回数',true)
    +(f.noConn?dash('　同時接続数の上限超過','共有ポートのため分けられません'):R('　同時接続数の上限超過',(cs.gate_conn_limit||0)+(cs.gate_overload||0),'IPごと/全体の上限'))
    +C('　手動ブロックリスト','gate_blocklist','')
    +C('　遮断中でも /health だけ答えた回数','lane_ok','予算内の通路で受け入れ、/health だけ返した回数')
    +C('　　うち /health 以外で切断','lane_other','通路では /health 以外は何も返しません')
    +C('TLS握手 成功','tls_ok','')
    +C('TLS握手 失敗/タイムアウト','tls_fail','waf.log には残りません',true)
    +C('リクエストなしで終わった接続','no_request','接続だけ/ゴミ/握手後の無言。waf.log には残りません',true)
    +C('　うち WAF のタイムアウトで切断','idle_timeout','Slowloris 等')
    +C('受付(accept)エラー','accept_error','待受キューあふれ/FD枯渇などの兆候。0が正常',true)
    +C('不正なHTTPリクエスト','bad_request','400系。waf.log には残りません',true)
    +R('処理したHTTPリクエスト',cs.requests,'通過/遮断/レート制限を問わず解析できた件数')
    +'</tbody>';
}
function addBlockIP(ip){
  if(!ip) return;
  if(!confirm(ip+' を手動ブロックリストに追加します。よろしいですか?')) return;
  secPost('/api/security/block',{ip});
}
const IP_BE_MAP={block:['blocklist','add'],unblock:['blocklist','remove'],allow:['ip_allowlist','add'],unallow:['ip_allowlist','remove'],
  blockcountry:['country_blocklist','add'],unblockcountry:['country_blocklist','remove'],allowcountry:['country_allowlist','add'],unallowcountry:['country_allowlist','remove']};
function secPost(url, body){
  const m=/^\/api\/security\/([a-z]+)$/.exec(url);
  if(IP_BE&&m&&IP_BE_MAP[m[1]]){
    const [kind,op]=IP_BE_MAP[m[1]];
    url='/api/security/bepolicy'; body={backend:IP_BE,kind:kind,op:op,value:(body.ip!==undefined?body.ip:body.country)};
  }
  return fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify(body||{})}).then(r=>r.json()).then(res=>{
      if(res.security) renderSecurity(res.security);
      else if(res.error) alert('エラー: '+res.error);
    });
}
function addBlock(){
  const el=document.getElementById('ipInput'); const ip=el.value.trim();
  if(!ip) return;
  secPost('/api/security/block',{ip}).then(()=>{ el.value=''; });
}
function unblockIP(ip){ secPost('/api/security/unblock',{ip}); }
const BAN_REASON={rate:'レート超過',burst:'バースト',conn_flood:'接続頻度(握手/接続フラッド)',manual:'手動',
  attack:'攻撃の繰り返し',slow:'低速接続(Slowloris)',connlimit:'同時接続上限の繰り返し超過'};
function extendBan(ip){ secPost('/api/security/extend',{ip,minutes:10}); }
function addBan(){
  const ip=document.getElementById('banIp').value.trim(), m=parseInt(document.getElementById('banMin').value||'60',10);
  if(!ip) return;
  secPost('/api/security/ban',{ip,minutes:m}).then(()=>{ document.getElementById('banIp').value=''; });
}
function addAllow(){
  const el=document.getElementById('allowInput'), ip=el.value.trim(); if(!ip) return;
  if(!confirm(ip+' を許可リストに追加します。\n許可リストに1件でも登録すると、'+(IP_BE?'このバックエンドは':'')+'登録外のIPからのアクセスは全て拒否されます。よろしいですか?')) return;
  secPost('/api/security/allow',{ip}).then(()=>{ el.value=''; });
}
function unallowIP(ip){ secPost('/api/security/unallow',{ip}); }
function addExempt(){
  const el=document.getElementById('exemptInput'), ip=el.value.trim(); if(!ip) return;
  secPost('/api/security/exempt',{ip}).then(()=>{ el.value=''; });
}
function unexemptIP(ip){ secPost('/api/security/unexempt',{ip}); }
function unbanIP(ip){ secPost('/api/security/unban',{ip}); }
function clearBans(){ secPost('/api/security/clearbans',{}); }
// 国リスト(ISO 3166-1 alpha-2 + 日本語名)。送信は国コード。/api/countries(249か国)で置き換える
let COUNTRIES=[
 ['JP','日本'],['US','アメリカ合衆国'],['CN','中国'],['KR','韓国'],['TW','台湾'],['HK','香港'],
 ['RU','ロシア'],['GB','イギリス'],['DE','ドイツ'],['FR','フランス'],['NL','オランダ'],['IT','イタリア'],
 ['ES','スペイン'],['SE','スウェーデン'],['CH','スイス'],['UA','ウクライナ'],['PL','ポーランド'],['RO','ルーマニア'],
 ['IN','インド'],['ID','インドネシア'],['VN','ベトナム'],['TH','タイ'],['PH','フィリピン'],['MY','マレーシア'],
 ['SG','シンガポール'],['PK','パキスタン'],['BD','バングラデシュ'],['IR','イラン'],['TR','トルコ'],['SA','サウジアラビア'],
 ['AE','アラブ首長国連邦'],['IL','イスラエル'],['CA','カナダ'],['BR','ブラジル'],['MX','メキシコ'],['AR','アルゼンチン'],
 ['AU','オーストラリア'],['NZ','ニュージーランド'],['ZA','南アフリカ'],['NG','ナイジェリア'],['EG','エジプト'],
 ['KZ','カザフスタン'],['BG','ブルガリア'],['CZ','チェコ'],['FI','フィンランド'],['NO','ノルウェー'],['DK','デンマーク'],
 ['BE','ベルギー'],['AT','オーストリア'],['IE','アイルランド'],['PT','ポルトガル'],['GR','ギリシャ'],['HU','ハンガリー']
];
let COUNTRY_EN={};
function initCountrySelect(){
  const dl=document.getElementById('countryOpts'); if(!dl||dl.dataset.ready) return;
  dl.dataset.ready='1';
  const fill=()=>{ dl.innerHTML=COUNTRIES.map(([cc,nm])=>`<option value="${esc(nm)} (${cc})">${esc(COUNTRY_EN[cc]||'')}</option>`).join(''); };
  fill();
  fetch('/api/countries').then(r=>r.json()).then(d=>{
    const cs=d.countries||[]; if(!cs.length) return;
    COUNTRIES=cs.map(c=>[c.code,c.ja]); cs.forEach(c=>{ COUNTRY_EN[c.code]=c.en; }); fill();
    if(window.__lastSec) renderSecurity(window.__lastSec);
  }).catch(()=>{});
}
function countryCode(text){
  const t=String(text||'').trim(); if(!t) return '';
  const m=t.match(/\(([A-Za-z]{2})\)\s*$/); if(m) return m[1].toUpperCase();
  if(/^[A-Za-z]{2}$/.test(t)) return t.toUpperCase();
  const low=t.toLowerCase();
  const f=COUNTRIES.find(([cc,nm])=>nm===t || (COUNTRY_EN[cc]||'').toLowerCase()===low)
       || COUNTRIES.find(([cc,nm])=>nm.indexOf(t)>=0 || (COUNTRY_EN[cc]||'').toLowerCase().indexOf(low)>=0);
  return f?f[0]:'';
}
function addCountry(){ countryOp('/api/security/blockcountry'); }
function addAllowCountry(){
  if(!confirm('許可リストに国を登録すると、登録外の国からのアクセスは全て拒否されます。よろしいですか?')) return;
  countryOp('/api/security/allowcountry');
}
function countryOp(url){
  const el=document.getElementById('countryInput'); const country=countryCode(el.value);
  if(!country){ alert('国が見つかりません。候補から選ぶか、国コード(例: CN)を入力してください。'); return; }
  secPost(url,{country}).then(()=>{ el.value=''; });
}
function unblockCountry(country){ secPost('/api/security/unblockcountry',{country}); }
function unallowCountry(country){ secPost('/api/security/unallowcountry',{country}); }
function ccName(c){ const f=COUNTRIES.find(x=>x[0]===String(c).toUpperCase()); return f?f[1]+' ('+f[0]+')':c; }

/* 攻撃の時間帯ヒートマップ(self_made_waf 由来) */
let HM_RANGE='7d';
function renderHeatmap(){
  const el=document.getElementById('heatmap'); if(!el) return;
  const cells=(window.__heat||{})[HM_RANGE]||[];
  const grid={}; let mx=0;
  cells.forEach(([w,h,n])=>{ grid[w+'-'+h]=n; if(n>mx) mx=n; });
  const days=['月','火','水','木','金','土','日'];
  let html='<table class="hm"><thead><tr><th></th>';
  for(let h=0;h<24;h++) html+=`<th>${h}</th>`;
  html+='<th>計</th></tr></thead><tbody>';
  for(let w=0;w<7;w++){
    html+=`<tr><th>${days[w]}</th>`; let sum=0;
    for(let h=0;h<24;h++){
      const n=grid[w+'-'+h]||0; sum+=n;
      const a=mx?Math.max(0.08,n/mx):0;
      html+=`<td title="${days[w]}曜 ${h}時台: ${n}件" style="${n?`background:rgba(227,73,72,${a.toFixed(2)})`:''}">${n?(n>999?Math.round(n/1000)+'k':n):''}</td>`;
    }
    html+=`<td class="hm-sum">${sum}</td></tr>`;
  }
  html+='</tbody></table>';
  el.innerHTML = mx ? html : '<div class="empty">この期間の攻撃(遮断/検知)はありません</div>';
}
document.addEventListener('click',ev=>{
  const b=ev.target.closest('#hmSeg button'); if(!b) return;
  document.querySelectorAll('#hmSeg button').forEach(x=>x.classList.toggle('on',x===b));
  HM_RANGE=b.dataset.v; renderHeatmap();
});
/* ユーザーメニュー(アカウント設定・ログアウト) */
function umClose(){ const m=document.getElementById('umMenu'),c=document.getElementById('userChip'); if(m) m.hidden=true; if(c) c.setAttribute('aria-expanded','false'); }
document.addEventListener('click',ev=>{
  const c=ev.target.closest('#userChip');
  if(c){ const m=document.getElementById('umMenu'); const open=m.hidden; m.hidden=!open; c.setAttribute('aria-expanded',open?'true':'false'); return; }
  if(ev.target.closest('#umAcc')){ umClose(); openAccountDlg(); return; }
  if(!ev.target.closest('#umMenu')||ev.target.closest('#umMenu button')) umClose();
});
document.addEventListener('keydown',ev=>{ if(ev.key==='Escape') umClose(); });
function openAccountDlg(){
  if(!AUTH.user) return;
  if(!AUTH.officer){ showPage('settings'); setTimeout(()=>{ try{ showSetTab('account'); }catch(e){} },400); return; }   // キー・オフィサーは設定画面に入れないので、パスワード変更だけの小さなダイアログを出す
  const ov=document.createElement('div'); ov.className='dlg-ov';
  ov.innerHTML='<div class="dlg" style="max-width:480px"><h3>アカウント設定</h3><div class="dlg-b" id="accDlgB"></div><div class="dlg-f"><button type="button" id="accDlgX">閉じる</button></div></div>';
  document.body.appendChild(ov);
  ov.querySelector('#accDlgB').innerHTML=accountHtml().replace('<div class="set-group"><h4>アカウント</h4>','<div>');
  accountInit();
  const close=()=>ov.remove();
  ov.querySelector('#accDlgX').onclick=close; ov.addEventListener('mousedown',e=>{ if(e.target===ov) close(); });
}
/* ログアウト(パスワード認証ありのとき) */
fetch('/api/auth').then(r=>r.json()).then(a=>{
  if(a.enabled){ ['logoutBtn','umSep2'].forEach(id=>{ const e=document.getElementById(id); if(e) e.hidden=false; }); }
  AUTH.enabled=!!a.enabled; AUTH.user=a.user||null; try{ alMerge(); }catch(e){}
  if(a.user){
    const c=document.getElementById('userChip');
    if(c){ if(a.user.role==='key_officer'){ const ua=document.getElementById('umAcc'); if(ua) ua.hidden=false; } { const rl=a.user.role==='admin'?'管理者':(a.user.role==='analyst'?'アナリスト':(a.user.role==='key_officer'?'キー・オフィサー':'一般')), dn=a.user.display||a.user.username; c.innerHTML=`<b>${esc(dn)}</b>${dn.indexOf(rl)>=0?'':`<small>${rl}</small>`}`; } }
    if(a.user.role==='key_officer'){ AUTH.officer=true; AUTH.limited=true; AUTH.guser=true; document.body.classList.add('limited','guser','kofficer'); showPage('enc'); }
    else if(a.user.role==='analyst'){ AUTH.analyst=true; AUTH.limited=true; document.body.classList.add('analyst','limited'); }
    else if(a.user.role!=='admin'){ AUTH.limited=true; AUTH.guser=true; document.body.classList.add('limited','guser');
      if(['rules'].includes(curPage)) showPage('home'); }
    else { loadAuthUsers(); loadOrgs(); }
    if(a.user.role==='admin'||a.user.role==='key_officer'){ const eb=document.getElementById('navEnc'); if(eb) eb.hidden=false; }
    if(a.user.role!=='key_officer'){ tkBadgeLoad(); setInterval(tkBadgeLoad,10000); }
  }
}).catch(()=>{});
function loadAuthUsers(){
  fetch('/api/users',{cache:'no-store'}).then(r=>r.ok?r.json():null).then(d=>{ if(d&&d.users) AUTH.users=d.users; }).catch(()=>{});
}

/* テーマ(ダーク/ライト) */
function applyTheme(t){
  document.documentElement.setAttribute('data-theme', t);
  const b=document.getElementById('themeBtn');
  if(b) b.textContent = t==='light' ? '☀ ライト' : '🌙 ダーク';
}
(function initTheme(){
  let t='dark';
  try{ t=localStorage.getItem('waf-theme')||'dark'; }catch(e){}
  applyTheme(t);
})();
/* 状態ログ(タブ) */
const SL_LABEL={paused:'稼働停止中',up:'稼働中',slow:'遅い',error:'異常応答(5xx)',down:'ダウン',unknown:'未確認',stopped:'監視停止(WAF停止中)'};
const SL_TNAME={process:'WAFプロセス',waf:'WAF待受ポート',backend:'接続先アプリ'};
let slData=null, slTimer=null, slSel='';
function slDur(sec){
  if(sec==null) return '—';
  if(sec<60) return sec+'秒';
  const m=Math.floor(sec/60), h=Math.floor(m/60), d=Math.floor(h/24);
  if(d>0) return d+'日'+(h%24)+'時間';
  if(h>0) return h+'時間'+(m%60)+'分';
  return m+'分'+(sec%60)+'秒';
}
const slChip=st=>`<span class="sl-chip sl-${esc(st)}"><span class="sl-dot"></span>${esc(SL_LABEL[st]||st)}</span>`;
function slCounts(c){
  const order=['up','slow','error','down','paused','unknown'], parts=order.filter(k=>c[k]).map(k=>`${SL_LABEL[k]} ${c[k]}件`);
  return '全 '+c.total+' 件: '+(parts.join(' / ')||'記録なし');
}
const slPct=v=>v==null?'—':v.toFixed(2)+' %';
const slFmt=t=>(t||'').replace('T',' ');
function slRender(){
  const d=slData; if(!d) return;
  if(!AUTH.limited) renderConnFlow();
  document.getElementById('slUpd').textContent='— 更新 '+slFmt(d.now)+'(5秒ごとに自動更新)';
  // 接続先の選択肢(登録済みのバックエンド)
  const sel=document.getElementById('slSel'), bl=d.backends||[];
  scOrgFill('sl','slOrg');
  scBeFill('sl',sel,bl.map(b=>({id:b.id,name:b.label})),'すべての接続先');
  slSel=SC.sl.be;
  const one=slSel?bl.find(b=>b.id===slSel):null;
  document.getElementById('slPickNote').textContent=(one||SC.sl.org)?'選んだ組織・接続先だけの状態・履歴を表示しています':'';
  const card=(s,big)=>`
    <div class="card sl-card sl-${esc(s.state)}"><h2>${esc(s.label)}</h2>
      <div class="sl-state sl-big"><span class="sl-dot"></span>${big||esc(SL_LABEL[s.state]||s.state)}</div>
      ${s.counts?`<div class="sl-sub">${slCounts(s.counts)}</div>`:`<div class="sl-sub">${s.since?esc(slFmt(s.since))+' から':'記録なし'}</div>`}
      <div class="sl-kv"><span>稼働率(24時間)</span><b>${slPct(s.uptime_24h)}</b></div>
      <div class="sl-kv"><span>稼働率(7日)</span><b>${slPct(s.uptime_7d)}</b></div>
      <div class="sl-kv"><span>ダウン/異常の回数(24時間)</span><b>${s.downs_24h} 回</b></div>
    </div>`;
  let agg=d.summary.backend;
  if(!one && SC.sl.org){          // 組織を選んだら、その組織の接続先だけで集計し直す
    const f=bl.filter(b=>scIn('sl',b.id)), c={total:f.length};
    f.forEach(b=>{ c[b.state]=(c[b.state]||0)+1; });
    const worst=['down','error','slow','up','paused','unknown'].find(st=>c[st])||'unknown';
    const avg=k=>{ const v=f.map(b=>b[k]).filter(x=>x!=null); return v.length?v.reduce((a,b)=>a+b,0)/v.length:null; };
    agg={label:agg.label,state:worst,counts:c,since:null,uptime_24h:avg('uptime_24h'),uptime_7d:avg('uptime_7d'),downs_24h:f.reduce((a,b)=>a+(b.downs_24h||0),0),timeline:[]};
  }
  const cn=agg.counts||{total:0};
  const bad=(cn.down||0)+(cn.error||0);
  const aggBig = bad>0 ? `ダウン/異常 ${bad}件<small>/ 全${cn.total}件</small>`
    : (cn.slow? `遅い ${cn.slow}件<small>/ 全${cn.total}件</small>`
    : (cn.total? `全${cn.total}件 ${esc(SL_LABEL[agg.state]||agg.state)}` : esc(SL_LABEL[agg.state]||agg.state)));
  document.getElementById('slCards').innerHTML=
    (d.summary.process?card(d.summary.process)+card(d.summary.waf):'')+(one?card(one):card(agg,aggBig));
  const end=new Date(d.now).getTime(), start=end-d.window_hours*3600e3, span=end-start;
  const tlRows=(d.summary.process?[['WAFプロセス',d.summary.process],['WAF待受ポート',d.summary.waf]]:[]).concat((one?[one]:bl.filter(b=>scIn('sl',b.id))).map(b=>[b.label,b]));
  document.getElementById('slTl').innerHTML=tlRows.map(([lab,sm])=>{
    const segs=(sm.timeline||[]).map(g=>{
      const a=Math.max(start,new Date(g.from).getTime()), b=Math.min(end,new Date(g.to).getTime());
      if(b<=a) return '';
      const l=((a-start)/span*100).toFixed(3), w=Math.max(0.15,(b-a)/span*100).toFixed(3);
      return `<i class="sl-${esc(g.state)}" style="left:${l}%;width:${w}%" title="${esc(SL_LABEL[g.state]||g.state)}: ${esc(slFmt(g.from))} 〜 ${esc(slFmt(g.to))}"></i>`;
    }).join('');
    return `<div class="lab" title="${esc(lab)}">${esc(lab)}</div><div class="sl-bar">${segs}</div>`; }).join('');
  const hh=t=>{ const x=new Date(t); return (x.getMonth()+1)+'/'+x.getDate()+' '+String(x.getHours()).padStart(2,'0')+':00'; };
  document.getElementById('slAx0').textContent=hh(start);
  document.getElementById('slAx1').textContent=hh(start+span/2);
  document.getElementById('slAx2').textContent=hh(end)+'(現在)';
  document.getElementById('slLegend').innerHTML=['up','slow','down','error','paused','stopped','unknown'].map(st=>
    `<span><span class="sl-dot sl-${st}"></span>${SL_LABEL[st]}</span>`).join('');
  const ft=document.getElementById('slfTarget'); if(ft.options.length<2) Object.keys(SL_TNAME).forEach(k=>ft.add(new Option(SL_TNAME[k],k)));
  const fs=document.getElementById('slfState'); if(fs.options.length<2) ['up','slow','down','error','paused','unknown'].forEach(k=>fs.add(new Option(SL_LABEL[k],k)));
  slRenderRows();
}
function slRenderRows(){
  const d=slData; if(!d) return;
  const t=document.getElementById('slfTarget').value, st=document.getElementById('slfState').value;
  const q=document.getElementById('slfText').value.trim().toLowerCase();
  const rows=d.events.filter(e=>(e.target!=='backend'||scIn('sl',e.backend))&&(!t||e.target===t)&&(!st||e.to===st||e.from===st)&&
    (!q||(e.detail||'').toLowerCase().includes(q)||e.ts.toLowerCase().includes(q)||(e.backend_name||SL_TNAME[e.target]||'').toLowerCase().includes(q)));
  document.getElementById('slCnt').textContent=rows.length+' 件 / 全 '+d.total_events+' 件';
  document.getElementById('slTb').innerHTML=rows.length?rows.map(e=>`<tr>
    <td>${esc(slFmt(e.ts))}</td><td>${esc(e.backend_name||SL_TNAME[e.target]||e.target)}</td>
    <td>${slChip(e.from)}<span class="sl-arrow">→</span>${slChip(e.to)}</td>
    <td>${e.ongoing?'<b>継続中</b> ':''}${esc(slDur(e.duration_sec))}</td>
    <td class="d adm-only">${esc(e.detail)}</td></tr>`).join(''):'<tr><td colspan="${AUTH.limited?4:5}" class="sl-empty">該当する履歴はありません</td></tr>';
}

/* 申請(チケット) */
let TK=null, TK_DRAFT=null, TK_OPEN={}, TK_MSG='', TK_ALL=false;
function tkDraftFrom(){
  const e=window.__detailEv; if(!e) return;
  TK_DRAFT={backend:e.backend||'', evidence:{ts:e.ts,method:e.method,path:e.path,query:(e.req&&e.req.query)||e.query||'',backend:e.backend,client_ip:e.client_ip||e.ip||'',action:e.action,
    hits:(e.hits||[]).map(h=>({id:h.id,severity:h.severity,field:h.field,description:h.description,matched:h.matched}))},
    subject:'誤検知の除外申請: '+((e.hits||[])[0]?e.hits[0].id:'')+' '+(e.path||'')};
  closeDetailIfAny(); showPage('tickets');
}
function closeDetailIfAny(){ const m=document.getElementById('modal'); if(m) m.classList.remove('open'); encWipe(); }
function tkBadgeLoad(){
  if(!AUTH.user) return;
  fetch('/api/tickets',{cache:'no-store'}).then(r=>r.ok?r.json():null).then(d=>{
    const b=document.getElementById('tkBadge'); if(!b||!d) return;
    const adm=d.role==='admin'||d.role==='analyst';
    const n=(d.tickets||[]).filter(t=>t.kind!=='log_review'&&(t.kind!=='decrypt'||t.can_approve)).filter(t=>adm?(d.role==='admin'?(t.stage!=='analyst'&&(t.status==='open'||t.status==='escalated')):t.status==='open'):(t.status==='done'||t.status==='rejected')&&!TK_OPEN[t.id]&&false).length;
    b.textContent=n; b.hidden=!n;
  }).catch(()=>{});
}
function tkSig(d){ const m={}; (d.tickets||[]).forEach(t=>{ m[t.id]=[t.status,t.updated,(t.comments||[]).length,t.resolution||'',t.stage||'',t.handler||''].join('|'); }); return m; }
let TK_FLASH={};
/* 申請の一覧を5秒ごとに取り直し、状態やコメントが変わった分だけ更新する。入力中の欄と開いている申請はそのまま */
function tkPoll(){
  if(curPage!=='tickets'||!TK||document.hidden) return;
  if(typeof auto!=='undefined'&&!auto) return;
  fetch('/api/tickets',{cache:'no-store'}).then(r=>r.ok?r.json():null).then(d=>{
    if(!d||curPage!=='tickets'||!TK) return;
    const ns=tkSig(d), os=TK.sig||{}, ch=Object.keys(ns).filter(id=>os[id]!==ns[id]);
    if(!ch.length&&Object.keys(os).length===Object.keys(ns).length) return;
    TK.d=d; TK.sig=ns; ch.forEach(id=>{ TK_FLASH[id]=Date.now(); });
    const keep={}; document.querySelectorAll('#tkList input[id],#tkList select[id]').forEach(i=>{ keep[i.id]=i.value; });
    const act=document.activeElement&&document.activeElement.id;
    renderTicketList();
    Object.keys(keep).forEach(k=>{ const i=document.getElementById(k); if(i) i.value=keep[k]; });
    if(act){ const i=document.getElementById(act); if(i) i.focus(); }
    const lv=document.getElementById('tkLive'); if(lv){ lv.textContent='● '+ch.length+'件の申請が更新されました('+new Date().toLocaleTimeString()+')'; lv.hidden=false; }
    tkBadgeLoad();
  }).catch(()=>{});
}
setInterval(tkPoll,5000);
function openTickets(){
  Promise.all([fetch('/api/tickets',{cache:'no-store'}).then(r=>r.json()),
               fetch('/api/security',{cache:'no-store'}).then(r=>r.ok?r.json():{backends:[]}).catch(()=>({backends:[]}))])
    .then(([d,sec])=>{ TK={d,sec,sig:tkSig(d)}; renderTicketForm(); renderTicketList(); const lv=document.getElementById('tkLive'); if(lv) lv.hidden=true; })
    .catch(()=>{ document.getElementById('tkList').innerHTML='<div class="hempty">取得できません</div>'; });
}
function tkKindsFor(role){
  const k=TK.d.kinds||{};
  const allow=role==='analyst'?['rule_proposal','inquiry','false_positive','log_review']:(role==='admin'?[]:['false_positive','inquiry','mode_unlock']);
  return allow.filter(x=>k[x]).map(x=>[x,k[x]]);
}
function renderTicketForm(){
  const el=document.getElementById('tkForm'); if(!el||!TK) return;
  const role=TK.d.role, bl=TK.sec.backends||[], dr=TK_DRAFT||{};
  const card=el.closest('.card'); if(card) card.style.display=(role==='admin')?'none':'';     // 管理者は申請を受ける側なので、申請フォームは出さない
  if(role==='admin'){ el.innerHTML=''; return; }
  const kinds=tkKindsFor(role);
  const kindSel=dr.evidence?'false_positive':kinds[0][0];
  el.innerHTML=`<div class="tk-form">
    <label>種類</label><select id="tkKind" onchange="tkKindChanged()">${kinds.map(([v,l])=>`<option value="${esc(v)}" ${v===kindSel?'selected':''}>${esc(l)}</option>`).join('')}</select>
    <label>接続先</label><select id="tkBe"><option value="">(指定なし)</option>${bl.map(b=>`<option value="${esc(b.id)}" ${b.id===dr.backend?'selected':''}>${esc(b.name)}</option>`).join('')}</select>
    <label>件名</label><input id="tkSubj" maxlength="120" value="${esc(dr.subject||'')}" placeholder="例: 記事投稿で遮断される(誤検知の除外をお願いします)">
    <label>内容</label><textarea id="tkBody" maxlength="2000" placeholder="何をしたときに、どうなったか。業務への影響や急ぎの度合いがあれば書いてください。"></textarea>
    ${dr.evidence?`<label>対象の通信</label><div class="tk-ev">${esc((dr.evidence.method||'')+' '+(dr.evidence.path||''))}${dr.evidence.query?'?'+esc(dr.evidence.query):''}<br>${(dr.evidence.hits||[]).map(h=>esc(h.id)+'('+esc(h.field||'')+')').join(' / ')}<br><span class="seemore">この通信の要点(ヘッダー・本文は含みません)が申請に添付されます。</span></div>`:''}
    <span></span><div><button type="button" onclick="tkSubmit()">申請する</button> <span class="seemore" id="tkMsg" style="${TK_MSG.startsWith('エラー')||TK_MSG==='通信エラー'?'color:var(--block)':'color:var(--pass,#1f9d55);font-weight:600'}">${esc(TK_MSG)}</span>${dr.evidence?` <button type="button" onclick="TK_DRAFT=null;renderTicketForm()">添付を外す</button>`:''}</div>
  </div>`;
}
function tkKindChanged(){
  const k=(document.getElementById('tkKind')||{}).value, s=document.getElementById('tkSubj'), b=document.getElementById('tkBody'); if(!s||!b) return;
  if(k==='log_review'){ s.placeholder='例: 10/20 のA社サイトへの不審なアクセスの中身を確認してほしい'; b.placeholder='確認してほしい期間・IP・パスと、調べたい目的を書いてください。接続先は必ず選びます。暗号化ログの復号は、キー・オフィサーが申請し、お客様側の担当者が承認します。'; }
  else { s.placeholder='例: 記事投稿で遮断される(誤検知の除外をお願いします)'; b.placeholder='何をしたときに、どうなったか。業務への影響や急ぎの度合いがあれば書いてください。'; }
}
function tkSubmit(){
  const v=id=>document.getElementById(id).value;
  const body={kind:v('tkKind'),backend:v('tkBe'),subject:v('tkSubj'),body:v('tkBody')};
  if(TK_DRAFT&&TK_DRAFT.evidence) body.evidence=TK_DRAFT.evidence;
  const m=document.getElementById('tkMsg');
  postJSON('/api/tickets',body).then(r=>{
    if(r.ok){ TK_DRAFT=null; TK_MSG='✓ 申請しました('+((r.ticket||{}).id||'')+')'; TK_OPEN[(r.ticket||{}).id]=true; openTickets(); setTimeout(()=>{ TK_MSG=''; const x=document.getElementById('tkMsg'); if(x) x.textContent=''; },6000); }
    else { TK_MSG='エラー: '+(r.error||'失敗'); m.textContent=TK_MSG; m.style.color='var(--block)'; }
  }).catch(()=>{ TK_MSG='通信エラー'; m.textContent=TK_MSG; });
}
function renderTicketList(){
  const el=document.getElementById('tkList'); if(!el||!TK) return;
  const all0=TK.d.tickets||[], role=TK.d.role, adm=role==='admin', ana=role==='analyst', st=TK.d.statuses||{}, kinds=TK.d.kinds||{};
  /* 管理者は、担当アナリストが一次対応中のものを初期表示で畳む。管理者宛て・アナリスト自身の申請・担当アナリストのいない組織の申請は前に出る */
  const hidden=adm?all0.filter(t=>t.stage==='analyst'):[];
  const ts=(adm&&!TK_ALL)?all0.filter(t=>t.stage!=='analyst'):all0;
  const bar=adm&&hidden.length?`<div class="tk-hid"><span class="seemore">アナリストが一次対応中の申請が ${hidden.length} 件あります${TK_ALL?'(表示中)':'(非表示)'}</span><button type="button" class="hbtn" onclick="TK_ALL=!TK_ALL;renderTicketList()">${TK_ALL?'管理者対応のものだけ表示':'すべて表示'}</button></div>`:'';
  if(!ts.length){ el.innerHTML=bar+'<div class="hempty">'+(adm&&hidden.length?'管理者の対応が必要な申請はありません':'申請はまだありません')+'</div>'; return; }
  el.innerHTML=bar+ts.map(t=>{
    const ev=t.evidence||{};
    const hitIds=(ev.hits||[]).map(h=>h.id).filter((x,i,a)=>a.indexOf(x)===i);
    const cm=(t.comments||[]).map(c=>`<div class="tk-cm"><b>${esc(c.by)}</b> <span class="seemore">${esc((c.at||'').replace('T',' '))}</span><br>${esc(c.text)}</div>`).join('');
    const evh=ev.path?`<div class="tk-ev">${esc((ev.method||'')+' '+ev.path)}${ev.query?'?'+esc(ev.query):''}<br>${(ev.hits||[]).map(h=>esc(h.id)+'['+esc(h.field||'')+'] '+esc(h.matched||'')).join('<br>')}</div>`:'';
    const prop=(t.proposal&&t.proposal.rule)?`<p><b>提案:</b> ${t.proposal.op==='exclude'?`パス <code>${esc(t.proposal.path_prefix)}</code> でルール <code>${esc(t.proposal.rule)}</code> を使わない設定にする(${t.proposal.minutes?Math.round(t.proposal.minutes/1440)+'日間':'無期限'})`:`このバックエンドでルール <code>${esc(t.proposal.rule)}</code> を使わない設定にする`}</p>`:'';
    const adminAct=adm?`<div class="tk-act">
        <select id="tkR-${esc(t.id)}">${hitIds.map(x=>`<option>${esc(x)}</option>`).join('')}<option value="*">すべてのルール(*)</option></select>
        <input id="tkP-${esc(t.id)}" size="22" value="${esc(ev.path||'')}" placeholder="除外するパス(例: /editor)">
        <select id="tkM-${esc(t.id)}"><option value="1440">1日</option><option value="10080">7日</option><option value="43200">30日</option><option value="0">無期限</option></select>
        <select id="tkMo-${esc(t.id)}"><option value="detect">このパスでは検知のみ</option><option value="off">このパスでは使わない</option></select>
        <button onclick="tkApprove('${esc(t.id)}')" ${t.backend?'':'disabled'}>承認してパス別の設定を追加</button>
        ${(t.proposal&&t.proposal.rule&&t.status!=='done')?`<button onclick="tkApproveDisable('${esc(t.id)}')">承認して提案を反映する</button>`:''}
        <button onclick="tkStatus('${esc(t.id)}','in_progress')">対応中</button>
        <button onclick="tkStatus('${esc(t.id)}','done')">完了</button>
        <button onclick="tkStatus('${esc(t.id)}','rejected')">却下</button></div>`:'';
    const open_=!['done','rejected'].includes(t.status);
    const anaAct=(ana&&t.status!=='escalated')?`<div class="tk-act">
        <select id="tkR-${esc(t.id)}">${hitIds.map(x=>`<option>${esc(x)}</option>`).join('')}<option value="*">すべてのルール(*)</option></select>
        <input id="tkP-${esc(t.id)}" size="22" value="${esc(ev.path||'')}" placeholder="対象のパス(例: /editor)">
        <select id="tkM-${esc(t.id)}"><option value="1440">1日</option><option value="10080">7日</option><option value="43200">30日</option><option value="0">無期限</option></select>
        <input type="hidden" id="tkMo-${esc(t.id)}" value="detect">
        <button onclick="tkApprove('${esc(t.id)}')" ${t.backend?'':'disabled'} title="アナリストは「検知のみ」まで設定できます">このパスでは検知のみにして完了</button>
        <button onclick="tkStatus('${esc(t.id)}','in_progress')">対応中</button>
        <button onclick="tkStatus('${esc(t.id)}','done')">完了</button>
        <button onclick="tkStatus('${esc(t.id)}','rejected')">却下</button></div>
      ${open_?`<div class="tk-act"><input id="tkE-${esc(t.id)}" size="44" placeholder="管理者へ依頼する理由(必須)"><button onclick="tkEscalate('${esc(t.id)}')">管理者へ依頼</button></div>
      <div class="tk-act"><input id="tkK-${esc(t.id)}" size="44" placeholder="キー・オフィサーへ依頼する理由(必須)" ${t.backend?'':'disabled'}><button onclick="tkToKo('${esc(t.id)}')" ${t.backend?'':'disabled'} title="暗号化ログの中身の確認が必要なとき。ログの確認依頼がキー・オフィサーに届きます">キー・オフィサーへ依頼</button></div>`:''}`
      :((ana&&t.status==='escalated')?'<div class="seemore" style="margin-top:6px">管理者へ依頼中です。管理者が対応すると状態が更新されます。</div>':'');
    const dec=t.kind==='decrypt', gr=t.grant||{};
    const decInfo=dec?`<p><b>復号の対象:</b> ${esc((gr.from||'').replace('T',' '))} 〜 ${esc((gr.to||'').replace('T',' '))}(接続先 ${esc(t.backend)})${t.enc_count!=null&&t.enc_count!==undefined?`<br><b>この期間の暗号化ログ:</b> ${t.enc_count} 件(承認すると、この件数すべてを申請者が復号できます)`:''}${t.org?`<br><b>組織:</b> ${esc(t.org)}`:''}${gr.approved_by?`<br><b>承認:</b> ${esc(gr.approved_by)} / ${esc((gr.until||'').replace('T',' '))} まで有効`:''}</p>`:'';
    const decAct=(dec&&t.can_approve)?`<div class="tk-act"><span class="seemore">この期間のログを、キー・オフィサー(${esc(t.by)})が復号することを承認しますか?</span>
        <select id="tkH-${esc(t.id)}"><option value="1">1時間</option><option value="8">8時間</option><option value="24" selected>24時間</option><option value="72">72時間</option><option value="168">7日</option></select>
        <button onclick="tkDecide('${esc(t.id)}',true)">承認する</button><button onclick="tkDecide('${esc(t.id)}',false)">却下する</button></div>`:(dec&&open_?'<div class="seemore" style="margin-top:6px">その組織側の担当者(一般ユーザー・アナリスト)の承認を待っています。</div>':'');
    const rv=t.kind==='log_review';
    const rvNote=rv?`<div class="seemore" style="margin-top:6px">${open_?'キー・オフィサーが対応します。必要なら、お客様側の承認を受けて復号します。':'対応済みです。'}</div>`:'';
    const stageNote=rv?'キー・オフィサー対応':dec?'':(t.stage==='analyst'?'アナリスト対応':(t.escalated_by?'管理者対応(依頼: '+esc(t.escalated_by)+')':''));
    return `<div class="tk-item ${TK_OPEN[t.id]?'open':''} ${(TK_FLASH[t.id]&&Date.now()-TK_FLASH[t.id]<4000)?'flash':''}" id="tk-${esc(t.id)}">
      <div class="tk-head" onclick="tkToggle('${esc(t.id)}')"><span class="id">${esc(t.id)}</span><span class="tk-st ${esc(t.status)}">${esc(st[t.status]||t.status)}</span>
        <span>${esc(t.subject)}</span>${stageNote?`<span class="tk-stage">${stageNote}${t.handler&&t.stage==='analyst'?' / 担当: '+esc(t.handler):''}</span>`:''}<span class="seemore">${esc(kinds[t.kind]||t.kind)} / ${esc(t.backend||'-')} / ${esc(t.by)} / ${esc((t.created||'').replace('T',' ').slice(0,16))}</span></div>
      <div class="tk-body">${t.body?`<p style="white-space:pre-wrap">${esc(t.body)}</p>`:''}${prop}${evh}${decInfo}${t.resolution?`<p><b>対応:</b> ${esc(t.resolution)}</p>`:''}${cm}
        <div class="tk-act"><input id="tkC-${esc(t.id)}" size="40" placeholder="コメントを書く"><button onclick="tkComment('${esc(t.id)}')">送信</button></div>${dec?decAct:(rv?rvNote:(adminAct+anaAct))}</div></div>`;
  }).join('');
}
function tkToggle(id){ TK_OPEN[id]=!TK_OPEN[id]; const e=document.getElementById('tk-'+id); if(e) e.classList.toggle('open',!!TK_OPEN[id]); }
function tkReload(r){ if(r&&r.ok){ openTickets(); } else alert('エラー: '+((r&&r.error)||'失敗')); }
function tkComment(id){ const v=document.getElementById('tkC-'+id).value; TK_OPEN[id]=true; postJSON('/api/tickets/comment',{id,text:v}).then(tkReload); }
function tkEscalate(id){
  const v=(document.getElementById('tkE-'+id)||{}).value||'';
  if(!v.trim()){ alert('管理者へ依頼する理由を入力してください'); return; }
  if(!confirm('管理者へ依頼します。以後、状態の変更は管理者が行います。よろしいですか?')) return;
  TK_OPEN[id]=true; postJSON('/api/tickets/escalate',{id,reason:v}).then(tkReload);
}
function tkToKo(id){
  const v=(document.getElementById('tkK-'+id)||{}).value||'';
  if(!v.trim()){ alert('キー・オフィサーへ依頼する理由を入力してください'); return; }
  if(!confirm('この申請の内容で、キー・オフィサーに「ログの確認依頼」を出します(この申請はそのまま続けられます)。よろしいですか?')) return;
  TK_OPEN[id]=true; postJSON('/api/tickets/to_ko',{id,reason:v}).then(r=>{ if(r&&r.ok===false) alert(r.error||'依頼できませんでした'); tkReload(); });
}
function tkDecide(id,ok){
  if(!confirm(ok?'復号を承認します。承認した期間のログを、キー・オフィサーが復号できるようになります(操作は記録されます)。よろしいですか?':'復号を却下します。よろしいですか?')) return;
  TK_OPEN[id]=true; postJSON('/api/enc/approve',{id,approve:ok,hours:ok?(document.getElementById('tkH-'+id)||{}).value:0}).then(tkReload);
}
function tkStatus(id,status){ TK_OPEN[id]=true; postJSON('/api/tickets/status',{id,status}).then(tkReload); }
function tkApproveDisable(id){
  if(!confirm('申請された「使わない」設定を反映します。よろしいですか?')) return;
  TK_OPEN[id]=true; postJSON('/api/tickets/status',{id,status:'done',approve:{apply:true}}).then(tkReload);
}
function tkApprove(id){
  const g=x=>document.getElementById(x+'-'+id).value;
  TK_OPEN[id]=true;
  postJSON('/api/tickets/status',{id,status:'done',approve:{rule:g('tkR'),path_prefix:g('tkP'),minutes:g('tkM'),mode:g('tkMo')}}).then(tkReload);
}

function slLoad(){
  fetch('/api/health-log',{cache:'no-store'}).then(r=>r.json()).then(d=>{ slData=d; slRender(); })
    .catch(()=>{ document.getElementById('slUpd').textContent='— 取得できません'; });
  loadMode();
}
let __modeBusy=false;
function loadMode(){
  if(__modeBusy) return; __modeBusy=true;
  fetch('/api/security',{cache:'no-store'}).then(r=>r.ok?r.json():null).then(s=>{ __modeBusy=false; if(s){ window.__lastSec=s; renderMode(s); } }).catch(()=>{__modeBusy=false;});
}
function fmtUntil(ts){
  if(!ts) return '';
  const left=Math.round(ts-Date.now()/1000);
  if(left<=0) return '';
  const h=Math.floor(left/3600), m=Math.round((left%3600)/60);
  return h?`あと約${h}時間`:`あと約${Math.max(1,m)}分`;
}
function renderMode(s){
  s=s||window.__lastSec; const body=document.getElementById('modeBody'); if(!body||!s) return;
  const adm=AUTH.user&&AUTH.user.role==='admin';
  const bl=(s.backends||[]).filter(b=>scIn('sl',b.id));
  const warn=document.getElementById('modeWarn');
  const det=bl.filter(b=>b.effective_mode==='detect');
  if(warn){ if(det.length){ warn.hidden=false; warn.textContent='⚠ 検知のみのバックエンドがあります('+det.map(b=>esc(b.name)).join('、')+')。このバックエンドは攻撃を遮断せず、記録だけしています。'; } else warn.hidden=true; }
  if(!bl.length){ body.innerHTML='<div class="hempty">'+(s.online===false?'単体起動のため防御モードの変更はできません(python waf.py で起動したときに操作できます)。':'バックエンドがありません')+'</div>'; return; }
  const offline=(s.online===false);
  body.innerHTML=bl.map(b=>{
    const em=b.effective_mode||'block';
    const badge=`<span class="mode-badge ${em==='detect'?'detect':'block'}">${em==='detect'?'検知のみ':'遮断'}</span>`;
    const ov=(b.mode_override==='block'||b.mode_override==='detect');
    const until=ov?fmtUntil(b.mode_until):'';
    const ovnote=ov?`<span class="seemore">上書き中${until?'('+until+')':'(無期限)'}</span>`:'<span class="seemore">全体設定に従う</span>';
    const lockbadge=b.mode_lock?'<span class="mode-badge lock">🔒ロック</span>':'';
    let btns='';
    if(offline){ btns='<span class="mlocknote">再起動で反映(単体起動)</span>'; }
    else if(AUTH.guser){ btns='<span class="mlocknote">変更は管理者・アナリストに依頼してください</span>'; }
    else if(b.mode_lock&&!adm){ btns='<span class="mlocknote">🔒 提供側がロック中(変更は申請してください)</span>'; }
    else if(em==='detect'){ btns=`<button onclick="setMode('${esc(b.id)}','block',0)">遮断に戻す</button>`; }
    else { btns=`<select id="md-${esc(b.id)}"><option value="60">1時間</option><option value="1440">24時間</option><option value="0">無期限</option></select>`
      +` <button onclick="setMode('${esc(b.id)}','detect',document.getElementById('md-${esc(b.id)}').value)">検知のみにする</button>`; }
    let admx='';
    if(adm&&!offline){
      admx=` <button onclick="setModeLock('${esc(b.id)}',${b.mode_lock?'false':'true'})">${b.mode_lock?'ロック解除':'ロック'}</button>`;
      if(ov) admx+=` <button onclick="setMode('${esc(b.id)}','',0)">全体に戻す</button>`;
    }
    return `<div class="mode-row"><span class="mnm">${esc(b.name)}</span>${badge}${lockbadge}${ovnote}<span class="grow"></span>${btns}${admx}</div>`;
  }).join('');
  const hist=document.getElementById('modeHist');
  if(hist){ const hs=(s.mode_history||[]).filter(h=>scIn('sl',h.backend));
    hist.innerHTML=(adm&&hs.length)?('最近の変更: '+hs.slice(0,5).map(h=>`${esc((h.time||'').replace('T',' '))} ${esc(h.backend_name||h.backend||'')}→${h.to==='detect'?'検知のみ':'遮断'}${h.by?'('+esc(h.by)+')':''}`).join(' / ')):''; }
}
function setMode(id,mode,minutes){
  const body={backend:id,mode:mode,minutes:minutes};
  if(AUTH.analyst){ const t=prompt('対応する申請番号を入力してください(例 T-0001)'); if(!t) return; body.ticket=t.trim(); }
  fetch('/api/security/bemode',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify(body)}).then(r=>r.json()).then(res=>{
      if(res.error){ alert('エラー: '+res.error); return; }
      if(res.security){ window.__lastSec=res.security; renderMode(res.security); }
    }).catch(()=>{});
}
function setModeLock(id,lock){
  fetch('/api/security/bemode',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({backend:id,lock:lock})}).then(r=>r.json()).then(res=>{
      if(res.error){ alert('エラー: '+res.error); return; }
      if(res.security){ window.__lastSec=res.security; renderMode(res.security); }
    }).catch(()=>{});
}
function slStart(){ slLoad(); if(!slTimer) slTimer=setInterval(slLoad,5000); }
function slStop(){ if(slTimer){ clearInterval(slTimer); slTimer=null; } }
['slfTarget','slfState'].forEach(i=>document.getElementById(i).addEventListener('change',slRenderRows));
document.getElementById('slfText').addEventListener('input',slRenderRows);
document.getElementById('ipSel').addEventListener('change',ev=>{ IP_BE=ev.target.value; if(window.__lastSec) renderSecurity(window.__lastSec); });
document.getElementById('ipOrg').addEventListener('change',ev=>{ SC.ip.org=ev.target.value; IP_BE=''; if(window.__lastSec) renderSecurity(window.__lastSec); });
document.getElementById('trafBe').addEventListener('change',ev=>changeTrafBe(ev.target.value));
document.getElementById('mapBe').addEventListener('change',ev=>changeMapBe(ev.target.value));
document.getElementById('mapOrg').addEventListener('change',ev=>changeMapOrg(ev.target.value));
document.getElementById('trafOrg').addEventListener('change',ev=>changeTrafOrg(ev.target.value));
document.getElementById('homeBe').addEventListener('change',ev=>changeHomeBe(ev.target.value));
document.getElementById('homeOrg').addEventListener('change',ev=>changeHomeOrg(ev.target.value));
document.getElementById('slOrg').addEventListener('change',ev=>{ SC.sl.org=ev.target.value; SC.sl.be=''; slSel=''; slRender(); if(window.__lastSec) renderMode(window.__lastSec); slLiveRender(healthLast, healthFails>=2); });
scopeLoad(); setInterval(scopeLoad,60000);
sparkHover(document.getElementById('slLive'));
document.getElementById('slSel').addEventListener('change',ev=>{ slSel=ev.target.value; SC.sl.be=slSel; slRender(); if(window.__lastSec) renderMode(window.__lastSec); slLiveRender(healthLast, healthFails>=2); });
/* ページ切替(ナビ) */
let curPage='home';
function showPage(p){
  curPage=p; document.body.dataset.page=p;
  document.querySelectorAll('.page').forEach(s=>s.classList.toggle('on', s.id==='page-'+p));
  document.querySelectorAll('#nav button').forEach(b=>b.classList.toggle('on', b.dataset.p===p));
  document.querySelectorAll('.hdr-link').forEach(b=>b.classList.toggle('on', b.dataset.p===p));
  // タブを開くたびに読み込む(ルール/設定は最新を取得)
  if(p!=='status') slStop();
  if(p!=='enc'){ encForgetKey(); ENC_GEN={}; }
  if(p==='status'){ slStart(); slLiveRender(healthLast, healthFails>=2); if(AUTH.limited) pollHealth(); }
  else if(p==='settings') openSettings();
  else if(p==='rules') openRules();
  else if(p==='tickets') openTickets();
  else if(p==='enc') loadEnc();
  else if(p==='traffic'){ renderCountries(); renderTraffic(); }
  else if(p==='home'){ renderHome(); loadOverview(); }
  else if(p==='map'){ if(!rtWorldReady) rtLoadWorld(0); }
  try{ window.scrollTo(0,0); }catch(e){}
  navHashSave();
}
// 開いているページ(設定ならタブも)をURLの # に残す。リロードしても同じ場所を開く
function navHashSave(){
  try{ const h='#'+curPage+(curPage==='settings'?'/'+sTab:''); if(location.hash!==h) history.replaceState(null,'',h); }catch(e){}
}
function navHashLoad(){
  try{
    const m=(location.hash||'').replace(/^#/,'').split('/'), pg=m[0];
    if(!pg||pg===curPage&&!m[1]||!document.getElementById('page-'+pg)) return false;
    if(pg==='settings'&&m[1]) sTab=m[1];
    showPage(pg); return true;
  }catch(e){ return false; }
}
document.querySelectorAll('#nav button, .hdr-link').forEach(b=>{ b.onclick=()=>showPage(b.dataset.p); });
// ホーム画面のカード内リンク(詳しく / ログ / 攻撃カテゴリ)
document.addEventListener('click',ev=>{
  const a=ev.target.closest&&ev.target.closest('[data-hgo]'); if(!a) return;
  ev.preventDefault();
  if(a.dataset.hgo==='settings-backend'){ sTab='backend'; showPage('settings'); } else showPage(a.dataset.hgo);
});
document.getElementById('hBe').addEventListener('click',ev=>{
  const b=ev.target.closest('button[data-be]'); if(!b||b.disabled) return;
  if(b.dataset.be==='edit'){ sTab='backend'; window.__beEditId=b.dataset.id; showPage('settings'); }
  else if(b.dataset.be==='stop') homeBeStop(b.dataset.id);
  else homeBeDelete(b.dataset.id);
});
document.querySelectorAll('#hmapSeg button').forEach(b=>{
  b.onclick=()=>{ document.querySelectorAll('#hmapSeg button').forEach(x=>x.classList.remove('on','neutral'));
    b.classList.add('on','neutral'); homeMapMode=b.dataset.m; if(window.__stats) homeMap(window.__stats); };
});

document.querySelectorAll('#trafRange button').forEach(b=>{
  b.onclick=()=>{ document.querySelectorAll('#trafRange button').forEach(x=>x.classList.remove('on'));
    b.classList.add('on'); trafRange=b.dataset.r; renderTraffic(); };
});
document.querySelectorAll('#mapRange button').forEach(b=>{
  b.onclick=()=>{ document.querySelectorAll('#mapRange button').forEach(x=>x.classList.remove('on'));
    b.classList.add('on'); mapRange=b.dataset.r; load(); };
});
document.getElementById('themeBtn').onclick=()=>{
  const cur=document.documentElement.getAttribute('data-theme')==='light'?'light':'dark';
  const next=cur==='light'?'dark':'light';
  applyTheme(next);
  try{ localStorage.setItem('waf-theme', next); }catch(e){}
};
document.getElementById('refreshBtn').onclick=load;
document.getElementById('autoBtn').onclick=(e)=>{
  auto=!auto; e.target.textContent='自動更新: '+(auto?'ON':'OFF');
  document.getElementById('dot').style.background=auto?'var(--pass)':'var(--ink-muted)';
};
document.getElementById('mClose').onclick=closeModal;
document.getElementById('modal').addEventListener('click',(ev)=>{ if(ev.target.id==='modal') closeModal(); });
document.getElementById('ipAdd').onclick=addBlock;
document.getElementById('ipInput').addEventListener('keydown',ev=>{ if(ev.key==='Enter') addBlock(); });
document.getElementById('banClear').onclick=clearBans;
initCountrySelect();
document.getElementById('countryAdd').onclick=addCountry;
document.getElementById('countryAllowAdd').onclick=addAllowCountry;
document.getElementById('banAdd').onclick=addBan;
document.getElementById('allowAdd').onclick=addAllow;
document.getElementById('exemptAdd').onclick=addExempt;
document.getElementById('countryUnknown').onchange=ev=>secPost('/api/security/countryunknown',{enabled:ev.target.checked});
['rf-cat','rf-sev','rf-text'].forEach(id=>document.getElementById(id).addEventListener('input',()=>{ if(rulesData) renderRules(); }));
['lf-action','lf-method','lf-text','lf-attack','lf-from','lf-to'].forEach(id=>document.getElementById(id).addEventListener('input',renderRecent));
document.getElementById('lf-backend').addEventListener('input',ev=>{ SC.ev.be=ev.target.value; beChipsRender(); renderRecent(); });
document.getElementById('lf-org').addEventListener('input',ev=>{ SC.ev.org=ev.target.value; SC.ev.be=''; beLfSync(); beChipsRender(); renderRecent(); });
document.getElementById('lf-backend').style.display='none'; document.getElementById('lf-org').style.display='none';
document.getElementById('lf-reset').onclick=()=>{
  ['lf-text','lf-from','lf-to'].forEach(id=>document.getElementById(id).value='');
  document.getElementById('lf-action').value=''; document.getElementById('lf-method').value='';
  SC.ev.org=''; SC.ev.be=''; document.getElementById('lf-backend').value=''; beLfSync(); beChipsRender();
  document.getElementById('lf-attack').checked=false; renderRecent();
};
let _allLoaded=false;
function loadAllEvents(){
  const btn=document.getElementById('lf-loadall');
  btn.textContent='読み込み中…'; btn.disabled=true;
  // limit=all: ログの全行。merge=0: 同じIPの連続する遮断ログをまとめず、1行ずつ返す
  fetch('/api/events?limit=all&merge=0').then(r=>r.json()).then(d=>{
    window.__recent = d.events||[];
    window.__logMeta = {lines_read:d.lines_read, lines_in_file:d.lines_in_file, truncated:d.truncated, requests:d.requests};
    if(!d.truncated && d.requests) window.__total_events = d.requests;
    _allLoaded=true; LOG_SHOW_MAX=1000;
    btn.textContent=d.truncated?`新しい方 ${d.returned.toLocaleString()} 行を読込済`:`全 ${d.returned.toLocaleString()} 行読込済`;
    btn.title=`ログファイル ${d.lines_in_file.toLocaleString()} 行 / 相当 ${d.requests.toLocaleString()} リクエスト`
      +(d.truncated?'(安全のため新しい方から上限まで)':'')+'。遮断(drop)は1秒ごとにまとめて記録されるため、1行が複数リクエスト(×N)を表します。';
    btn.disabled=false;
    renderRecent();
  }).catch(()=>{ btn.textContent='全件読み込み'; btn.disabled=false; });
}
document.getElementById('lf-loadall').onclick=loadAllEvents;
document.getElementById('lf-export').onclick=function(){
  const btn=this; const d10=v=>(v||'').slice(0,10);
  const qs=new URLSearchParams({backend:(document.getElementById('lf-backend').value==='__none'?'__none':scStr('ev')),from:d10(document.getElementById('lf-from').value),to:d10(document.getElementById('lf-to').value),
    attacks_only:document.getElementById('lf-attack').checked?'1':'0',format:document.getElementById('lf-expfmt').value});
  btn.disabled=true; const t0=btn.textContent; btn.textContent='書き出し中…';
  fetch('/api/logs/export?'+qs.toString()).then(async r=>{
    if(!r.ok){ let m='失敗'; try{ m=(await r.json()).error||m; }catch(e){} throw new Error(m); }
    const rows=r.headers.get('X-Rows'), tr=r.headers.get('X-Truncated')==='1';
    const cd=r.headers.get('Content-Disposition')||''; const nm=(/filename="([^"]+)"/.exec(cd)||[])[1]||'waf-log.txt';
    const b=await r.blob(); const a=document.createElement('a'); a.href=URL.createObjectURL(b); a.download=nm; document.body.appendChild(a); a.click(); a.remove();
    setTimeout(()=>URL.revokeObjectURL(a.href),4000);
    alert(rows+' 行を書き出しました'+(tr?'(上限の10万行で打ち切りました。期間を分けて書き出してください)':'')+'。');
  }).catch(e=>alert('書き出せませんでした: '+e.message)).finally(()=>{ btn.disabled=false; btn.textContent=t0; });
};
document.addEventListener('keydown',(ev)=>{ if(ev.key==='Escape'){ closeModal(); } });
load();
rtInit();
try{
  const o=sessionStorage.getItem('waf-open'); sessionStorage.removeItem('waf-open');
  if(o){ const [pg,tb]=o.split('|'); if(tb) sTab=tb; if(pg) showPage(pg); }
  else navHashLoad();                                  // リロード前に開いていたページへ戻る
}catch(e){}
window.addEventListener('hashchange',()=>{ navHashLoad(); });
attachZoom('map', ()=>{ if(worldReady) drawMap(); });
attachZoom('rtmap', ()=>{ rtDrawServer(); });
setInterval(()=>{if(auto)load();}, 6000);
</script>
</body>
</html>
"""


def main():
    ap = argparse.ArgumentParser(description="WAF ダッシュボード + 攻撃マップ")
    ap.add_argument("--port", type=int, default=8090, help="待受ポート (既定: 8090)")
    ap.add_argument("--host", default="127.0.0.1", help="待受ホスト (既定: 127.0.0.1)")
    ap.add_argument("--cert", help="HTTPSで待ち受ける場合の証明書(PEM)。--key と一緒に指定")
    ap.add_argument("--key", help="HTTPSで待ち受ける場合の秘密鍵(PEM)")
    ap.add_argument("--log", default=None, help="読み込む waf.log のパス")
    ap.add_argument("--no-geo", action="store_true",
                    help="ジオロケーション(外部API)を全て無効化する")
    ap.add_argument("--no-egress", action="store_true",
                    help="内部IPを自ホストの出口グローバルIPで地図化する処理だけ無効化")
    ap.add_argument("--ttl", type=int, default=60,
                    help="出口グローバルIPを取り直す間隔(秒)。VPN切替に追従(既定60)")
    args = ap.parse_args()

    log_path = args.log
    if not log_path:
        cfg_path = os.path.join(CONFIG_DIR, "waf_config.json")
        log_file = "waf.log"
        if os.path.exists(cfg_path):
            try:
                with open(cfg_path, "r", encoding="utf-8") as f:
                    log_file = json.load(f).get("log_file", "waf.log")
            except (ValueError, OSError):
                pass
        log_path = _dpath(log_file)

    geo = GeoResolver(enabled=not args.no_geo, egress=not args.no_egress, ttl=args.ttl)
    # logs/(WEBごとの日次ログ)があればそこから読む。なければ waf.log(1ファイル)
    source, control = None, None
    cfg_path_ = os.path.join(CONFIG_DIR, "waf_config.json")
    try:
        with open(cfg_path_, "r", encoding="utf-8") as f_:
            log_dir_ = json.load(f_).get("log_dir") or "logs"
    except (ValueError, OSError):
        log_dir_ = "logs"
    logs_root_ = _dpath(log_dir_)
    if not args.log and os.path.isdir(logs_root_):
        import waf_logstore
        control = FileConfigControl(cfg_path_)

        def _resolver():
            c_ = control._load()
            return (list(c_.get("orgs") or []), list(c_.get("backends") or []), list(wx.users_of(c_)))
        source = waf_logstore.LogStore(logs_root_, _resolver)
        log_path = logs_root_
    handler = make_handler(log_path, geo, control=control, source=source)
    httpd = TLSThreadingHTTPServer((args.host, args.port), handler)
    if args.cert and args.key:
        import ssl as _ssl
        _ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
        _ctx.load_cert_chain(certfile=args.cert, keyfile=args.key)
        httpd.ssl_context, httpd.is_tls = _ctx, True
    browse = "127.0.0.1" if args.host in ("0.0.0.0", "", "::") else args.host
    print("=" * 66)
    print(" WAF ダッシュボード + 攻撃マップ 起動")
    print(f"  URL : {'https' if httpd.is_tls else 'http'}://{browse}:{args.port}")
    print(f"  ログ: {log_path}"
          + ("" if os.path.exists(log_path) else "  (まだ存在しません。WAFを動かすと生成されます)"))
    print(f"  ジオ: {'有効 (ip-api.com)' if geo.enabled else '無効 (--no-geo)'}"
          + ("" if not geo.enabled else
             ("  / 内部IPは出口グローバルIP(ipinfo等)で地図化" if geo.egress
              else "  / 出口IP解決は無効 (--no-egress)")))
    print("=" * 66)
    print(" 画面は約4秒ごとに自動更新されます。停止は Ctrl+C。")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n停止しました。")
        httpd.shutdown()


if __name__ == "__main__":
    main()
