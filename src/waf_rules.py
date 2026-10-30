# -*- coding: utf-8 -*-
"""waf_rules.py: 署名ルールの定義と多段デコード

検査対象の文字列にマッチしたルール一覧を返す検出エンジン。waf.py から呼ばれる。
マッチ前に、URL/HTML/Unicodeなどの難読化を多段デコードで正規化する。
ルールはカテゴリごとにまとめ、カテゴリ単位のON/OFFとルールID単位の無効化(disabled_rules)に対応する。各ルールは severity(critical/high/medium/low)を持つ。
"""

import base64
import html
import re
import unicodedata
from urllib.parse import unquote_plus


# ---------------------------------------------------------------------------
# 正規化(多段デコード)
# ---------------------------------------------------------------------------
def normalize(value):
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)

    decoded = value
    for _ in range(3):                        # URLデコード(多重エンコード対策)
        new = unquote_plus(decoded)
        if new == decoded:
            break
        decoded = new
    for _ in range(3):                        # HTMLエンティティ
        new = html.unescape(decoded)
        if new == decoded:
            break
        decoded = new
    decoded = unicodedata.normalize("NFKC", decoded)   # 全角を半角にするなど

    # ゼロ幅・制御文字でシグネチャを分断する回避への対策
    stripped = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f​-‏﻿]", "", decoded)
    variants = {value, decoded, stripped}
    return "\n".join(variants)


def _c(pattern):
    return re.compile(pattern, re.IGNORECASE | re.DOTALL)


# ---------------------------------------------------------------------------
# カテゴリのメタ情報(ダッシュボード表示用)
# ---------------------------------------------------------------------------
CATEGORY_LABELS = {
    "xss":       "XSS",
    "sqli":      "SQLインジェクション",
    "traversal": "パストラバーサル/LFI",
    "cmdi":      "コマンドインジェクション",
    "ssrf":      "SSRF",
    "xxe":       "XXE",
    "ssti":      "テンプレート注入(SSTI)",
    "nosqli":    "NoSQLインジェクション",
    "ldap":      "LDAPインジェクション",
    "crlf":      "CRLF/ヘッダ注入",
    "redirect":  "オープンリダイレクト",
    "upload":    "危険なファイルアップロード",
    "scanner":   "スキャナ/偵察",
    "deser":     "安全でないデシリアライズ",
    "protocol":  "既知脆弱性/その他",
    "logic":     "ロジック検出(難読化/多重エンコード)",
    "response":  "レスポンス検査(Stored XSS 無害化)",
}
CATEGORIES = list(CATEGORY_LABELS.keys())


# ---------------------------------------------------------------------------
# ルール定義: (id, category, severity, 説明, 正規表現)
# ---------------------------------------------------------------------------
XSS_RULES = [
    ("XSS-001", "xss", "critical", "<script> タグ", _c(r"<\s*script")),
    ("XSS-002", "xss", "critical", "</script> 終了タグ", _c(r"<\s*/\s*script")),
    ("XSS-003", "xss", "high", "javascript: スキーム", _c(r"javascript\s*:")),
    ("XSS-004", "xss", "high", "vbscript: スキーム", _c(r"vbscript\s*:")),
    ("XSS-005", "xss", "high", "data:text/html スキーム", _c(r"data\s*:\s*text/html")),
    ("XSS-006", "xss", "high", "インラインイベントハンドラ (on...=)", _c(r"\bon[a-z]{3,}\s*=")),
    ("XSS-007", "xss", "high", "<iframe> タグ", _c(r"<\s*iframe")),
    ("XSS-008", "xss", "high", "<svg> タグ", _c(r"<\s*svg")),
    ("XSS-009", "xss", "high", "<img ... onerror 等", _c(r"<\s*img[^>]*\bon[a-z]+\s*=")),
    ("XSS-010", "xss", "high", "危険タグ(body/object/embed/base/link/meta/form/math/details/marquee)",
     _c(r"<\s*(body|object|embed|base|link|meta|form|math|details|marquee|template|portal)\b")),
    ("XSS-011", "xss", "medium", "document.cookie 参照", _c(r"document\s*\.\s*cookie")),
    ("XSS-012", "xss", "medium", "eval( / Function( 呼び出し", _c(r"\b(eval|Function)\s*\(")),
    ("XSS-013", "xss", "medium", "fetch/XHR/sendBeacon 送信",
     _c(r"\b(fetch\s*\(|XMLHttpRequest|navigator\s*\.\s*sendBeacon)")),
    ("XSS-014", "xss", "medium", "document.write / location 操作",
     _c(r"(document\s*\.\s*write|location\s*\.\s*(href|replace|assign))")),
    ("XSS-015", "xss", "high", "srcdoc / formaction 属性", _c(r"\b(srcdoc|formaction)\s*=")),
    ("XSS-016", "xss", "medium", "CSS expression() / url(javascript:)",
     _c(r"(expression\s*\(|url\s*\(\s*['\"]?\s*javascript)")),
    ("XSS-017", "xss", "high", "<script src=> 外部読み込み", _c(r"<\s*script[^>]*\bsrc\s*=")),
    ("XSS-018", "xss", "medium", "String.fromCharCode 難読化", _c(r"String\s*\.\s*fromCharCode")),
    ("XSS-019", "xss", "medium", "atob/btoa/unescape 難読化", _c(r"\b(atob|btoa|unescape|decodeURIComponent)\s*\(")),
    ("XSS-020", "xss", "high", "innerHTML/outerHTML/insertAdjacentHTML への代入",
     _c(r"(innerHTML|outerHTML|insertAdjacentHTML)\s*(=|\()")),
    ("XSS-021", "xss", "high", "angular/vue テンプレート式 {{...}}", _c(r"\{\{.*?\}\}")),
    ("XSS-022", "xss", "medium", "<style> による注入", _c(r"<\s*style[\s>]")),
    # self_made_waf 由来
    ("XSS-023", "xss", "medium", "JSシンク呼び出し (alert/prompt/confirm)", _c(r"\b(alert|prompt|confirm)\s*\(")),
]

SQLI_RULES = [
    ("SQLI-001", "sqli", "high", "UNION SELECT", _c(r"\bunion\b[\s\S]{0,40}\bselect\b")),
    ("SQLI-002", "sqli", "high", "タウトロジー (OR 1=1 等)",
     _c(r"(\bor\b|\band\b)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+")),
    ("SQLI-003", "sqli", "medium", "SQLコメント (-- / # / /* */)", _c(r"(--\s|#|/\*|\*/)")),
    ("SQLI-004", "sqli", "high", "時間ベース (SLEEP/BENCHMARK/WAITFOR/pg_sleep)",
     _c(r"\b(sleep|benchmark|waitfor\s+delay|pg_sleep|dbms_pipe\.receive_message)\s*\(")),
    ("SQLI-005", "sqli", "high", "スタッククエリ/危険句",
     _c(r";\s*(drop|insert|update|delete|alter|create|truncate|grant)\b")),
    ("SQLI-006", "sqli", "medium", "メタテーブル/危険関数",
     _c(r"\b(information_schema|sysobjects|sys\.tables|xp_cmdshell|load_file|into\s+(out|dump)file|utl_http|dbms_)\b")),
    ("SQLI-007", "sqli", "medium", "文字列連結/エンコード (CONCAT/CHAR/UNHEX/0x..)",
     _c(r"\b(concat|char|unhex|hex|ascii)\s*\(|0x[0-9a-f]{4,}")),
    ("SQLI-008", "sqli", "high", "認証回避 (' OR '1'='1 等)",
     _c(r"['\"]\s*(or|and)\s*['\"]?[\w]+['\"]?\s*=\s*['\"]?[\w]+")),
    ("SQLI-009", "sqli", "medium", "コメント終端のクォート脱出 (' --)", _c(r"['\"]\s*;?\s*--")),
    ("SQLI-010", "sqli", "high", "ブーリアン/エラーベース (extractvalue/updatexml)",
     _c(r"\b(extractvalue|updatexml|exp\s*\(|floor\s*\(\s*rand)")),
    ("SQLI-011", "sqli", "medium", "SELECT ... FROM", _c(r"\bselect\b[\s\S]{0,80}\bfrom\b")),
    ("SQLI-012", "sqli", "medium", "SQL句の単独出現",
     _c(r"\b(group\s+by|order\s+by|having|union\s+all)\b")),
    # self_made_waf 由来
    ("SQLI-013", "sqli", "medium", "クォート直後の終端 (' ; / '# / '/*)", _c(r"['\"]\s*(;|#|/\*)")),
    ("SQLI-014", "sqli", "high", "DROP TABLE / TRUNCATE TABLE", _c(r"\b(drop|truncate)\s+table\b")),
    ("SQLI-015", "sqli", "high", "WAITFOR DELAY (MSSQL時間ベース)", _c(r"\bwaitfor\s+(delay|time)\b")),
    ("SQLI-016", "sqli", "medium", "SELECT 直後の列指定 (SELECT */NULL/数値/関数)",
     _c(r"\bselect\b(?:\s|/\*.*?\*/)+(?:\*|[\w.@`]+\s*\(|[\w.@`]+\s*,|null\b|\d+\b)")),
]

TRAVERSAL_RULES = [
    ("LFI-001", "traversal", "high", "ディレクトリトラバーサル (../ ..\\)", _c(r"(\.\./|\.\.\\){1,}")),
    ("LFI-002", "traversal", "high", "エンコード済みトラバーサル (%2e%2e / ..%2f / %c0%ae)",
     _c(r"(%2e%2e|%252e|\.\.%2f|\.\.%5c|%c0%ae|%uff0e)")),
    ("LFI-003", "traversal", "high", "機微ファイル参照",
     _c(r"(/etc/(passwd|shadow|hosts|group)|boot\.ini|win\.ini|/proc/self/environ|\.ssh/id_rsa|/var/log/|web\.config|\.htaccess)")),
    ("LFI-004", "traversal", "medium", "PHP/ファイルラッパー",
     _c(r"(php://|file://|expect://|zip://|phar://|glob://|data://)")),
    ("LFI-005", "traversal", "medium", "NULLバイトによる拡張子回避", _c(r"%00|\x00")),
    ("LFI-006", "traversal", "medium", "絶対パス参照 (/etc /var /root)", _c(r"(^|[?&=])/(etc|var|root|proc|sys)/")),
    ("LFI-007", "traversal", "high", "Windowsシステムパス (C:\\Windows / boot.ini / win.ini)",
     _c(r"([a-z]:\\windows|boot\.ini|win\.ini)")),
]

CMDI_RULES = [
    ("CMDI-001", "cmdi", "high", "シェルメタ文字によるコマンド連結",
     _c(r"(;|\|\||&&|\$\(|`|\|\s*)\s*(cat|ls|id|whoami|uname|curl|wget|nc|bash|sh|python|perl|powershell|pwd|env|hostname)\b")),
    ("CMDI-002", "cmdi", "high", "コマンド置換 $(...) / バッククォート", _c(r"(\$\([^)]*\)|`[^`]*`)")),
    ("CMDI-003", "cmdi", "medium", "典型コマンド/シェルパス",
     _c(r"\b(/bin/(ba|z|c)?sh|/usr/bin/|nc\s+-e|powershell\s+-(enc|e|c)|certutil\s+-urlcache|bitsadmin)\b")),
    ("CMDI-004", "cmdi", "high", "ダウンロード&実行",
     _c(r"\b(wget|curl)\b[\s\S]{0,80}(\|\s*(sh|bash|python)|-o\s)")),
    ("CMDI-005", "cmdi", "medium", "IFS/環境変数による回避", _c(r"\$\{?IFS\}?|\$\{PATH\}")),
    ("CMDI-006", "cmdi", "high", "Windowsコマンド (cmd /c, &, type)",
     _c(r"\bcmd(\.exe)?\s*/[ck]\b|\btype\s+%|\b(net\s+user|net\s+localgroup)\b")),
]

SSRF_RULES = [
    ("SSRF-001", "ssrf", "high", "クラウドメタデータ (169.254.169.254)",
     _c(r"(169\.254\.169\.254|metadata\.google\.internal|metadata\.azure)")),
    ("SSRF-002", "ssrf", "high", "内部ホスト参照 (localhost/127.0.0.1/0.0.0.0)",
     _c(r"https?://(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|127\.1)\b")),
    ("SSRF-003", "ssrf", "medium", "プライベートIPへのURL",
     _c(r"https?://(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)")),
    ("SSRF-004", "ssrf", "high", "危険スキーム (gopher/dict/file/ftp)",
     _c(r"\b(gopher|dict|ftp|file|ldap|tftp)://")),
    ("SSRF-005", "ssrf", "medium", "URLパラメータへの外部URL埋め込み",
     _c(r"[?&](url|uri|target|dest|redirect|next|data|path|continue|host|site|domain|callback|out|view|to|image|img|load)=https?%3a")),
]

XXE_RULES = [
    ("XXE-001", "xxe", "critical", "DOCTYPE/ENTITY 宣言", _c(r"<!(DOCTYPE|ENTITY)\b")),
    ("XXE-002", "xxe", "high", "外部エンティティ SYSTEM/PUBLIC", _c(r"<!ENTITY[\s\S]{0,80}(SYSTEM|PUBLIC)")),
    ("XXE-003", "xxe", "high", "XML内のfile://参照", _c(r"<!ENTITY[\s\S]{0,80}(file://|http://|php://)")),
    ("XXE-004", "xxe", "medium", "パラメータエンティティ (%xxe;)", _c(r"%\w+;\s*]?>|<!ENTITY\s+%")),
]

SSTI_RULES = [
    ("SSTI-001", "ssti", "high", "テンプレート式 ${...} / #{...}", _c(r"(\$\{[^}]{1,80}\}|#\{[^}]{1,80}\})")),
    ("SSTI-002", "ssti", "high", "Jinja/Twig {{ 7*7 }} 類", _c(r"\{\{[\s\S]{0,80}(\*|config|self|request|__class__|__globals__)[\s\S]{0,80}\}\}")),
    ("SSTI-003", "ssti", "high", "ERB/JSP <%= %> / <% %>", _c(r"<%[=\s][\s\S]{0,80}%>")),
    ("SSTI-004", "ssti", "high", "Pythonオブジェクト探索 (__class__/__mro__/__subclasses__)",
     _c(r"__(class|mro|subclasses|globals|builtins|import|base)__")),
    ("SSTI-005", "ssti", "medium", "Freemarker/Velocity ディレクティブ", _c(r"(<#assign|<#list|#set\s*\(|\$!?\{)")),
]

NOSQLI_RULES = [
    ("NOSQL-001", "nosqli", "high", "Mongo演算子 ($where/$ne/$gt/$regex 等)",
     _c(r"\$\s*(where|ne|gt|gte|lt|lte|in|nin|regex|exists|or|and|not)\b")),
    ("NOSQL-002", "nosqli", "high", "配列演算子注入 (param[$ne]=)", _c(r"\[\s*\$\w+\s*\]")),
    ("NOSQL-003", "nosqli", "medium", "JS評価 (this./sleep/function())",
     _c(r"(this\.\w+|function\s*\(\s*\)\s*\{|return\s+true)")),
]

LDAP_RULES = [
    ("LDAP-001", "ldap", "high", "LDAPフィルタ注入 (*)(|( 等", _c(r"[)(][\s]*[|&!][\s]*\(|\*\)\s*\(|\)\(\|")),
    ("LDAP-002", "ldap", "medium", "ワイルドカード/属性注入", _c(r"\(\s*[a-z]+\s*=\s*\*\s*\)")),
]

CRLF_RULES = [
    ("CRLF-001", "crlf", "high", "CRLF注入 (%0d%0a / \\r\\n)", _c(r"(%0d%0a|%0a%0d|%0d|%0a|\r\n|\\r\\n)")),
    ("CRLF-002", "crlf", "high", "HTTPレスポンス分割 (Set-Cookie/Location注入)",
     _c(r"(%0d%0a|\r\n)\s*(set-cookie|location|content-length|content-type)\s*:")),
    ("CRLF-003", "crlf", "medium", "ヘッダ分割によるXSS (<script> 後続)", _c(r"(%0d%0a|\r\n)[\s\S]{0,40}<script")),
]

REDIRECT_RULES = [
    ("OR-001", "redirect", "medium", "オープンリダイレクト (//evil / https://evil)",
     _c(r"[?&](url|uri|redirect|redirect_uri|next|return|returnurl|dest|destination|continue|goto|out|target|rurl|u)=(https?:)?//[^/]")),
    ("OR-002", "redirect", "medium", "バックスラッシュ/@ を使った回避", _c(r"[?&]\w+=https?:/\\|@[a-z0-9.-]+\.[a-z]{2,}/")),
]

UPLOAD_RULES = [
    ("UP-001", "upload", "high", "危険な拡張子のファイル名",
     _c(r"filename\s*=\s*['\"][^'\"]+\.(php\d?|phtml|jsp|jspx|asp|aspx|aspx|cer|jsp|sh|exe|dll|bat|cmd|py|pl|cgi|htaccess|war)\b")),
    ("UP-002", "upload", "medium", "多重拡張子 (.jpg.php 等)", _c(r"\.(jpg|png|gif|jpeg|pdf|txt)\.(php\d?|jsp|asp|exe|sh)\b")),
    ("UP-003", "upload", "medium", "Webshell/スクリプト痕跡",
     _c(r"(<\?php|<%@\s*page|system\s*\(\s*\$_|passthru\s*\(|shell_exec\s*\()")),
]

SCANNER_RULES = [
    ("SCAN-001", "scanner", "high", "既知スキャナ User-Agent",
     _c(r"\b(sqlmap|nikto|nmap|acunetix|nessus|openvas|dirbuster|gobuster|wpscan|masscan|nuclei|zgrab|whatweb|wfuzz|hydra|burp(suite)?|havij|arachni)\b")),
    ("SCAN-002", "scanner", "medium", "機微パス探索 (.env/.git/.aws/wp-admin 等)",
     _c(r"(/\.env\b|/\.git/|/\.aws/|/\.svn/|/wp-(admin|login|config)|/phpmyadmin|/\.well-known/|/actuator\b|/server-status|/\.DS_Store|/config\.(php|json|yml))")),
    ("SCAN-003", "scanner", "medium", "攻撃ツールの痕跡 (nikto/sqlmap系文字列)",
     _c(r"\b(\(nikto\)|sqlmap/|acunetix-|nessus-|openvas|w3af\.|nuclei/|dirbuster)\b")),
]

DESER_RULES = [
    ("DES-001", "deser", "high", "Javaシリアライズ (rO0AB / aced0005)", _c(r"(rO0AB|\xac\xed\x00\x05|aced0005)")),
    ("DES-002", "deser", "high", "PHPシリアライズオブジェクト (O:1:/a:)", _c(r"\bO:\d+:\"|\ba:\d+:\{")),
    ("DES-003", "deser", "medium", "Pythonピクル/__reduce__", _c(r"(__reduce__|cos\nsystem|c__builtin__)")),
]

PROTOCOL_RULES = [
    ("PROTO-001", "protocol", "critical", "Log4Shell (${jndi:ldap/rmi/dns})",
     _c(r"\$\{jndi:(ldap|ldaps|rmi|dns|iiop|nis|corba|nds)://")),
    ("PROTO-002", "protocol", "critical", "Log4j lookup難読化 (${lower:} 等)",
     _c(r"\$\{(lower|upper|env|sys|date|java|main|ctx|base64|::-?j):")),
    ("PROTO-003", "protocol", "high", "Spring4Shell (class.module.classLoader)",
     _c(r"class\.module\.classLoader|class\[.module.\]")),
    ("PROTO-004", "protocol", "high", "NULLバイト注入", _c(r"%00|\x00")),
    ("PROTO-005", "protocol", "medium", "プロトタイプ汚染 (__proto__/constructor.prototype)",
     _c(r"(__proto__|constructor\s*\.\s*prototype|\[['\"]__proto__['\"]\])")),
    ("PROTO-006", "protocol", "high", "GraphQL introspection / バッチ悪用", _c(r"__schema\s*\{|__typename|\bmutation\b[\s\S]{0,40}\{")),
    ("PROTO-007", "protocol", "medium", "ヘッダ偽装 (X-Forwarded-Host/X-Original-URL)",
     _c(r"\b(x-original-url|x-rewrite-url|x-forwarded-host)\b\s*:")),
    ("PROTO-008", "protocol", "high", "SSTI/RCE 共通 (Runtime.exec/ProcessBuilder)",
     _c(r"(Runtime\s*\.\s*getRuntime|ProcessBuilder|os\.system|subprocess\.(Popen|call|run))")),
]

# ---------------------------------------------------------------------------
# ロジック検出(ヒューリスティック)
#   シグネチャに一致しない難読化・多重エンコード・動的コード構築を、値の性質から判定する。regex だけでは捉えにくいものの補完
# ---------------------------------------------------------------------------
LOGIC_META = [
    ("LOGIC-001", "logic", "high",   "JSFuck等の非英数字のみの難読化コード"),
    ("LOGIC-002", "logic", "high",   "多重エンコードで隠された危険ペイロード"),
    ("LOGIC-003", "logic", "high",   "Base64/Hexに隠された実行コード"),
    ("LOGIC-004", "logic", "medium", "文字コードエスケープによる難読化"),
    ("LOGIC-005", "logic", "medium", "文字列連結/配列による動的コード構築の兆候"),
    ("LOGIC-006", "logic", "medium", "エントロピーの高い長大なトークン(難読化/エンコードの疑い)"),
]

_JSF_CHARS = set("[]()!+ \t\n")
_B64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}[\s,:-]?){12,}")
_ESC_RE = re.compile(r"\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|&#x?[0-9]+;|%u[0-9a-fA-F]{4}|\\[0-7]{2,3}")
_DANGER = re.compile(
    r"(<\s*script|<\s*/\s*script|<\s*img|<\s*svg|<\s*iframe|javascript\s*:|vbscript\s*:|"
    r"on[a-z]{3,}\s*=|eval\s*\(|Function\s*\(|String\.fromCharCode|document\s*\.\s*cookie|"
    r"alert\s*\(|prompt\s*\(|atob\s*\(|unescape\s*\(|import\s*\(|require\s*\(|"
    r"union\s+select|/etc/passwd|/bin/(sh|bash)|cmd\.exe|powershell|base64,|"
    r"\{\{.*?\}\}|\$\{.*?\})", re.IGNORECASE | re.DOTALL)


def _shannon_entropy(s):
    if not s:
        return 0.0
    from math import log2
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * log2(c / n) for c in freq.values())


def _deep_decode(s):
    """URL/HTMLエンティティを可能な限り多段でデコードする"""
    cur = s
    for _ in range(5):
        nxt = unquote_plus(cur)
        if nxt == cur:
            break
        cur = nxt
    for _ in range(5):
        nxt = html.unescape(cur)
        if nxt == cur:
            break
        cur = nxt
    return cur


def scan_logic(value, disabled_rules=None):
    """値の性質から判定するヒューリスティック検出"""
    disabled_rules = disabled_rules or set()
    if value is None:
        return []
    s = value if isinstance(value, str) else str(value)
    if not s or len(s) < 8:
        return []
    hits = []

    def add(rid, sev, desc, snippet):
        if rid in disabled_rules:
            return
        snip = str(snippet)
        if len(snip) > 120:
            snip = snip[:120] + "..."
        hits.append({"id": rid, "category": "logic", "severity": sev,
                     "description": desc, "matched": snip})

    # LOGIC-001: JSFuck等、記号だけで構成された難読化
    if len(s) >= 24:
        jsf = sum(1 for c in s if c in _JSF_CHARS)
        if jsf / len(s) >= 0.85 and ("[]" in s or "!+" in s or "+[" in s or "(!" in s):
            add("LOGIC-001", "high", "JSFuck等の非英数字のみの難読化コード", s[:60])

    # LOGIC-002: 多重エンコード。浅いデコードでは無害に見えて、深くデコードすると危険になるもの
    base_hit = bool(_DANGER.search(s))
    deep = _deep_decode(s)
    if not base_hit and _DANGER.search(deep) and deep != s:
        add("LOGIC-002", "high", "多重エンコードで隠された危険ペイロード", deep[:80])

    # LOGIC-003: Base64 / 連続HEX に隠された実行コード
    found_enc = False
    for m in _B64_RE.finditer(s):
        blob = m.group(0)
        try:
            dec = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False).decode("utf-8", "replace")
        except Exception:
            continue
        if _DANGER.search(dec):
            add("LOGIC-003", "high", "Base64に隠された実行コード(" + dec[:24].strip() + "…)", blob[:40])
            found_enc = True
            break
    if not found_enc:
        for m in _HEX_RE.finditer(s):
            hx = re.sub(r"[\s,:-]", "", m.group(0))
            if len(hx) % 2:
                hx = hx[:-1]
            try:
                dec = bytes.fromhex(hx).decode("utf-8", "replace")
            except Exception:
                continue
            if _DANGER.search(dec):
                add("LOGIC-003", "high", "Hexに隠された実行コード(" + dec[:24].strip() + "…)", m.group(0)[:40])
                break

    # LOGIC-004: \xNN \uNNNN &#NN; %uNNNN 等のエスケープを多用した難読化
    esc = len(_ESC_RE.findall(s))
    if esc >= 6:
        add("LOGIC-004", "medium", "文字コードエスケープによる難読化(%d箇所)" % esc, s[:60])

    # LOGIC-005: 文字列連結・配列アクセスで識別子を動的に組み立てる難読化
    if re.search(r"(constructor|eval|alert|cookie|fromCharCode|location|document|window)", s, re.I):
        concat = len(re.findall(r"['\"]\s*\+|\+\s*['\"]", s))
        bracket = len(re.findall(r"\[\s*['\"]", s))
        if concat >= 2 or bracket >= 2:
            add("LOGIC-005", "medium", "文字列連結/配列による動的コード構築の兆候", s[:60])

    # LOGIC-006: 長くて高エントロピーなトークン(難読化・エンコードの疑い)
    for tok in re.findall(r"\S{40,}", s):
        if _shannon_entropy(tok) >= 4.3 and not tok.startswith(("http://", "https://")):
            add("LOGIC-006", "medium", "高エントロピーの長大トークン(難読化の疑い)", tok[:50])
            break

    return hits


ALL_RULES = {
    "xss": XSS_RULES,
    "sqli": SQLI_RULES,
    "traversal": TRAVERSAL_RULES,
    "cmdi": CMDI_RULES,
    "ssrf": SSRF_RULES,
    "xxe": XXE_RULES,
    "ssti": SSTI_RULES,
    "nosqli": NOSQLI_RULES,
    "ldap": LDAP_RULES,
    "crlf": CRLF_RULES,
    "redirect": REDIRECT_RULES,
    "upload": UPLOAD_RULES,
    "scanner": SCANNER_RULES,
    "deser": DESER_RULES,
    "protocol": PROTOCOL_RULES,
}


# レスポンス検査(waf_extras.RESPONSE_RULES)のメタ情報。バックエンドの応答HTMLを検査する
RESPONSE_META = [
    ("RESP-001", "response", "critical", "応答の<script>内に alert/eval/document.cookie 等"),
    ("RESP-002", "response", "high", "応答の自動発火イベント属性(onerror= 等)に危険な処理"),
    ("RESP-003", "response", "high", "応答の href/src 等の javascript: URL"),
    ("RESP-004", "response", "high", "応答の iframe/object/embed の srcdoc・javascript:・data:text/html"),
]


def list_rules():
    """全ルールのメタ情報を返す(ダッシュボードのルール管理用)"""
    out = []
    for cat in CATEGORIES:
        for rule_id, c, severity, desc, _regex in ALL_RULES.get(cat, []):
            out.append({"id": rule_id, "category": c, "severity": severity, "description": desc})
    # ロジック検出(regexなしのヒューリスティック)も一覧に含める
    for rule_id, c, severity, desc in LOGIC_META + RESPONSE_META:
        out.append({"id": rule_id, "category": c, "severity": severity, "description": desc})
    return out


def rule_count():
    return sum(len(v) for v in ALL_RULES.values()) + len(LOGIC_META) + len(RESPONSE_META)


# ---------------------------------------------------------------------------
# 検査本体
# ---------------------------------------------------------------------------
def scan_value(value, enabled_categories, disabled_rules=None):
    """値を正規化し、有効カテゴリかつ無効化されていないルールで検査する。
    マッチしたルールの dict のリストを返す
    """
    disabled_rules = disabled_rules or set()
    normalized = normalize(value)
    hits = []
    for category in enabled_categories:
        if category == "logic":
            hits.extend(scan_logic(value, disabled_rules))
            continue
        if category == "response":      # 応答側の検査(waf_extras.inspect_response)。リクエストには使わない
            continue
        for rule_id, cat, severity, desc, regex in ALL_RULES.get(category, []):
            if rule_id in disabled_rules:
                continue
            m = regex.search(normalized)
            if m:
                snippet = m.group(0)
                if len(snippet) > 120:
                    snippet = snippet[:120] + "..."
                hits.append({
                    "id": rule_id, "category": cat, "severity": severity,
                    "description": desc, "matched": snippet,
                })
    return hits
