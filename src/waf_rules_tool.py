#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""waf_rules_tool.py: 追加ルール(custom_rules.json)の管理ツール。提供側のローカル専用

  python3 waf_rules_tool.py                # http://127.0.0.1:8099 を開く
  python3 src/waf_rules_tool.py --port 8099   # 追加ルールは config/custom_rules.json

WAF本体・ダッシュボードとは別プロセス。127.0.0.1 だけで待ち受け、ループバック以外の接続とHostが合わない要求は拒否する。
追加/編集/削除、構文チェック(重い正規表現は弾く)、文字列テスト、過去ログへの当てはめ(誤検知の確認)、保存(旧版を残す)、旧版への復元ができる。
保存すると稼働中のWAFが数秒以内に検査して入れ替える(再起動不要)。新しいルールは既定で detect。誤検知がないことを確認してから block にする。
"""
import argparse
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE_DIR = os.path.dirname(os.path.abspath(__file__))          # src/
ROOT = os.path.dirname(BASE_DIR)                                # waf.py のあるフォルダ
sys.path.insert(0, BASE_DIR)
import waf_custom  # noqa: E402
import waf_rules  # noqa: E402


PAGE = r"""<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>WAF 追加ルール管理</title>
<style>
:root{--bg:#121311;--sf:#1a1a19;--sf2:#222220;--bd:#33332f;--ink:#f0efec;--ink2:#c3c2b7;--mut:#8b8a80;--ok:#1baf7a;--ng:#e34948;--wn:#eda100}
@media (prefers-color-scheme:light){:root{--bg:#f6f5f1;--sf:#fff;--sf2:#efeee9;--bd:#d9d7cf;--ink:#1c1c1a;--ink2:#46453f;--mut:#76756c}}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.6 system-ui,"Hiragino Sans","Yu Gothic",sans-serif}
main{max-width:1100px;margin:0 auto;padding:16px}
h1{font-size:20px;margin:6px 0 2px} h2{font-size:15px;margin:0 0 10px}
.card{background:var(--sf);border:1px solid var(--bd);border-radius:10px;padding:14px 16px;margin-top:14px}
.sub{color:var(--mut);font-size:12.5px}
table{width:100%;border-collapse:collapse} th,td{text-align:left;padding:6px 8px;border-top:1px solid var(--bd);vertical-align:top;font-size:13px} th{color:var(--mut);font-weight:600;border-top:0}
input,select,textarea{background:var(--sf2);color:var(--ink);border:1px solid var(--bd);border-radius:7px;padding:6px 9px;font:inherit;box-sizing:border-box;width:100%}
textarea{min-height:64px;font-family:ui-monospace,Menlo,Consolas,monospace}
button{background:var(--sf2);color:var(--ink);border:1px solid var(--bd);border-radius:7px;padding:6px 13px;cursor:pointer;font:inherit}
button.pri{background:var(--ok);border-color:var(--ok);color:#06140e;font-weight:700}
.g{display:grid;grid-template-columns:130px 1fr;gap:8px 12px;align-items:center;max-width:860px}
.b{display:inline-block;padding:1px 9px;border-radius:999px;font-size:12px;font-weight:700;background:var(--sf2)}
.b.det{color:var(--wn)} .b.blk{color:var(--ok)}
.msg{margin-top:8px;padding:8px 12px;border-radius:8px;background:var(--sf2);white-space:pre-wrap} .msg.ng{border:1px solid var(--ng)} .msg.ok{border:1px solid var(--ok)}
code{background:var(--sf2);padding:1px 5px;border-radius:4px}
</style></head><body><main>
<h1>WAF 追加ルール管理 <span class="sub" id="ver"></span></h1>
<div class="sub">このツールは自分のPC(127.0.0.1)だけで動きます。保存すると稼働中のWAFが数秒以内に検査して入れ替えます(再起動不要)。新しいルールは「検知のみ」から始めてください。</div>

<div class="card"><h2>ルール一覧 <span class="sub" id="cnt"></span></h2>
<table><thead><tr><th>ID</th><th>名前 / 説明</th><th>対象</th><th>重大度</th><th>モード</th><th>有効</th><th></th></tr></thead><tbody id="tb"></tbody></table>
<div style="margin-top:10px"><button onclick="newRule()">＋ ルールを追加</button></div></div>

<div class="card" id="edCard" hidden><h2 id="edTitle">ルールの編集</h2>
<div class="g">
<label>ルールID</label><input id="fId" placeholder="CUS-2026-001">
<label>名前</label><input id="fName" placeholder="例: ○○製品の脆弱性 CVE-2026-xxxx">
<label>正規表現 <span style="font-weight:400;opacity:.7">(URLのパス・各パラメータの値・本文・ヘッダー値を<b>1つずつ</b>検査します。URL全体には当てません)</span></label><textarea id="fPat" placeholder="例: /cgi-bin/vuln\.cgi\?cmd="></textarea>
<label>検査対象</label><select id="fTarget"><option value="all">すべて</option><option value="path">パス</option><option value="query">クエリ</option><option value="body">本文</option><option value="header">ヘッダー</option></select>
<label>重大度</label><select id="fSev"><option>critical</option><option>high</option><option selected>medium</option><option>low</option></select>
<label>モード</label><select id="fMode"><option value="detect" selected>検知のみ(まずはこちら)</option><option value="block">遮断</option></select>
<label>CVE / 参考</label><input id="fCve" placeholder="CVE-2026-xxxx">
<label>説明</label><input id="fDesc" placeholder="ログに表示される説明">
<label>有効</label><select id="fEn"><option value="1" selected>有効</option><option value="0">無効</option></select>
</div>
<div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap">
<button onclick="doCheck()">構文チェック</button><button onclick="applyRule()">この内容を一覧に反映</button><button onclick="cancelEdit()">閉じる</button></div>
<div style="margin-top:12px" class="g"><label>試しの文字列</label><textarea id="tText" placeholder="攻撃の例を貼り付けて「試す」を押すと、このルールに一致するか確認できます"></textarea></div>
<div style="margin-top:8px"><button onclick="doTest()">試す</button></div>
<div id="edMsg"></div></div>

<div class="card"><h2>保存</h2>
<div class="g"><label>変更メモ</label><input id="note" placeholder="何を変えたか(履歴に残ります)"><label>担当者名</label><input id="by" placeholder="あなたの名前"></div>
<div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap"><button onclick="doReplay()">過去ログで検証(誤検知の事前確認)</button><button class="pri" onclick="doSave()">検査して保存</button></div>
<div id="svMsg"></div></div>

<div class="card"><h2>版の履歴 <span class="sub">— 保存のたびに旧版を残します。「戻す」で復元できます</span></h2>
<table><thead><tr><th>保存時刻</th><th>版</th><th>件数</th><th>担当者</th><th>メモ</th><th></th></tr></thead><tbody id="hs"></tbody></table></div>
</main>
<script>
let RULES=[], EDIT=-1;
const esc=s=>String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const api=(u,b)=>fetch(u,b===undefined?{cache:'no-store'}:{method:'POST',headers:{'Content-Type':'application/json','X-Tool':'1'},body:JSON.stringify(b)}).then(r=>r.json());
function msg(id,t,ok){ document.getElementById(id).innerHTML=t?`<div class="msg ${ok?'ok':'ng'}">${esc(t)}</div>`:''; }
function load(){ api('/api/rules').then(d=>{ RULES=d.rules||[]; document.getElementById('ver').textContent='— 現在 v'+d.version+(d.error?'(読み込みエラー: '+d.error+')':'');
  renderList(); renderHist(d.snapshots||[]); }); }
function renderList(){
  document.getElementById('cnt').textContent=RULES.length+'件';
  document.getElementById('tb').innerHTML=RULES.map((r,i)=>`<tr><td><code>${esc(r.id)}</code></td><td>${esc(r.name||'')}<div class="sub">${esc(r.description||'')} ${esc(r.cve||'')}</div></td><td>${esc(r.target)}</td><td>${esc(r.severity)}</td>
   <td><span class="b ${r.mode==='block'?'blk':'det'}">${r.mode==='block'?'遮断':'検知のみ'}</span></td><td>${r.enabled===false?'無効':'有効'}</td>
   <td><button onclick="editRule(${i})">編集</button> <button onclick="delRule(${i})">削除</button></td></tr>`).join('')||'<tr><td colspan="7" class="sub">追加ルールはまだありません</td></tr>';
}
function renderHist(sn){
  document.getElementById('hs').innerHTML=sn.map(s=>`<tr><td>${esc((s.saved_at||'').replace('T',' '))}</td><td>v${esc(s.version)}</td><td>${esc(s.count)}</td><td>${esc(s.saved_by||'')}</td><td>${esc(s.note||'')}</td>
   <td><button onclick="rollback('${esc(s.name)}')">この版に戻す</button></td></tr>`).join('')||'<tr><td colspan="6" class="sub">まだ旧版はありません</td></tr>';
}
const F=id=>document.getElementById(id);
function fill(r){ F('fId').value=r.id||''; F('fName').value=r.name||''; F('fPat').value=r.pattern||''; F('fTarget').value=r.target||'all'; F('fSev').value=r.severity||'medium';
  F('fMode').value=r.mode||'detect'; F('fCve').value=r.cve||''; F('fDesc').value=r.description||''; F('fEn').value=(r.enabled===false)?'0':'1'; }
function read(){ return {id:F('fId').value.trim(),name:F('fName').value.trim(),pattern:F('fPat').value,target:F('fTarget').value,severity:F('fSev').value,mode:F('fMode').value,
  cve:F('fCve').value.trim(),description:F('fDesc').value.trim(),enabled:F('fEn').value==='1'}; }
function newRule(){ EDIT=-1; fill({}); F('edTitle').textContent='ルールを追加'; F('edCard').hidden=false; msg('edMsg',''); F('fId').focus(); }
function editRule(i){ EDIT=i; fill(RULES[i]); F('edTitle').textContent='ルールの編集: '+RULES[i].id; F('edCard').hidden=false; msg('edMsg',''); }
function cancelEdit(){ F('edCard').hidden=true; }
function delRule(i){ if(confirm(RULES[i].id+' を一覧から外します(保存するまで反映されません)')){ RULES.splice(i,1); renderList(); } }
function doCheck(){ msg('edMsg','確認中…',true); api('/api/check',{rule:read()}).then(r=>msg('edMsg',r.ok?'問題ありません(構文・重さの検査に通りました)':r.error,r.ok)); }
function applyRule(){ api('/api/check',{rule:read()}).then(r=>{ if(!r.ok){ msg('edMsg',r.error,false); return; }
  const n=r.rule; if(EDIT>=0) RULES[EDIT]=n; else { if(RULES.some(x=>x.id===n.id)){ msg('edMsg',n.id+' はすでにあります',false); return; } RULES.push(n); }
  renderList(); F('edCard').hidden=true; msg('svMsg','一覧に反映しました。「検査して保存」で確定します',true); }); }
function doTest(){ api('/api/test',{rule:read(),text:F('tText').value}).then(r=>msg('edMsg',r.ok?(r.matched?('一致しました: '+r.matched):'一致しませんでした'):r.error,r.ok&&r.matched)); }
function doReplay(){ msg('svMsg','過去ログを確認中…',true); api('/api/replay',{rules:RULES}).then(r=>{ if(!r.ok){ msg('svMsg',r.error,false); return; }
  const lines=['確認したログ: '+r.scanned+' 件'].concat((r.results||[]).map(x=>`${x.id}: 一致 ${x.matched_total} 件(うち、通していた通信 ${x.on_pass} 件 / すでに検知・遮断していた通信 ${x.on_detect_block} 件)`+(x.on_pass?'\n   ※「通していた通信」に一致すると、遮断にすると誤検知になる可能性があります':'')));
  msg('svMsg',lines.join('\n'),true); }); }
function doSave(){ msg('svMsg','検査して保存中…',true); api('/api/save',{rules:RULES,note:F('note').value,by:F('by').value}).then(r=>{ if(r.ok){ msg('svMsg','保存しました(v'+r.version+')。稼働中のWAFが数秒以内に反映します',true); load(); } else msg('svMsg',r.error,false); }); }
function rollback(n){ if(!confirm(n+' の内容に戻します。いまの状態も旧版として残ります')) return; api('/api/rollback',{name:n,by:F('by').value}).then(r=>{ if(r.ok){ msg('svMsg','戻しました(v'+r.version+')',true); load(); } else msg('svMsg',r.error,false); }); }
load();
</script></body></html>
"""


def _latest_log(p):
    """指定の waf.log があればそれ、なければ data/logs/_all/ の最新の日次ログを使う"""
    if os.path.exists(p):
        return p
    import glob
    c = sorted(glob.glob(os.path.join(ROOT, "data", "logs", "_all", "*.log")))
    return c[-1] if c else p


def make_handler(rules_path, log_path, port):
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype="application/json; charset=utf-8"):
            data = body if isinstance(body, bytes) else body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            self.wfile.write(data)

        def _json(self, code, obj):
            self._send(code, json.dumps(obj, ensure_ascii=False))

        def _guard(self):
            """ループバックからの接続で、Hostが自分自身のときだけ通す(DNSリバインディング対策)"""
            if self.client_address[0] not in ("127.0.0.1", "::1", "::ffff:127.0.0.1"):
                self._json(403, {"ok": False, "error": "このツールはローカル専用です"})
                return False
            host = (self.headers.get("Host") or "").lower()
            if host not in (f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"):
                self._json(403, {"ok": False, "error": "Host が正しくありません"})
                return False
            return True

        def do_GET(self):
            if not self._guard():
                return
            if self.path.split("?")[0] == "/":
                return self._send(200, PAGE, "text/html; charset=utf-8")
            if self.path.split("?")[0] == "/api/rules":
                try:
                    rules, ver = waf_custom.read_file(rules_path)
                    err = ""
                except ValueError as e:
                    rules, ver, err = [], 0, str(e)
                return self._json(200, {"rules": rules, "version": ver, "error": err,
                                        "snapshots": waf_custom.list_snapshots(rules_path)})
            self._json(404, {"ok": False, "error": "not found"})

        def do_POST(self):
            if not self._guard():
                return
            if self.headers.get("X-Tool") != "1":          # 別ページからの送信(CSRF)を弾く
                return self._json(403, {"ok": False, "error": "不正なリクエストです"})
            try:
                n = int(self.headers.get("Content-Length") or 0)
                up = json.loads(self.rfile.read(min(n, 2_000_000)) or b"{}")
            except (ValueError, OSError):
                return self._json(400, {"ok": False, "error": "JSONが正しくありません"})
            p = self.path.split("?")[0]
            try:
                if p == "/api/check":
                    return self._json(200, {"ok": True, "rule": waf_custom.validate_rule(up.get("rule"))})
                if p == "/api/test":
                    r = waf_custom.validate_rule(up.get("rule"))
                    import re as _re
                    m = _re.compile(r["pattern"], _re.I | _re.S).search(waf_rules.normalize(str(up.get("text") or "")))
                    return self._json(200, {"ok": True, "matched": (m.group(0)[:120] if m else "")})
                if p == "/api/replay":
                    rules = waf_custom.validate_all(up.get("rules") or [])
                    return self._json(200, dict(ok=True, **waf_custom.replay(rules, _latest_log(log_path))))
                if p == "/api/save":
                    v = waf_custom.save_file(rules_path, up.get("rules") or [], by=str(up.get("by") or ""), note=str(up.get("note") or ""))
                    return self._json(200, {"ok": True, "version": v})
                if p == "/api/rollback":
                    return self._json(200, {"ok": True, "version": waf_custom.restore_snapshot(rules_path, str(up.get("name") or ""), by=str(up.get("by") or ""))})
            except ValueError as e:
                return self._json(400, {"ok": False, "error": str(e)})
            except Exception as e:
                return self._json(500, {"ok": False, "error": str(e)})
            self._json(404, {"ok": False, "error": "not found"})
    return H


def main(argv=None):
    ap = argparse.ArgumentParser(description="WAF 追加ルール管理ツール(ローカル専用)")
    ap.add_argument("--port", type=int, default=8099)
    ap.add_argument("--file", default=os.path.join(ROOT, "config", "custom_rules.json"), help="追加ルールのファイル")
    ap.add_argument("--log", default=os.path.join(ROOT, "data", "waf.log"), help="過去ログ検証に使うログ(無ければ data/logs/_all/ の最新の日次ログ)")
    a = ap.parse_args(argv)
    httpd = ThreadingHTTPServer(("127.0.0.1", a.port), make_handler(os.path.abspath(a.file), os.path.abspath(a.log), a.port))
    print(f"WAF 追加ルール管理ツール: http://127.0.0.1:{a.port}  (ファイル: {a.file})")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
