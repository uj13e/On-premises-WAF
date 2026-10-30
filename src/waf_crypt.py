# -*- coding: utf-8 -*-
"""ログ詳細(リクエスト/レスポンスのヘッダ・Cookie・ボディ・クエリ)の暗号化。
方式: ハイブリッド暗号。1件ごとのランダムなAES-256鍵でAES-256-GCM暗号化し、その鍵をお客様側の公開鍵(RSA-OAEP / SHA-256)で包んで保存する。WAFが持つのは公開鍵だけ。
保存形式(ログ1件の "enc"): {"v":1, "alg":"RSA-OAEP-256+AES-256-GCM", "kid":"<公開鍵の指紋>", "ek":b64, "iv":b64, "ct":b64(暗号文+GCMタグ)}。復号後は JSON {"req":{...}, "resp":{...}, "query":"..."}
単体でも使える: python waf_crypt.py keygen <出力名> で <出力名>.public.pem / .private.pem を作り、decrypt <秘密鍵.pem> <ログ.jsonl> で復号結果を標準出力へ出す
"""
import base64
import hashlib
import json
import os
import sys
import threading

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    AVAILABLE = True
except Exception:          # cryptography が無い環境(暗号化ONのときだけ必要)
    AVAILABLE = False

ALG = "RSA-OAEP-256+AES-256-GCM"
# ログから外して暗号文に入れる項目。接続元IP・時刻・アクション・検知ルールなど集計に要るものは平文のまま
SECRET_FIELDS = ("req", "resp", "query")

_lock = threading.Lock()


def b64e(b):
    return base64.b64encode(b).decode("ascii")


def b64d(s):
    return base64.b64decode(s.encode("ascii"))


def _oaep():
    return padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def key_id(pub):
    der = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()[:16]


def load_public(pem):
    """公開鍵(PEM)を読む。RSA 2048bit 以上だけ受け付ける。不正なら ValueError"""
    if not AVAILABLE:
        raise ValueError("暗号化には Python の cryptography パッケージが必要です(pip install cryptography)")
    try:
        pub = serialization.load_pem_public_key((pem or "").strip().encode("utf-8"))
    except Exception:
        raise ValueError("公開鍵(PEM形式)として読めません。「-----BEGIN PUBLIC KEY-----」から始まる内容を貼り付けてください")
    if not isinstance(pub, rsa.RSAPublicKey):
        raise ValueError("RSAの公開鍵を指定してください")
    if pub.key_size < 2048:
        raise ValueError("鍵が短すぎます(RSA 2048bit以上)")
    return pub


class _Broken:
    kid = ""

    def seal(self, obj):
        raise RuntimeError("公開鍵が使えません")


class Sealer:
    def __init__(self, pem):
        self.pub = load_public(pem)
        self.kid = key_id(self.pub)

    def seal(self, obj):
        dek = os.urandom(32)
        iv = os.urandom(12)
        plain = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        ct = AESGCM(dek).encrypt(iv, plain, self.kid.encode("ascii"))     # kid を認証データに含める(別の鍵のものとすり替えられない)
        ek = self.pub.encrypt(dek, _oaep())
        return {"v": 1, "alg": ALG, "kid": self.kid, "ek": b64e(ek), "iv": b64e(iv), "ct": b64e(ct)}


_state = {"enabled": False, "keys": {}, "default": None}
_chain_fn = None            # backend_id: [所属組織, その親, ...](近い順)。組織ごとの鍵の選択に使う


def set_chain_fn(fn):
    global _chain_fn
    _chain_fn = fn


def _make(pem):
    try:
        return Sealer(pem)
    except ValueError:
        return _Broken()          # 鍵が使えない。その組織は詳細を平文で残さない


def configure(conf):
    """設定 {"enabled":bool, "org_keys":{組織ID:公開鍵PEM}, "public_key":既定の鍵} を反映する。
    使えない鍵があっても落とさず、その組織の詳細は捨てる(平文では残さない)。使えない組織IDの一覧を返す
    """
    conf = conf if isinstance(conf, dict) else {}
    keys, bad = {}, []
    for org, pem in (conf.get("org_keys") or {}).items():
        if pem:
            k = _make(pem)
            keys[str(org)] = k
            if isinstance(k, _Broken):
                bad.append(str(org))
    default = None
    if conf.get("public_key"):
        default = _make(conf["public_key"])
        if isinstance(default, _Broken):
            bad.append("")
    with _lock:
        _state["enabled"] = bool(conf.get("enabled"))
        _state["keys"], _state["default"] = keys, default
    return bad


def _pick(backend):
    st = _state
    chain = []
    if _chain_fn is not None:
        try:
            chain = _chain_fn(backend or "") or []
        except Exception:
            chain = []
    for org in chain:
        if org in st["keys"]:
            return st["keys"][org]
    return st["default"]


def seal_record(rec):
    """ログ1件の秘匿項目を、そのバックエンドの組織の鍵で暗号化して rec を書き換える。
    鍵が未登録の組織は暗号化しない。鍵が壊れているときは詳細を捨てる(平文は残さない)
    """
    if not _state["enabled"]:
        return rec
    if not any(rec.get(k) for k in SECRET_FIELDS):
        return rec
    s = _pick(rec.get("backend"))
    if s is None:
        return rec
    plain = {k: rec.pop(k) for k in SECRET_FIELDS if k in rec}
    try:
        rec["enc"] = s.seal(plain)
    except Exception:
        rec["enc_error"] = True
    return rec


def decrypt_record(enc, private_pem, password=None):
    """enc を秘密鍵(PEM)で復号して dict を返す(オフライン用)"""
    priv = serialization.load_pem_private_key(private_pem.encode("utf-8") if isinstance(private_pem, str) else private_pem, password=password)
    dek = priv.decrypt(b64d(enc["ek"]), _oaep())
    plain = AESGCM(dek).decrypt(b64d(enc["iv"]), b64d(enc["ct"]), enc.get("kid", "").encode("ascii"))
    return json.loads(plain.decode("utf-8"))


def generate_keypair(bits=3072):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    pem_priv = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    pem_pub = priv.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return pem_pub, pem_priv


def view(le):
    """設定画面に返す内容。各鍵の指紋だけで、公開鍵も秘密鍵も返さない"""
    le = le if isinstance(le, dict) else {}
    kids = {}
    if AVAILABLE:
        for org, pem in (le.get("org_keys") or {}).items():
            try:
                kids[str(org)] = key_id(load_public(pem))
            except ValueError:
                kids[str(org)] = ""
    dk = ""
    if AVAILABLE and le.get("public_key"):
        try:
            dk = key_id(load_public(le["public_key"]))
        except ValueError:
            dk = ""
    return {"enabled": bool(le.get("enabled")), "org_kids": kids, "default_kid": dk, "available": AVAILABLE}


def has_keys(le):
    le = le if isinstance(le, dict) else {}
    return bool(le.get("public_key")) or any((le.get("org_keys") or {}).values())


def apply(cur, up, valid_orgs=None):
    """設定の更新を検証して、保存する設定を返す。不正なら ValueError(何も変えない)
    up: {"enabled":bool, "org_keys":{組織ID: 公開鍵PEM(空=その組織の鍵を外す)}}
    """
    new = dict(cur) if isinstance(cur, dict) else {}
    new["org_keys"] = dict(new.get("org_keys") or {})
    if "enabled" in up:
        new["enabled"] = bool(up["enabled"])
    if isinstance(up.get("org_keys"), dict):
        for org, pem in up["org_keys"].items():
            org = str(org)
            if valid_orgs is not None and org not in valid_orgs:
                raise ValueError("組織が見つかりません: %s" % org)
            pem = str(pem or "").strip()
            if pem:
                load_public(pem)                  # 形式・長さの検証
                new["org_keys"][org] = pem
            else:
                new["org_keys"].pop(org, None)
    new.setdefault("enabled", False)
    new.setdefault("public_key", "")
    if new["enabled"] and not has_keys(new):
        raise ValueError("暗号化をONにするには、組織の公開鍵を1つ以上登録してください")
    configure(new)
    return new


# 復号の操作記録。各行に前の行のハッシュを含めてつなぎ、改ざんを検知する
_alock = threading.Lock()
_alast = {}


def _canon(e):
    return json.dumps(e, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def audit_append(path, entry):
    import datetime as _dt
    e = {k: v for k, v in entry.items() if k not in ("prev", "hash")}
    e.setdefault("ts", _dt.datetime.now().isoformat(timespec="seconds"))
    with _alock:
        prev = _alast.get(path)
        if prev is None:
            prev = ""
            try:
                with open(path, "rb") as f:
                    f.seek(0, os.SEEK_END)
                    n = f.tell()
                    f.seek(max(0, n - 8192))
                    lines = [x for x in f.read().decode("utf-8", "replace").splitlines() if x.strip()]
                if lines:
                    prev = json.loads(lines[-1]).get("hash", "")
            except (OSError, ValueError):
                prev = ""
        e["prev"] = prev
        e["hash"] = hashlib.sha256((prev + _canon({k: v for k, v in e.items() if k != "hash"})).encode("utf-8")).hexdigest()
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
        _alast[path] = e["hash"]
    return e


def audit_read(path, limit=300):
    """(新しい順の記録, つながりが正しいか)"""
    rows, ok, prev = [], True, ""
    try:
        with open(path, "r", encoding="utf-8") as f:
            for ln in f:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    e = json.loads(ln)
                except ValueError:
                    ok = False
                    continue
                h = hashlib.sha256((str(e.get("prev", "")) + _canon({k: v for k, v in e.items() if k != "hash"})).encode("utf-8")).hexdigest()
                if e.get("prev", "") != prev or e.get("hash") != h:
                    ok = False
                prev = e.get("hash", "")
                rows.append(e)
    except OSError:
        pass
    return rows[::-1][:limit], ok


def _main(argv):
    if not AVAILABLE:
        print("cryptography パッケージが必要です: pip install cryptography"); return 2
    if len(argv) >= 3 and argv[1] == "keygen":
        pub, priv = generate_keypair()
        open(argv[2] + ".public.pem", "w").write(pub)
        fd = os.open(argv[2] + ".private.pem", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(priv)
        print("作成しました: %s.public.pem(WAFの設定に貼る) / %s.private.pem(お客様だけが保管。WAFには置かない)" % (argv[2], argv[2]))
        return 0
    if len(argv) >= 4 and argv[1] == "decrypt":
        priv = open(argv[2], "r").read()
        for line in open(argv[3], "r", encoding="utf-8"):
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
                if isinstance(e.get("enc"), dict):
                    e.update(decrypt_record(e.pop("enc"), priv))
            except Exception as ex:
                e = {"error": "復号できません: %s" % ex}
            print(json.dumps(e, ensure_ascii=False))
        return 0
    print(__doc__); return 1


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
