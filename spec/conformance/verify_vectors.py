#!/usr/bin/env python3
"""Independent check of the spec/conformance/vectors/*.json known-answer vectors.

This does not import anything from meiosis. It implements RFC 8785 (JCS), the
content-ID derivation and the world-hash encoding from their descriptions, and
uses the `blake3` and `cryptography` packages for the primitives. If it agrees
with the Go implementation, the vectors describe the format and not a quirk of
one program.

    python3 -m venv .venv && .venv/bin/pip install blake3 cryptography
    .venv/bin/python spec/conformance/verify_vectors.py
"""
import base64
import decimal
import json
import os
import struct
import sys

import blake3
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

HERE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors")


def load(name):
    with open(os.path.join(HERE, name), encoding="utf-8") as f:
        return json.load(f)


# ---- RFC 8785 ---------------------------------------------------------------

def es6_number(text):
    """Serialise a JSON number the way ECMAScript Number::toString does."""
    d = decimal.Decimal(text)
    x = float(d)
    if x == 0:
        return "0"
    sign = "-" if x < 0 else ""
    # shortest round-trip digits and exponent from repr
    digits, exp = repr(abs(x)), 0
    dec = decimal.Decimal(digits)
    t = dec.as_tuple()
    ds = "".join(map(str, t.digits)).rstrip("0") or "0"
    n = len(ds)
    e10 = dec.adjusted() + 1  # position of the decimal point relative to the digits
    k = n
    if k <= e10 <= 21:
        s = ds + "0" * (e10 - k)
    elif 0 < e10 <= 21:
        s = ds[:e10] + "." + ds[e10:]
    elif -6 < e10 <= 0:
        s = "0." + "0" * (-e10) + ds
    else:
        e = e10 - 1
        mant = ds[0] + ("." + ds[1:] if len(ds) > 1 else "")
        s = mant + "e" + ("+" if e >= 0 else "-") + str(abs(e))
    return sign + s


def utf16_key(s):
    return s.encode("utf-16-be")


def jcs(value):
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, Number):
        return es6_number(value.text)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(jcs(v) for v in value) + "]"
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: utf16_key(kv[0]))
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + jcs(v) for k, v in items) + "}"
    raise TypeError(type(value))


class Number:
    def __init__(self, text):
        self.text = text


def parse(text):
    return json.loads(text, parse_float=Number, parse_int=Number)


# ---- checks -------------------------------------------------------------------

failures = []


def check(cond, msg):
    if not cond:
        failures.append(msg)


def canonical():
    for c in load("canonical.json")["cases"]:
        got = jcs(parse(c["input"]))
        check(got == c["canonical"], "canonical %r: python %r != vector %r" % (c["name"], got, c["canonical"]))


def signatures():
    d = load("signatures.json")
    seed = bytes.fromhex(d["seed_hex"])
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    check(base64.b64encode(pub).decode() == d["public_key"], "public key does not derive from the seed")
    pk = Ed25519PublicKey.from_public_bytes(pub)
    for c in d["cases"]:
        obj = parse(json.dumps(c["object"]))
        obj.pop("signature", None)
        msg = jcs(obj)
        check(msg == c["canonical_unsigned"], "signature %r: canonical form differs" % c["name"])
        sig = base64.b64decode(c["signature"])
        try:
            pk.verify(sig, msg.encode("utf-8"))
        except Exception as exc:  # noqa: BLE001
            failures.append("signature %r does not verify: %s" % (c["name"], exc))
        check(priv.sign(msg.encode("utf-8")) == sig, "signature %r is not the deterministic Ed25519 signature" % c["name"])


B32 = "abcdefghijklmnopqrstuvwxyz234567"


def b32(data):
    return base64.b32encode(data).decode().lower().rstrip("=")


def content_ids():
    for c in load("content-ids.json")["cases"]:
        digest = blake3.blake3(c["canonical"].encode("utf-8")).digest()
        check(c["id"] == c["prefix"] + b32(digest), "content id %r: python %s != vector %s" % (c["name"], c["prefix"] + b32(digest), c["id"]))


def world_hashes():
    for c in load("world-hashes.json")["cases"]:
        files = sorted(((f["path"].encode("utf-8"), base64.b64decode(f["content_base64"])) for f in c["files"]), key=lambda f: f[0])
        h = blake3.blake3()
        for path, content in files:
            h.update(struct.pack(">Q", len(path)) + path + struct.pack(">Q", len(content)) + content)
        check(h.hexdigest() == c["world"], "world %r: python %s != vector %s" % (c["name"], h.hexdigest(), c["world"]))


for fn in (canonical, signatures, content_ids, world_hashes):
    fn()
if failures:
    print("\n".join("FAIL: " + f for f in failures))
    sys.exit(1)
print("all vectors verified independently of the Go implementation")
