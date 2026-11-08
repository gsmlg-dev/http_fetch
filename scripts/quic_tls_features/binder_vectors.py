#!/usr/bin/env python3
"""Reproduce public deterministic TLS binder vectors using Python stdlib only."""
import hashlib
import hmac
import json


def vector(hash_name, multiple, retry):
    digest = lambda data: hashlib.new(hash_name, data).digest()
    size = len(digest(b""))
    psk = bytes(range(size))
    def expand(secret, label, context):
        label = b"tls13 " + label
        info = size.to_bytes(2, "big") + bytes([len(label)]) + label + bytes([len(context)]) + context
        return hmac.new(secret, info + b"\x01", hash_name).digest()
    def ext(i, value):
        return i.to_bytes(2, "big") + len(value).to_bytes(2, "big") + value
    def msg(i, value):
        return bytes([i]) + len(value).to_bytes(3, "big") + value
    identity = b"\x00\x06ticket\x00\x00\x00\x0a"
    if multiple:
        identity += b"\x00\x05other\x00\x00\x00\x0b"
    binders = bytes([size]) + bytes(size)
    if multiple:
        binders += bytes([size]) + bytes([0x55]) * size
    payload = len(identity).to_bytes(2, "big") + identity + len(binders).to_bytes(2, "big") + binders
    exts = ext(43, b"\x02\x03\x04") + ext(10, b"\x00\x02\x00\x1d") + ext(51, b"\x00\x24\x00\x1d\x00\x20" + bytes([9])+bytes(31)) + ext(45,b"\x01\x01") + ext(41,payload)
    suite = b"\x13\x01" if size == 32 else b"\x13\x02"
    body = b"\x03\x03" + bytes(range(32)) + b"\x00\x00\x02" + suite + b"\x01\x00" + len(exts).to_bytes(2,"big") + exts
    hello = msg(1,body)
    partial = hello[:-len(binders)-2]
    prefix = msg(254, digest(b"public first ClientHello")) + msg(2,b"public HelloRetryRequest") if retry else b""
    early = hmac.new(bytes(size), psk, hash_name).digest()
    binder_key = expand(early,b"res binder",digest(b""))
    finished = expand(binder_key,b"finished",b"")
    binder = hmac.new(finished,digest(prefix+partial),hash_name).digest()
    encoded = partial + len(binders).to_bytes(2,"big") + bytes([size]) + binder + binders[size+1:]
    early_traffic = expand(early,b"c e traffic",digest(encoded))
    return dict(hash=hash_name, multiple=multiple, retry=retry, psk=psk.hex(), prefix=prefix.hex(), hello=encoded.hex(), binder=binder.hex(), early_traffic=early_traffic.hex())

print(json.dumps([vector(h,m,r) for h in ("sha256","sha384") for m in (False,True) for r in (False,True)],indent=2))
