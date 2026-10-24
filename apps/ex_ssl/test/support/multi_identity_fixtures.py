#!/usr/bin/env python3
"""Independent bounded R47 fixtures. Private contents never enter output/logs."""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

OUT = Path(sys.argv[1])
os.umask(0o077)
OUT.mkdir(mode=0o700, exist_ok=False)
OPENSSL = shutil.which("openssl")
if not OPENSSL:
    raise SystemExit("BLOCKED_ENV openssl unavailable")


def run(*args):
    p = subprocess.run([OPENSSL, *map(str, args)], stdin=subprocess.DEVNULL,
                       capture_output=True, timeout=20, check=False)
    if p.returncode:
        print(json.dumps({"event": "fixture_failure", "tool": args[0],
                          "returncode": p.returncode}))
        raise SystemExit(2)
    return p.stdout


def key(name, kind="rsa", bits=2048):
    path = OUT / (name + ".key")
    params = ["-algorithm", "RSA", "-pkeyopt", f"rsa_keygen_bits:{bits}"]
    if kind.startswith("p"):
        curve = "prime256v1" if kind == "p256" else "secp384r1"
        params = ["-algorithm", "EC", "-pkeyopt", f"ec_paramgen_curve:{curve}"]
    elif kind in ["ed25519", "ed448"]:
        params = ["-algorithm", kind.upper()]
    run("genpkey", *params, "-out", path)
    return path


def public(path, keypath, **extra):
    der = run("x509", "-in", path, "-outform", "DER")
    return dict(cert=str(path), key=str(keypath), der_b64=base64.b64encode(der).decode(),
                sha256=hashlib.sha256(der).hexdigest(), **extra)


def root(name, kind="rsa"):
    k = key(name, kind)
    c = OUT / (name + ".pem")
    run("req", "-x509", "-new", "-key", k, "-out", c, "-days", "2", "-sha256",
        "-subj", "/CN=R47-" + name, "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    return public(c, k)


serial = 100


def issue(name, issuer, kind="rsa", bits=2048, existing_key=None, ca=False, server=False, digest=None, large=False):
    global serial
    k = existing_key or key(name, kind, bits)
    csr, cert, ext = [OUT / (name + suffix) for suffix in [".csr", ".pem", ".ext"]]
    run("req", "-new", "-key", k, "-out", csr, "-subj", "/CN=R47-" + name,
        *(["-" + digest] if digest else []))
    constraints = "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n" if ca else (
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
        "extendedKeyUsage=" + ("serverAuth" if server else "clientAuth") + "\n")
    if server:
        constraints += "subjectAltName=DNS:r47.server,IP:127.0.0.1\n"
    if large:
        constraints += "1.3.6.1.4.1.55555.1=ASN1:UTF8String:" + "p" * 20000 + "\n"
    ext.write_text(constraints)
    serial += 1
    run("x509", "-req", "-in", csr, "-CA", issuer["cert"], "-CAkey", issuer["key"],
        "-set_serial", str(serial), "-days", "2", "-sha256", "-extfile", ext, "-out", cert)
    return public(cert, k, issuer_sha256=issuer["sha256"])


def restricted(name, rsa_key, digest, salt):
    raw = OUT / (name + ".rsa.der")
    conf = OUT / (name + ".private.conf")
    der = OUT / (name + ".pkcs8.der")
    pem = OUT / (name + ".key")
    run("rsa", "-in", rsa_key, "-traditional", "-outform", "DER", "-out", raw)
    conf.write_text(f"""asn1=SEQUENCE:private
[private]
version=INTEGER:0
algorithm=SEQUENCE:algorithm
key=FORMAT:HEX,OCTETSTRING:{raw.read_bytes().hex()}
[algorithm]
oid=OID:rsassaPss
parameters=SEQUENCE:pss
[pss]
hash=EXPLICIT:0,SEQUENCE:hash
mgf=EXPLICIT:1,SEQUENCE:mgf
salt=EXPLICIT:2,INTEGER:{salt}
trailer=EXPLICIT:3,INTEGER:1
[hash]
oid=OID:{digest}
params=NULL
[mgf]
oid=OID:mgf1
params=SEQUENCE:hash
""")
    run("asn1parse", "-genconf", conf, "-out", der, "-noout")
    encoded = base64.b64encode(der.read_bytes()).decode()
    pem.write_text("-----BEGIN PRIVATE KEY-----\n" + "\n".join(encoded[i:i+64] for i in range(0, len(encoded), 64)) + "\n-----END PRIVATE KEY-----\n")
    run("pkey", "-in", pem, "-check", "-noout")
    return pem


roots = {name: root(name, "p256" if name == "client-ec" else "rsa")
         for name in ["server-root", "client-a", "client-b", "client-c", "client-ec"]}
server = issue("server", roots["server-root"], server=True)
intermediates = {letter: issue("intermediate-" + letter, roots["client-" + letter], ca=True)
                 for letter in ["a", "b"]}
identities = {}
for name, kind, bits, issuer in [
    ("rsa2048-a", "rsa", 2048, "a"), ("rsa3072-a", "rsa", 3072, "a"),
    ("rsa2048-equal", "rsa", 2048, "a"), ("rsa2048-b", "rsa", 2048, "b"),
    ("p256-a", "p256", 0, "a"), ("p384-a", "p384", 0, "a"),
    ("p256-b", "p256", 0, "b"), ("p256-ecissuer", "p256", 0, "ec"),
    ("ed25519-a", "ed25519", 0, "a"), ("ed448-a", "ed448", 0, "a")]:
    identities[name] = issue(name, roots["client-" + issuer], kind, bits)
for name, issuer in [("chain-a", "a"), ("chain-b", "b")]:
    f = issue(name, intermediates[issuer])
    f["chain"] = [f["cert"], intermediates[issuer]["cert"], roots["client-" + issuer]["cert"]]
    for label, count in [("partial", 2), ("full", 3)]:
        bundle = OUT / (name + "." + label + ".pem")
        bundle.write_bytes(b"".join(Path(path).read_bytes() for path in f["chain"][:count]))
        f[label + "_cert"] = str(bundle)
    identities[name] = f
for name, rsa, digest, salt in [
    ("pss256-a", "rsa2048-a", "sha256", 32),
    ("pss384-a", "rsa2048-a", "sha384", 48),
    ("pss256-strong", "rsa3072-a", "sha256", 32)]:
    k = restricted(name, identities[rsa]["key"], digest, salt)
    identities[name] = issue(name, roots["client-a"], existing_key=k, digest=digest)
identities["pss256-equal"] = issue("pss256-equal", roots["client-a"],
    existing_key=identities["pss256-a"]["key"], digest="sha256")
identities["rsa2048-same-key"] = issue("rsa2048-same-key", roots["client-a"],
    existing_key=identities["rsa2048-a"]["key"])
identities["large-a"] = issue("large-a", roots["client-a"],
    existing_key=identities["rsa2048-a"]["key"], large=True)
for name in ["rsa2048-a", "p256-a"]:
    f = identities[name]
    secret = OUT / (name + ".password")
    secret.write_text("R47_SYNTHETIC_" + name + "_independent")
    encrypted = OUT / (name + ".encrypted.key")
    run("pkcs8", "-topk8", "-in", f["key"], "-out", encrypted, "-v2", "aes-256-cbc",
        "-v2prf", "hmacWithSHA256", "-iter", "2048", "-passout", "file:" + str(secret))
    f.update(encrypted_key=str(encrypted), password_file=str(secret))
for name, f in identities.items():
    combined = OUT / (name + ".combined.pem")
    combined.write_bytes(Path(f["cert"]).read_bytes() + Path(f["key"]).read_bytes())
    f["combined"] = str(combined)
trust = OUT / "client-trust.pem"
trust.write_bytes(b"".join(Path(roots[name]["cert"]).read_bytes()
                         for name in ["client-a", "client-b", "client-ec"]))
manifest = dict(roots=roots, intermediates=intermediates, server=server,
                identities=identities, client_trust=str(trust), openssl=run("version").decode().strip())
(OUT / "fixtures.json").write_text(json.dumps(manifest, indent=2) + "\n")
print(json.dumps({"event": "fixtures_generated", "identities": len(identities),
                  "roots": len(roots), "openssl": manifest["openssl"]}))
