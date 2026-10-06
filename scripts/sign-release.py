#!/usr/bin/env python3
"""Release signatures for qsh, in the minisign format (https://jedisct1.github.io/minisign/).

The release workflow signs SHA256SUMS with the release key; `qsh install` and install.sh check
that signature (SHA256SUMS.minisig) against the public key compiled into qsh and printed in
docs/security.md, and so can anyone: `minisign -Vm SHA256SUMS -P <public key>`.

Only Python's standard library (BLAKE2b) and the openssl command (Ed25519, OpenSSL 3) are
used, so that the workflow needs nothing installed.

  sign-release.py keygen DIR
      A new key pair: DIR/qsh-release.key, an unencrypted minisign secret key (mode 0600; it
      becomes the repository secret QSH_MINISIGN_KEY and is never committed), and
      DIR/qsh-release.pub, the public key.
  sign-release.py sign KEY FILE COMMENT
      FILE.minisig: FILE's BLAKE2b-512 signed with KEY (a secret key file as keygen writes it),
      with the trusted comment COMMENT (`qsh X.Y.Z SHA256SUMS`).
"""

import base64
import hashlib
import os
import subprocess
import sys
import tempfile

PKCS8_PREFIX = bytes.fromhex("302e020100300506032b657004220420")


def die(message):
    sys.exit(f"sign-release.py: {message}")


def pem_of(seed):
    der = PKCS8_PREFIX + seed
    body = base64.encodebytes(der).decode().replace("\n", "")
    return f"-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n"


def openssl(args, tmp):
    result = subprocess.run(["openssl", *args], cwd=tmp, capture_output=True)
    if result.returncode != 0:
        die(f"openssl {' '.join(args)}: {result.stderr.decode().strip()}")
    return result.stdout


def with_key(seed, action):
    with tempfile.TemporaryDirectory() as tmp:
        os.chmod(tmp, 0o700)
        key = os.path.join(tmp, "key.pem")
        fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(pem_of(seed))
        return action(tmp, key)


def public_of(seed):
    der = with_key(seed, lambda tmp, key: openssl(["pkey", "-in", key, "-pubout", "-outform", "DER"], tmp))
    return der[-32:]


def ed25519_sign(seed, message):
    def action(tmp, key):
        msg = os.path.join(tmp, "message")
        with open(msg, "wb") as f:
            f.write(message)
        return openssl(["pkeyutl", "-sign", "-inkey", key, "-rawin", "-in", msg], tmp)

    sig = with_key(seed, action)
    if len(sig) != 64:
        die("openssl made no Ed25519 signature")
    return sig


def keygen(directory):
    seed = os.urandom(32)
    key_id = os.urandom(8)
    pk = public_of(seed)
    sk = seed + pk
    checksum = hashlib.blake2b(b"Ed" + key_id + sk, digest_size=32).digest()
    # Ed, no key derivation (unencrypted), BLAKE2b checksum; salt and limits unused
    secret = b"Ed" + b"\0\0" + b"B2" + bytes(32) + bytes(8) + bytes(8) + key_id + sk + checksum
    public = b"Ed" + key_id + pk
    key_hex = f"{int.from_bytes(key_id, 'little'):016X}"
    os.makedirs(directory, mode=0o700, exist_ok=True)
    secret_path = os.path.join(directory, "qsh-release.key")
    fd = os.open(secret_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(f"untrusted comment: minisign secret key {key_hex} (qsh releases, unencrypted)\n")
        f.write(base64.b64encode(secret).decode() + "\n")
    with open(os.path.join(directory, "qsh-release.pub"), "w") as f:
        f.write(f"untrusted comment: minisign public key {key_hex}\n")
        f.write(base64.b64encode(public).decode() + "\n")
    print(base64.b64encode(public).decode())


def read_secret(path):
    with open(path) as f:
        lines = [line.strip() for line in f if line.strip()]
    if len(lines) != 2 or not lines[0].startswith("untrusted comment:"):
        die(f"{path}: not a minisign secret key file")
    raw = base64.b64decode(lines[1], validate=True)
    if len(raw) != 158 or raw[:2] != b"Ed" or raw[4:6] != b"B2":
        die(f"{path}: not a minisign Ed25519 secret key")
    if raw[2:4] != b"\0\0":
        die(f"{path}: an encrypted key; this script signs with unencrypted keys only")
    key_id, sk, checksum = raw[54:62], raw[62:126], raw[126:158]
    if hashlib.blake2b(b"Ed" + key_id + sk, digest_size=32).digest() != checksum:
        die(f"{path}: the key's checksum does not match")
    seed, pk = sk[:32], sk[32:]
    if public_of(seed) != pk:
        die(f"{path}: the key's halves do not belong together")
    return seed, key_id


def sign(key_path, file_path, comment):
    if "\n" in comment or "\r" in comment:
        die("the trusted comment must be one line")
    seed, key_id = read_secret(key_path)
    with open(file_path, "rb") as f:
        message = f.read()
    sig = ed25519_sign(seed, hashlib.blake2b(message).digest())
    global_sig = ed25519_sign(seed, sig + comment.encode())
    with open(file_path + ".minisig", "w") as f:
        f.write("untrusted comment: signature from the qsh release key\n")
        f.write(base64.b64encode(b"ED" + key_id + sig).decode() + "\n")
        f.write(f"trusted comment: {comment}\n")
        f.write(base64.b64encode(global_sig).decode() + "\n")


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "keygen":
        keygen(sys.argv[2])
    elif len(sys.argv) == 5 and sys.argv[1] == "sign":
        sign(sys.argv[2], sys.argv[3], sys.argv[4])
    else:
        die("usage: sign-release.py keygen DIR | sign KEY FILE COMMENT")


if __name__ == "__main__":
    main()
