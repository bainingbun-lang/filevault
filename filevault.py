import argparse
import getpass
import os
import sys

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"FVLT"
VERSION = 1
HEAD = len(MAGIC) + 1 + 16 + 12


class VaultError(Exception):
    pass


def derive(password, salt):
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode())


def encrypt(data, password):
    salt, nonce = os.urandom(16), os.urandom(12)
    ct = AESGCM(derive(password, salt)).encrypt(nonce, data, None)
    return MAGIC + bytes([VERSION]) + salt + nonce + ct


def decrypt(blob, password):
    if len(blob) < HEAD + 16 or blob[:4] != MAGIC:
        raise VaultError("no es un archivo filevault")
    if blob[4] != VERSION:
        raise VaultError(f"version {blob[4]} no soportada")
    salt, nonce, ct = blob[5:21], blob[21:33], blob[33:]
    try:
        return AESGCM(derive(password, salt)).decrypt(nonce, ct, None)
    except InvalidTag:
        raise VaultError("contraseña incorrecta o archivo alterado")


def get_password(args, confirm):
    if args.password_stdin:
        return sys.stdin.readline().rstrip("\n")
    pw = getpass.getpass("Contraseña: ")
    if confirm and pw != getpass.getpass("Repite la contraseña: "):
        raise VaultError("las contraseñas no coinciden")
    return pw


def lock(args):
    if not os.path.isfile(args.file):
        raise VaultError(f"no existe: {args.file}")
    out = args.file + ".vault"
    if os.path.exists(out) and not args.force:
        raise VaultError(f"{out} ya existe (usa --force)")
    pw = get_password(args, True)
    with open(args.file, "rb") as f:
        blob = encrypt(f.read(), pw)
    with open(out, "wb") as f:
        f.write(blob)
    if args.delete_original:
        os.remove(args.file)
    print(out)


def unlock(args):
    if not args.file.endswith(".vault"):
        raise VaultError("el archivo debe terminar en .vault")
    if not os.path.isfile(args.file):
        raise VaultError(f"no existe: {args.file}")
    out = args.file[:-6]
    if os.path.exists(out) and not args.force:
        raise VaultError(f"{out} ya existe (usa --force)")
    pw = get_password(args, False)
    with open(args.file, "rb") as f:
        data = decrypt(f.read(), pw)
    with open(out, "wb") as f:
        f.write(data)
    print(out)


def main(argv=None):
    p = argparse.ArgumentParser(prog="filevault")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, fn in (("lock", lock), ("unlock", unlock)):
        s = sub.add_parser(name)
        s.add_argument("file")
        s.add_argument("--password-stdin", action="store_true")
        s.add_argument("--force", action="store_true")
        if name == "lock":
            s.add_argument("--delete-original", action="store_true")
        s.set_defaults(fn=fn)
    args = p.parse_args(argv)
    try:
        args.fn(args)
    except (VaultError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
