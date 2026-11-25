import os

from filevault import VaultError, decrypt, encrypt


def fails(fn, *a):
    try:
        fn(*a)
    except VaultError:
        return True
    return False


text = "hola, ñandú\n".encode() * 50
binary = os.urandom(4096)
for data in (text, binary, b""):
    assert decrypt(encrypt(data, "pw"), "pw") == data

blob = encrypt(text, "pw")
assert fails(decrypt, blob, "otra")

bad = bytearray(blob)
bad[-1] ^= 1
assert fails(decrypt, bytes(bad), "pw")

assert fails(decrypt, b"XXXX" + blob[4:], "pw")
assert fails(decrypt, blob[:4] + bytes([9]) + blob[5:], "pw")
assert fails(decrypt, b"FV", "pw")

assert encrypt(text, "pw") != encrypt(text, "pw")
print("ok")
