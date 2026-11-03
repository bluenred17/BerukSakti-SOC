#!/usr/bin/env python3
"""Kelola akun dashboard Beruk Sakti. Jalankan dengan sudo di VPS.

  sudo python3 manage_users.py add budi --role admin      # kata sandi diminta lewat prompt
  sudo python3 manage_users.py passwd budi
  sudo python3 manage_users.py role budi analyst
  sudo python3 manage_users.py del budi
  sudo python3 manage_users.py list

Peran: viewer (hanya baca), analyst (boleh triage dan kelola kasus), admin (semua, termasuk melihat daftar pengguna).
Kata sandi tidak pernah diberikan sebagai argumen supaya tidak masuk riwayat shell.
"""
import argparse
import getpass
import grp
import hashlib
import json
import os
import re
import sys
import tempfile

USERS_FILE = os.environ.get("USERS_FILE", "/etc/soc-automation/users.json")
SERVICE_GROUP = os.environ.get("SERVICE_GROUP", "socauto")
ROLES = ("viewer", "analyst", "admin")
NAME_RE = re.compile(r"^[a-z0-9._-]{3,32}$")
MIN_LEN = 12


def hash_password(pw, salt=None, n=2**14, r=8, p=1):
    salt = salt or os.urandom(16)
    dk = hashlib.scrypt(pw.encode(), salt=salt, n=n, r=r, p=p, dklen=32)
    return "scrypt$%d$%d$%d$%s$%s" % (n, r, p, salt.hex(), dk.hex())


def load():
    try:
        with open(USERS_FILE, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def save(users):
    d = os.path.dirname(USERS_FILE)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".users-")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2, sort_keys=True)
        f.write("\n")
    os.chmod(tmp, 0o640)
    try:
        os.chown(tmp, 0, grp.getgrnam(SERVICE_GROUP).gr_gid)
    except (KeyError, PermissionError):
        pass
    os.replace(tmp, USERS_FILE)


def ask_password():
    pw = getpass.getpass("Kata sandi (min %d karakter): " % MIN_LEN)
    if len(pw) < MIN_LEN:
        sys.exit("Kata sandi terlalu pendek.")
    if pw != getpass.getpass("Ulangi kata sandi: "):
        sys.exit("Kata sandi tidak sama.")
    return pw


def need_user(users, name):
    if name not in users:
        sys.exit("Pengguna '%s' tidak ada." % name)


def main():
    ap = argparse.ArgumentParser(description="Kelola akun dashboard Beruk Sakti")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("add")
    a.add_argument("name")
    a.add_argument("--role", choices=ROLES, default="viewer")
    sub.add_parser("list")
    for c in ("passwd", "del"):
        sub.add_parser(c).add_argument("name")
    r = sub.add_parser("role")
    r.add_argument("name")
    r.add_argument("role", choices=ROLES)
    args = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("Jalankan dengan sudo.")
    users = load()
    name = getattr(args, "name", "").lower()

    if args.cmd == "list":
        for n, u in sorted(users.items()):
            print("%-20s %s" % (n, u.get("role", "viewer")))
        if not users:
            print("(belum ada pengguna)")
        return
    if args.cmd == "add":
        if not NAME_RE.match(name):
            sys.exit("Nama pengguna harus 3-32 karakter: huruf kecil, angka, titik, minus, atau garis bawah.")
        if name in users:
            sys.exit("Pengguna '%s' sudah ada; pakai passwd atau role." % name)
        users[name] = {"hash": hash_password(ask_password()), "role": args.role}
    elif args.cmd == "passwd":
        need_user(users, name)
        users[name]["hash"] = hash_password(ask_password())
    elif args.cmd == "role":
        need_user(users, name)
        users[name]["role"] = args.role
    elif args.cmd == "del":
        need_user(users, name)
        del users[name]
    save(users)
    print("Selesai: %s %s" % (args.cmd, name))
    if args.cmd in ("passwd", "role", "del"):
        print("Sesi yang sedang aktif tetap berlaku sampai habis atau restart layanan.")


if __name__ == "__main__":
    main()
