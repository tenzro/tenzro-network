#!/usr/bin/env python3
"""Write a directory as an uncompressed newc (SVR4) cpio archive on stdout,
reproducibly: names sorted, owner and group 0, every time set to EPOCH, inode
numbers assigned in name order, no device numbers.

    newc.py <dir> <epoch>
"""

import os
import stat
import sys


def entry(out, ino, name, mode, nlink, mtime, data):
    namez = name.encode() + b"\0"
    hdr = "070701" + "".join(
        f"{v:08X}"
        for v in (ino, mode, 0, 0, nlink, mtime, len(data), 0, 0, 0, 0, len(namez), 0)
    )
    out.write(hdr.encode() + namez)
    out.write(b"\0" * ((4 - (110 + len(namez)) % 4) % 4))
    out.write(data)
    out.write(b"\0" * ((4 - len(data) % 4) % 4))


def main():
    root, epoch = sys.argv[1], int(sys.argv[2])
    paths = []
    for dirpath, dirnames, filenames in os.walk(root):
        for n in dirnames + filenames:
            paths.append(os.path.relpath(os.path.join(dirpath, n), root))
    out = sys.stdout.buffer
    for ino, rel in enumerate(sorted(paths), start=1):
        full = os.path.join(root, rel)
        st = os.lstat(full)
        perm = stat.S_IMODE(st.st_mode)
        if stat.S_ISLNK(st.st_mode):
            entry(out, ino, rel, stat.S_IFLNK | 0o777, 1, epoch, os.readlink(full).encode())
        elif stat.S_ISDIR(st.st_mode):
            entry(out, ino, rel, stat.S_IFDIR | perm, 2, epoch, b"")
        elif stat.S_ISREG(st.st_mode):
            with open(full, "rb") as f:
                entry(out, ino, rel, stat.S_IFREG | perm, 1, epoch, f.read())
        else:
            raise SystemExit(f"unsupported file type: {rel}")
    entry(out, 0, "TRAILER!!!", 0, 1, 0, b"")


if __name__ == "__main__":
    main()
