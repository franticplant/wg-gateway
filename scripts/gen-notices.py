#!/usr/bin/env python3
"""Regenerate THIRD_PARTY_NOTICES.txt from the modules the binary links."""
import os
import subprocess

SPDX = {
    "github.com/google/btree": "Apache-2.0",
    "gvisor.dev/gvisor": "Apache-2.0",
    "golang.zx2c4.com/wireguard": "MIT",
}

out = subprocess.check_output(
    ["go", "list", "-deps", "-f", "{{with .Module}}{{.Path}}|{{.Version}}|{{.Dir}}{{end}}", "."],
    text=True,
).split("\n")

mods = sorted({l for l in out if l and not l.startswith("wg-gateway")})
parts = [
    "THIRD-PARTY NOTICES\n\nwg-gateway includes the following third-party software. Each is\n"
    "redistributed under its own license, reproduced below.\n"
]

for m in mods:
    path, version, d = m.split("|")
    name = next(x for x in sorted(os.listdir(d)) if x.upper().startswith(("LICENSE", "COPYING")))
    body = open(os.path.join(d, name)).read().strip()
    header = f"{path} {version}  ({SPDX.get(path, 'BSD-3-Clause')})"
    parts.append("=" * 78 + "\n" + header + "\n" + "=" * 78 + "\n\n" + body + "\n")

open("THIRD_PARTY_NOTICES.txt", "w").write("\n".join(parts))
