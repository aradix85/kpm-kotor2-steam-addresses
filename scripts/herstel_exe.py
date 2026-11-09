"""Rebuild the original KOTOR 2 Steam executable in a work copy.

The installed swkotor2.exe carries Lane's two static KPM patches (4GBPatch and
BorderlessFullscreen). Each patch's hooks file records the original bytes, so
writing those back must give the exact original build. The script refuses to
write anything unless the result hashes to KPM's Steam build.

The game's own exe is only read, never written.

Usage: py -3 herstel_exe.py <installed swkotor2.exe> <KPM checkout> <output exe>
"""
import hashlib, os, re, sys, tomllib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe import PE

STEAM_SHA = "6A522E71631DCEE93467BD2010F3B23D9145326E1E2E89305F13AB104DBBFFEF"
STATIC_PATCHES = ["4GBPatch", "BorderlessFullscreen"]


def main(exe_path, kpm_root, out_path):
    data = bytearray(open(exe_path, "rb").read())
    if hashlib.sha256(data).hexdigest().upper() == STEAM_SHA:
        print("installed exe is already the original build")
    else:
        pe = PE(data)
        for name in STATIC_PATCHES:
            path = os.path.join(kpm_root, "Patches", name, "kotor2-steam-aspyr.hooks.toml")
            with open(path, "rb") as f:
                cfg = tomllib.load(f)
            if STEAM_SHA not in cfg["metadata"]["target_versions"]:
                sys.exit(f"{path} does not target the Steam build")
            for h in cfg["hooks"]:
                if h["type"] != "static":
                    continue
                off = pe.va_to_off(h["address"])
                orig, repl = bytes(h["original_bytes"]), bytes(h["replacement_bytes"])
                cur = bytes(data[off:off + len(orig)])
                if cur == repl:
                    data[off:off + len(orig)] = orig
                    print(f"{name}: restored {len(orig)} bytes at {h['address']:#010x}")
                elif cur == orig:
                    print(f"{name}: not applied at {h['address']:#010x}, nothing to undo")
                else:
                    sys.exit(f"{name}: unexpected bytes at {h['address']:#010x}: {cur.hex(' ')}")
    got = hashlib.sha256(data).hexdigest().upper()
    if got != STEAM_SHA:
        sys.exit(f"result hashes to {got}, not the Steam build {STEAM_SHA}; nothing written")
    with open(out_path, "wb") as f:
        f.write(data)
    print(f"OK: {out_path} is the original Steam build (SHA-256 {STEAM_SHA[:16]}...)")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    main(*sys.argv[1:])
