"""Independent check: does each new Steam function end the way KPM's GOG row says?

A __stdcall/__thiscall function pops its stack parameters with `ret N`. The
function's length comes from KPM's GOG db (distance to the next GOG function);
code is byte-identical, so the Steam bytes just before s + length (padding
stripped) should end in `ret N` with N = 4 x the stack parameters in the GOG
row's signature. Rows from the trusted pairs and rows from the block method
should agree equally often; a wrong address would land on unrelated bytes.

Usage: py -3 controle_ret.py <original exe> <KPM checkout> <rapport.json>
"""
import bisect, json, os, sqlite3, sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe import PE


def stack_params(notes):
    if notes is None or notes.strip() in ("", "void"):
        return 0
    ps = [p.strip() for p in notes.split(",") if p.strip()]
    if ps and ps[0].split()[-1] == "this":
        ps = ps[1:]
    return len(ps)


def check(exe, kpm, rapport):
    pe = PE(open(exe, "rb").read())
    g = sqlite3.connect(f"file:{os.path.join(kpm, 'AddressDatabases', 'kotor2_gog_aspyr.db')}?mode=ro", uri=True)
    gog = {(c, f): (a, n) for c, f, a, n in g.execute("select class_name, function_name, address, notes from functions")}
    addrs = sorted({v[0] for v in gog.values()})
    rep = json.load(open(rapport, encoding="utf-8"))
    stats = {}
    for r in rep["added"]:
        method = "pair" if r["method"].startswith("pair") else r["method"]
        st = stats.setdefault(method, Counter())
        ga, notes = gog[(r["class"], r["function"])]
        i = bisect.bisect_right(addrs, ga)
        if i >= len(addrs) or addrs[i] - ga > 0x4000:
            st["no length"] += 1
            continue
        s = int(r["steam"], 16)
        try:
            tail = pe.read(s, addrs[i] - ga)
        except ValueError:
            st["unreadable"] += 1
            continue
        tail = tail.rstrip(b"\xCC\x90")
        n = 4 * stack_params(notes)
        if len(tail) >= 3 and tail[-3] == 0xC2:
            got = tail[-2] | tail[-1] << 8
            st["ret N matches" if got == n else "ret N differs"] += 1
        elif tail.endswith(b"\xC3"):
            st["plain ret"] += 1
        else:
            st["other ending"] += 1
    for m, st in stats.items():
        rn = st["ret N matches"] + st["ret N differs"]
        rate = st["ret N matches"] / rn if rn else 0
        print(f"{m:14} ret-N agreement {rate:6.1%} ({st['ret N matches']}/{rn})  {dict(st)}")
    return stats


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    check(*sys.argv[1:])
