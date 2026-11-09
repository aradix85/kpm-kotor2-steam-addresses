"""Extend KPM's kotor2_steam_aspyr.db from KPM's own GOG database.

The Steam and GOG builds of KOTOR 2 are one compile, relinked: code is
byte-identical, but functions sit at other addresses. So a Steam row is a copy
of the GOG row (name, calling convention, parameter size, notes) with the Steam
address. Steam <-> GOG address pairs come from:

  pairs   Voice of the Old Republic's export (k2-functions-added.csv): the same
          RTTI vtable slot in both builds, or addresses the mod uses in game.
  blokken (--blokken) other GOG functions in a run of functions that moved
          together, i.e. strictly between two pairs with the same Steam-GOG
          distance. Functions at the edge of a run are reported, not added:
          the leave-one-out check shows that guess is wrong too often.

Every Steam address must start a function in the original Steam exe (it is a
call target or a stored pointer). Existing KPM rows are never changed.

Usage: py -3 bouw_steam_db.py --kpm <KPM checkout> --export <kpm-address-export>
                              --exe <original swkotor2.exe> --out <dir> [--blokken]
"""
import argparse, bisect, csv, hashlib, json, os, shutil, sqlite3, sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe import PE
from bewijs import Evidence, mangle


def ro(path):
    return sqlite3.connect(f"file:{path}?mode=ro", uri=True)


class Builder:
    def __init__(self, a):
        self.a = a
        dbdir = os.path.join(a.kpm, "AddressDatabases")
        self.steam_src = os.path.join(dbdir, "kotor2_steam_aspyr.db")
        self.gog_src = os.path.join(dbdir, "kotor2_gog_aspyr.db")
        self.migration = os.path.join(a.kpm, "tools", "SqliteTools", "Migrations",
                                      "005_add_class_vtable.sql")
        exe = open(a.exe, "rb").read()
        sha = hashlib.sha256(exe).hexdigest().upper()
        st = ro(self.steam_src)
        if sha not in [r[0] for r in st.execute("select sha256_hash from game_version")]:
            sys.exit(f"{a.exe} (SHA-256 {sha}) is not the build of kotor2_steam_aspyr.db")
        self.ev = Evidence(PE(exe))

        g = ro(self.gog_src)
        self.gog = {}
        self.gog_by_addr = defaultdict(list)
        for c, f, ad, n, cc, ps in g.execute(
                "select class_name, function_name, address, notes, calling_convention,"
                " param_size_bytes from functions"):
            self.gog[(c, f)] = (ad, n, cc, ps)
            self.gog_by_addr[ad].append((c, f))
        self.gog_addrs = sorted(self.gog_by_addr)

        self.steam = {(c, f): ad for c, f, ad in
                      st.execute("select class_name, function_name, address from functions")}
        self.steam_offsets = {(c, m) for c, m in st.execute("select class_name, member_name from offsets")}
        self.steam_classes = {r[0] for r in st.execute("select class_name from classes")}
        self.steam_schema = max(r[0] for r in st.execute("select version from schema_version"))

        self.added = {}            # (cls, fn) -> dict
        self.steam_to_gog = {}     # steam addr -> gog addr, for every known pair
        self.report = Counter()
        self.conflicts = []

    # ---- pairs --------------------------------------------------------------
    def load_pairs(self):
        by_gog, by_steam = defaultdict(set), defaultdict(set)
        raw = []
        with open(os.path.join(self.a.export, "k2-functions-added.csv"), newline="") as f:
            for r in csv.DictReader(f):
                s, g = int(r["steam_address"], 16), int(r["gog_address"], 16)
                raw.append((s, g, r["source"]))
                by_gog[g].add(s)
                by_steam[s].add(g)
        # KPM's existing Steam rows are pairs too, through the GOG name
        for name, s in self.steam.items():
            if name in self.gog:
                g = self.gog[name][0]
                by_gog[g].add(s)
                by_steam[s].add(g)
                self.steam_to_gog.setdefault(s, g)
        self.pairs = []
        for s, g, src in raw:
            if len(by_gog[g]) > 1 or len(by_steam[s]) > 1:
                self.report["pair dropped: inconsistent with another pair or a KPM row"] += 1
                self.conflicts.append({"kind": "inconsistent pair", "steam": hex(s), "gog": hex(g),
                                       "steam_for_gog": sorted(map(hex, by_gog[g])),
                                       "gog_for_steam": sorted(map(hex, by_steam[s]))})
                continue
            self.pairs.append((s, g, src))
        self.anchors = {g: s for s, g, _ in self.pairs}
        for name, s in self.steam.items():
            if name in self.gog:
                self.anchors.setdefault(self.gog[name][0], s)
        self.anchor_g = sorted(self.anchors)

    def add(self, name, s, g, method):
        if name in self.steam:
            if self.steam[name] == s:
                self.report["already in KPM Steam db, same address"] += 1
            else:
                self.report["conflict with existing KPM Steam row (kept KPM)"] += 1
                self.conflicts.append({"kind": "existing row differs", "name": "::".join(name),
                                       "kpm_steam": hex(self.steam[name]), "derived": hex(s)})
            return
        if name in self.added:
            return
        _, notes, cc, ps = self.gog[name]
        self.added[name] = {"steam": s, "gog": g, "method": method, "notes": notes,
                            "cc": cc, "ps": ps, "evidence": self.ev.kinds(s)}
        self.steam_to_gog[s] = g
        self.report[f"added: {method}"] += 1

    def phase_pairs(self):
        for s, g, src in self.pairs:
            if not self.ev.in_code(s) or not self.ev.starts(s):
                self.report["pair skipped: Steam address has no function-start evidence"] += 1
                continue
            names = self.gog_by_addr.get(g)
            if not names:
                self.report["pair skipped: GOG address unnamed in KPM's GOG db"] += 1
                continue
            for name in names:
                self.add(name, s, g, f"pair:{src}")

    # ---- runs of functions that moved together --------------------------------
    def predict(self, g, exclude=None):
        """Steam address for GOG function g, or None. Only uses anchors != exclude."""
        i = bisect.bisect_left(self.anchor_g, g)
        lo, hi = i - 1, i
        while hi < len(self.anchor_g) and self.anchor_g[hi] in (g, exclude):
            hi += 1
        while lo >= 0 and self.anchor_g[lo] == exclude:
            lo -= 1
        if lo < 0 or hi >= len(self.anchor_g):
            return None, "outside anchors"
        gl, gr = self.anchor_g[lo], self.anchor_g[hi]
        dl, dr = self.anchors[gl] - gl, self.anchors[gr] - gr
        ev = self.ev
        if dl == dr:
            s = g + dl
            return (s, "block:inside") if ev.starts(s) else (None, "inside, no evidence")
        # different distances: walk from each anchor towards g, every function on
        # the way (plus one beyond g) must start a function at that distance
        ia, ib = bisect.bisect_right(self.gog_addrs, gl), bisect.bisect_left(self.gog_addrs, gr)
        run = self.gog_addrs[ia:ib]
        k = run.index(g)
        left = all(ev.starts(x + dl) for x in run[:k + 2])
        right = all(ev.starts(x + dr) for x in run[max(k - 1, 0):])
        if left and right:
            return None, "edge, both sides fit"
        if left:
            return g + dl, "block:edge"
        if right:
            return g + dr, "block:edge"
        return None, "edge, no fit"

    def phase_blocks(self):
        # leave-one-out on the export pairs first: how often would we be wrong?
        loo = Counter()
        wrong = []
        for s, g, _ in self.pairs:
            if g not in self.gog_by_addr:
                continue
            p, why = self.predict(g, exclude=g)
            if p is None:
                loo["no prediction"] += 1
            elif p == s:
                loo[f"correct ({why})"] += 1
            else:
                loo[f"WRONG ({why})"] += 1
                wrong.append({"gog": hex(g), "steam": hex(s), "predicted": hex(p), "how": why})
        self.loo, self.loo_wrong = dict(loo), wrong
        known = {g for g in self.anchors}
        for g in self.gog_addrs:
            if g in known:
                continue
            names = [n for n in self.gog_by_addr[g] if n not in self.steam and n not in self.added]
            if not names:
                continue
            s, why = self.predict(g)
            if s is None:
                self.report[f"not derived: {why}"] += 1
                continue
            if why != "block:inside":
                # leave-one-out shows the edge walk is wrong too often; never used
                self.report["not derived: edge of a run (not trusted)"] += 1
                continue
            if s in self.steam_to_gog and self.steam_to_gog[s] != g:
                self.report["not derived: Steam address already taken"] += 1
                continue
            for name in names:
                self.add(name, s, g, why)

    # ---- classes and offsets ---------------------------------------------------
    def classes(self):
        out = []
        e = ro(os.path.join(self.a.export, "kotor2_steam_aspyr.db"))
        for cls, vt in e.execute("select class_name, vtable from classes where vtable is not null"):
            if cls in self.steam_classes:
                continue
            name = self.ev.rtti_class(vt)
            m = mangle(cls)
            if name in (f".?AV{m}@@", f".?AU{m}@@"):
                out.append((cls, vt))
            else:
                self.report["class skipped: RTTI name does not match"] += 1
        self.new_classes = sorted(out)

    def offsets(self):
        g = ro(self.gog_src)
        self.new_offsets = sorted(
            r for r in g.execute("select class_name, member_name, offset, notes from offsets")
            if (r[0], r[1]) not in self.steam_offsets)

    # ---- output ------------------------------------------------------------------
    def write(self):
        os.makedirs(self.a.out, exist_ok=True)
        dst = os.path.join(self.a.out, "kotor2_steam_aspyr.db")
        shutil.copyfile(self.steam_src, dst)
        c = sqlite3.connect(dst)
        if self.steam_schema < 5:
            c.executescript(open(self.migration, encoding="utf-8").read())
        c.executemany(
            "insert into functions (class_name, function_name, address, notes,"
            " calling_convention, param_size_bytes) values (?,?,?,?,?,?)",
            [(n[0], n[1], r["steam"], r["notes"], r["cc"], r["ps"])
             for n, r in sorted(self.added.items())])
        c.executemany("insert into classes (class_name, vtable) values (?,?)", self.new_classes)
        c.executemany("insert into offsets (class_name, member_name, offset, notes) values (?,?,?,?)",
                      self.new_offsets)
        c.commit()
        c.execute("vacuum")
        c.close()
        rep = {
            "counts": dict(sorted(self.report.items())),
            "functions_added": len(self.added),
            "classes_added": len(self.new_classes),
            "offsets_added": len(self.new_offsets),
            "leave_one_out": getattr(self, "loo", None),
            "leave_one_out_wrong": getattr(self, "loo_wrong", None),
            "conflicts": self.conflicts,
            "added": [{"class": n[0], "function": n[1], "steam": hex(r["steam"]),
                       "gog": hex(r["gog"]), "method": r["method"], "evidence": r["evidence"]}
                      for n, r in sorted(self.added.items())],
        }
        with open(os.path.join(self.a.out, "rapport.json"), "w", encoding="utf-8") as f:
            json.dump(rep, f, indent=1)
        print(json.dumps({k: v for k, v in rep.items() if k not in ("added", "conflicts", "leave_one_out_wrong")}, indent=1))
        print(f"conflicts: {len(self.conflicts)}, wrong leave-one-out predictions: {len(rep['leave_one_out_wrong'] or [])}")


def main():
    p = argparse.ArgumentParser()
    for k in ("kpm", "export", "exe", "out"):
        p.add_argument(f"--{k}", required=True)
    p.add_argument("--blokken", action="store_true")
    a = p.parse_args()
    b = Builder(a)
    b.load_pairs()
    b.phase_pairs()
    if a.blokken:
        b.phase_blocks()
    b.classes()
    b.offsets()
    b.write()


if __name__ == "__main__":
    main()
