"""Checks for the generated kotor2_steam_aspyr.db before it goes to KPM.

Run from the kpm-steam-adressen folder:
    py -3 -m unittest discover -s tests -v
Set STEAM_DB to test another output (default: werk/met-blokken/kotor2_steam_aspyr.db).
"""
import csv, hashlib, json, os, sqlite3, subprocess, sys, unittest
from collections import defaultdict

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "scripts"))
from pe import PE
from bewijs import Evidence, mangle

KPM = os.environ.get("KPM", os.path.join(BASE, "..", "Kotor-Patch-Manager"))
EXPORT = os.path.join(BASE, "bron-votor", "docs", "kpm-address-export")
EXE = os.path.join(BASE, "werk", "swkotor2_steam_original.exe")
OUT = os.environ.get("STEAM_DB", os.path.join(BASE, "werk", "met-blokken", "kotor2_steam_aspyr.db"))
ORIG = os.path.join(KPM, "AddressDatabases", "kotor2_steam_aspyr.db")
GOG = os.path.join(KPM, "AddressDatabases", "kotor2_gog_aspyr.db")


def ro(p):
    return sqlite3.connect(f"file:{p}?mode=ro", uri=True)


def rows(db, sql):
    return ro(db).execute(sql).fetchall()


class SteamDbTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(EXE, "rb") as f:
            data = f.read()
        cls.sha = hashlib.sha256(data).hexdigest().upper()
        cls.pe = PE(data)
        cls.ev = Evidence(cls.pe)
        q = "select class_name, function_name, address, notes, calling_convention, param_size_bytes from functions"
        cls.out_f = {(r[0], r[1]): r[2:] for r in rows(OUT, q)}
        cls.orig_f = {(r[0], r[1]): r[2:] for r in rows(ORIG, q)}
        cls.gog_f = {(r[0], r[1]): r[2:] for r in rows(GOG, q)}
        cls.new_f = {k: v for k, v in cls.out_f.items() if k not in cls.orig_f}

    # -- the database itself ----------------------------------------------------
    def test_integrity_and_schema(self):
        self.assertEqual(rows(OUT, "pragma integrity_check"), [("ok",)])
        self.assertEqual(rows(OUT, "select max(version) from schema_version"), [(5,)])
        for t in ("functions", "global_pointers", "offsets", "classes", "game_version", "schema_version"):
            self.assertEqual([c[1:3] for c in rows(OUT, f"pragma table_info({t})")],
                             [c[1:3] for c in rows(GOG, f"pragma table_info({t})")], t)

    def test_exe_is_the_database_build(self):
        self.assertEqual(rows(OUT, "select sha256_hash from game_version"), [(self.sha,)])

    def test_existing_kpm_rows_unchanged(self):
        for name, v in self.orig_f.items():
            self.assertEqual(self.out_f.get(name), v, name)
        for t, cols in (("global_pointers", "pointer_name, address, notes"),
                        ("offsets", "class_name, member_name, offset, notes"),
                        ("game_version", "sha256_hash, game_name, version_string, description, platform")):
            orig = set(rows(ORIG, f"select {cols} from {t}"))
            self.assertTrue(orig <= set(rows(OUT, f"select {cols} from {t}")), t)
        self.assertEqual(rows(OUT, "select count(*) from global_pointers"),
                         rows(ORIG, "select count(*) from global_pointers"))

    def test_no_duplicates(self):
        for t, key in (("functions", "class_name, function_name"), ("offsets", "class_name, member_name"),
                       ("classes", "class_name")):
            self.assertEqual(rows(OUT, f"select {key} from {t} group by {key} having count(*) > 1"), [], t)

    # -- functions --------------------------------------------------------------
    def test_new_functions_start_a_function_in_the_exe(self):
        bad = [(n, hex(v[0])) for n, v in self.new_f.items()
               if not (self.ev.in_code(v[0]) and self.ev.starts(v[0]))]
        self.assertEqual(bad, [])

    def test_new_functions_mirror_the_gog_row(self):
        for name, v in self.new_f.items():
            self.assertIn(name, self.gog_f, name)
            self.assertEqual(v[1:], self.gog_f[name][1:], name)  # notes, convention, param size

    def test_steam_and_gog_addresses_map_one_to_one(self):
        s2g, g2s = defaultdict(set), defaultdict(set)
        for name, v in self.out_f.items():
            if name in self.gog_f:
                s2g[v[0]].add(self.gog_f[name][0])
                g2s[self.gog_f[name][0]].add(v[0])
        self.assertEqual({hex(k): v for k, v in s2g.items() if len(v) > 1}, {})
        self.assertEqual({hex(k): v for k, v in g2s.items() if len(v) > 1}, {})

    def test_export_pairs_are_respected(self):
        gog_by_addr = defaultdict(list)
        for name, v in self.gog_f.items():
            gog_by_addr[v[0]].append(name)
        with open(os.path.join(EXPORT, "k2-functions-added.csv"), newline="") as f:
            for r in csv.DictReader(f):
                s, g = int(r["steam_address"], 16), int(r["gog_address"], 16)
                for name in gog_by_addr.get(g, []):
                    if name in self.out_f:
                        self.assertEqual(self.out_f[name][0], s, name)

    def test_block_method_never_wrong_in_leave_one_out(self):
        with open(os.path.join(os.path.dirname(OUT), "rapport.json"), encoding="utf-8") as f:
            rep = json.load(f)
        loo = rep.get("leave_one_out") or {}
        if any(r["method"] == "block:inside" for r in rep["added"]):
            self.assertGreater(loo.get("correct (block:inside)", 0), 500)
            self.assertNotIn("WRONG (block:inside)", loo)
        self.assertFalse([r for r in rep["added"] if r["method"] == "block:edge"])

    def test_block_rows_end_like_their_gog_row(self):
        """ret-N agreement of block rows must be as good as that of the trusted pairs."""
        import contextlib, io
        from controle_ret import check
        with contextlib.redirect_stdout(io.StringIO()):
            st = check(EXE, KPM, os.path.join(os.path.dirname(OUT), "rapport.json"))
        def rate(c):
            n = c["ret N matches"] + c["ret N differs"]
            return c["ret N matches"] / n if n else None
        if "block:inside" in st:
            self.assertGreaterEqual(rate(st["block:inside"]), rate(st["pair"]) - 0.05)

    # -- classes and offsets ----------------------------------------------------
    def test_vtables_match_rtti(self):
        for cls, vt in rows(OUT, "select class_name, vtable from classes where vtable is not null"):
            self.assertIn(self.ev.rtti_class(vt), (f".?AV{mangle(cls)}@@", f".?AU{mangle(cls)}@@"), cls)
            self.assertFalse(self.ev.in_code(vt), cls)
            self.assertTrue(self.ev.in_code(self.pe.u32(vt)), cls)

    def test_offsets_equal_gog(self):
        gog = {(c, m): (o, n) for c, m, o, n in rows(GOG, "select class_name, member_name, offset, notes from offsets")}
        out = {(c, m): (o, n) for c, m, o, n in rows(OUT, "select class_name, member_name, offset, notes from offsets")}
        self.assertEqual(set(gog), set(out))
        self.assertEqual({k for k in out if out[k][0] != gog[k][0]}, set())

    # -- KPM's own tooling --------------------------------------------------------
    def test_kpm_merge_tool_reads_it(self):
        tool = os.path.join(KPM, "tools", "merge-address-db.py")
        env = dict(os.environ, PYTHONIOENCODING="utf-8")
        r = subprocess.run([sys.executable, tool, "--dump", OUT], capture_output=True,
                           text=True, encoding="utf-8", errors="replace", env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(sum(1 for l in r.stdout.splitlines() if l.startswith("functions ")),
                         len(self.out_f))


if __name__ == "__main__":
    unittest.main()
