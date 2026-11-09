"""Sanity check of the test suite: plant faults in a copy, every one must be caught.

Usage: py -3 mutatietest.py <dir with kotor2_steam_aspyr.db and rapport.json>
"""
import os, shutil, sqlite3, subprocess, sys, tempfile

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MUTATIONS = {
    "new function moved 0x10": "update functions set address = address + 16 where id = (select max(id) from functions)",
    "existing KPM row changed": "update functions set address = address + 16 where id = (select min(id) from functions)",
    "vtable off by 4": "update classes set vtable = vtable + 4 where id = (select max(id) from classes)",
    "offset changed": "update offsets set offset = offset + 4 where id = (select max(id) from offsets)",
    "notes differ from GOG": "update functions set notes = 'x' where id = (select max(id) from functions)",
    "global removed": "delete from global_pointers where id = (select max(id) from global_pointers)",
    "function name not in GOG": "update functions set function_name = function_name || '_x' where id = (select max(id) from functions)",
}


def main(src):
    caught = 0
    for name, sql in MUTATIONS.items():
        d = tempfile.mkdtemp()
        shutil.copy(os.path.join(src, "kotor2_steam_aspyr.db"), d)
        shutil.copy(os.path.join(src, "rapport.json"), d)
        db = os.path.join(d, "kotor2_steam_aspyr.db")
        c = sqlite3.connect(db); c.execute(sql); c.commit(); c.close()
        env = dict(os.environ, STEAM_DB=db, PYTHONWARNINGS="ignore")
        r = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests"],
                           cwd=BASE, env=env, capture_output=True, text=True)
        ok = r.returncode != 0
        caught += ok
        failed = [l.split("(")[0].replace("FAIL: ", "").replace("ERROR: ", "").strip()
                  for l in r.stderr.splitlines() if l.startswith(("FAIL:", "ERROR:"))]
        print(f"{'caught ' if ok else 'MISSED '} {name}: {', '.join(failed)}")
        shutil.rmtree(d, ignore_errors=True)
    print(f"{caught}/{len(MUTATIONS)} planted faults caught")
    sys.exit(0 if caught == len(MUTATIONS) else 1)


if __name__ == "__main__":
    main(sys.argv[1])
