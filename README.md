# KOTOR 2 Steam addresses for Kotor Patch Manager

Scripts and tests that extend [Kotor Patch Manager](https://github.com/LaneDibello/Kotor-Patch-Manager)'s
`kotor2_steam_aspyr.db` (Steam Aspyr build, SHA-256 `6A522E71...`) from KPM's own
`kotor2_gog_aspyr.db`, using only the Steam executable.

Result: 3,191 new functions (from 50), 331 class vtables and 757 struct offsets.
No existing row changes. The per-row report is in [results/rapport.json](results/rapport.json).

## Method

The Steam and GOG builds are one compile, relinked: the code is byte-identical,
but functions moved in blocks. So a Steam row is a copy of the GOG row (name,
calling convention, parameter size, notes), and only the address changes.

- **Pairs (1,079 functions).** [Voice of the Old Republic](https://github.com/JeanStiletto/voice-of-the-old-republic)'s
  [address export](https://github.com/JeanStiletto/voice-of-the-old-republic/tree/main/docs/kpm-address-export)
  pairs Steam and GOG addresses through the same RTTI vtable slot in both builds,
  or through addresses the mod uses in game. Each pair is named by KPM's GOG row
  at the GOG address.
- **Blocks (2,112 functions).** A GOG function strictly between two pairs with
  the same Steam−GOG distance moved with them. Functions at the edge of a block
  are left out, because the leave-one-out check below shows that guess is wrong
  too often.
- **Classes.** A vtable is added only when the RTTI name in the Steam exe matches the class.
- **Offsets.** Struct layouts are identical between the two builds, so the missing GOG offsets are copied.

Every new address must start a function in the Steam exe: it is a near-call
target or a pointer stored in a data section.

## Checks

| Check | Result |
| --- | --- |
| Leave-one-out: hide each known pair, predict it from the others | block rule 674 right, 0 wrong; edge rule 22 of 247 wrong (not used) |
| Function ends in `ret N` matching the GOG signature's stack parameters | 94.2% of block rows, 92.6% of pair rows |
| `tests/` (13 tests) | pass |
| `scripts/mutatietest.py`: plant 7 kinds of faults, tests must catch them | 7/7 caught |
| KPM `SqliteTools validate` and `tools/merge-address-db.py --dump` | pass |

## Running it

You need Python 3.11+, a KPM checkout next to this folder (`../Kotor-Patch-Manager`),
the export folder from Voice of the Old Republic in `bron-votor/docs/kpm-address-export`,
and your own Steam `swkotor2.exe`. The game exe is only read.

```
py -3 scripts/herstel_exe.py "<Steam>/steamapps/common/Knights of the Old Republic II/swkotor2.exe" ../Kotor-Patch-Manager werk/swkotor2_steam_original.exe
py -3 scripts/bouw_steam_db.py --kpm ../Kotor-Patch-Manager --export bron-votor/docs/kpm-address-export --exe werk/swkotor2_steam_original.exe --out werk/met-blokken --blokken
py -3 -m unittest discover -s tests -v
py -3 scripts/mutatietest.py werk/met-blokken
```

`herstel_exe.py` undoes KPM's static 4GBPatch and BorderlessFullscreen, using
their recorded `original_bytes`, in case they are installed. It writes nothing
unless the result hashes to the Steam build.

The scripts were written with Claude. No game code or bytes are included.
Address data credit: JeanStiletto / Voice of the Old Republic.
