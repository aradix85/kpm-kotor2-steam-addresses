# KPM: KOTOR 2 Steam-adressen

Scripts die de KOTOR 2 Steam-database van Kotor Patch Manager uitbreiden met de
gegevens van Voice of the Old Republic en KPM's eigen GOG-database. Je hebt
alleen de Steam-versie nodig.

## Mappen

- `scripts\` de scripts
- `tests\` de controles (13 tests)
- `bron-votor\` alleen de exportmap van JeanStiletto (commit 98cd6e9)
- `werk\` uitvoer en de herstelde exe; dit gaat nooit naar GitHub

KPM zelf staat in `..\Kotor-Patch-Manager` (upstream, commit 405ccc3).

## Opnieuw draaien

Vanuit deze map, in volgorde:

```
py -3 scripts\herstel_exe.py "C:\steam\steamapps\common\Knights of the Old Republic II\swkotor2.exe" ..\Kotor-Patch-Manager werk\swkotor2_steam_original.exe
py -3 scripts\bouw_steam_db.py --kpm ..\Kotor-Patch-Manager --export bron-votor\docs\kpm-address-export --exe werk\swkotor2_steam_original.exe --out werk\met-blokken --blokken
py -3 -m unittest discover -s tests -v
py -3 scripts\mutatietest.py werk\met-blokken
dotnet run --project ..\Kotor-Patch-Manager\tools\SqliteTools -c Release -- validate --database werk\met-blokken\kotor2_steam_aspyr.db
```

Zonder `--blokken` (en met `--out werk\alleen-paren`) krijg je alleen de
rechtstreeks gevonden paren. Voor die versie test je met
`set STEAM_DB=werk\alleen-paren\kotor2_steam_aspyr.db`.

## Wat de scripts doen

1. `herstel_exe.py` zet de twee statische KPM-patches (4GB en randloos
   scherm) terug in een kopie van je exe. Het schrijft alleen iets als de hash
   daarna precies KPM's Steam-versie is (6A522E71...). Je game zelf wordt alleen
   gelezen.
2. `bouw_steam_db.py` begint met KPM's huidige Steam-database en voegt toe:
   - functies: elke Steam-functie is een kopie van de GOG-regel (naam,
     aanroepconventie, parameters, notities) met het Steam-adres;
   - vtables van 331 klassen, alleen als de RTTI-naam in de exe klopt;
   - de 757 struct-offsets uit de GOG-database die nog ontbreken (zelfde
     compilatie, dus zelfde offsets).
   Bestaande KPM-regels worden nooit veranderd.
3. De tests controleren onder meer: elk nieuw adres is een echte functiestart
   in de exe, Steam- en GOG-adressen horen één op één bij elkaar, alle
   bestaande regels zijn ongewijzigd, en de vtables kloppen met de RTTI. Er is
   ook een onafhankelijke controle op de return-instructies (`controle_ret.py`).
4. `mutatietest.py` bouwt opzettelijk fouten in een kopie en controleert dat de
   tests ze allemaal vangen.

## Uitkomst (9 november 2026)

- 3.191 nieuwe functies (KPM had er 50): 1.079 uit paren, 2.112 uit blokken
- 331 vtables, 757 offsets, 0 conflicten
- foutmeting met weglaten-en-voorspellen: blokmethode 674 keer goed, 0 keer fout;
  de randmethode zat 22 van de 247 keer fout en wordt daarom niet gebruikt
- return-controle: 94,2% (blokken) tegen 92,6% (paren)
- alle 13 tests slagen, 7 van de 7 ingebouwde fouten gevangen, KPM's
  SqliteTools-validatie geslaagd
