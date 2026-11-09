"""Evidence, from one executable alone, that an address starts a function.

A function start is any address in a code section that is
  * the target of a near call (E8 rel32) somewhere in a code section, or
  * stored as a pointer in a non-code section (vtables, callback tables).
Random E8 bytes almost never land inside the 5 MB of code, so the set is clean.
"""
import struct


class Evidence:
    def __init__(self, pe):
        self.pe = pe
        self.calls, self.ptrs = set(), set()
        code = [(s[1], s[1] + max(s[2], s[4])) for s in pe.code_sections()]

        def in_code(v):
            return any(lo <= v < hi for lo, hi in code)

        for _, va, _, rptr, rsize, _ in pe.code_sections():
            buf = pe.data[rptr:rptr + rsize]
            i = buf.find(b"\xE8")
            while i != -1 and i + 5 <= len(buf):
                t = (va + i + 5 + struct.unpack_from("<i", buf, i + 1)[0]) & 0xFFFFFFFF
                if in_code(t):
                    self.calls.add(t)
                i = buf.find(b"\xE8", i + 1)
        for _, va, _, rptr, rsize, _ in pe.data_sections():
            buf = pe.data[rptr:rptr + (rsize & ~3)]
            for (v,) in struct.iter_unpack("<I", buf):
                if in_code(v):
                    self.ptrs.add(v)
        self._code = code

    def in_code(self, va):
        return any(lo <= va < hi for lo, hi in self._code)

    def starts(self, va):
        return va in self.calls or va in self.ptrs

    def kinds(self, va):
        k = []
        if va in self.calls:
            k.append("call")
        if va in self.ptrs:
            k.append("ptr")
        return k

    def rtti_class(self, vtable):
        """Mangled RTTI name of the complete object locator just before a vtable."""
        try:
            col = self.pe.u32(vtable - 4)
            td = self.pe.u32(col + 12)
            raw = self.pe.read(td + 8, 256)
            return raw.split(b"\0", 1)[0].decode("latin-1")
        except (ValueError, struct.error):
            return None


def mangle(class_name):
    """'A::B' -> 'B@A' (MSVC order). Template names are not handled."""
    return "@".join(reversed(class_name.split("::")))
