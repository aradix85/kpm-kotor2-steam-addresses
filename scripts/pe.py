"""Minimal read-only PE32 helpers: sections, VA <-> file offset, reading bytes."""
import struct


class PE:
    def __init__(self, data: bytes):
        self.data = bytes(data)
        d = self.data
        if d[:2] != b"MZ":
            raise ValueError("not a PE file")
        self.pe = struct.unpack_from("<I", d, 0x3C)[0]
        if d[self.pe:self.pe + 4] != b"PE\0\0":
            raise ValueError("bad PE signature")
        nsec = struct.unpack_from("<H", d, self.pe + 6)[0]
        optsz = struct.unpack_from("<H", d, self.pe + 20)[0]
        opt = self.pe + 24
        if struct.unpack_from("<H", d, opt)[0] != 0x10B:
            raise ValueError("not PE32")
        self.characteristics_offset = self.pe + 22
        self.base = struct.unpack_from("<I", d, opt + 28)[0]
        self.sections = []  # (name, va, vsize, raw_ptr, raw_size, characteristics)
        sh = opt + optsz
        for i in range(nsec):
            o = sh + 40 * i
            name = d[o:o + 8].rstrip(b"\0").decode("latin-1")
            vsize, rva, rsize, rptr = struct.unpack_from("<IIII", d, o + 8)
            ch = struct.unpack_from("<I", d, o + 36)[0]
            self.sections.append((name, self.base + rva, vsize, rptr, rsize, ch))

    def section_of(self, va):
        for s in self.sections:
            if s[1] <= va < s[1] + max(s[2], s[4]):
                return s
        return None

    def va_to_off(self, va):
        if self.base <= va < self.base + 0x1000:  # headers
            return va - self.base
        s = self.section_of(va)
        if s is None:
            raise ValueError(f"VA {va:#x} is in no section")
        off = va - s[1]
        if off >= s[4]:
            raise ValueError(f"VA {va:#x} has no file bytes")
        return s[3] + off

    def read(self, va, n):
        o = self.va_to_off(va)
        return self.data[o:o + n]

    def u32(self, va):
        return struct.unpack("<I", self.read(va, 4))[0]

    def code_sections(self):
        return [s for s in self.sections if s[5] & 0x20000000]  # IMAGE_SCN_MEM_EXECUTE

    def data_sections(self):
        return [s for s in self.sections if not s[5] & 0x20000000]

    def in_code(self, va):
        s = self.section_of(va)
        return s is not None and bool(s[5] & 0x20000000)
