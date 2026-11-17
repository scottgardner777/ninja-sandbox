"""A small, dependency-free ELF parser for the Reverse tab.

Gives the analyst what `readelf -h -l -S -d --dyn-syms` would, from bytes alone: header (class, endianness,
machine, type, entry), program headers (segments: flags, sizes, whether a PT_INTERP is present = dynamic),
section headers (names, sizes, entropy per section), the DT_NEEDED libraries and the dynamic symbol table
(imports = undefined symbols, exports = defined). Static, stripped Mirai-style bots have no dynamic section:
that itself is a finding, so the parser says "static, stripped" instead of returning nothing.

Never raises on malformed input: every field is best-effort and `errors` lists what could not be read.
"""
from __future__ import annotations

import math
import struct
from typing import Any, Dict, List

MACHINES = {0: "none", 2: "sparc", 3: "x86", 4: "m68k", 8: "mips", 20: "ppc", 21: "ppc64", 40: "arm", 42: "sh4",
            43: "sparc64", 50: "ia64", 62: "x86-64", 183: "aarch64", 243: "riscv", 247: "bpf"}
TYPES = {0: "NONE", 1: "REL (relocatable)", 2: "EXEC (executable)", 3: "DYN (shared object / PIE)", 4: "CORE"}
PT = {0: "NULL", 1: "LOAD", 2: "DYNAMIC", 3: "INTERP", 4: "NOTE", 6: "PHDR", 7: "TLS", 0x6474e550: "GNU_EH_FRAME",
      0x6474e551: "GNU_STACK", 0x6474e552: "GNU_RELRO", 0x6474e553: "GNU_PROPERTY", 0x70000003: "MIPS_ABIFLAGS"}
SHT = {0: "NULL", 1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA", 5: "HASH", 6: "DYNAMIC", 7: "NOTE", 8: "NOBITS",
       9: "REL", 11: "DYNSYM", 14: "INIT_ARRAY", 15: "FINI_ARRAY", 0x6ffffff6: "GNU_HASH", 0x6ffffffe: "VERNEED",
       0x6fffffff: "VERSYM"}
DT_NEEDED, DT_STRTAB, DT_SYMTAB, DT_RPATH, DT_RUNPATH, DT_SONAME, DT_FLAGS_1, DT_INIT, DT_INIT_ARRAY = 1, 5, 6, 15, 29, 14, 0x6ffffffb, 12, 25
OSABI = {0: "SYSV", 3: "Linux", 9: "FreeBSD", 97: "ARM", 255: "standalone"}


def entropy(b: bytes) -> float:
    if not b:
        return 0.0
    counts = [0] * 256
    for c in b:
        counts[c] += 1
    n = len(b)
    return round(-sum((c / n) * math.log2(c / n) for c in counts if c), 3)


def _cstr(b: bytes, off: int, limit: int = 256) -> str:
    if off < 0 or off >= len(b):
        return ""
    end = b.find(b"\x00", off, off + limit)
    return b[off:(end if end != -1 else off + limit)].decode("latin1", "replace")


def parse(b: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {"is_elf": b[:4] == b"\x7fELF", "errors": []}
    if not out["is_elf"] or len(b) < 52:
        out["errors"].append("not an ELF or truncated header")
        return out
    cls = b[4]
    bits = 64 if cls == 2 else 32
    le = b[5] == 1
    e = "<" if le else ">"
    out.update({"bits": bits, "endian": "little" if le else "big", "osabi": OSABI.get(b[7], str(b[7])), "abi_version": b[8]})
    try:
        if bits == 64:
            (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum,
             e_shentsize, e_shnum, e_shstrndx) = struct.unpack(e + "HHIQQQIHHHHHH", b[16:64])
        else:
            (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum,
             e_shentsize, e_shnum, e_shstrndx) = struct.unpack(e + "HHIIIIIHHHHHH", b[16:52])
    except struct.error as ex:
        out["errors"].append(f"header: {ex}")
        return out
    out.update({"type": TYPES.get(e_type, str(e_type)), "machine": MACHINES.get(e_machine, str(e_machine)), "machine_id": e_machine,
                "entry": hex(e_entry), "flags": hex(e_flags), "phnum": e_phnum, "shnum": e_shnum, "size": len(b)})

    # ── program headers ──────────────────────────────────────────────────────────────────────────────────
    segs: List[Dict[str, Any]] = []
    interp = None
    dyn_off = dyn_size = 0
    for i in range(min(e_phnum, 64)):
        o = e_phoff + i * e_phentsize
        try:
            if bits == 64:
                p_type, p_flags, p_offset, p_vaddr, _pa, p_filesz, p_memsz, p_align = struct.unpack(e + "IIQQQQQQ", b[o:o + 56])
            else:
                p_type, p_offset, p_vaddr, _pa, p_filesz, p_memsz, p_flags, p_align = struct.unpack(e + "IIIIIIII", b[o:o + 32])
        except struct.error:
            out["errors"].append(f"phdr {i} truncated")
            break
        fl = ("R" if p_flags & 4 else "-") + ("W" if p_flags & 2 else "-") + ("X" if p_flags & 1 else "-")
        seg = {"type": PT.get(p_type, hex(p_type)), "flags": fl, "offset": p_offset, "vaddr": hex(p_vaddr),
               "filesz": p_filesz, "memsz": p_memsz}
        if p_type == 1 and p_filesz and p_offset < len(b):
            seg["entropy"] = entropy(b[p_offset:p_offset + min(p_filesz, 1 << 22)])
        if p_type == 3:
            interp = _cstr(b, p_offset)
        if p_type == 2:
            dyn_off, dyn_size = p_offset, p_filesz
        segs.append(seg)
    out["segments"] = segs
    out["interp"] = interp
    out["rwx_segment"] = any(s["flags"] == "RWX" for s in segs)
    out["exec_stack"] = any(s["type"] == "GNU_STACK" and "X" in s["flags"] for s in segs)

    # ── section headers (stripped binaries often have none) ──────────────────────────────────────────────
    secs: List[Dict[str, Any]] = []
    shstr = None
    raw_sh = []
    for i in range(min(e_shnum, 128)):
        o = e_shoff + i * e_shentsize
        try:
            if bits == 64:
                sh_name, sh_type, sh_flags, sh_addr, sh_off, sh_size, sh_link, sh_info, _al, sh_entsize = struct.unpack(e + "IIQQQQIIQQ", b[o:o + 64])
            else:
                sh_name, sh_type, sh_flags, sh_addr, sh_off, sh_size, sh_link, sh_info, _al, sh_entsize = struct.unpack(e + "IIIIIIIIII", b[o:o + 40])
        except struct.error:
            out["errors"].append(f"shdr {i} truncated")
            break
        raw_sh.append((sh_name, sh_type, sh_flags, sh_addr, sh_off, sh_size, sh_link, sh_entsize))
    if raw_sh and 0 <= e_shstrndx < len(raw_sh):
        so = raw_sh[e_shstrndx][4]
        shstr = so if so < len(b) else None
    for (sh_name, sh_type, sh_flags, sh_addr, sh_off, sh_size, sh_link, sh_entsize) in raw_sh:
        name = _cstr(b, shstr + sh_name) if shstr is not None else ""
        sec = {"name": name, "type": SHT.get(sh_type, hex(sh_type)), "addr": hex(sh_addr), "offset": sh_off, "size": sh_size,
               "flags": ("W" if sh_flags & 1 else "") + ("A" if sh_flags & 2 else "") + ("X" if sh_flags & 4 else "")}
        if sh_type not in (0, 8) and sh_size and sh_off < len(b):
            sec["entropy"] = entropy(b[sh_off:sh_off + min(sh_size, 1 << 22)])
        secs.append(sec)
    out["sections"] = secs
    out["stripped"] = not any(s["type"] == "SYMTAB" for s in secs)
    out["section_names"] = [s["name"] for s in secs if s["name"]]
    upx = b.find(b"UPX!") != -1 or any(n.startswith("UPX") for n in out["section_names"])
    out["packer"] = "UPX" if upx else None

    # ── dynamic section: NEEDED libs, SONAME, RPATH ──────────────────────────────────────────────────────
    needed: List[str] = []
    dyn = {}
    strtab_addr = symtab_addr = None
    if dyn_off and dyn_off < len(b):
        esz = 16 if bits == 64 else 8
        fmt = e + ("qQ" if bits == 64 else "iI")
        for i in range(min(dyn_size // esz, 512)):
            o = dyn_off + i * esz
            try:
                tag, val = struct.unpack(fmt, b[o:o + esz])
            except struct.error:
                break
            if tag == 0:
                break
            dyn.setdefault(tag, []).append(val)
            if tag == DT_STRTAB:
                strtab_addr = val
            if tag == DT_SYMTAB:
                symtab_addr = val
        # map vaddr -> file offset through the LOAD segments
        def v2o(v: int):
            for i in range(min(e_phnum, 64)):
                o = e_phoff + i * e_phentsize
                try:
                    if bits == 64:
                        p_type, _f, p_offset, p_vaddr, _pa, p_filesz, _m, _a = struct.unpack(e + "IIQQQQQQ", b[o:o + 56])
                    else:
                        p_type, p_offset, p_vaddr, _pa, p_filesz, _m, _f, _a = struct.unpack(e + "IIIIIIII", b[o:o + 32])
                except struct.error:
                    return None
                if p_type == 1 and p_vaddr <= v < p_vaddr + p_filesz:
                    return p_offset + (v - p_vaddr)
            return None
        so = v2o(strtab_addr) if strtab_addr is not None else None
        if so is not None:
            for v in dyn.get(DT_NEEDED, []):
                needed.append(_cstr(b, so + v))
            for tag, key in ((DT_SONAME, "soname"), (DT_RPATH, "rpath"), (DT_RUNPATH, "runpath")):
                for v in dyn.get(tag, []):
                    out[key] = _cstr(b, so + v)
        # dynamic symbols: find the DYNSYM section for its size, else read until the string table
        imports: List[str] = []
        exports: List[str] = []
        dynsym = next((s for s in secs if s["type"] == "DYNSYM"), None)
        syo = v2o(symtab_addr) if symtab_addr is not None else None
        if syo is not None and so is not None:
            ent = 24 if bits == 64 else 16
            count = (dynsym["size"] // ent) if dynsym else max(0, min((so - syo) // ent, 4096))
            for i in range(1, min(count, 4096)):
                o = syo + i * ent
                try:
                    if bits == 64:
                        st_name, st_info, _oth, st_shndx, _val, _sz = struct.unpack(e + "IBBHQQ", b[o:o + 24])
                    else:
                        st_name, _val, _sz, st_info, _oth, st_shndx = struct.unpack(e + "IIIBBH", b[o:o + 16])
                except struct.error:
                    break
                nm = _cstr(b, so + st_name, 128)
                if not nm:
                    continue
                (imports if st_shndx == 0 else exports).append(nm)
        out["imports"] = sorted(set(imports))[:400]
        out["exports"] = sorted(set(exports))[:200]
    out["needed"] = needed
    out["linkage"] = "dynamic" if (interp or needed) else "static"
    out["summary"] = (f"{out['machine']} {bits}-bit {out['endian']}-endian {out['type'].split(' ')[0]}, "
                      f"{out['linkage']}{', stripped' if out['stripped'] else ''}"
                      + (f", packed ({out['packer']})" if out["packer"] else "")
                      + (f", {len(needed)} shared libs" if needed else ""))
    return out
