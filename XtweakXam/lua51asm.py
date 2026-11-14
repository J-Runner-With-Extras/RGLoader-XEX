import sys, struct

# Lua 5.1 bytecode reader/writer for the dash format (big-endian, 4-byte int/size_t,
# 4-byte instructions, 8-byte double). Round-trips a chunk byte for byte, can strip
# debug info, and can insert instructions into a function (fixing up jumps).
#
# usage:
#   lua51asm.py roundtrip in.lub
#   lua51asm.py gamelib in.lub out.lub out.h    # build the box art patch for Marketplace.GameLibrary

OPS = ['MOVE', 'LOADK', 'LOADBOOL', 'LOADNIL', 'GETUPVAL', 'GETGLOBAL', 'GETTABLE', 'SETGLOBAL',
       'SETUPVAL', 'SETTABLE', 'NEWTABLE', 'SELF', 'ADD', 'SUB', 'MUL', 'DIV', 'MOD', 'POW', 'UNM',
       'NOT', 'LEN', 'CONCAT', 'JMP', 'EQ', 'LT', 'LE', 'TEST', 'TESTSET', 'CALL', 'TAILCALL',
       'RETURN', 'FORLOOP', 'FORPREP', 'TFORLOOP', 'SETLIST', 'CLOSE', 'CLOSURE', 'VARARG']
OP = {n: i for i, n in enumerate(OPS)}
SBX_BIAS = 131071
JUMPS = {OP['JMP'], OP['FORLOOP'], OP['FORPREP']}


class Reader:
    def __init__(s, d):
        s.d, s.p = d, 0
    def take(s, n):
        s.p += n
        return s.d[s.p - n:s.p]
    def u8(s):
        return s.take(1)[0]
    def u32(s):
        return struct.unpack('>I', s.take(4))[0]
    def str(s):
        n = s.u32()
        return None if n == 0 else s.take(n)[:-1]


class Writer:
    def __init__(s):
        s.b = bytearray()
    def u8(s, v):
        s.b.append(v)
    def u32(s, v):
        s.b += struct.pack('>I', v)
    def str(s, v):
        if v is None:
            s.u32(0)
        else:
            s.u32(len(v) + 1)
            s.b += v + b'\0'


# constants are kept as (tag, raw bytes) so doubles round-trip exactly
def read_func(r):
    f = {'src': r.str(), 'line': r.u32(), 'last': r.u32()}
    f['nups'], f['params'], f['vararg'], f['stack'] = r.u8(), r.u8(), r.u8(), r.u8()
    f['code'] = [r.u32() for _ in range(r.u32())]
    k = []
    for _ in range(r.u32()):
        t = r.u8()
        k.append((t, b'' if t == 0 else r.take(1) if t == 1 else r.take(8) if t == 3 else r.str()))
    f['k'] = k
    f['protos'] = [read_func(r) for _ in range(r.u32())]
    f['lines'] = [r.u32() for _ in range(r.u32())]
    f['locals'] = [(r.str(), r.u32(), r.u32()) for _ in range(r.u32())]
    f['upvals'] = [r.str() for _ in range(r.u32())]
    return f


def write_func(w, f):
    w.str(f['src'])
    w.u32(f['line']); w.u32(f['last'])
    for x in (f['nups'], f['params'], f['vararg'], f['stack']):
        w.u8(x)
    w.u32(len(f['code']))
    for i in f['code']:
        w.u32(i)
    w.u32(len(f['k']))
    for t, v in f['k']:
        w.u8(t)
        if t == 4:
            w.str(v)
        else:
            w.b += v
    w.u32(len(f['protos']))
    for p in f['protos']:
        write_func(w, p)
    w.u32(len(f['lines']))
    for l in f['lines']:
        w.u32(l)
    w.u32(len(f['locals']))
    for n, a, b in f['locals']:
        w.str(n); w.u32(a); w.u32(b)
    w.u32(len(f['upvals']))
    for n in f['upvals']:
        w.str(n)


HEADER = b'\x1bLuaQ\x00\x00\x04\x04\x04\x08\x00'


def load(d):
    assert d[:12] == HEADER, d[:12]
    r = Reader(d)
    r.p = 12
    f = read_func(r)
    return f, d[r.p:]


def dump(f):
    w = Writer()
    w.b += HEADER
    write_func(w, f)
    return bytes(w.b)


def strip(f):
    f['lines'], f['locals'], f['upvals'] = [], [], []
    for p in f['protos']:
        strip(p)


# --- instruction encoding ---
def iABC(op, a, b, c):
    return OP[op] | a << 6 | c << 14 | b << 23

def iABx(op, a, bx):
    return OP[op] | a << 6 | bx << 14

def iAsBx(op, a, sbx):
    return iABx(op, a, sbx + SBX_BIAS)

def opcode(i):
    return i & 0x3F

def sbx(i):
    return (i >> 14) - SBX_BIAS


def kindex(f, s):
    """Index of string constant s, appended if missing."""
    key = (4, s.encode('latin1'))
    if key not in f['k']:
        f['k'].append(key)
    return f['k'].index(key)


def rk(f, s):
    i = kindex(f, s)
    assert i < 256, 'constant index %d not usable as RK' % i
    return 256 + i


def insert(f, at, new):
    """Insert instructions before pc `at`. Jumps into `at` land on the new code."""
    n = len(new)
    old = f['code']
    out = []
    for pc, ins in enumerate(old):
        if opcode(ins) in JUMPS:
            tgt = pc + 1 + sbx(ins)
            npc = pc + (n if pc >= at else 0)
            ntgt = tgt + (n if tgt > at else 0)
            ins = (ins & 0x3FFF) | (ntgt - npc - 1 + SBX_BIAS) << 14
        out.append(ins)
    f['code'] = out[:at] + new + out[at:]


def find_proto(f, name):
    # find the proto stored as field `name` (CLOSURE rX,n ... SETTABLE rY K(name) rX) in the main function
    for pc, ins in enumerate(f['code']):
        if opcode(ins) == OP['SETTABLE']:
            b = (ins >> 23) & 0x1FF
            if b >= 256 and f['k'][b - 256] == (4, name.encode()):
                c = (ins >> 14) & 0x1FF
                prev = f['code'][pc - 1]
                assert opcode(prev) == OP['CLOSURE'] and (prev >> 6) & 0xFF == c
                return f['protos'][prev >> 14]
    raise KeyError(name)


PREFIX = '\x01ROOT\x01/66acd000-77fe-1000-9115-d802'   # placeholder, replaced by the console root at runtime
SUFFIX = '/1033/boxartlg.jpg'
LIST = '\x01LIST\x01'   # placeholder, replaced at runtime by '|<tid>' per .jpg and '|<tid>p' per .png in LOCAL_DIR
LOCAL_DIR = '\x01DIR\x01'   # placeholder, replaced at runtime by 'file://<cover folder>\'


def boxart_helper():
    """function(titleId) -> LOCAL_DIR/<tid>.jpg|png when listed, else (when a root is
    set) the image cache path for <root>/...d802<tid>/1033/boxartlg.jpg, or ''"""
    h = {'src': None, 'line': 0, 'last': 0, 'nups': 0, 'params': 1, 'vararg': 0, 'stack': 8,
         'code': [], 'k': [], 'protos': [], 'lines': [], 'locals': [], 'upvals': []}
    h['code'] = [
        # r1 = string.format('%08x', titleId); download.xbox.com paths are lowercase
        iABx('GETGLOBAL', 1, kindex(h, 'string')),
        iABC('GETTABLE', 1, 1, rk(h, 'format')),
        iABx('LOADK', 2, kindex(h, '%08x')),
        iABC('MOVE', 3, 0, 0),
        iABC('CALL', 1, 3, 2),
        # r2 = string.match(LIST, '|' .. r1 .. '(p?)')
        iABx('GETGLOBAL', 2, kindex(h, 'string')),
        iABC('GETTABLE', 2, 2, rk(h, 'match')),
        iABx('LOADK', 3, kindex(h, LIST)),
        iABx('LOADK', 4, kindex(h, '|')),
        iABC('MOVE', 5, 1, 0),
        iABx('LOADK', 6, kindex(h, '(p?)')),
        iABC('CONCAT', 4, 4, 6),
        iABC('CALL', 2, 3, 2),
        # if r2 then return LOCAL_DIR .. r1 .. (r2 == 'p' and '.png' or '.jpg') end
        iABC('TEST', 2, 0, 0),
        iAsBx('JMP', 0, 9),
        iABx('LOADK', 3, kindex(h, LOCAL_DIR)),
        iABC('MOVE', 4, 1, 0),
        iABC('EQ', 0, 2, rk(h, 'p')),
        iAsBx('JMP', 0, 2),
        iABx('LOADK', 5, kindex(h, '.png')),
        iAsBx('JMP', 0, 1),
        iABx('LOADK', 5, kindex(h, '.jpg')),
        iABC('CONCAT', 3, 3, 5),
        iABC('RETURN', 3, 2, 0),
        # if PREFIX == '' (no cover art root set) then return '' end
        iABC('EQ', 0, rk(h, PREFIX), rk(h, '')),
        iAsBx('JMP', 0, 2),
        iABx('LOADK', 2, kindex(h, '')),
        iABC('RETURN', 2, 2, 0),
        # r2 = require('Xbox.Dash.ImageCache').GetGlobalCache():GetImage(PREFIX .. r1 .. SUFFIX)
        iABx('GETGLOBAL', 2, kindex(h, 'require')),
        iABx('LOADK', 3, kindex(h, 'Xbox.Dash.ImageCache')),
        iABC('CALL', 2, 2, 2),
        iABC('GETTABLE', 2, 2, rk(h, 'GetGlobalCache')),
        iABC('CALL', 2, 1, 2),
        iABC('SELF', 2, 2, rk(h, 'GetImage')),
        iABx('LOADK', 4, kindex(h, PREFIX)),
        iABC('MOVE', 5, 1, 0),
        iABx('LOADK', 6, kindex(h, SUFFIX)),
        iABC('CONCAT', 4, 4, 6),
        iABC('CALL', 2, 3, 2),
        # GetImage returns the path string, or an HRESULT number on failure
        iABx('GETGLOBAL', 3, kindex(h, 'type')),
        iABC('MOVE', 4, 2, 0),
        iABC('CALL', 3, 2, 2),
        iABC('EQ', 0, 3, rk(h, 'string')),
        iAsBx('JMP', 0, 1),
        iABC('RETURN', 2, 2, 0),
        iABx('LOADK', 2, kindex(h, '')),
        iABC('RETURN', 2, 2, 0),
        iABC('RETURN', 0, 1, 0),
    ]
    return h


def patch_gamelib(main):
    f = find_proto(main, 'ConvertToLibraryItem')
    code = f['code']
    # expect the stock layout: pc 102 NEWTABLE r17, pc 104 boxart = r6, r5 = numeric title id
    assert code[102] == iABC('NEWTABLE', 17, 0, 19), hex(code[102])
    assert code[104] == iABC('SETTABLE', 17, rk(f, 'boxart'), 6), hex(code[104])
    assert not f['protos'] and f['nups'] == 0
    f['protos'].append(boxart_helper())
    new = [
        # local ok, v = pcall(helper, titleId)
        iABx('GETGLOBAL', 17, kindex(f, 'pcall')),
        iABx('CLOSURE', 18, 0),
        iABC('MOVE', 19, 5, 0),
        iABC('CALL', 17, 3, 3),
        # if ok then boxart = v else print('[RGLoader] box art:', v) (when print exists)
        iABC('TEST', 17, 0, 0),
        iAsBx('JMP', 0, 2),
        iABC('MOVE', 6, 18, 0),
        iAsBx('JMP', 0, 6),
        iABx('GETGLOBAL', 19, kindex(f, 'print')),
        iABC('TEST', 19, 0, 0),
        iAsBx('JMP', 0, 3),
        iABx('LOADK', 20, kindex(f, '[RGLoader] box art:')),
        iABC('MOVE', 21, 18, 0),
        iABC('CALL', 19, 3, 1),
    ]
    insert(f, 102, new)
    f['stack'] = max(f['stack'], 22)


def main():
    cmd = sys.argv[1]
    d = open(sys.argv[2], 'rb').read()
    f, tail = load(d)
    assert dump(f) + tail == d, 'round trip mismatch'
    if cmd == 'roundtrip':
        print('ok, %d bytes, %d trailing' % (len(d), len(tail)))
        return
    assert cmd == 'gamelib'
    strip(f)
    patch_gamelib(f)
    out = dump(f)
    open(sys.argv[3], 'wb').write(out)
    # cut the chunk at the strings filled in at runtime, in chunk order
    parts, rest = [], out
    for s in (LIST, LOCAL_DIR, PREFIX):
        marker = struct.pack('>I', len(s) + 1) + s.encode('latin1') + b'\0'
        assert out.count(marker) == 1
        at = rest.index(marker)
        parts.append(rest[:at])
        rest = rest[at + len(marker):]
    print('original %d bytes, patched %d bytes' % (len(d), len(out)))

    def arr(name, b):
        rows = [', '.join('0x%02X' % x for x in b[i:i + 16]) for i in range(0, len(b), 16)]
        return 'static const unsigned char %s[%d] = {\n\t%s\n};\n' % (name, len(b), ',\n\t'.join(rows))

    with open(sys.argv[4], 'w', newline='\r\n') as h:
        h.write('// Generated by lua51asm.py from Marketplace.GameLibrary.lub (dash 17489/17559).\n')
        h.write('// Stripped chunk with ConvertToLibraryItem setting boxart from the local cover\n')
        h.write('// folder, else from the cover art root when one is set (root string empty = none).\n')
        h.write('// Chunk = GameLib_Part[0] + str(list) + GameLib_Part[1] + str("file://" + folder + "\\\\")\n')
        h.write('//       + GameLib_Part[2] + str(root + "%s") + GameLib_Part[3],\n' % PREFIX[6:])
        h.write('// where str(s) = u32(len+1) + s + NUL.\n')
        h.write('#pragma once\n\n')
        fnv = 0x811C9DC5
        for x in d:
            fnv = ((fnv ^ x) * 0x01000193) & 0xFFFFFFFF
        h.write('#define GAMELIB_ORIG_SIZE %d\n' % len(d))
        h.write('#define GAMELIB_ORIG_FNV1A 0x%08X\n' % fnv)
        h.write('#define GAMELIB_PATH_PREFIX "%s"\n\n' % PREFIX[6:])
        h.write(arr('GameLib_OrigStart', d[:64]))
        for i, b in enumerate(parts + [rest]):
            h.write(arr('GameLib_Part%d' % i, b))


if __name__ == '__main__':
    main()
