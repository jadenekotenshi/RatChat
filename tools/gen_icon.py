#!/usr/bin/env python3
"""Generate app/RatChat.tiff, the application icon, in the layout NeXT's own tools write.

    python3 tools/gen_icon.py                      # writes app/RatChat.tiff
    python3 tools/gen_icon.py --preview out.png    # also writes an 8x preview of both images
    python3 tools/gen_icon.py --show FILE.tiff out.png   # decode any NeXT icon TIFF to a PNG

The format was copied from /NextApps/Edit.app (a working NeXTSTEP application): one TIFF file
holding two 48x48 images, big-endian, uncompressed, with premultiplied alpha
(private tag 32995 = 1, i.e. "matteing"):

    image 1: 2 bits/sample, gray + alpha, PLANAR (all gray rows, then all alpha rows)
    image 2: 4 bits/sample, R G B A, chunky   (12-bit colour, for colour displays)

Pure Python; PIL is used only for the optional PNG preview.
"""
import struct
import sys

W = H = 48


# ----------------------------------------------------------------------------- drawing
class Canvas:
    def __init__(self):
        self.px = [[(0, 0, 0, 0)] * W for _ in range(H)]

    def put(self, x, y, c):
        if 0 <= x < W and 0 <= y < H:
            self.px[y][x] = c if len(c) == 4 else (c[0], c[1], c[2], 255)

    def rect(self, x0, y0, x1, y1, c):            # inclusive corners
        for y in range(y0, y1 + 1):
            for x in range(x0, x1 + 1):
                self.put(x, y, c)

    def frame(self, x0, y0, x1, y1, c):
        for x in range(x0, x1 + 1):
            self.put(x, y0, c)
            self.put(x, y1, c)
        for y in range(y0, y1 + 1):
            self.put(x0, y, c)
            self.put(x1, y, c)

    def bitmap(self, x0, y0, rows, c):            # '#' pixels are painted
        for dy, row in enumerate(rows):
            for dx, ch in enumerate(row):
                if ch == '#':
                    self.put(x0 + dx, y0 + dy, c)


BLACK = (0, 0, 0)
SHADOW = (85, 85, 85)
FUR = (150, 140, 135)
FUR_DK = (110, 100, 96)
PINK = (225, 150, 160)


def blob_outlined(cv, bands, fur_color):
    """bands: rows of (y0, y1, x0, x1) -- stacked bands approximating a rounded silhouette.
    Draws a 1px black outline (each band's bounds expanded by 1) before the fur color on top,
    so the whole combined shape reads with a crisp edge rather than blending into the background."""
    for y0, y1, x0, x1 in bands:
        cv.rect(x0 - 1, y0 - 1, x1 + 1, y1 + 1, BLACK)
    for y0, y1, x0, x1 in bands:
        cv.rect(x0, y0, x1, y1, fur_color)


def draw():
    cv = Canvas()
    # drop shadow (NeXT icons carry one, down and to the right)
    cv.rect(10, 13, 45, 41, SHADOW)

    # tail: a thin curve trailing off the back of the body, to the lower-left
    cv.bitmap(1, 29, ["......###",
                      "....###..",
                      "..###....",
                      ".##......",
                      "##......."], BLACK)
    cv.bitmap(2, 30, ["......##",
                      "....###.",
                      "..###...",
                      ".##.....",
                      "##......"], FUR_DK)

    # body + head: one continuous stacked-band silhouette (body wide in the middle, tapering to
    # the tail at the back and narrowing into the smaller head at the front), outlined as a whole
    # so there is no seam where the two would otherwise meet.
    blob_outlined(cv, [
        (18, 19, 16, 30),
        (20, 23, 12, 33),
        (24, 31, 9, 35),
        (32, 35, 11, 33),
        (36, 38, 14, 29),
        (39, 40, 17, 25),
        (13, 14, 34, 40),
        (15, 18, 31, 43),
        (19, 24, 30, 44),
        (25, 26, 32, 42),
        (27, 27, 34, 40),
    ], FUR)
    # a little shading along the spine, on top of the fur (no separate outline needed here)
    for y0, y1, x0, x1 in [(19, 24, 12, 15), (25, 33, 9, 12)]:
        cv.rect(x0, y0, x1, y1, FUR_DK)

    # feet, peeking out from under the body
    cv.rect(15, 39, 19, 41, FUR_DK)
    cv.rect(25, 39, 29, 41, FUR_DK)

    # ears: two small circles overlapping the top of the head, so they read as attached rather
    # than floating above it
    cv.bitmap(28, 8, [".######.",
                      "########",
                      "########",
                      "########",
                      ".######."], BLACK)
    cv.bitmap(36, 8, [".######.",
                      "########",
                      "########",
                      "########",
                      ".######."], BLACK)
    cv.bitmap(29, 9, [".####.",
                      "######",
                      "######",
                      ".####."], FUR)
    cv.bitmap(37, 9, [".####.",
                      "######",
                      "######",
                      ".####."], FUR)
    cv.bitmap(30, 10, [".##.",
                      "####",
                      ".##."], PINK)
    cv.bitmap(38, 10, [".##.",
                      "####",
                      ".##."], PINK)

    # eye and nose
    cv.rect(38, 19, 39, 20, BLACK)
    cv.rect(42, 21, 43, 22, PINK)
    cv.frame(42, 21, 43, 22, BLACK)

    # whiskers
    cv.bitmap(43, 20, ["#..",
                      ".#."], BLACK)
    cv.bitmap(43, 23, [".#.",
                      "#.."], BLACK)

    return cv


# ----------------------------------------------------------------------------- TIFF out
def gray2(c):
    r, g, b, a = c
    if a == 0:
        return 0, 0
    lum = 0.30 * r + 0.59 * g + 0.11 * b
    return min(3, int(lum / 255.0 * 3 + 0.5)), 3


def pack2(rows):                                   # rows of 2-bit values -> bytes, MSB first
    out = bytearray()
    for row in rows:
        for i in range(0, len(row), 4):
            v = 0
            for k in range(4):
                v = (v << 2) | row[i + k]
            out.append(v)
    return bytes(out)


def build_tiff(cv):
    g, a = [], []
    rgba = bytearray()
    for y in range(H):
        gr, ar = [], []
        for x in range(W):
            gv, av = gray2(cv.px[y][x])
            gr.append(gv)
            ar.append(av)
            r, gg, b, al = cv.px[y][x]
            if al == 0:
                r = gg = b = 0                     # premultiplied
            rgba.append(((r >> 4) << 4) | (gg >> 4))
            rgba.append(((b >> 4) << 4) | (al >> 4))
        g.append(gr)
        a.append(ar)
    gplane, aplane = pack2(g), pack2(a)
    assert len(gplane) == len(aplane) == 576 and len(rgba) == 4608

    def ifd(entries, next_ifd):
        # entries: (tag, type, count, value-or-offset), value already an int; SHORT values sit in the high half
        out = struct.pack('>H', len(entries))
        for tag, typ, cnt, val in entries:
            if isinstance(val, tuple):                # inline SHORTs (at most two fit)
                out += struct.pack('>HHI', tag, typ, cnt) + struct.pack('>HH', *val)
            elif typ == 3 and cnt == 1:
                out += struct.pack('>HHIHH', tag, typ, cnt, val, 0)
            else:
                out += struct.pack('>HHII', tag, typ, cnt, val)
        return out + struct.pack('>I', next_ifd)

    ifd1 = 8 + 576 * 2                             # 1160
    n_ent = 13
    ifd_len = 2 + n_ent * 12 + 4
    data1 = ifd1 + ifd_len                         # out-of-line values of image 1
    off_strip = data1                              # 2 x LONG  (strip offsets)
    off_cnt = data1 + 8                            # 2 x LONG  (strip byte counts)
    off_xr = data1 + 16
    off_yr = data1 + 24
    pix2 = data1 + 32                              # image 2 pixel data
    ifd2 = pix2 + len(rgba)
    data2 = ifd2 + ifd_len
    off_bps = data2                                # 4 x SHORT
    off_xr2 = data2 + 8
    off_yr2 = data2 + 16
    end = data2 + 24

    e1 = [(256, 3, 1, W), (257, 3, 1, H), (258, 3, 2, (2, 2)), (259, 3, 1, 1), (262, 3, 1, 1),
          (273, 4, 2, off_strip), (277, 3, 1, 2), (279, 4, 2, off_cnt), (282, 5, 1, off_xr),
          (283, 5, 1, off_yr), (284, 3, 1, 2), (296, 3, 1, 2), (32995, 3, 1, 1)]
    e2 = [(256, 3, 1, W), (257, 3, 1, H), (258, 3, 4, off_bps), (259, 3, 1, 1), (262, 3, 1, 2),
          (273, 4, 1, pix2), (277, 3, 1, 4), (279, 4, 1, len(rgba)), (282, 5, 1, off_xr2),
          (283, 5, 1, off_yr2), (284, 3, 1, 1), (296, 3, 1, 2), (32995, 3, 1, 1)]
    body1 = ifd(e1, ifd2)
    out = bytearray(b'MM' + struct.pack('>HI', 42, ifd1))
    out += gplane + aplane
    assert len(out) == ifd1
    out += body1
    out += struct.pack('>IIII', 8, 8 + 576, 576, 576)              # strip offsets, strip byte counts
    out += struct.pack('>IIII', 72 * 10000, 10000, 72 * 10000, 10000)  # 72 dpi x and y
    assert len(out) == pix2
    out += rgba
    assert len(out) == ifd2
    out += ifd(e2, 0)
    out += struct.pack('>HHHH', 4, 4, 4, 4)
    out += struct.pack('>IIII', 72 * 10000, 10000, 72 * 10000, 10000)
    assert len(out) == end
    return bytes(out)


# ----------------------------------------------------------------------------- TIFF in (for checks)
def decode(data):
    """Return [(gray+alpha image as rows of (r,g,b,a)), (rgba image)] from a NeXT icon TIFF."""
    assert data[:2] == b'MM'
    ifd = struct.unpack('>I', data[4:8])[0]
    images = []
    while ifd:
        n = struct.unpack('>H', data[ifd:ifd + 2])[0]
        tags = {}
        for i in range(n):
            tag, typ, cnt, val = struct.unpack('>HHI4s', data[ifd + 2 + i * 12:ifd + 14 + i * 12])
            size = {3: 2, 4: 4, 5: 8}[typ] * cnt
            raw = val[:size] if size <= 4 else data[struct.unpack('>I', val)[0]:][:size]
            fmt = {3: 'H', 4: 'I', 5: 'I'}[typ]
            tags[tag] = struct.unpack('>%d%s' % (cnt * (2 if typ == 5 else 1), fmt), raw)
        ifd = struct.unpack('>I', data[ifd + 2 + n * 12:ifd + 6 + n * 12])[0]
        w, h = tags[256][0], tags[257][0]
        bps, spp, planar = tags[258][0], tags[277][0], tags[284][0]
        assert tags[259][0] == 1, "only uncompressed is handled"
        offs, cnts = tags[273], tags[279]
        strips = [data[o:o + c] for o, c in zip(offs, cnts)]
        bits = bps * spp if planar == 1 else bps
        if planar == 2:
            def samples(strip):
                v = []
                for byte in strip:
                    for s in range(8 - bps, -1, -bps):
                        v.append((byte >> s) & ((1 << bps) - 1))
                return v
            gv, av = samples(strips[0]), samples(strips[1])
            mx = (1 << bps) - 1
            img = [[(gv[y * w + x] * 255 // mx,) * 3 + (av[y * w + x] * 255 // mx,) for x in range(w)] for y in range(h)]
        else:
            v = []
            for byte in strips[0]:
                for s in range(8 - bps, -1, -bps):
                    v.append((byte >> s) & ((1 << bps) - 1))
            mx = (1 << bps) - 1
            img = []
            for y in range(h):
                row = []
                for x in range(w):
                    p = v[(y * w + x) * spp:(y * w + x + 1) * spp]
                    row.append(tuple(c * 255 // mx for c in p))
                img.append(row)
        images.append(img)
    return images


def preview(images, path, scale=8):
    from PIL import Image
    tile = 48 * scale
    canvas = Image.new('RGBA', (tile * len(images) + 16 * (len(images) + 1), tile + 32), (170, 170, 170, 255))
    for k, img in enumerate(images):
        im = Image.new('RGBA', (48, 48))
        for y in range(48):
            for x in range(48):
                r, g, b, a = img[y][x]
                if a:                              # un-premultiply for display
                    r, g, b = min(255, r * 255 // a), min(255, g * 255 // a), min(255, b * 255 // a)
                im.putpixel((x, y), (r, g, b, a))
        canvas.paste(im.resize((tile, tile), Image.NEAREST), (16 + k * (tile + 16), 16),
                     im.resize((tile, tile), Image.NEAREST))
    canvas.save(path)


def main(argv):
    if len(argv) == 4 and argv[1] == '--show':
        preview(decode(open(argv[2], 'rb').read()), argv[3])
        return 0
    out = 'app/RatChat.tiff'
    data = build_tiff(draw())
    open(out, 'wb').write(data)
    print("wrote %s (%d bytes)" % (out, len(data)))
    if len(argv) == 3 and argv[1] == '--preview':
        preview(decode(data), argv[2])
        print("wrote", argv[2])
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
