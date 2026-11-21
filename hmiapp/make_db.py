#!/usr/bin/env python3
# EntryNav2-CarPlay RHMI resource database generator.
# SPDX-License-Identifier: GPL-3.0-or-later
"""Build EntryCarPlay_ALL_Texts.zip and EntryCarPlay_ALL_Images.zip from hmiapp/EntryCarPlay.xml.

Both archives are deterministic (fixed ZipInfo timestamps and permissions) and
generated with only the Python 3 standard library. Every textId and imageId
referenced in the RHMI XML description is enumerated and verified against the
defined resources so missing IDs fail the build loudly.

Usage:
    make_db.py [--xml PATH] [--out-dir DIR] [--texts PATH] [--images PATH] [--check]
"""

import argparse
import math
import struct
import sys
import xml.etree.ElementTree as ET
import zipfile
import zlib
from pathlib import Path

FIXED_DATE = (2026, 1, 1, 0, 0, 0)

# Language codes expected by BMW HU_ENTRYNAV2 HmiMain3D (matching PluginsCoded apps).
LANGS = (
    ("de", "Deutsch"),
    ("en-UK", "English (UK)"),
    ("en-US", "English (US)"),
    ("es-ES", "Espanol"),
    ("es-US", "Espanol (US)"),
    ("fr-FR", "Francais"),
    ("fr-CA", "Francais (CA)"),
    ("it", "Italiano"),
    ("pt", "Portugues"),
    ("ru", "Russian"),
)

# English fallback strings used across all language files (ASCII-only for iDrive safety).
TEXTS = {
    1: "Apple CarPlay",
    2: "Apple CarPlay: Connecting...",
    3: "Apple CarPlay (Reboot for BT audio)",
    10: "Start Apple CarPlay",
    11: "Stop Apple CarPlay",
    13: "Connecting to iPhone...",
    14: "Open Apple CarPlay",
    15: "Start automatically",
    16: "Help",
    17: "USB cable instead of wireless",
    18: "Start CarPlay (Reboot for BT audio)",
    20: "NAV: CarPlay navigation",
    21: "MEDIA: CarPlay media",
    22: "COM / steering wheel phone button: CarPlay phone",
    23: "MENU: iDrive - OPTION: this menu - BACK: back",
    24: "Wireless: pair iPhone with BMW Bluetooth",
    25: "USB cable: connect iPhone data cable to USB port",
    26: "EntryNav2-CarPlay (GPLv3)",
    27: "github.com/oguzkarcan/EntryNav2-CarPlay",
    30: " ",
}

# Optional per-language overrides (same fallback pattern: English base + overrides).
LANG_TEXTS = {}

# Spinner animation IDs referenced by rhmi::kImgSpinFirst / kSpinFrames in hold_machine.hpp.
SPIN_FIRST_ID = 55010
SPIN_FRAMES = 8


def parse_xml_references(xml_path):
    """Return (text_ids, image_ids, image_dims) enumerated from EntryCarPlay.xml."""
    try:
        tree = ET.parse(str(xml_path))
    except ET.ParseError as exc:
        raise SystemExit("FAIL: cannot parse {}: {}".format(xml_path, exc))

    root = tree.getroot()
    text_ids = set()
    image_ids = set()
    image_model_to_id = {}

    for elem in root.iter():
        if "textId" in elem.attrib:
            raw = elem.attrib["textId"]
            try:
                text_ids.add(int(raw))
            except ValueError:
                raise SystemExit("FAIL: non-integer textId {!r} in {}".format(raw, xml_path))

        if "imageId" in elem.attrib:
            raw = elem.attrib["imageId"]
            try:
                img_id = int(raw)
            except ValueError:
                raise SystemExit("FAIL: non-integer imageId {!r} in {}".format(raw, xml_path))
            image_ids.add(img_id)
            if elem.tag == "imageIdModel" and "id" in elem.attrib:
                image_model_to_id[elem.attrib["id"]] = img_id

    # Extract explicit image component dimensions (property id="9" width, id="10" height).
    image_dims = {}
    for elem in root.iter("image"):
        model_ref = elem.attrib.get("model")
        if model_ref not in image_model_to_id:
            continue
        props = {}
        for prop in elem.findall("./properties/property"):
            pid = prop.attrib.get("id")
            val = prop.attrib.get("value")
            if pid in ("9", "10") and val is not None:
                try:
                    props[pid] = int(val)
                except ValueError:
                    pass
        if "9" in props and "10" in props:
            image_dims[image_model_to_id[model_ref]] = (props["9"], props["10"])

    return text_ids, image_ids, image_dims


def encode_rgba_png(width, height, rgba_rows):
    """Encode a 32-bit RGBA PNG (color_type=6, bit_depth=8) from row bytearrays."""
    def chunk(tag, data):
        return (
            struct.pack(">I", len(data))
            + tag
            + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        )

    raw = bytearray()
    for row in rgba_rows:
        raw.append(0)  # filter type 0 (None)
        raw.extend(row)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
        + chunk(b"IEND", b"")
    )


def _clamp_u8(v):
    if v <= 0:
        return 0
    if v >= 255:
        return 255
    return int(v)


def _blend_pixel(row, x, r, g, b, a):
    if a <= 0:
        return
    idx = x * 4
    if a >= 255:
        row[idx] = r
        row[idx + 1] = g
        row[idx + 2] = b
        row[idx + 3] = 255
        return
    src_a = a / 255.0
    dst_a = row[idx + 3] / 255.0
    out_a = src_a + dst_a * (1.0 - src_a)
    if out_a <= 0.0:
        return
    row[idx] = _clamp_u8((r * src_a + row[idx] * dst_a * (1.0 - src_a)) / out_a)
    row[idx + 1] = _clamp_u8((g * src_a + row[idx + 1] * dst_a * (1.0 - src_a)) / out_a)
    row[idx + 2] = _clamp_u8((b * src_a + row[idx + 2] * dst_a * (1.0 - src_a)) / out_a)
    row[idx + 3] = _clamp_u8(out_a * 255.0 + 0.5)


def _sd_round_box(px, py, cx, cy, hw, hh, rad):
    qx = abs(px - cx) - hw + rad
    qy = abs(py - cy) - hh + rad
    dx = max(qx, 0.0)
    dy = max(qy, 0.0)
    return math.hypot(dx, dy) + min(max(qx, qy), 0.0) - rad


def _sd_triangle(px, py, ax, ay, bx, by, cx, cy):
    def edge(x0, y0, x1, y1):
        ex = x1 - x0
        ey = y1 - y0
        vx = px - x0
        vy = py - y0
        t = (vx * ex + vy * ey) / (ex * ex + ey * ey)
        t = 0.0 if t < 0.0 else (1.0 if t > 1.0 else t)
        return math.hypot(vx - ex * t, vy - ey * t), ex * vy - ey * vx

    d0, c0 = edge(ax, ay, bx, by)
    d1, c1 = edge(bx, by, cx, cy)
    d2, c2 = edge(cx, cy, ax, ay)
    d = min(d0, d1, d2)
    inside = (c0 >= 0.0 and c1 >= 0.0 and c2 >= 0.0) or (c0 <= 0.0 and c1 <= 0.0 and c2 <= 0.0)
    return -d if inside else d


def make_entry_icon(w=63, h=54):
    """Generate an original 63x54 RGBA icon: rounded cyan-blue projection badge with play glyph."""
    rows = [bytearray(w * 4) for _ in range(h)]
    cx = (w - 1) * 0.5
    cy = (h - 1) * 0.5
    for y in range(h):
        row = rows[y]
        t_y = y / float(h - 1)
        bg_r = int(20 + 18 * (1.0 - t_y))
        bg_g = int(105 + 75 * (1.0 - t_y))
        bg_b = int(215 + 30 * (1.0 - t_y))
        for x in range(w):
            # Outer rounded badge
            d_box = _sd_round_box(x, y, cx, cy, 22.0, 20.0, 8.5)
            cov = max(0.0, min(1.0, 0.7 - d_box))
            if cov > 0.0:
                _blend_pixel(row, x, bg_r, bg_g, bg_b, int(cov * 255.0 + 0.5))
                # Subtle inner highlight border
                d_rim = abs(d_box + 1.2) - 0.6
                if d_rim < 0.8:
                    rim_cov = max(0.0, min(1.0, 0.7 - d_rim)) * cov
                    _blend_pixel(row, x, 190, 235, 255, int(rim_cov * 95.0))

            # Left dock column (three small rounded white tiles)
            for idx_dot, dy in enumerate((-7.5, 0.0, 7.5)):
                d_dot = _sd_round_box(x, y, cx - 10.5, cy + dy, 2.3, 2.3, 1.0)
                dcov = max(0.0, min(1.0, 0.6 - d_dot))
                if dcov > 0.0:
                    _blend_pixel(row, x, 245, 250, 255, int(dcov * 245.0))

            # Play triangle on right side (generic media/projection symbol)
            d_tri = _sd_triangle(x, y, cx - 1.5, cy - 8.5, cx - 1.5, cy + 8.5, cx + 13.0, cy)
            tcov = max(0.0, min(1.0, 0.6 - d_tri))
            if tcov > 0.0:
                _blend_pixel(row, x, 255, 255, 255, int(tcov * 255.0))

    return encode_rgba_png(w, h, rows)


def make_preview_image(w=549, h=484):
    """Generate an original 549x484 RGBA preview image for the iDrive Media preview pane."""
    # Precompute a vertical slate gradient row template, then paint geometric shapes via bounding boxes.
    rows = []
    for y in range(h):
        t = y / float(h - 1)
        r = int(14 + 10 * (1.0 - t))
        g = int(20 + 18 * (1.0 - t))
        b = int(34 + 28 * (1.0 - t))
        row_px = bytes((r, g, b, 240)) * w
        rows.append(bytearray(row_px))

    def paint_round_box(cx, cy, hw, hh, rad, r, g, b, a):
        x0 = max(0, int(cx - hw - 2))
        x1 = min(w - 1, int(cx + hw + 2))
        y0 = max(0, int(cy - hh - 2))
        y1 = min(h - 1, int(cy + hh + 2))
        for py in range(y0, y1 + 1):
            row = rows[py]
            for px in range(x0, x1 + 1):
                d = _sd_round_box(px, py, cx, cy, hw, hh, rad)
                if d < 0.8:
                    cov = max(0.0, min(1.0, 0.7 - d))
                    _blend_pixel(row, px, r, g, b, int(a * cov))

    # Outer bezel card
    paint_round_box(w * 0.5, h * 0.5, 232.0, 178.0, 26.0, 26, 38, 58, 255)
    paint_round_box(w * 0.5, h * 0.5, 224.0, 170.0, 22.0, 18, 26, 42, 255)

    # Sidebar dock on the left of the preview dashboard
    paint_round_box(84.0, h * 0.5, 24.0, 146.0, 12.0, 32, 48, 72, 255)
    for dy, col in ((-80.0, (48, 165, 245)), (0.0, (56, 200, 150)), (80.0, (125, 145, 240))):
        paint_round_box(84.0, h * 0.5 + dy, 13.0, 13.0, 5.0, col[0], col[1], col[2], 255)

    # Main dashboard navigation tile (left-center)
    paint_round_box(236.0, h * 0.5, 112.0, 146.0, 16.0, 28, 66, 108, 255)
    # Stylized route ribbon inside the nav tile
    paint_round_box(228.0, h * 0.5 + 32.0, 52.0, 10.0, 5.0, 72, 195, 255, 235)
    paint_round_box(270.0, h * 0.5 - 24.0, 10.0, 62.0, 5.0, 72, 195, 255, 235)
    paint_round_box(270.0, h * 0.5 - 78.0, 18.0, 18.0, 9.0, 245, 250, 255, 245)

    # Secondary media & status tiles (right column)
    paint_round_box(426.0, h * 0.5 - 76.0, 62.0, 70.0, 14.0, 34, 88, 138, 255)
    paint_round_box(426.0, h * 0.5 + 76.0, 62.0, 70.0, 14.0, 34, 54, 86, 255)

    # Play glyph inside top-right media tile
    tcx, tcy = 428.0, h * 0.5 - 76.0
    for py in range(int(tcy - 28), int(tcy + 29)):
        row = rows[py]
        for px in range(int(tcx - 24), int(tcx + 29)):
            d = _sd_triangle(px, py, tcx - 14.0, tcy - 20.0, tcx - 14.0, tcy + 20.0, tcx + 20.0, tcy)
            if d < 0.8:
                cov = max(0.0, min(1.0, 0.7 - d))
                _blend_pixel(row, px, 240, 248, 255, int(250 * cov))

    # Waveform bars inside bottom-right tile
    for idx, bar_h in enumerate((14.0, 28.0, 20.0, 32.0, 16.0)):
        bx = 394.0 + idx * 16.0
        paint_round_box(bx, h * 0.5 + 76.0, 4.0, bar_h, 4.0, 120, 210, 255, 230)

    return encode_rgba_png(w, h, rows)


def make_clear_png(w=549, h=484):
    """Generate a fully transparent RGBA PNG for the blank hold state (state 13)."""
    zero_row = bytearray(w * 4)
    return encode_rgba_png(w, h, (zero_row for _ in range(h)))


def make_spinner_frame(frame_idx, total_frames=SPIN_FRAMES, w=63, h=54):
    """Generate one frame of a 63x54 RGBA 8-dot circular spinner."""
    rows = [bytearray(w * 4) for _ in range(h)]
    cx = (w - 1) * 0.5
    cy = (h - 1) * 0.5
    orbit_r = 16.0
    for dot in range(total_frames):
        angle = (2.0 * math.pi * dot) / total_frames - math.pi * 0.5
        dx = cx + orbit_r * math.cos(angle)
        dy = cy + orbit_r * math.sin(angle)
        age = (frame_idx - dot) % total_frames
        alpha = int(255 * max(0.18, 1.0 - age / float(total_frames)))
        dot_r = 3.2 if age == 0 else 2.5
        for py in range(max(0, int(dy - 6)), min(h, int(dy + 7))):
            row = rows[py]
            for px in range(max(0, int(dx - 6)), min(w, int(dx + 7))):
                d = math.hypot(px - dx, py - dy) - dot_r
                if d < 0.8:
                    cov = max(0.0, min(1.0, 0.7 - d))
                    _blend_pixel(row, px, 140, 215, 255, int(alpha * cov))
    return encode_rgba_png(w, h, rows)


def build_images_dict():
    """Return {image_id: png_bytes} for all EntryCarPlay images."""
    images = {
        55001: make_entry_icon(63, 54),
        55002: make_preview_image(549, 484),
        55003: make_clear_png(549, 484),
    }
    for frame in range(SPIN_FRAMES):
        images[SPIN_FIRST_ID + frame] = make_spinner_frame(frame, SPIN_FRAMES, 63, 54)
    return images


def png_dimensions(png_bytes):
    if len(png_bytes) < 24 or png_bytes[:8] != b"\x89PNG\r\n\x1a\n" or png_bytes[12:16] != b"IHDR":
        raise SystemExit("FAIL: generated data is not a valid PNG")
    return struct.unpack(">II", png_bytes[16:24])


def validate_consistency(xml_path, images):
    """Fail loudly if EntryCarPlay.xml references any missing textId/imageId or mismatched image size."""
    xml_text_ids, xml_image_ids, xml_image_dims = parse_xml_references(xml_path)

    missing_texts = sorted(tid for tid in xml_text_ids if tid not in TEXTS)
    if missing_texts:
        raise SystemExit(
            "FAIL: {} references textId(s) with no defined text: {}".format(xml_path, missing_texts)
        )

    for lang_code, _ in LANGS:
        merged = dict(TEXTS)
        merged.update(LANG_TEXTS.get(lang_code, {}))
        for tid in sorted(xml_text_ids):
            val = merged.get(tid)
            if not isinstance(val, str) or len(val) == 0:
                raise SystemExit(
                    "FAIL: language {} has empty/missing text for XML textId {}".format(lang_code, tid)
                )
        for tid, val in merged.items():
            try:
                val.encode("ascii")
            except UnicodeEncodeError:
                raise SystemExit(
                    "FAIL: language {} textId {} must be ASCII-only: {!r}".format(lang_code, tid, val)
                )

    missing_images = sorted(iid for iid in xml_image_ids if iid not in images)
    if missing_images:
        raise SystemExit(
            "FAIL: {} references imageId(s) with no generated image: {}".format(xml_path, missing_images)
        )

    for iid, (exp_w, exp_h) in sorted(xml_image_dims.items()):
        actual_w, actual_h = png_dimensions(images[iid])
        if (actual_w, actual_h) != (exp_w, exp_h):
            raise SystemExit(
                "FAIL: imageId {} is {}x{}, but {} specifies {}x{}".format(
                    iid, actual_w, actual_h, xml_path, exp_w, exp_h
                )
            )

    manifest_path = xml_path.parent / "EntryCarPlay.manifest"
    if manifest_path.is_file():
        manifest_text = manifest_path.read_text(encoding="utf-8")
        for expected_zip in ("EntryCarPlay_ALL_Texts.zip", "EntryCarPlay_ALL_Images.zip"):
            if expected_zip not in manifest_text:
                raise SystemExit(
                    "FAIL: {} does not reference {}".format(manifest_path, expected_zip)
                )

    return xml_text_ids, xml_image_ids


def add_zip_member(archive, name, data):
    info = zipfile.ZipInfo(name, FIXED_DATE)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3  # Unix
    info.external_attr = 0o644 << 16
    archive.writestr(info, data)


def write_texts_zip(dest_path):
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(str(dest_path), "w") as archive:
        for lang_code, lang_name in LANGS:
            merged = dict(TEXTS)
            merged.update(LANG_TEXTS.get(lang_code, {}))
            lines = ["100000={}\n".format(lang_name)]
            for key in sorted(merged.keys()):
                lines.append("{}={}\n".format(key, merged[key]))
            body = "".join(lines).encode("utf-8")
            add_zip_member(archive, "{}.txt".format(lang_code), body)


def write_images_zip(dest_path, images):
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(str(dest_path), "w") as archive:
        for image_id in sorted(images.keys()):
            add_zip_member(archive, "{}.png".format(image_id), images[image_id])


def main(argv=None):
    default_xml = Path(__file__).resolve().parent / "EntryCarPlay.xml"
    parser = argparse.ArgumentParser(
        description="Generate EntryCarPlay_ALL_Texts.zip and EntryCarPlay_ALL_Images.zip"
    )
    parser.add_argument(
        "--xml",
        type=Path,
        default=default_xml,
        help="Path to EntryCarPlay.xml (default: %(default)s)",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="Output directory for both zip archives",
    )
    parser.add_argument(
        "--texts",
        type=Path,
        default=None,
        help="Explicit output path for EntryCarPlay_ALL_Texts.zip",
    )
    parser.add_argument(
        "--images",
        type=Path,
        default=None,
        help="Explicit output path for EntryCarPlay_ALL_Images.zip",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify XML/resource consistency without writing zip files",
    )
    args = parser.parse_args(argv)

    images = build_images_dict()
    xml_text_ids, xml_image_ids = validate_consistency(args.xml, images)

    if args.check:
        print(
            "check ok: {} textIds ({} total), {} imageIds ({} total) from {}".format(
                len(xml_text_ids), len(TEXTS), len(xml_image_ids), len(images), args.xml
            )
        )
        return 0

    texts_path = args.texts
    images_path = args.images
    if args.out_dir is not None:
        if texts_path is None:
            texts_path = args.out_dir / "EntryCarPlay_ALL_Texts.zip"
        if images_path is None:
            images_path = args.out_dir / "EntryCarPlay_ALL_Images.zip"

    if texts_path is None and images_path is None:
        raise SystemExit("FAIL: pass --out-dir DIR, --texts PATH, --images PATH, or --check")

    written = []
    if texts_path is not None:
        write_texts_zip(texts_path)
        written.append(str(texts_path))
    if images_path is not None:
        write_images_zip(images_path, images)
        written.append(str(images_path))

    print(
        "wrote {} (verified {} XML textIds, {} XML imageIds)".format(
            ", ".join(written), len(xml_text_ids), len(xml_image_ids)
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
