#!/usr/bin/env python3
"""
Deterministic seed corpus generator for EntryNav2-CarPlay libFuzzer harnesses.
Synthesizes minimal valid and boundary-case inputs from open protocol specs
and repo test helpers (zero proprietary captures).
"""

import os
import struct

ROOT = os.path.dirname(os.path.abspath(__file__))
CORPUS_DIR = os.path.join(ROOT, "corpus")


def write_seed(target, name, data):
    d = os.path.join(CORPUS_DIR, target)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), "wb") as f:
        f.write(data)


def iap2_checksum(data):
    return (-sum(data)) & 0xFF


def make_iap2_link_pkt(ctrl, seq, ack, sid, payload=b""):
    has_payload = len(payload) > 0
    total_len = 9 + (len(payload) + 1 if has_payload else 0)
    hdr = struct.pack(">HHBBBB", 0xFF5A, total_len, ctrl, seq, ack, sid)
    hdr += bytes([iap2_checksum(hdr)])
    if has_payload:
        return hdr + payload + bytes([iap2_checksum(payload)])
    return hdr


def make_iap2_param(pid, payload):
    return struct.pack(">HH", 4 + len(payload), pid) + payload


def make_iap2_csm(msg_id, params=b""):
    return struct.pack(">HHH", 0x4040, 6 + len(params), msg_id) + params


def make_bplist_header_dict(k, v_int):
    # Minimal valid binary plist: 3 objects: {k: v_int}
    # Obj 0: dict(1): key ref 1, val ref 2
    # Obj 1: ascii string k
    # Obj 2: int(v_int) as 4 bytes (0x12)
    kb = k.encode("ascii")
    o0 = bytes([0xD1, 0x01, 0x02])
    if len(kb) < 15:
        o1 = bytes([0x50 | len(kb)]) + kb
    else:
        o1 = bytes([0x5F, 0x10, len(kb)]) + kb
    o2 = bytes([0x12]) + struct.pack(">I", v_int & 0xFFFFFFFF)
    body = b"bplist00" + o0 + o1 + o2
    off0 = 8
    off1 = off0 + len(o0)
    off2 = off1 + len(o1)
    off_table_pos = len(body)
    offsets = struct.pack(">BBB", off0, off1, off2)
    trailer = struct.pack(">6xBBQQQ", 1, 1, 3, 0, off_table_pos)
    return body + offsets + trailer


def gen_all():
    # 1. iap2_link
    write_seed("iap2_link", "empty", b"")
    write_seed("iap2_link", "detect", b"\xFF\x55\x02\x00\xEE\x10")
    syn_payload = bytes([1, 4, 3, 2, 10, 0, 50, 0, 0xFF, 0x5A, 1, 0, 10, 0, 1, 11, 2, 1])
    write_seed("iap2_link", "syn", make_iap2_link_pkt(0x80, 1, 0, 0, syn_payload))
    write_seed("iap2_link", "ack", make_iap2_link_pkt(0x40, 2, 1, 0))
    write_seed("iap2_link", "eak", make_iap2_link_pkt(0x60, 2, 1, 0, b"\x02\x03"))
    write_seed("iap2_link", "data", make_iap2_link_pkt(0x40, 3, 2, 10, b"\x40\x40\x00\x06\xAA\xBB"))
    write_seed("iap2_link", "rst", make_iap2_link_pkt(0x10, 0, 0, 0))

    # 2. iap2_session
    write_seed("iap2_session", "empty", b"")
    csm_start_id = make_iap2_csm(0x1D00)
    csm_auth_chal = make_iap2_csm(0xAA02, make_iap2_param(0, b"\x11" * 20))
    csm_wifi = make_iap2_csm(
        0x5701,
        make_iap2_param(0, b"CarPlay-AP\x00")
        + make_iap2_param(1, b"pass1234\x00")
        + make_iap2_param(2, b"\x02")
        + make_iap2_param(3, struct.pack(">H", 36)),
    )
    csm_avail = make_iap2_csm(
        0x4E09,
        make_iap2_param(0, b"\x00")
        + make_iap2_param(1, b"192.168.1.2\x00")
        + make_iap2_param(2, b"fe80::1\x00")
        + make_iap2_param(3, struct.pack(">H", 7000)),
    )
    write_seed("iap2_session", "start_id", csm_start_id)
    write_seed("iap2_session", "auth_chal", csm_auth_chal)
    write_seed("iap2_session", "wifi_info", csm_wifi)
    write_seed("iap2_session", "cp_avail", csm_avail)
    write_seed(
        "iap2_session",
        "stream_multi",
        csm_start_id + csm_auth_chal + csm_wifi + csm_avail,
    )

    # 3. cdc_ncm
    write_seed("cdc_ncm", "ntb_params", struct.pack("<HHIIHHHBBH", 28, 3, 16384, 4, 2048, 0, 16384, 4, 2, 0))
    # NTH16 (12 bytes) + NDP16 (16 bytes) + 8-byte datagram
    dgram = b"\x60\x00\x00\x00\x00\x04\x11\x40"
    ndp16 = struct.pack("<IHBBHHHH", 0x304D434E, 16, 0, 0, 28, len(dgram), 0, 0)
    nth16 = struct.pack("<IHHHH", 0x484D434E, 12, 1, 28 + len(dgram), 12)
    write_seed("cdc_ncm", "ntb16_valid", nth16 + ndp16 + dgram)

    # 4. usb_descriptors
    dev_desc = struct.pack("<BBHBBBBHHHBBBB", 18, 1, 0x0200, 0, 0, 0, 64, 0x05AC, 0x12A8, 0x0100, 1, 2, 3, 1)
    cfg_body = (
        struct.pack("<BBBBBBBB", 8, 11, 0, 2, 2, 13, 0, 0)  # IAD NCM
        + struct.pack("<BBBBBBBBB", 9, 4, 0, 0, 1, 2, 13, 0, 0)  # NCM comm
        + struct.pack("<BBBBHB", 7, 5, 0x81, 3, 16, 10)  # EP int
        + struct.pack("<BBBBBBBBB", 9, 4, 1, 0, 0, 10, 0, 1, 0)  # NCM data alt0
        + struct.pack("<BBBBBBBBB", 9, 4, 1, 1, 2, 10, 0, 1, 0)  # NCM data alt1
        + struct.pack("<BBBBHB", 7, 5, 0x82, 2, 512, 0)
        + struct.pack("<BBBBHB", 7, 5, 0x03, 2, 512, 0)
        + struct.pack("<BBBBBBBBB", 9, 4, 2, 0, 2, 0xFF, 0xF0, 0, 0)  # iAP2 bulk
        + struct.pack("<BBBBHB", 7, 5, 0x84, 2, 512, 0)
        + struct.pack("<BBBBHB", 7, 5, 0x05, 2, 512, 0)
    )
    cfg_desc = struct.pack("<BBHBBBBB", 9, 2, 9 + len(cfg_body), 3, 1, 0, 0xC0, 250) + cfg_body
    write_seed("usb_descriptors", "usbfs", dev_desc + cfg_desc)
    write_seed("usb_descriptors", "str_utf16", b"\x0A\x03B\x00M\x00W\x00!\x00")
    write_seed("usb_descriptors", "mac_str", b"0123456789AB")

    # 5. rtsp_message
    write_seed(
        "rtsp_message",
        "post_setup",
        b"POST /setup RTSP/1.0\r\nCSeq: 1\r\nContent-Type: application/x-apple-binary-plist\r\nContent-Length: 4\r\n\r\nTEST",
    )
    write_seed("rtsp_message", "get_info", b"GET /info RTSP/1.0\r\nCSeq: 0\r\n\r\n")
    write_seed("rtsp_message", "resp_200", b"RTSP/1.0 200 OK\r\nCSeq: 2\r\nContent-Length: 0\r\n\r\n")

    # 6. bplist_codec
    write_seed("bplist_codec", "dict_int", make_bplist_header_dict("type", 110))
    write_seed("bplist_codec", "min_trailer", b"bplist00" + b"\x00" + b"\x08" + struct.pack(">6xBBQQQ", 1, 1, 1, 0, 9))

    # 7. tlv8_codec
    write_seed("tlv8_codec", "pair_m1", b"\x00\x01\x01\x06\x01\x01")
    write_seed("tlv8_codec", "fragmented", b"\x03" + bytes([255]) + b"A" * 255 + b"\x03\x04BBBB\xFF\x00")

    # 8. sdp_record
    write_seed("sdp_record", "uuid_std", b"00000000-deca-fade-deca-deafdecacaff")
    write_seed("sdp_record", "reg_resp", struct.pack(">BHHB", 0x82, 0x1234, 4, 0x00) + struct.pack(">I", 0x00010002)[0:3])
    write_seed("sdp_record", "reg_ok", struct.pack(">BHHI", 0x82, 0x1234, 4, 0x00010002))
    write_seed("sdp_record", "rem_ok", struct.pack(">BHHB", 0x84, 0x1234, 1, 0))

    # 9. dnssd_txt
    write_seed("dnssd_txt", "airplay_txt", b"\x0cdeviceid=11\x0bfeatures=0x\x04rsf=")

    # 10. event_channel
    write_seed(
        "event_channel",
        "rtsp_get_info",
        b"GET /info RTSP/1.0\r\nCSeq: 1\r\n\r\n",
    )
    bp = make_bplist_header_dict("type", 110)
    write_seed(
        "event_channel",
        "rtsp_setup",
        b"POST /setup RTSP/1.0\r\nCSeq: 2\r\nContent-Type: application/x-apple-binary-plist\r\nContent-Length: "
        + str(len(bp)).encode("ascii")
        + b"\r\n\r\n"
        + bp,
    )
    write_seed("event_channel", "bplist_raw", bp)

    # 11. audio_rtp
    rtp = struct.pack(">BBHII", 0x80, 0x60, 1, 480, 0x12345678) + b"\x00" * 32 + b"\x11" * 16
    write_seed("audio_rtp", "rtp_min", rtp)
    write_seed("audio_rtp", "jb_cmds", b"\x00\x01\x04ABCD\x00\x02\x04EFGH\x00\x03\x04IJKL")

    # 12. screen_stream
    shdr = struct.pack("<IHHd", 4, 0x0100, 0, 123.5) + b"\x00" * 112
    avcc = bytes([1, 0x64, 0, 0x1F, 0xFF, 0xE1, 0, 4, 0x67, 0x64, 0, 0x1F, 1, 0, 3, 0x68, 0xEE, 0x3C])
    write_seed("screen_stream", "hdr_data", shdr + b"\x00\x00\x00\x02\x65\x88")
    write_seed("screen_stream", "avcc", avcc)

    # 13. pairing_srp
    m1 = b"\x00\x01\x00\x06\x01\x01"
    write_seed("pairing_srp", "pair_m1", m1)
    write_seed("pairing_srp", "framed_m1", struct.pack(">H", len(m1)) + m1)
    write_seed("pairing_srp", "ntp_48", b"\xE3" + b"\x00" * 47)


if __name__ == "__main__":
    gen_all()
    print("Generated seed corpora in", CORPUS_DIR)
