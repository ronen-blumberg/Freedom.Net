#!/usr/bin/env python3
"""
Freedom Net Client - terminal IM client for the Freedom Net server.

Pure-Python, no third-party dependencies. Wire-compatible with client.c:
same packet format, same KDF, same AES. A Python client can join a C
server, a C client can join a Python server.

Usage:
    python3 client.py <server> <port> <keyphrase> [<nickname>] [<room>]

Pass "" for nickname or room to let the server pick one randomly.

Commands at the prompt:
    /join <room>          join a room (or switch to it)
    /part [<room>]        leave a room (default: current)
    /msg  <nick> <text>   private message
    /send <nick> <abs-path>  send a file (<= 10 MB)
    /me   <action>        emote in current room
    /nick <newnick>       change your nickname
    /who  [<room>]        list users in a room
    /list                 list all rooms on the server
    /ignore [<nick>]      hide messages/DMs/files from a user (no args: list)
    /unignore <nick>      stop ignoring a user
    /quit                 disconnect
    /help                 show this list
    //text                send a literal chat line that starts with '/'
"""

import hashlib
import os
import socket
import struct
import sys
import threading
import time

APP_NAME           = "Freedom Net"
APP_VERSION        = "0.1.2"
KDF_TAG            = b"FreedomNet-v1"

MAX_NICK           = 32
MAX_ROOM           = 32
MAX_TEXT           = 1024
MAX_ROOMS_PER_USER = 10
MAX_IGNORED        = 64

AES_BLOCK          = 16
AES_ROUNDS         = 14
KDF_ITER           = 100_000

MAX_FILE_BYTES     = 10 * 1024 * 1024
MAX_FILE_HDR       = 1024
MAX_PAYLOAD        = MAX_FILE_BYTES + MAX_FILE_HDR
MAX_PLAINTEXT      = MAX_PAYLOAD + 1
MAX_FRAME          = 16 + MAX_PLAINTEXT + 16

PKT_HELLO = ord('H')
PKT_MSG   = ord('M')
PKT_EMOTE = ord('O')
PKT_DM    = ord('D')
PKT_FILE  = ord('F')
PKT_WHO   = ord('W')
PKT_LIST  = ord('L')
PKT_NICK  = ord('N')
PKT_JOIN  = ord('J')
PKT_PART  = ord('T')
PKT_SYS   = ord('X')
PKT_ERR   = ord('E')
PKT_PING  = ord('P')
PKT_QUIT  = ord('Q')

LINE_CHAT, LINE_SYSTEM, LINE_FILE, LINE_DM, LINE_EMOTE = range(5)


# ===== AES-256-CBC (matches server.py / server.c) =====

_AES_SBOX = bytes((
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
))
_AES_INVSBOX = bytes((
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
))
_AES_RCON = bytes((0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36))

def _xtime(x):
    return ((x << 1) ^ (((x >> 7) & 1) * 0x1b)) & 0xff

def _gmul(x, y):
    r = 0
    for _ in range(8):
        if y & 1:
            r ^= x
        x = _xtime(x)
        y >>= 1
    return r & 0xff

def aes_key_expansion(key):
    assert len(key) == 32
    rk = bytearray(4 * 4 * (AES_ROUNDS + 1))
    rk[:32] = key
    for i in range(8, 4 * (AES_ROUNDS + 1)):
        t = bytearray(rk[(i - 1) * 4:(i - 1) * 4 + 4])
        if i % 8 == 0:
            t[0], t[1], t[2], t[3] = t[1], t[2], t[3], t[0]
            t[0] = _AES_SBOX[t[0]]; t[1] = _AES_SBOX[t[1]]
            t[2] = _AES_SBOX[t[2]]; t[3] = _AES_SBOX[t[3]]
            t[0] ^= _AES_RCON[i // 8]
        elif i % 8 == 4:
            t[0] = _AES_SBOX[t[0]]; t[1] = _AES_SBOX[t[1]]
            t[2] = _AES_SBOX[t[2]]; t[3] = _AES_SBOX[t[3]]
        for j in range(4):
            rk[i * 4 + j] = rk[(i - 8) * 4 + j] ^ t[j]
    return bytes(rk)

def _add_round_key(s, rk, off):
    for i in range(16):
        s[i] ^= rk[off + i]

def _sub_bytes(s):
    for i in range(16):
        s[i] = _AES_SBOX[s[i]]

def _inv_sub_bytes(s):
    for i in range(16):
        s[i] = _AES_INVSBOX[s[i]]

def _shift_rows(s):
    s[1], s[5], s[9], s[13] = s[5], s[9], s[13], s[1]
    s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
    s[3], s[7], s[11], s[15] = s[15], s[3], s[7], s[11]

def _inv_shift_rows(s):
    s[13], s[9], s[5], s[1] = s[9], s[5], s[1], s[13]
    s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
    s[3], s[7], s[11], s[15] = s[7], s[11], s[15], s[3]

def _mix_columns(s):
    for i in range(4):
        a0, a1, a2, a3 = s[i*4], s[i*4+1], s[i*4+2], s[i*4+3]
        t = a0 ^ a1 ^ a2 ^ a3
        s[i*4]   ^= t ^ _xtime(a0 ^ a1)
        s[i*4+1] ^= t ^ _xtime(a1 ^ a2)
        s[i*4+2] ^= t ^ _xtime(a2 ^ a3)
        s[i*4+3] ^= t ^ _xtime(a3 ^ a0)

def _inv_mix_columns(s):
    for i in range(4):
        a0, a1, a2, a3 = s[i*4], s[i*4+1], s[i*4+2], s[i*4+3]
        s[i*4]   = _gmul(a0, 0x0e) ^ _gmul(a1, 0x0b) ^ _gmul(a2, 0x0d) ^ _gmul(a3, 0x09)
        s[i*4+1] = _gmul(a0, 0x09) ^ _gmul(a1, 0x0e) ^ _gmul(a2, 0x0b) ^ _gmul(a3, 0x0d)
        s[i*4+2] = _gmul(a0, 0x0d) ^ _gmul(a1, 0x09) ^ _gmul(a2, 0x0e) ^ _gmul(a3, 0x0b)
        s[i*4+3] = _gmul(a0, 0x0b) ^ _gmul(a1, 0x0d) ^ _gmul(a2, 0x09) ^ _gmul(a3, 0x0e)

def aes_encrypt_block(rk, block16):
    s = bytearray(block16)
    _add_round_key(s, rk, 0)
    for r in range(1, AES_ROUNDS):
        _sub_bytes(s); _shift_rows(s); _mix_columns(s)
        _add_round_key(s, rk, r * 16)
    _sub_bytes(s); _shift_rows(s)
    _add_round_key(s, rk, AES_ROUNDS * 16)
    return bytes(s)

def aes_decrypt_block(rk, block16):
    s = bytearray(block16)
    _add_round_key(s, rk, AES_ROUNDS * 16)
    for r in range(AES_ROUNDS - 1, 0, -1):
        _inv_shift_rows(s); _inv_sub_bytes(s)
        _add_round_key(s, rk, r * 16)
        _inv_mix_columns(s)
    _inv_shift_rows(s); _inv_sub_bytes(s)
    _add_round_key(s, rk, 0)
    return bytes(s)

def aes_cbc_encrypt(rk, iv, data):
    pad = AES_BLOCK - (len(data) % AES_BLOCK)
    padded = data + bytes([pad]) * pad
    out = bytearray()
    prev = iv
    for i in range(0, len(padded), AES_BLOCK):
        blk = bytes(a ^ b for a, b in zip(padded[i:i+AES_BLOCK], prev))
        ct = aes_encrypt_block(rk, blk)
        out += ct
        prev = ct
    return bytes(out)

def aes_cbc_decrypt(rk, iv, data):
    if len(data) == 0 or len(data) % AES_BLOCK:
        return None
    out = bytearray()
    prev = iv
    for i in range(0, len(data), AES_BLOCK):
        ct = data[i:i+AES_BLOCK]
        blk = aes_decrypt_block(rk, ct)
        out += bytes(a ^ b for a, b in zip(blk, prev))
        prev = ct
    pad = out[-1]
    if pad < 1 or pad > 16:
        return None
    if any(out[-1 - i] != pad for i in range(pad)):
        return None
    return bytes(out[:-pad])


def derive_key(passphrase):
    pw = passphrase.encode("utf-8") if isinstance(passphrase, str) else passphrase
    h = hashlib.sha256()
    h.update(pw)
    h.update(KDF_TAG)
    buf = h.digest()
    for _ in range(KDF_ITER):
        h = hashlib.sha256()
        h.update(buf)
        h.update(pw)
        buf = h.digest()
    return buf


# ===== Wire framing =====

def _recv_all(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("connection closed")
        buf += chunk
    return bytes(buf)


def send_packet(sock, rk, ptype, payload=b""):
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    pt = bytes([ptype]) + payload
    if len(pt) > MAX_PLAINTEXT:
        raise ValueError("plaintext too long")
    iv = os.urandom(16)
    ct = aes_cbc_encrypt(rk, iv, pt)
    framelen = 16 + len(ct)
    sock.sendall(struct.pack(">I", framelen) + iv + ct)


def recv_packet(sock, rk):
    (framelen,) = struct.unpack(">I", _recv_all(sock, 4))
    if framelen < 32 or framelen > MAX_FRAME:
        raise ValueError("bad frame length")
    iv = _recv_all(sock, 16)
    ct = _recv_all(sock, framelen - 16)
    pt = aes_cbc_decrypt(rk, iv, ct)
    if pt is None or len(pt) < 1:
        raise ValueError("decrypt failed")
    return pt[0], pt[1:]


def read_u8_string(p, off):
    if off + 1 > len(p):
        raise ValueError("short")
    n = p[off]; off += 1
    if off + n > len(p):
        raise ValueError("short")
    s = p[off:off+n].decode("utf-8", errors="replace")
    return s, off + n


def name_is_valid(s, maxlen):
    if not s:
        return False
    if len(s) >= maxlen:
        return False
    for c in s:
        if ord(c) <= 0x20 or ord(c) == 0x7f or c in (':', ','):
            return False
    return True


# ===== Terminal + log =====

_print_lock = threading.Lock()
_use_colors = False
_log_file = None
g_nick = ""


def term_init():
    global _use_colors
    try:
        if sys.stdout.isatty():
            _use_colors = True
    except Exception:
        pass


def _fmt(text, kind):
    cR = "\x1b[0m"    if _use_colors else ""
    cT = "\x1b[90m"   if _use_colors else ""
    cS = "\x1b[1;36m" if _use_colors else ""
    cO = "\x1b[1;32m" if _use_colors else ""
    cY = "\x1b[33m"   if _use_colors else ""
    cM = "\x1b[1;35m" if _use_colors else ""
    cB = "\x1b[1;34m" if _use_colors else ""
    cE = "\x1b[35m"   if _use_colors else ""
    ts = time.strftime("%H:%M:%S")
    if kind == LINE_CHAT:
        # text like "[room] nick: message" -> color the nick
        i = text.find(": ")
        if i >= 0:
            head = text[:i]
            tail = text[i+2:]
            space = head.rfind(" ")
            prefix = head[:space+1] if space >= 0 else ""
            nick = head[space+1:]
            color = cS if nick == g_nick else cO
            return f"{cT}[{ts}]{cR} {prefix}{color}{nick}{cR}: {tail}"
    if kind == LINE_FILE:   return f"{cT}[{ts}]{cR} {cM}{text}{cR}"
    if kind == LINE_DM:     return f"{cT}[{ts}]{cR} {cB}{text}{cR}"
    if kind == LINE_EMOTE:  return f"{cT}[{ts}]{cR} {cE}{text}{cR}"
    return f"{cT}[{ts}]{cR} {cY}{text}{cR}"


def term_putline(text, kind=LINE_SYSTEM):
    with _print_lock:
        print(_fmt(text, kind), flush=True)
        if _log_file is not None:
            ts = time.strftime("%Y-%m-%d %H:%M:%S")
            _log_file.write(f"[{ts}] {text}\n")
            _log_file.flush()


def log_open(nick):
    global _log_file
    safe = "".join(c if (c.isprintable() and c not in "/\\:") else "_" for c in nick) or "anon"
    fn = f"freedom-net-{safe}.log"
    if _log_file is not None:
        try: _log_file.close()
        except Exception: pass
        _log_file = None
    try:
        _log_file = open(fn, "ab")
    except Exception:
        term_putline(f"Could not open log file {fn} - logging disabled.")
        return
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    _log_file.write(f"\n========== {APP_NAME} {APP_VERSION} session {ts} as \"{nick}\" ==========\n".encode())
    _log_file.flush()
    # Wrap the binary file with a thin text shim for the writes above to work.
    class _W:
        def __init__(self, f): self._f = f
        def write(self, s):
            if isinstance(s, str): s = s.encode("utf-8", errors="replace")
            return self._f.write(s)
        def flush(self): self._f.flush()
        def close(self): self._f.close()
    _log_file = _W(_log_file)
    term_putline(f"Logging this session to ./{fn}")


# ===== Client state =====

g_sock = None
g_send_lock = threading.Lock()
g_rk = None
g_rooms = []          # list of room names this user is in
g_current_room = None
g_state_lock = threading.Lock()
g_ignored = set()     # nicknames whose messages/DMs/files we drop locally


def is_ignored(nick):
    with g_state_lock:
        return nick in g_ignored


def ignore_add(nick):
    with g_state_lock:
        if nick in g_ignored:
            return "already"
        if len(g_ignored) >= MAX_IGNORED:
            return "full"
        g_ignored.add(nick)
        return "ok"


def ignore_remove(nick):
    with g_state_lock:
        if nick not in g_ignored:
            return False
        g_ignored.remove(nick)
        return True


def ignore_list():
    with g_state_lock:
        return sorted(g_ignored)


def send_packet_locked(ptype, payload=b""):
    if g_sock is None:
        return False
    with g_send_lock:
        try:
            send_packet(g_sock, g_rk, ptype, payload)
            return True
        except Exception:
            return False


def add_room_local(room):
    global g_current_room
    with g_state_lock:
        if room not in g_rooms:
            if len(g_rooms) < MAX_ROOMS_PER_USER:
                g_rooms.append(room)
                g_current_room = room
        else:
            g_current_room = room


def remove_room_local(room):
    global g_current_room
    with g_state_lock:
        if room in g_rooms:
            g_rooms.remove(room)
            if not g_rooms:
                g_current_room = None
            elif g_current_room == room:
                g_current_room = g_rooms[-1]


def get_current_room():
    with g_state_lock:
        return g_current_room


# ===== Senders =====

def send_hello(nick, room):
    nb = nick.encode("utf-8"); rb = room.encode("utf-8")
    if len(nb) > 255 or len(rb) > 255:
        return False
    payload = bytes([len(nb)]) + nb + bytes([len(rb)]) + rb
    return send_packet_locked(PKT_HELLO, payload)


def send_room_text(ptype, room, text):
    rb = room.encode("utf-8"); tb = text.encode("utf-8")
    if not (0 < len(rb) <= 255 and 0 < len(tb) <= MAX_TEXT):
        return False
    return send_packet_locked(ptype, bytes([len(rb)]) + rb + tb)


def send_dm(recip, text):
    rb = recip.encode("utf-8"); tb = text.encode("utf-8")
    if not (0 < len(rb) <= 255 and 0 < len(tb) <= MAX_TEXT):
        return False
    return send_packet_locked(PKT_DM, bytes([len(rb)]) + rb + tb)


def send_simple_string(ptype, s):
    sb = s.encode("utf-8")
    if not (0 < len(sb) <= 255):
        return False
    return send_packet_locked(ptype, bytes([len(sb)]) + sb)


def path_is_absolute(p):
    if not p:
        return False
    if p.startswith("/"):
        return True
    if len(p) >= 2 and p[0].isalpha() and p[1] == ":":
        return True
    return False


def path_basename(p):
    i = max(p.rfind("/"), p.rfind("\\"))
    return p if i < 0 else p[i+1:]


def send_file_to(recip, abspath):
    rb = recip.encode("utf-8")
    if not (0 < len(rb) <= 255):
        term_putline("Invalid recipient."); return False
    if not path_is_absolute(abspath):
        term_putline("File path must be absolute."); return False
    base = path_basename(abspath)
    if not base or base in (".", "..") or len(base.encode("utf-8")) > 255:
        term_putline("Bad filename."); return False
    try:
        with open(abspath, "rb") as f:
            data = f.read(MAX_FILE_BYTES + 1)
    except Exception as e:
        term_putline(f"Cannot open file: {abspath} ({e})"); return False
    if len(data) > MAX_FILE_BYTES:
        term_putline(f"File too large: > {MAX_FILE_BYTES} bytes"); return False
    fb = base.encode("utf-8")
    payload = (bytes([len(rb)]) + rb
               + bytes([len(fb)]) + fb
               + struct.pack(">I", len(data))
               + data)
    ok = send_packet_locked(PKT_FILE, payload)
    if ok:
        term_putline(f'--> file to {recip}: "{base}" ({len(data)} bytes)', LINE_FILE)
    return ok


# ===== Inbound packet handlers =====

def save_received_file(sender, fname, body):
    base = path_basename(fname)
    if not base or base in (".", ".."):
        term_putline(f"Bad filename from {sender}, ignored."); return
    save = base
    idx = 1
    while os.path.exists(save):
        if idx > 9999:
            term_putline("Too many name collisions, dropping file."); return
        save = f"{base}.{idx}"; idx += 1
    try:
        with open(save, "wb") as f:
            f.write(body)
    except Exception as e:
        term_putline(f"Write failed for {save}: {e}"); return
    term_putline(f'<-- file from {sender}: "{fname}" ({len(body)} bytes) saved as ./{save}', LINE_FILE)


def on_pkt_msg(payload):
    try:
        room, off = read_u8_string(payload, 0)
        sender, off = read_u8_string(payload, off)
    except ValueError:
        return
    if is_ignored(sender):
        return
    text = payload[off:].decode("utf-8", errors="replace")
    term_putline(f"[{room}] {sender}: {text}", LINE_CHAT)


def on_pkt_emote(payload):
    try:
        room, off = read_u8_string(payload, 0)
        sender, off = read_u8_string(payload, off)
    except ValueError:
        return
    if is_ignored(sender):
        return
    text = payload[off:].decode("utf-8", errors="replace")
    term_putline(f"[{room}] * {sender} {text} *", LINE_EMOTE)


def on_pkt_sys(payload):
    try:
        room, off = read_u8_string(payload, 0)
    except ValueError:
        return
    text = payload[off:].decode("utf-8", errors="replace")
    term_putline(f"[{room}] {text}")


def on_pkt_err(payload):
    text = payload.decode("utf-8", errors="replace")
    term_putline(f"[server] {text}")


def on_pkt_dm(payload):
    try:
        sender, off = read_u8_string(payload, 0)
    except ValueError:
        return
    if is_ignored(sender):
        return
    text = payload[off:].decode("utf-8", errors="replace")
    term_putline(f"[DM from {sender}] {text}", LINE_DM)


def on_pkt_file(payload):
    try:
        sender, off = read_u8_string(payload, 0)
        if is_ignored(sender):
            return
        if off + 1 > len(payload): return
        fnl = payload[off]; off += 1
        if fnl == 0 or off + fnl + 4 > len(payload): return
        fname = payload[off:off+fnl].decode("utf-8", errors="replace")
        off += fnl
        (fsz,) = struct.unpack(">I", payload[off:off+4]); off += 4
        if fsz > MAX_FILE_BYTES or off + fsz != len(payload): return
        body = payload[off:]
    except Exception:
        return
    save_received_file(sender, fname, body)


def on_pkt_who(payload):
    try:
        room, off = read_u8_string(payload, 0)
        if off + 1 > len(payload): return
        count = payload[off]; off += 1
        nicks = []
        for _ in range(count):
            n, off = read_u8_string(payload, off)
            nicks.append(n)
    except ValueError:
        return
    term_putline(f"[{room}] users ({count}): " + ", ".join(nicks))


def on_pkt_list(payload):
    try:
        if len(payload) < 1: return
        count = payload[0]; off = 1
        items = []
        for _ in range(count):
            n, off = read_u8_string(payload, off)
            if off + 2 > len(payload): break
            nm, = struct.unpack(">H", payload[off:off+2]); off += 2
            items.append((n, nm))
    except Exception:
        return
    term_putline(f"rooms ({count}): " + ", ".join(f"{n}({m})" for n, m in items))


def on_pkt_join(payload):
    try:
        room, off = read_u8_string(payload, 0)
        nick, _ = read_u8_string(payload, off)
    except ValueError:
        return
    if nick == g_nick:
        add_room_local(room)
        term_putline(f"* you joined {room} *")
    else:
        term_putline(f"[{room}] * {nick} joined *")


def on_pkt_part(payload):
    try:
        room, off = read_u8_string(payload, 0)
        nick, _ = read_u8_string(payload, off)
    except ValueError:
        return
    if nick == g_nick:
        remove_room_local(room)
        term_putline(f"* you left {room} *")
    else:
        term_putline(f"[{room}] * {nick} left *")


def on_pkt_nick_ack(payload):
    global g_nick
    newnick = payload.decode("utf-8", errors="replace")
    if not newnick: return
    g_nick = newnick
    term_putline(f"* you are now known as {newnick} *")
    log_open(newnick)


# ===== Receive thread =====

def recv_thread():
    global g_sock
    handlers = {
        PKT_MSG:   on_pkt_msg,
        PKT_EMOTE: on_pkt_emote,
        PKT_SYS:   on_pkt_sys,
        PKT_ERR:   on_pkt_err,
        PKT_DM:    on_pkt_dm,
        PKT_FILE:  on_pkt_file,
        PKT_WHO:   on_pkt_who,
        PKT_LIST:  on_pkt_list,
        PKT_JOIN:  on_pkt_join,
        PKT_PART:  on_pkt_part,
        PKT_NICK:  on_pkt_nick_ack,
    }
    while True:
        try:
            ptype, payload = recv_packet(g_sock, g_rk)
        except Exception:
            term_putline("Connection closed by server.")
            break
        h = handlers.get(ptype)
        if h:
            h(payload)
    s = g_sock; g_sock = None
    if s is not None:
        try: s.close()
        except Exception: pass


# ===== Connect =====

def do_connect(host, port, passphrase, want_nick, want_room):
    global g_sock, g_rk, g_nick
    try:
        info = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except Exception as e:
        term_putline(f"DNS resolution failed for {host}: {e}")
        return False
    sock = None
    for fam, typ, proto, _can, sa in info:
        try:
            sock = socket.socket(fam, typ, proto)
            sock.connect(sa)
            break
        except Exception:
            try:
                if sock: sock.close()
            except Exception: pass
            sock = None
    if sock is None:
        term_putline(f"Could not connect to {host}:{port}")
        return False
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except Exception:
        pass

    g_rk = aes_key_expansion(derive_key(passphrase))
    g_sock = sock

    try:
        if not send_hello(want_nick, want_room):
            term_putline("Failed to send hello.")
            sock.close(); g_sock = None; return False
        ptype, payload = recv_packet(sock, g_rk)
    except Exception:
        term_putline("Server hung up during handshake (bad keyphrase?).")
        try: sock.close()
        except Exception: pass
        g_sock = None; return False

    if ptype == PKT_ERR:
        term_putline(f"Server rejected: {payload.decode('utf-8', errors='replace')}")
        sock.close(); g_sock = None; return False
    if ptype != PKT_HELLO:
        term_putline("Bad handshake from server.")
        sock.close(); g_sock = None; return False
    try:
        nick, off = read_u8_string(payload, 0)
        room, _ = read_u8_string(payload, off)
    except ValueError:
        term_putline("Malformed hello-ack.")
        sock.close(); g_sock = None; return False

    g_nick = nick
    add_room_local(room)
    term_putline(f'Connected as "{nick}" in room "{room}".')
    log_open(nick)

    t = threading.Thread(target=recv_thread, daemon=True)
    t.start()
    return True


# ===== Input loop =====

HELP = [
    "Commands:",
    "  /join <room>          join a room (or switch to it)",
    "  /part [<room>]        leave a room (default: current)",
    "  /msg <nick> <text>    private message",
    "  /send <nick> <abs-path>  send a file (<= 10 MB)",
    "  /me <action>          emote in current room",
    "  /nick <newnick>       change your nickname",
    "  /who [<room>]         list users in a room",
    "  /list                 list all rooms on the server",
    "  /ignore [<nick>]      hide messages/DMs/files from a user (no args: list)",
    "  /unignore <nick>      stop ignoring a user",
    "  /quit                 disconnect",
    "  //text                send a literal line that starts with '/'",
]

def show_help():
    for h in HELP:
        term_putline(h)


def handle_input(line):
    global g_sock, g_current_room
    s = line.strip()
    if not s:
        return
    if s.startswith("/") and not s.startswith("//"):
        parts = s.split(None, 1)
        cmd = parts[0]
        rest = parts[1] if len(parts) > 1 else ""
        if cmd == "/quit":
            send_packet_locked(PKT_QUIT, b"")
            sk = g_sock
            g_sock = None
            if sk is not None:
                try: sk.close()
                except Exception: pass
            return
        if cmd == "/help":
            show_help(); return
        if cmd == "/list":
            send_packet_locked(PKT_LIST, b""); return
        if cmd == "/who":
            room = rest.strip() or get_current_room()
            if not room:
                term_putline("Not in any room."); return
            send_simple_string(PKT_WHO, room); return
        if cmd == "/join":
            room = rest.strip()
            if not room:
                term_putline("Usage: /join <room>"); return
            if not name_is_valid(room, MAX_ROOM):
                term_putline("Invalid room name."); return
            with g_state_lock:
                if room in g_rooms:
                    g_current_room = room
                    term_putline(f"* switched to room {room} *")
                    return
            send_simple_string(PKT_JOIN, room); return
        if cmd == "/part":
            room = rest.strip() or get_current_room()
            if not room:
                term_putline("Not in any room."); return
            send_simple_string(PKT_PART, room); return
        if cmd == "/nick":
            nn = rest.strip()
            if not nn:
                term_putline("Usage: /nick <newnick>"); return
            if not name_is_valid(nn, MAX_NICK):
                term_putline("Invalid nickname."); return
            send_simple_string(PKT_NICK, nn); return
        if cmd == "/me":
            text = rest.strip()
            if not text:
                term_putline("Usage: /me <action>"); return
            room = get_current_room()
            if not room:
                term_putline("Not in any room."); return
            send_room_text(PKT_EMOTE, room, text); return
        if cmd == "/msg":
            sub = rest.split(None, 1)
            if len(sub) < 2 or not sub[1].strip():
                term_putline("Usage: /msg <nick> <text>"); return
            to, text = sub[0], sub[1].strip()
            send_dm(to, text)
            term_putline(f"[DM to {to}] {text}", LINE_DM)
            return
        if cmd == "/send":
            sub = rest.split(None, 1)
            if len(sub) < 2 or not sub[1].strip():
                term_putline("Usage: /send <nick> <absolute-path>"); return
            to, path = sub[0], sub[1].strip()
            send_file_to(to, path); return
        if cmd == "/ignore":
            nick = rest.strip()
            if not nick:
                lst = ignore_list()
                if not lst:
                    term_putline("No users ignored.")
                else:
                    term_putline(f"Ignoring ({len(lst)}): " + ", ".join(lst))
                return
            if not name_is_valid(nick, MAX_NICK):
                term_putline("Invalid nickname."); return
            if nick == g_nick:
                term_putline("You cannot ignore yourself."); return
            r = ignore_add(nick)
            if r == "already":
                term_putline(f"* already ignoring {nick} *")
            elif r == "full":
                term_putline(f"Ignore list is full (max {MAX_IGNORED}).")
            else:
                term_putline(f"* ignoring {nick} *")
            return
        if cmd == "/unignore":
            nick = rest.strip()
            if not nick:
                term_putline("Usage: /unignore <nick>"); return
            if ignore_remove(nick):
                term_putline(f"* no longer ignoring {nick} *")
            else:
                term_putline(f"* {nick} was not ignored *")
            return
        if cmd == "/connect":
            term_putline("Already connected; /quit first."); return
        term_putline(f"Unknown command: {cmd}  (try /help)")
        return

    text = s[1:] if s.startswith("//") else s
    room = get_current_room()
    if not room:
        term_putline("Not in any room; /join one first.")
        return
    send_room_text(PKT_MSG, room, text)


# ===== main =====

def main():
    if not (4 <= len(sys.argv) <= 6):
        sys.stderr.write(
            f"Usage: {sys.argv[0]} <server> <port> <keyphrase> [<nickname>] [<room>]\n"
            'Pass "" for nickname or room to let the server pick one.\n'
        )
        sys.exit(2)
    server = sys.argv[1]
    try:
        port = int(sys.argv[2])
    except ValueError:
        sys.stderr.write("port must be an integer\n"); sys.exit(2)
    if not (0 < port < 65536):
        sys.stderr.write("port out of range\n"); sys.exit(2)
    passphrase = sys.argv[3]
    if not passphrase:
        sys.stderr.write("keyphrase cannot be empty\n"); sys.exit(2)
    want_nick = sys.argv[4] if len(sys.argv) >= 5 else ""
    want_room = sys.argv[5] if len(sys.argv) >= 6 else ""

    term_init()
    term_putline(f"{APP_NAME} {APP_VERSION} client. Connecting to {server}:{port} ...")

    if not do_connect(server, port, passphrase, want_nick, want_room):
        sys.exit(1)

    try:
        for line in sys.stdin:
            if g_sock is None:
                break
            handle_input(line)
    except KeyboardInterrupt:
        pass
    finally:
        if _log_file is not None:
            try: _log_file.close()
            except Exception: pass


if __name__ == "__main__":
    main()
