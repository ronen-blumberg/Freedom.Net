#!/usr/bin/env python3
"""
Freedom Net Server - end-to-end encrypted IRC-style chat server.

Pure-Python, no third-party dependencies. Wire-compatible with server.c:
the same packet format, same KDF (SHA-256 100k iters with "FreedomNet-v1"),
same AES-256-CBC framing. A Python server accepts C clients and vice versa.

Usage:
    python3 server.py <port> <keyphrase>

The server is a pure relay; it has no nickname.
"""

import hashlib
import os
import signal
import socket
import struct
import sys
import threading
import time

APP_NAME           = "Freedom Net"
APP_VERSION        = "0.1.0"
KDF_TAG            = b"FreedomNet-v1"

MAX_NICK           = 32
MAX_ROOM           = 32
MAX_TEXT           = 1024
MAX_USERS_PER_ROOM = 25
MAX_ROOMS_PER_USER = 10
MAX_CLIENTS        = 200
MAX_ROOMS          = 100

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


# ===== AES-256-CBC + PKCS#7 (pure-Python, wire-compatible with server.c) =====

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

def _send_all(sock, data):
    sock.sendall(data)


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
    _send_all(sock, struct.pack(">I", framelen) + iv + ct)


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


# ===== Validation =====

def name_is_valid(s, maxlen):
    if not s:
        return False
    if len(s) >= maxlen:
        return False
    for c in s:
        if ord(c) <= 0x20 or ord(c) == 0x7f or c in (':', ','):
            return False
    return True


def read_u8_string(p, off):
    if off + 1 > len(p):
        raise ValueError("short")
    n = p[off]; off += 1
    if off + n > len(p):
        raise ValueError("short")
    s = p[off:off+n].decode("utf-8", errors="replace")
    return s, off + n


# ===== Server state =====

class Client:
    __slots__ = ("sock", "nick", "addr", "rooms", "send_lock")
    def __init__(self, sock, nick, addr):
        self.sock = sock
        self.nick = nick
        self.addr = addr
        self.rooms = []        # list of room names this client is in
        self.send_lock = threading.Lock()


class Server:
    def __init__(self, rk):
        self.rk = rk
        self.lock = threading.RLock()
        self.clients = []      # list of Client (active only)
        self.rooms = {}        # name -> list[Client]
        self.running = True

    # ---- locked helpers ----
    def _client_count(self):
        return len(self.clients)

    def _find_by_nick(self, nick):
        for c in self.clients:
            if c.nick == nick:
                return c
        return None

    def _nick_in_use(self, nick):
        return self._find_by_nick(nick) is not None

    def _add_to_room(self, client, room):
        """Return (ok, error_msg)."""
        members = self.rooms.get(room)
        if members is None:
            if len(self.rooms) >= MAX_ROOMS:
                return False, "no free room slots"
            members = []
            self.rooms[room] = members
        if len(members) >= MAX_USERS_PER_ROOM:
            return False, "room full"
        if len(client.rooms) >= MAX_ROOMS_PER_USER:
            return False, "you are already in the maximum number of rooms"
        if client in members:
            return False, "already in that room"
        members.append(client)
        client.rooms.append(room)
        return True, ""

    def _remove_from_room(self, client, room):
        members = self.rooms.get(room)
        if not members:
            return
        if client in members:
            members.remove(client)
        if room in client.rooms:
            client.rooms.remove(room)
        if not members:
            del self.rooms[room]

    # ---- sending ----
    def _send_to(self, client, ptype, payload=b""):
        """Best-effort send; returns False on error."""
        with client.send_lock:
            try:
                send_packet(client.sock, self.rk, ptype, payload)
                return True
            except Exception:
                return False

    def send_err(self, client, text):
        self._send_to(client, PKT_ERR, text.encode("utf-8"))

    def broadcast_room(self, room, ptype, payload, exclude=None):
        with self.lock:
            members = list(self.rooms.get(room, ()))
        for c in members:
            if c is exclude:
                continue
            self._send_to(c, ptype, payload)

    def unicast_to_nick(self, nick, ptype, payload):
        with self.lock:
            c = self._find_by_nick(nick)
        if c is None:
            return False
        return self._send_to(c, ptype, payload)

    # ---- random nick / room ----
    _ADJ = ("anon","brisk","calm","dark","quiet","wild","still","quick","faint","hidden",
            "lone","gentle","silent","misty","stormy","glowing","velvet","amber","scarlet","azure")
    _NOUN = ("fox","owl","wolf","raven","river","stone","ember","cloud","pine","echo",
             "drift","moon","sun","mist","shade","blade","spark","leaf","wave","comet")

    def _random_nick(self):
        for _ in range(64):
            r = os.urandom(4)
            n = f"{self._ADJ[r[0] % len(self._ADJ)]}_{self._NOUN[r[1] % len(self._NOUN)]}{int.from_bytes(r[2:4], 'big') % 1000}"
            if not self._nick_in_use(n):
                return n
        return n

    def _random_room(self):
        # prefer joining an existing non-full room
        avail = [name for name, m in self.rooms.items()
                 if len(m) < MAX_USERS_PER_ROOM]
        if avail:
            return avail[int.from_bytes(os.urandom(2), "big") % len(avail)]
        return f"lobby_{int.from_bytes(os.urandom(2), 'big') % 1000}"


SERVER = None


def log(msg):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    sys.stderr.write(f"[{ts}] {msg}\n")
    sys.stderr.flush()


# ===== Packet builders =====

def build_room_msg(room, sender, text_bytes):
    r = room.encode("utf-8"); s = sender.encode("utf-8")
    if len(r) > 255 or len(s) > 255 or len(text_bytes) > MAX_TEXT:
        return None
    return bytes([len(r)]) + r + bytes([len(s)]) + s + text_bytes


def build_join_part(room, nick):
    r = room.encode("utf-8"); n = nick.encode("utf-8")
    if len(r) > 255 or len(n) > 255:
        return None
    return bytes([len(r)]) + r + bytes([len(n)]) + n


def build_sys_payload(room, text):
    r = room.encode("utf-8"); t = text.encode("utf-8")
    if len(r) > 255 or len(t) > MAX_TEXT:
        return None
    return bytes([len(r)]) + r + t


def build_hello_ack(nick, room):
    n = nick.encode("utf-8"); r = room.encode("utf-8")
    return bytes([len(n)]) + n + bytes([len(r)]) + r


# ===== Handlers =====

def handle_hello(sock, addr):
    ptype, payload = recv_packet(sock, SERVER.rk)
    if ptype != PKT_HELLO:
        send_packet(sock, SERVER.rk, PKT_ERR, b"expected HELLO")
        return None
    try:
        req_nick, off = read_u8_string(payload, 0)
        req_room, off = read_u8_string(payload, off)
    except ValueError:
        send_packet(sock, SERVER.rk, PKT_ERR, b"bad hello")
        return None

    with SERVER.lock:
        if req_nick == "":
            nick = SERVER._random_nick()
        else:
            if not name_is_valid(req_nick, MAX_NICK):
                send_packet(sock, SERVER.rk, PKT_ERR, b"invalid nickname")
                return None
            if SERVER._nick_in_use(req_nick):
                send_packet(sock, SERVER.rk, PKT_ERR, b"nickname in use")
                return None
            nick = req_nick

        if req_room == "":
            room = SERVER._random_room()
        else:
            if not name_is_valid(req_room, MAX_ROOM):
                send_packet(sock, SERVER.rk, PKT_ERR, b"invalid room name")
                return None
            room = req_room

        if len(SERVER.clients) >= MAX_CLIENTS:
            send_packet(sock, SERVER.rk, PKT_ERR, b"server full")
            return None

        client = Client(sock, nick, addr)
        SERVER.clients.append(client)
        ok, err = SERVER._add_to_room(client, room)
        if not ok:
            SERVER.clients.remove(client)
            send_packet(sock, SERVER.rk, PKT_ERR, err.encode())
            return None

    SERVER._send_to(client, PKT_HELLO, build_hello_ack(nick, room))
    jp = build_join_part(room, nick)
    if jp:
        SERVER.broadcast_room(room, PKT_JOIN, jp, exclude=client)
    log(f"connect: {addr} as \"{nick}\" -> room \"{room}\"")
    return client


def handle_msg_or_emote(client, ptype, payload):
    try:
        room, off = read_u8_string(payload, 0)
    except ValueError:
        return
    text = payload[off:]
    if not text or len(text) > MAX_TEXT:
        return
    with SERVER.lock:
        if room not in SERVER.rooms or client not in SERVER.rooms[room]:
            SERVER.send_err(client, "you are not in that room")
            return
        sender = client.nick
    out = build_room_msg(room, sender, text)
    if out is None:
        return
    SERVER.broadcast_room(room, ptype, out)


def handle_dm(client, payload):
    try:
        recip, off = read_u8_string(payload, 0)
    except ValueError:
        return
    text = payload[off:]
    if not text or len(text) > MAX_TEXT:
        return
    with SERVER.lock:
        sender = client.nick
        target = SERVER._find_by_nick(recip)
    if target is None:
        SERVER.send_err(client, f'no such user "{recip}"')
        return
    sb = sender.encode("utf-8")
    out = bytes([len(sb)]) + sb + text
    SERVER._send_to(target, PKT_DM, out)


def handle_file(client, payload):
    # Client wire:  [u8 rlen][recip][u8 fnlen][fname][u32 size][bytes]
    # Server fwd :  [u8 slen][sender][u8 fnlen][fname][u32 size][bytes]
    try:
        recip, off = read_u8_string(payload, 0)
        if off + 1 > len(payload):
            return
        fnl = payload[off]; off += 1
        if fnl == 0 or off + fnl + 4 > len(payload):
            return
        fname = payload[off:off+fnl].decode("utf-8", errors="replace")
        off += fnl
        (fsz,) = struct.unpack(">I", payload[off:off+4]); off += 4
        if fsz > MAX_FILE_BYTES or off + fsz != len(payload):
            return
        body = payload[off:]
    except Exception:
        return
    with SERVER.lock:
        sender = client.nick
        target = SERVER._find_by_nick(recip)
    if target is None:
        SERVER.send_err(client, f'no such user "{recip}"; file not delivered')
        return
    sb = sender.encode("utf-8"); fb = fname.encode("utf-8")
    out = (bytes([len(sb)]) + sb
           + bytes([len(fb)]) + fb
           + struct.pack(">I", fsz)
           + body)
    SERVER._send_to(target, PKT_FILE, out)
    log(f"file relay: {sender} -> {recip} ({fname}, {fsz} bytes)")


def handle_who(client, payload):
    try:
        room, _ = read_u8_string(payload, 0)
    except ValueError:
        return
    with SERVER.lock:
        members = SERVER.rooms.get(room)
        if members is None:
            SERVER.send_err(client, "no such room")
            return
        nicks = [c.nick for c in members]
    rb = room.encode("utf-8")
    out = bytearray([len(rb)]) + rb + bytes([len(nicks)])
    for n in nicks:
        nb = n.encode("utf-8")
        out += bytes([len(nb)]) + nb
    SERVER._send_to(client, PKT_WHO, bytes(out))


def handle_list(client):
    with SERVER.lock:
        items = [(name, len(m)) for name, m in SERVER.rooms.items()]
    out = bytearray([len(items)])
    for name, nm in items:
        rb = name.encode("utf-8")
        out += bytes([len(rb)]) + rb + struct.pack(">H", nm)
    SERVER._send_to(client, PKT_LIST, bytes(out))


def handle_nick(client, payload):
    try:
        newnick, _ = read_u8_string(payload, 0)
    except ValueError:
        return
    if not name_is_valid(newnick, MAX_NICK):
        SERVER.send_err(client, "invalid nickname")
        return
    with SERVER.lock:
        if newnick == client.nick:
            return
        if SERVER._nick_in_use(newnick):
            SERVER.send_err(client, "nickname in use")
            return
        oldnick = client.nick
        client.nick = newnick
        rooms_snap = list(client.rooms)
    SERVER._send_to(client, PKT_NICK, newnick.encode("utf-8"))
    note = f"* {oldnick} is now known as {newnick} *"
    for r in rooms_snap:
        p = build_sys_payload(r, note)
        if p:
            SERVER.broadcast_room(r, PKT_SYS, p)
    log(f"rename: {oldnick} -> {newnick}")


def handle_join(client, payload):
    try:
        room, _ = read_u8_string(payload, 0)
    except ValueError:
        return
    if not name_is_valid(room, MAX_ROOM):
        SERVER.send_err(client, "invalid room name")
        return
    with SERVER.lock:
        ok, err = SERVER._add_to_room(client, room)
        nick = client.nick
    if not ok:
        SERVER.send_err(client, err)
        return
    jp = build_join_part(room, nick)
    if jp:
        SERVER.broadcast_room(room, PKT_JOIN, jp)
    log(f"join: {nick} -> {room}")


def handle_part(client, payload):
    try:
        room, _ = read_u8_string(payload, 0)
    except ValueError:
        return
    with SERVER.lock:
        nick = client.nick
        if room not in client.rooms:
            SERVER.send_err(client, "you are not in that room")
            return
    jp = build_join_part(room, nick)
    if jp:
        SERVER.broadcast_room(room, PKT_PART, jp)
    with SERVER.lock:
        SERVER._remove_from_room(client, room)
    log(f"part: {nick} <- {room}")


def client_cleanup(client):
    with SERVER.lock:
        rooms_snap = list(client.rooms)
        if client in SERVER.clients:
            SERVER.clients.remove(client)
    nick = client.nick
    for r in rooms_snap:
        jp = build_join_part(r, nick)
        if jp:
            SERVER.broadcast_room(r, PKT_PART, jp, exclude=client)
        with SERVER.lock:
            SERVER._remove_from_room(client, r)
    try:
        client.sock.close()
    except Exception:
        pass
    log(f"disconnect: {nick}")


def client_thread(sock, addr_str):
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except Exception:
        pass
    try:
        client = handle_hello(sock, addr_str)
    except Exception as e:
        try: sock.close()
        except Exception: pass
        log(f"hello failed from {addr_str}: {e}")
        return
    if client is None:
        try: sock.close()
        except Exception: pass
        return
    try:
        while True:
            try:
                ptype, payload = recv_packet(sock, SERVER.rk)
            except Exception:
                break
            if ptype in (PKT_MSG, PKT_EMOTE):
                handle_msg_or_emote(client, ptype, payload)
            elif ptype == PKT_DM:
                handle_dm(client, payload)
            elif ptype == PKT_FILE:
                handle_file(client, payload)
            elif ptype == PKT_WHO:
                handle_who(client, payload)
            elif ptype == PKT_LIST:
                handle_list(client)
            elif ptype == PKT_NICK:
                handle_nick(client, payload)
            elif ptype == PKT_JOIN:
                handle_join(client, payload)
            elif ptype == PKT_PART:
                handle_part(client, payload)
            elif ptype == PKT_QUIT:
                break
            elif ptype == PKT_PING:
                pass
            # unknown -> ignore
    finally:
        client_cleanup(client)


# ===== main / accept loop =====

def main():
    global SERVER
    if len(sys.argv) != 3:
        sys.stderr.write(f"Usage: {sys.argv[0]} <port> <keyphrase>\n")
        sys.exit(2)
    try:
        port = int(sys.argv[1])
    except ValueError:
        sys.stderr.write("port must be an integer\n"); sys.exit(2)
    if not (0 < port < 65536):
        sys.stderr.write("port out of range\n"); sys.exit(2)
    passphrase = sys.argv[2]
    if not passphrase:
        sys.stderr.write("keyphrase cannot be empty\n"); sys.exit(2)

    rk = aes_key_expansion(derive_key(passphrase))
    SERVER = Server(rk)

    lsn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsn.bind(("0.0.0.0", port))
    lsn.listen(32)

    def stop(signum, frame):
        SERVER.running = False
        try: lsn.close()
        except Exception: pass
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    log(f"{APP_NAME} {APP_VERSION} server listening on port {port}")

    try:
        while SERVER.running:
            try:
                cs, ca = lsn.accept()
            except OSError:
                break
            ip, p = ca[0], ca[1]
            addr_str = f"{ip}:{p}"
            t = threading.Thread(target=client_thread, args=(cs, addr_str), daemon=True)
            t.start()
    finally:
        try: lsn.close()
        except Exception: pass
        log(f"{APP_NAME} server shutting down")


if __name__ == "__main__":
    main()
