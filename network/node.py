import os
import socket
import json
import struct
import threading
import time
import argparse
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Tuple

# =========================
# .env loader (sans dépendance externe)
# =========================
def load_dotenv(path: str = ".env") -> None:
    if not os.path.exists(path):
        return
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                os.environ.setdefault(k, v)
    except Exception:
        pass

load_dotenv()

# =========================
# Config
# =========================
MCAST_GRP = os.getenv("MCAST_GRP", "239.255.42.99")
MCAST_PORT = int(os.getenv("MCAST_PORT", "6000"))
TTL = int(os.getenv("MCAST_TTL", "1"))

HELLO_INTERVAL = float(os.getenv("HELLO_INTERVAL", "30"))
PEER_DEAD_AFTER = float(os.getenv("PEER_DEAD_AFTER", "90"))

# Module 1.3: port via .env, défaut 7777
TCP_PORT = int(os.getenv("TCP_PORT", "7777"))

# IMPORTANT: base pour persistance
# (on finalise PEER_DB_PATH après avoir déterminé le port réel)
PEER_DB_PATH_ENV = os.getenv("PEER_DB_PATH", "").strip()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Archipel node (Sprint 1 mesh/discovery)")
    parser.add_argument("--tcp-port", type=int, default=TCP_PORT, help="TCP listening port (default: 7777)")
    parser.add_argument("--node-id-hex", type=str, default=os.getenv("NODE_ID_HEX", ""), help="Node ID as 64-hex chars")
    parser.add_argument("--hello-interval", type=float, default=HELLO_INTERVAL, help="HELLO send interval in seconds")
    parser.add_argument("--peer-dead-after", type=float, default=PEER_DEAD_AFTER, help="Peer timeout in seconds")
    parser.add_argument("--peer-db-path", type=str, default=PEER_DB_PATH_ENV, help="Peer table persistence path")
    parser.add_argument("--print-interval", type=float, default=5.0, help="Peer table print interval in seconds")
    return parser.parse_args()

# =========================
# Node ID: bytes[32] (Ed25519 public key)
# NODE_ID_HEX = 64 hex -> 32 bytes
# =========================
def get_node_id_bytes(node_id_hex: str = "") -> bytes:
    hx = (node_id_hex or "").strip().lower()
    if not hx:
        b = os.urandom(32)
        print("[WARN] NODE_ID_HEX absent : génération d'un node_id aléatoire (dev only).")
        print(f"       Exemple à mettre dans .env : NODE_ID_HEX={b.hex()}")
        return b
    try:
        b = bytes.fromhex(hx)
        if len(b) != 32:
            raise ValueError("NODE_ID_HEX doit décoder en 32 bytes")
        return b
    except Exception as e:
        raise SystemExit(f"NODE_ID_HEX invalide: {e}")

# =========================
# Module 1.2 — Peer Table
# =========================
@dataclass
class PeerInfo:
    node_id: bytes
    ip: str
    tcp_port: int
    last_seen: float
    shared_files: List[str] = field(default_factory=list)
    reputation: float = 0.0

class PeerTable:
    def __init__(self, my_node_id: bytes):
        self._lock = threading.Lock()
        self._peers: Dict[bytes, PeerInfo] = {}
        self.my_node_id = my_node_id

    def upsert(
        self,
        node_id: bytes,
        ip: str,
        tcp_port: int,
        shared_files: Optional[List[str]] = None,
        reputation: Optional[float] = None,
        touch_last_seen: bool = True,
    ):
        # ✅ Ne jamais ajouter "self"
        if node_id == self.my_node_id:
            return

        now = time.time()
        with self._lock:
            old = self._peers.get(node_id)
            self._peers[node_id] = PeerInfo(
                node_id=node_id,
                ip=ip,
                tcp_port=int(tcp_port),
                last_seen=(now if touch_last_seen else (old.last_seen if old else now)),
                shared_files=(shared_files if shared_files is not None else (old.shared_files if old else [])),
                reputation=(float(reputation) if reputation is not None else (old.reputation if old else 0.0)),
            )

    def cleanup(self, max_age_sec: float = PEER_DEAD_AFTER):
        now = time.time()
        with self._lock:
            dead = [nid for nid, p in self._peers.items() if (now - p.last_seen) > max_age_sec]
            for nid in dead:
                del self._peers[nid]

    def snapshot(self) -> List[dict]:
        with self._lock:
            return [
                {
                    "node_id_hex": p.node_id.hex(),
                    "ip": p.ip,
                    "tcp_port": p.tcp_port,
                    "last_seen": p.last_seen,
                    "shared_files": list(p.shared_files),
                    "reputation": float(p.reputation),
                }
                for p in self._peers.values()
            ]

    # ---- persistance disque ----
    def save(self, path: str):
        data = {"saved_at": time.time(), "peers": self.snapshot()}
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)
        os.replace(tmp, path)

    def load(self, path: str):
        if not os.path.exists(path):
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            peers = data.get("peers", [])
            if not isinstance(peers, list):
                return
            with self._lock:
                self._peers.clear()
                for item in peers:
                    hx = item.get("node_id_hex")
                    ip = item.get("ip")
                    tcp_port = item.get("tcp_port")
                    last_seen = item.get("last_seen")
                    shared_files = item.get("shared_files", [])
                    reputation = item.get("reputation", 0.0)

                    if not (isinstance(hx, str) and isinstance(ip, str) and isinstance(tcp_port, int)):
                        continue
                    try:
                        nid = bytes.fromhex(hx)
                        if len(nid) != 32 or nid == self.my_node_id:
                            continue
                    except Exception:
                        continue

                    self._peers[nid] = PeerInfo(
                        node_id=nid,
                        ip=ip,
                        tcp_port=int(tcp_port),
                        last_seen=float(last_seen) if isinstance(last_seen, (int, float)) else time.time(),
                        shared_files=list(shared_files) if isinstance(shared_files, list) else [],
                        reputation=float(reputation) if isinstance(reputation, (int, float)) else 0.0,
                    )
        except Exception:
            pass

# =========================
# Module 1.3 — TCP TLV + keepalive ping/pong
# TLV = Type(1 byte) + Length(4 bytes big-endian) + Value
# =========================
TLV_HDR = struct.Struct("!BI")
T_PEER_LIST = 0x01
T_PING = 0x02
T_PONG = 0x03

def tlv_pack(t: int, value: bytes) -> bytes:
    return TLV_HDR.pack(t, len(value)) + value

def tlv_try_unpack(buf: bytes) -> Tuple[Optional[int], Optional[bytes], bytes]:
    if len(buf) < TLV_HDR.size:
        return None, None, buf
    t, ln = TLV_HDR.unpack(buf[:TLV_HDR.size])
    need = TLV_HDR.size + ln
    if len(buf) < need:
        return None, None, buf
    val = buf[TLV_HDR.size:need]
    rest = buf[need:]
    return t, val, rest

class TCPServer:
    def __init__(self, bind_ip: str, port: int, peer_table: PeerTable, my_node_id: bytes, stop: threading.Event):
        self.bind_ip = bind_ip
        self.port = port
        self.peer_table = peer_table
        self.my_node_id = my_node_id
        self.stop = stop
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                pass

    def start(self) -> int:
        self._srv.bind((self.bind_ip, self.port))
        self._srv.listen(50)  # backlog >= 10 connexions
        real_port = self._srv.getsockname()[1]
        print(f"TCP server listening on {self.bind_ip}:{real_port} (backlog=50)")
        threading.Thread(target=self._accept_loop, daemon=True).start()
        return real_port

    def _accept_loop(self):
        self._srv.settimeout(1.0)
        while not self.stop.is_set():
            try:
                conn, addr = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True).start()

        try:
            self._srv.close()
        except Exception:
            pass

    def _handle_client(self, conn: socket.socket, addr):
        conn.settimeout(1.0)
        buf = b""
        last_pong = time.time()

        # Keep-alive: ping toutes les 15s
        def keepalive():
            nonlocal last_pong
            while not self.stop.is_set():
                try:
                    conn.sendall(tlv_pack(T_PING, b""))
                except Exception:
                    return
                for _ in range(150):  # 15s en pas de 0.1
                    if self.stop.is_set():
                        return
                    time.sleep(0.1)
                if time.time() - last_pong > 45:
                    try:
                        conn.close()
                    except Exception:
                        pass
                    return

        threading.Thread(target=keepalive, daemon=True).start()

        try:
            while not self.stop.is_set():
                try:
                    data = conn.recv(4096)
                    if not data:
                        break
                    buf += data
                except socket.timeout:
                    continue
                except OSError:
                    break

                while True:
                    t, val, rest = tlv_try_unpack(buf)
                    if t is None:
                        break
                    buf = rest

                    if t == T_PING:
                        try:
                            conn.sendall(tlv_pack(T_PONG, b""))
                        except Exception:
                            pass
                    elif t == T_PONG:
                        last_pong = time.time()
                    elif t == T_PEER_LIST:
                        obj = None
                        try:
                            obj = json.loads(val.decode("utf-8"))
                        except Exception:
                            obj = None

                        peers = obj.get("peers") if isinstance(obj, dict) else None
                        if isinstance(peers, list):
                            for p in peers:
                                hx = p.get("node_id_hex")
                                ip = p.get("ip")
                                port = p.get("tcp_port")
                                shared_files = p.get("shared_files", [])
                                reputation = p.get("reputation", 0.0)

                                if isinstance(hx, str) and isinstance(ip, str) and isinstance(port, int):
                                    try:
                                        nid = bytes.fromhex(hx)
                                        if len(nid) != 32:
                                            continue
                                    except Exception:
                                        continue

                                    # ✅ ne pas ajouter self
                                    if nid == self.my_node_id:
                                        continue

                                    self.peer_table.upsert(
                                        nid, ip, port,
                                        shared_files=list(shared_files) if isinstance(shared_files, list) else None,
                                        reputation=float(reputation) if isinstance(reputation, (int, float)) else None,
                                        touch_last_seen=False,
                                    )

                            print(f"[TCP] PEER_LIST reçu de {addr[0]}:{addr[1]} -> table={len(self.peer_table.snapshot())} peers")
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def close(self):
        try:
            self._srv.close()
        except Exception:
            pass

# =========================
# Discovery (UDP multicast) + PEER_LIST en TCP TLV
# =========================
TYPE_HELLO = "HELLO"

def build_hello(node_id: bytes, tcp_port: int) -> bytes:
    pkt = {
        "type": TYPE_HELLO,
        "node_id_hex": node_id.hex(),
        "tcp_port": int(tcp_port),
        "timestamp": int(time.time() * 1000),
    }
    return json.dumps(pkt, separators=(",", ":")).encode("utf-8")

def parse_packet(data: bytes) -> Optional[dict]:
    try:
        return json.loads(data.decode("utf-8"))
    except Exception:
        return None

def send_peer_list_tcp(my_node_id: bytes, peer_table: PeerTable, to_ip: str, to_tcp_port: int, timeout=2.0) -> bool:
    payload = {
        "type": "PEER_LIST",
        "node_id_hex": my_node_id.hex(),
        "timestamp": int(time.time() * 1000),
        "peers": peer_table.snapshot(),  # déjà sans self
    }
    b = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    msg = tlv_pack(T_PEER_LIST, b)
    try:
        with socket.create_connection((to_ip, int(to_tcp_port)), timeout=timeout) as s:
            s.sendall(msg)
        return True
    except Exception:
        return False

def discovery_loop(
    my_node_id: bytes,
    my_tcp_port: int,
    peer_table: PeerTable,
    stop_event: threading.Event,
    hello_interval: float,
    peer_dead_after: float,
):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError:
            pass
    sock.bind(("", MCAST_PORT))

    mreq = struct.pack("4s4s", socket.inet_aton(MCAST_GRP), socket.inet_aton("0.0.0.0"))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, TTL)

    def send_hello_periodically():
        while not stop_event.is_set():
            hello = build_hello(my_node_id, my_tcp_port)
            sock.sendto(hello, (MCAST_GRP, MCAST_PORT))
            print(f"[{my_node_id.hex()[:8]}] HELLO envoyé (tcp={my_tcp_port})")

            for _ in range(max(1, int(hello_interval * 10))):
                if stop_event.is_set():
                    break
                time.sleep(0.1)

    threading.Thread(target=send_hello_periodically, daemon=True).start()

    sock.settimeout(1.0)
    while not stop_event.is_set():
        peer_table.cleanup(peer_dead_after)

        try:
            data, (src_ip, _src_udp_port) = sock.recvfrom(65535)
        except socket.timeout:
            continue
        except OSError:
            break

        pkt = parse_packet(data)
        if not pkt or pkt.get("type") != TYPE_HELLO:
            continue

        hx = pkt.get("node_id_hex")
        tcp_port = pkt.get("tcp_port")

        if not (isinstance(hx, str) and isinstance(tcp_port, int)):
            continue

        try:
            nid = bytes.fromhex(hx)
            if len(nid) != 32:
                continue
        except Exception:
            continue

        if nid == my_node_id:
            continue

        peer_table.upsert(nid, src_ip, tcp_port)
        print(f"[{my_node_id.hex()[:8]}] HELLO reçu de {hx[:8]} ({src_ip}:{tcp_port})")

        ok = send_peer_list_tcp(my_node_id, peer_table, src_ip, tcp_port)
        if ok:
            print(f"[{my_node_id.hex()[:8]}] PEER_LIST envoyé en TCP -> {src_ip}:{tcp_port}")
        else:
            print(f"[{my_node_id.hex()[:8]}] PEER_LIST TCP échoué -> {src_ip}:{tcp_port}")

    try:
        sock.close()
    except Exception:
        pass

# =========================
# Loops utilitaires
# =========================
def periodic_print(peer_table: PeerTable, stop: threading.Event, every_sec: float = 5.0):
    while not stop.is_set():
        snap = peer_table.snapshot()
        print(f"[TABLE] {len(snap)} peers -> {snap}")
        for _ in range(int(every_sec * 10)):
            if stop.is_set():
                break
            time.sleep(0.1)

def periodic_save(peer_table: PeerTable, stop: threading.Event, path: str, every_sec: float = 5.0):
    while not stop.is_set():
        try:
            peer_table.save(path)
        except Exception:
            pass
        time.sleep(every_sec)

# =========================
# Main (le "nœud")
# =========================
if __name__ == "__main__":
    args = parse_args()
    my_node_id = get_node_id_bytes(args.node_id_hex)

    stop = threading.Event()

    # TCP server
    peer_table = PeerTable(my_node_id=my_node_id)
    tcp = TCPServer("0.0.0.0", args.tcp_port, peer_table, my_node_id, stop)
    real_tcp_port = tcp.start()

    # ✅ fichier de persistance unique par instance (par port), sauf si override PEER_DB_PATH
    if args.peer_db_path:
        peer_db_path = args.peer_db_path
    else:
        peer_db_path = f"peer_table_{real_tcp_port}.json"

    # load après avoir déterminé le path
    peer_table.load(peer_db_path)

    # Discovery
    threading.Thread(
        target=discovery_loop,
        args=(my_node_id, real_tcp_port, peer_table, stop, args.hello_interval, args.peer_dead_after),
        daemon=True,
    ).start()

    # Logs + persistance
    threading.Thread(target=periodic_print, args=(peer_table, stop, args.print_interval), daemon=True).start()
    threading.Thread(target=periodic_save, args=(peer_table, stop, peer_db_path), daemon=True).start()

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        stop.set()
        try:
            peer_table.save(peer_db_path)
        except Exception:
            pass
        tcp.close()
        print("\nStopping...")
