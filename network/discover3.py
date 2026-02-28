import socket
import json
import struct
import threading
import time
from dataclasses import dataclass, asdict

#Port 
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("0.0.0.0", 0))  # port auto
server.listen()

MY_TCP_PORT = server.getsockname()[1]

print("TCP server running on port", MY_TCP_PORT)


##
MCAST_GRP = "239.255.42.99"
MCAST_PORT = 6000
HELLO_INTERVAL = 30.0
TTL = 1  # 1 = réseau local

TYPE_HELLO = "HELLO"
TYPE_PEER_LIST = "PEER_LIST"


@dataclass
class PeerInfo:
    ip: str
    port: int
    last_seen: float


class PeerTable:
    def __init__(self):
        self._lock = threading.Lock()
        self._peers = {}  # node_id -> PeerInfo

    def upsert(self, node_id: str, ip: str, port: int):
        now = time.time()
        with self._lock:
            self._peers[node_id] = PeerInfo(ip=ip, port=port, last_seen=now)

    def snapshot(self):
        with self._lock:
            # retourne une copie sérialisable
            return [
                {"node_id": nid, "ip": p.ip, "port": p.port, "last_seen": p.last_seen}
                for nid, p in self._peers.items()
            ]

    def cleanup(self, max_age_sec: float = 90.0):
        """Optionnel : supprime les peers trop vieux."""
        now = time.time()
        with self._lock:
            to_del = [nid for nid, p in self._peers.items() if now - p.last_seen > max_age_sec]
            for nid in to_del:
                del self._peers[nid]


def build_packet(pkt_type: str, payload: dict) -> bytes:
    pkt = {"type": pkt_type, **payload}
    return json.dumps(pkt, separators=(",", ":")).encode("utf-8")


def parse_packet(data: bytes) -> dict | None:
    try:
        return json.loads(data.decode("utf-8"))
    except Exception:
        return None


def reply_with_peer_list(sock: socket.socket, peer_table: PeerTable, to_ip: str, to_port: int, my_node_id: str):
    payload = {
        "node_id": my_node_id,
        "timestamp": int(time.time() * 1000),
        "peers": peer_table.snapshot(),
    }
    pkt = build_packet(TYPE_PEER_LIST, payload)
    sock.sendto(pkt, (to_ip, to_port))


def discovery_loop(my_node_id: str, my_tcp_port: int, peer_table: PeerTable, stop_event: threading.Event):
    # Socket UDP multicast
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

    # Permet à plusieurs processus d'écouter le même port sur la même machine (selon OS)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Bind sur le port de découverte
    sock.bind(("", MCAST_PORT))

    # Rejoindre le groupe multicast
    mreq = struct.pack("4s4s", socket.inet_aton(MCAST_GRP), socket.inet_aton("0.0.0.0"))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    # TTL multicast (réseau local)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, TTL)

    # (Optionnel) Désactiver le loopback multicast (sinon tu peux recevoir tes propres HELLO)
    # sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)

    def send_hello_periodically():
        while not stop_event.is_set():
            hello = build_packet(TYPE_HELLO, {
                "node_id": my_node_id,
                "tcp_port": my_tcp_port,
                "timestamp": int(time.time() * 1000),
            })
            sock.sendto(hello, (MCAST_GRP, MCAST_PORT))
            
            print(f"[{my_node_id}] HELLO envoyé (tcp={my_tcp_port})")
            
            # sleep en petites tranches pour réagir vite au stop_event
            for _ in range(int(HELLO_INTERVAL * 10)):
                if stop_event.is_set():
                    break
                time.sleep(0.1)

    sender_thread = threading.Thread(target=send_hello_periodically, daemon=True)
    sender_thread.start()

    # Boucle réception
    sock.settimeout(1.0)
    while not stop_event.is_set():
        peer_table.cleanup()  # ou peer_table.cleanup(90.0)
        try:
            data, (src_ip, src_port) = sock.recvfrom(65535)
        except socket.timeout:
            peer_table.cleanup()
            continue

        pkt = parse_packet(data)
        if not pkt or "type" not in pkt:
            continue

        # Ignore nos propres messages
        if pkt.get("node_id") == my_node_id:
            continue

        if pkt["type"] == TYPE_HELLO:
            node_id = pkt.get("node_id")
            tcp_port = pkt.get("tcp_port")

            if not node_id or not isinstance(tcp_port, int):
                continue

            # Ajoute/maj le peer
            peer_table.upsert(node_id, src_ip, tcp_port)
            print(f"[{my_node_id}] HELLO reçu de {node_id} ({src_ip}:{tcp_port})")
            print(f"[{my_node_id}] peers = {peer_table.snapshot()}")

            # Répond en unicast au port UDP source (src_port)
            reply_with_peer_list(sock, peer_table, src_ip, src_port, my_node_id)

        elif pkt["type"] == TYPE_PEER_LIST:
            peers = pkt.get("peers")
            if isinstance(peers, list):
                for p in peers:
                    nid = p.get("node_id")
                    ip = p.get("ip")
                    port = p.get("port")
                    if nid and nid != my_node_id and isinstance(port, int) and isinstance(ip, str):
                        peer_table.upsert(nid, ip, port)

    try:
        sock.close()
    except Exception:
        pass

def tcp_server_loop(server_socket, stop_event):
    print("TCP accept loop started")

    while not stop_event.is_set():
        try:
            server_socket.settimeout(1.0)
            conn, addr = server_socket.accept()
            print(f"TCP connection from {addr}")
            conn.close()
        except socket.timeout:
            continue
        
        
if __name__ == "__main__":
    my_node_id = "node-C"

    peer_table = PeerTable()
    stop = threading.Event()

    tcp_thread = threading.Thread(
        target=tcp_server_loop,
        args=(server, stop),
        daemon=True
    )
    tcp_thread.start()

    try:
        discovery_loop(my_node_id, MY_TCP_PORT, peer_table, stop)
    except KeyboardInterrupt:
        stop.set()
        try:
            server.close()
        except Exception:
            pass
        print("\nStopping...")