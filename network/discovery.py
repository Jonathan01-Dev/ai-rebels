"""Compatibility entrypoint for Sprint 1 discovery.

This module intentionally delegates to network/node.py so the project has a
single source of truth for:
- UDP multicast HELLO discovery (239.255.42.99:6000)
- TCP unicast PEER_LIST exchange (TLV)
- peer table timeout/persistence
"""

from network.node import (
    PeerTable,
    TCPServer,
    discovery_loop,
    get_node_id_bytes,
    parse_args,
    periodic_print,
    periodic_save,
)

import time
import threading


if __name__ == "__main__":
    args = parse_args()
    my_node_id = get_node_id_bytes(args.node_id_hex)
    stop = threading.Event()

    peer_table = PeerTable(my_node_id=my_node_id)
    tcp = TCPServer("0.0.0.0", args.tcp_port, peer_table, my_node_id, stop)
    real_tcp_port = tcp.start()

    if args.peer_db_path:
        peer_db_path = args.peer_db_path
    else:
        peer_db_path = f"peer_table_{real_tcp_port}.json"

    peer_table.load(peer_db_path)

    threading.Thread(
        target=discovery_loop,
        args=(my_node_id, real_tcp_port, peer_table, stop, args.hello_interval, args.peer_dead_after),
        daemon=True,
    ).start()
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
