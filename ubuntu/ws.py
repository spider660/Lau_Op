#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket, threading, sys, select, yaml, os

# 🔥 Burner message
BURNER = (
    b"HTTP/1.1 200 OK\r\n\r\n"
    b"HTTP/1.1 101 Switching Protocols\r\n"
    b"Upgrade: websocket\r\n"
    b"Connection: Upgrade\r\n"
    b"\r\n"
    b"🔥 SCRIPT BY SPIDER - Telegram: t.me/spid_3r 🔥\r\n"
    b"https://wa.me/254112011036\r\n"
)

# --- Proxy Handler ---
class ProxyHandler(threading.Thread):
    def __init__(self, client, addr, target_host, target_port):
        threading.Thread.__init__(self)
        self.client = client
        self.addr = addr
        self.target_host = target_host
        self.target_port = target_port

    def run(self):
        try:
            buffer = self.client.recv(8192)
            if not buffer:
                self.client.close()
                return

            first_line = buffer.decode(errors='ignore').split("\n", 1)[0]
            if "CONNECT" in first_line or "Upgrade: websocket" in buffer.decode(errors="ignore"):
                self.handle_connect()
            else:
                self.client.close()
        except Exception:
            self.client.close()

    def handle_connect(self):
        try:
            target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target.connect((self.target_host, self.target_port))

            # Send burner banner
            self.client.sendall(BURNER)

            print(f"[{self.addr[0]}:{self.addr[1]}] CONNECT {self.target_host}:{self.target_port} -> Banner Sent")

            self.relay(target)
        except Exception:
            self.client.close()

    def relay(self, target):
        try:
            sockets = [self.client, target]
            while True:
                r, _, e = select.select(sockets, [], sockets, 3)
                if e:
                    break
                if r:
                    for s in r:
                        data = s.recv(8192)
                        if not data:
                            return
                        if s is self.client:
                            target.sendall(data)
                        else:
                            self.client.sendall(data)
        except:
            pass
        finally:
            self.client.close()
            target.close()

# --- Proxy Server ---
class ProxyServer(threading.Thread):
    def __init__(self, listen_port, target_host, target_port):
        threading.Thread.__init__(self)
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port

    def run(self):
        print(f"[+] Listening on 0.0.0.0:{self.listen_port} -> {self.target_host}:{self.target_port}")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", self.listen_port))
        sock.listen(100)

        while True:
            client, addr = sock.accept()
            handler = ProxyHandler(client, addr, self.target_host, self.target_port)
            handler.start()

# --- Config Loader ---
def load_config(path):
    with open(path, "r") as f:
        return yaml.safe_load(f)

# --- Main ---
if __name__ == "__main__":
    base_path = os.path.dirname(os.path.abspath(__file__))
    cfg_path = os.path.join(base_path, "tun.conf")

    cfg = load_config(cfg_path)
    listeners = cfg.get("listen", [])

    servers = []
    for entry in listeners:
        lh = entry.get("target_host", "127.0.0.1")
        tp = entry.get("target_port", 22)
        lp = entry.get("listen_port", 8080)
        server = ProxyServer(lp, lh, tp)
        server.start()
        servers.append(server)

    try:
        for s in servers:
            s.join()
    except KeyboardInterrupt:
        print("\n[!] Stopping all listeners...")
        sys.exit(0)
