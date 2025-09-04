#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket, threading, sys, select, random

# 🔥 Burner list (rotates each new client connection)
BURNERS = [
    b"\033[92mSCRIPT BY \033[93mSPIDER\033[0m (\033[94mTelegram: t.me/spid_3r\033[0m)\r\n",
    b"👑 SPIDER STORE — 2024 Stable Edition 👑\r\n",
    b"⚡ Respect the source, Fear the SPIDER ⚡\r\n",
    b"🔥 Official Script — Pirated copies are BUGGED 🔥\r\n",
    b"💀 SPIDER Proxy: Fast, Secure, Untouchable 💀\r\n"
]

def get_random_burner():
    return random.choice(BURNERS)

# WebSocket upgrade response
WS_RESPONSE = (
    b"HTTP/1.1 101 Switching Protocols\r\n"
    b"Upgrade: websocket\r\n"
    b"Connection: Upgrade\r\n"
    b"\r\n"
)

class ProxyServer:
    def __init__(self, host='0.0.0.0', port=8080):
        self.host = host
        self.port = port
        self.threads = []
        self.start()

    def start(self):
        print(f"[+] Proxy listening on {self.host}:{self.port}")
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port))
            self.sock.listen(100)
            while True:
                client, addr = self.sock.accept()
                handler = ProxyHandler(client, addr, self)
                handler.start()
                self.threads.append(handler)
        except KeyboardInterrupt:
            print("\n[!] Shutting down proxy...")
            for t in self.threads:
                t.join()
            self.sock.close()
            sys.exit(0)

    def printLog(self, log):
        print(log)

class ProxyHandler(threading.Thread):
    def __init__(self, client, addr, server):
        threading.Thread.__init__(self)
        self.client = client
        self.addr = addr
        self.server = server
        self.client_buffer = ''
        self.log = f"[{addr[0]}:{addr[1]}]"

    def run(self):
        try:
            self.client_buffer = self.client.recv(8192).decode('utf-8', errors='ignore')
            if not self.client_buffer:
                self.client.close()
                return

            first_line = self.client_buffer.split('\n')[0]
            parts = first_line.split()
            if len(parts) < 2:
                self.client.close()
                return

            method, path = parts[0], parts[1]
            if method.upper() == 'CONNECT' or "Upgrade: websocket" in self.client_buffer:
                self.method_WS(path)
            else:
                self.client.close()
        except Exception:
            self.client.close()

    def connect_target(self, path):
        try:
            host, port = path.split(':')
            port = int(port)
        except:
            host, port = path, 80
        self.target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.target.connect((host, port))

    def method_WS(self, path):
        self.log += ' - WS ' + path
        self.connect_target(path)

        # Pick a random banner
        random_burner = get_random_burner()

        # First send 200 OK + banner
        burner_msg = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Connection: keep-alive\r\n"
            b"\r\n" +
            random_burner +
            b"https://wa.me/254112011036\r\n"
        )
        self.client.sendall(burner_msg)

        # Then send WebSocket 101 upgrade
        self.client.sendall(WS_RESPONSE)

        # Log locally
        self.server.printLog(self.log)
        print(f"🔥 Banner sent: {random_burner.decode(errors='ignore').strip()}")

        self.doCONNECT()

    def doCONNECT(self):
        try:
            sockets = [self.client, self.target]
            while True:
                r, w, e = select.select(sockets, [], sockets, 3)
                if e:
                    break
                if r:
                    for s in r:
                        data = s.recv(8192)
                        if not data:
                            return
                        if s is self.client:
                            self.target.sendall(data)
                        else:
                            self.client.sendall(data)
        except:
            pass
        finally:
            self.client.close()
            self.target.close()


if __name__ == '__main__':
    host = "0.0.0.0"
    port = 8080
    ProxyServer(host, port)
