#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket, threading, sys, select, argparse

# --- Parse config file (tun.conf) ---
def load_config(path):
    config = {}
    try:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, value = line.split("=", 1)
                    config[key.strip()] = value.strip()
    except Exception as e:
        print(f"[!] Failed to load config: {e}")
    return config


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

            first_line = self.client_buffer.split('\n', 1)[0]
            parts = first_line.split()
            if len(parts) < 2:
                self.client.close()
                return

            method, path = parts[0], parts[1]
            if method.upper() == 'CONNECT':
                self.method_CONNECT(path)
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

    def method_CONNECT(self, path):
        self.log += ' - CONNECT ' + path
        self.connect_target(path)

        # 1) Send 200 OK to client
        self.client.sendall(b"HTTP/1.1 200 OK\r\n\r\n")

        # 2) Send 101 Switching Protocols
        self.client.sendall(
            b"HTTP/1.1 101 Switching Protocols\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n"
            b"\r\n"
        )

        # 3) Send Burner (shows in APK logs)
        burner = (
            b"🔥 SCRIPT BY SPIDER - Telegram: t.me/spid_3r 🔥\r\n"
            b"https://wa.me/254112011036\r\n"
        )
        self.client.sendall(burner)

        # Log on server side
        self.server.printLog(self.log)
        print("🔥 Burner sent to client")

        # Start tunneling
        self.doCONNECT()

    def doCONNECT(self):
        try:
            sockets = [self.client, self.target]
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
                            self.target.sendall(data)
                        else:
                            self.client.sendall(data)
        except:
            pass
        finally:
            self.client.close()
            self.target.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", help="Path to config file", default="/opt/spider/tun.conf")
    args = parser.parse_args()

    cfg = load_config(args.file)
    host = cfg.get("LISTEN", "0.0.0.0")
    port = int(cfg.get("PORT", "8080"))

    ProxyServer(host, port)
