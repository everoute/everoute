#!/usr/bin/env python3
import socket
import json
import os
from pathlib import Path

SOCKET_PATH = "/var/run/vs-controller/vs-controller.sock"

Path(SOCKET_PATH).parent.mkdir(parents=True, exist_ok=True)

server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server_socket.bind(SOCKET_PATH)
server_socket.listen(5)

print("running dpi mock server: {SOCKET_PATH}")
print("return alive always")

response = {
    "result": {
        "ec": "E_OK",
        "error": "",
        "data": {
            "DPI": "alive"
        }
    }
}

response_json = json.dumps(response)

try:
    while True:
        client_connection, _ = server_socket.accept()

        client_connection.recv(4096)

        client_connection.send(response_json.encode('utf-8'))
        client_connection.close()
        print("process a health check request, return alive status")

except KeyboardInterrupt:
    print("stop server")
finally:
    server_socket.close()
