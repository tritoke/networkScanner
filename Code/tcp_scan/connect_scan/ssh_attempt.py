#!/usr/bin/python3
from contextlib import closing
import socket
LOCAL_IP = "192.168.1.159"
PORT = 22

address = ("127.0.0.1", 22)

with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
    try:
        s.connect(address)
        print(f"connection on port {PORT} succedded")
    except ConnectionRefusedError:
        print(f"print port {PORT} is closed")

