#!/usr/bin/python3

def connect_scan(address, ports):
    import socket
    from contextlib import closing

    for port in ports:
        try:
            with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
                s.connect((address, port))
                print(f"connection on port {port} succedded")
        except ConnectionRefusedError:
            pass
if __name__ == "__main__":
    connect_scan("192.168.1.159", range(65535))
