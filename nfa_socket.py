import sys
import socket

def connect(addr='/var/run/netifyd/netifyd.sock', port=None):
    if port is None:
        sd = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    else:
        sd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        if port is None:
            sd.connect(addr)
        else:
            sd.connect(addr, port)
    except socket.error as e:
        print("Error connecting to: %s: %s" %(addr, e.strerror))
        return None

    print("Connected to: %s" %(addr))

    return sd
