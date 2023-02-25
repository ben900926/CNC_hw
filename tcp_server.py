import socket
import os

IP = socket.gethostbyname(socket.gethostname())
PORT = 8888
ADDR = (IP, PORT)
SIZE = 10240
FORMAT = "utf-8"

def convert_to_bytes(no):
    result = bytearray()
    result.append(no & 255)
    for i in range(3):
        no = no >> 8
        result.append(no & 255)
    return result

def bytes_to_number(b):
    # if Python2.x
    # b = map(ord, b)
    res = 0
    for i in range(4):
        res += b[i] << (i*8)
    return res


def main():
    print("[STARTING] Server is starting.")
    """ Staring a TCP socket. """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
 
    """ Bind the IP and PORT to the server. """
    server.bind(ADDR)
 
    """ Server is listening, i.e., server is now waiting for the client to connected. """
    server.listen()
    print("[LISTENING] Server is listening.")
 
    while True:
        """ Server has accepted the connection from the client. """
        conn, addr = server.accept()
        print(f"[NEW CONNECTION] {addr} connected.")
 
        """ Receiving the filename from the client. """
        filename = conn.recv(SIZE).decode(FORMAT)
        print(f"[RECV] Receiving the filename.")
        file = open(filename, "w")
        #conn.send("Filename received.".encode(FORMAT))
 
        """ Receiving the file data from the client. """
        len = os.path.getsize("sample_file.txt")
        data = conn.recv(len).decode(FORMAT)
        print(f"[RECV] Receiving the file data.")
        file.write(data)
        #conn.send("File data received".encode(FORMAT))
 
        """ Closing the file. """
        file.close()
 
        """ Closing the connection from the client. """
        conn.close()
        print(f"[DISCONNECTED] {addr} disconnected.")
 
if __name__ == "__main__":
    main()