import socket
import os # get file size 
IP = socket.gethostbyname(socket.gethostname())
PORT = 8888
ADDR = (IP, PORT)
FORMAT = "utf-8"
SIZE = 10240

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
    """ Staring a TCP socket. """
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
 
    """ Connecting to the server. """
    client.connect(ADDR)
 
    """ Opening and reading the file data. """
    file = open("sample_file.txt", "r")
    data = file.read()
 
    """ Sending the filename to the server. """
    client.send("yt.txt".encode(FORMAT))
    #msg = client.recv(SIZE).decode(FORMAT)
    #print(f"[SERVER]: {msg}")
 
    """ Sending the file data to the server. """
    len = os.path.getsize("sample_file.txt")
    print("size: ", len)
    client.send(data.encode(FORMAT))
    #msg = client.recv(len).decode(FORMAT)
    #print(f"[SERVER]: {msg}")
 
    """ Closing the file. """
    file.close()
 
    """ Closing the connection from the server. """
    client.close()
 
 
if __name__ == "__main__":
    main()