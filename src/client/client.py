#test test
from socket import *
import os

serverName = '127.0.0.1'
serverPort = 8926  

def upload_file(filename, clientSocket):
    try:
        filesize = os.path.getsize(filename)
        clientSocket.send(f"UPLOAD {filename} {filesize}".encode())
        
        with open(filename, "rb") as f:
            while True:
                chunk = f.read(1024)
                if not chunk:
                    break
                clientSocket.send(chunk)
        
        print(clientSocket.recv(1024).decode())  
    
    except Exception as e:
        print(f"Upload error: {str(e)}")

def download_file(filename, clientSocket):
    try:
        clientSocket.send(f"DOWNLOAD {filename}".encode())
        response = clientSocket.recv(1024).decode()
        
        if response.startswith("filesize"):
            filesize = int(response.split()[1])
            clientSocket.send("START".encode())
            
            with open(f"downloaded_{filename}", "wb") as f:
                received = 0
                while received < filesize:
                    chunk = clientSocket.recv(1024)
                    if not chunk:
                        break
                    f.write(chunk)
                    received += len(chunk)
            print(f"Downloaded {filename} successfully")
        else:
            print(response)  # Error message
    
    except Exception as e:
        print(f"Download error: {str(e)}")

while True:
    clientSocket = socket(AF_INET, SOCK_STREAM)
    clientSocket.connect((serverName, serverPort))
    
    
    command = input("Enter command (LIST/UPLOAD filename/DOWNLOAD filename/EXIT): ").strip().upper()
    
    if command == "EXIT":
        clientSocket.close()
        break
    
    elif command == "LIST":
        clientSocket.send(b"LIST")
        print("Available files:")
        print(clientSocket.recv(4096).decode())
    
    elif command.startswith("UPLOAD "):
        filename = command.split()[1]
        upload_file(filename, clientSocket)
    
    elif command.startswith("DOWNLOAD "):
        filename = command.split()[1]
        download_file(filename, clientSocket)
    
    else:
        print("Invalid command. Format:")
        print("LIST | UPLOAD filename | DOWNLOAD filename | EXIT")
    
    clientSocket.close()