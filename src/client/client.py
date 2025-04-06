#test test
from socket import *
import os

serverName = '127.0.0.1'
serverPort = 8926  

def upload_file(filename, clientSocket):
    try:
        filesize = os.path.getsize(filename) # automates file size by getting size and inform the server
                                        #how much data it should expect(bytes).
        
        clientSocket.send(f"UPLOAD {filename} {filesize}".encode())
        
        with open(filename, "rb") as f:
            while True:
                chunk = f.read(1024)
                if not chunk:
                    break
                clientSocket.send(chunk) #this block of code reads the file in 1 KB (1024 bytes) chunks 
                                    #and sends each to the server until the whole file is sent.
        
        print(clientSocket.recv(1024).decode())  #for confirmation
    
    except Exception as e:
        print(f"Upload error: {str(e)}")#handles errors in commands such as a file not found

def download_file(filename, clientSocket):
    try:
        clientSocket.send(f"DOWNLOAD {filename}".encode())#sends a message requesting a file from the server
        response = clientSocket.recv(1024).decode()#receives its response(either confirmation+file size or error)
        
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
                    received += len(chunk)#this block of code creates a new file with prefix downloaded_, 
                                        #receives the file in chunks, and writes it to disk.

            print(f"Downloaded {filename} successfully") 
        else:
            print(response)  
    
    except Exception as e:
        print(f"Download error: {str(e)}")

while True: #runs until the user exits
    clientSocket = socket(AF_INET, SOCK_STREAM)
    clientSocket.connect((serverName, serverPort))#connects to the server
    
    
    command = input("Enter command (LIST/UPLOAD filename/DOWNLOAD filename/EXIT): ").strip().upper()
    #prompts the user for a command and turns it into uppercase(to make it case-insensitive)
    
    if command == "EXIT":
        clientSocket.close()
        break #closes the socket and exits the loop(it terminates the client)
    
    elif command == "LIST":
        clientSocket.send(b"LIST")
        print("Available files:")
        print(clientSocket.recv(4096).decode()) #asks the server for list of files, it then receives and prints it
    
    elif command.startswith("UPLOAD "):
        filename = command.split()[1]
        upload_file(filename, clientSocket) #extracts file name ftom the command and calls the upload function
    
    elif command.startswith("DOWNLOAD "):
        filename = command.split()[1]
        download_file(filename, clientSocket)#extracts file name ftom the command and calls the download function
    
    else:
        print("Invalid command. Format:")
        print("LIST | UPLOAD filename | DOWNLOAD filename | EXIT") #prints usage info if the command doesn’t match any supported format
    
    clientSocket.close()