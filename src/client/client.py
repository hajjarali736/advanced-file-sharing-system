from socket import *
import os
import logging

serverName = '127.0.0.1'
serverPort = 8926  
log_file_path = os.path.join(os.path.dirname(__file__), "logs.txt")

logging.basicConfig(
    filename=log_file_path,      # log file name
    level=logging.INFO,       # log INFO and higher levels (WARNING, ERROR, etc.)
    format="%(asctime)s - %(message)s"  # log format
)

def log_message(message):
    logging.info(message)  # log the message with a timestamp

def upload_file(filename, clientSocket, overwrite):
    try:
        filesize = os.path.getsize(filename) # automates file size by getting size and inform the server
                                        #how much data it should expect(bytes).
        log_message(f"Preparing to upload {filename} of size {filesize} bytes")
        if overwrite:
            clientSocket.send(f"UPLOAD {filename} {filesize} -o".encode())
        else:
            clientSocket.send(f"UPLOAD {filename} {filesize}".encode())
        
        with open(filename, "rb") as f:
            while True:
                chunk = f.read(1024)
                if not chunk:
                    break
                clientSocket.send(chunk) #this block of code reads the file in 1 KB (1024 bytes) chunks 
                                    #and sends each to the server until the whole file is sent.
        
        response = clientSocket.recv(1024).decode()  #for confirmation
        print(response)
        log_message(f"Upload response: {response}")
    
    except Exception as e:
        error_message = f"Upload error: {str(e)}" #handles errors in commands such as a file not found
        print(error_message)
        log_message(error_message)

def download_file(filename, clientSocket):
    try:
        log_message(f"Requesting download for {filename}")
        clientSocket.send(f"DOWNLOAD {filename}".encode()) #sends a message requesting a file from the server
        response = clientSocket.recv(1024).decode() #receives its response(either confirmation+file size or error)
        
        if response.startswith("filesize"):
            filesize = int(response.split()[1])
            log_message(f"File size received: {filesize} bytes")
            clientSocket.send("START".encode())
            
            with open(filename, "wb") as f:
                received = 0
                while received < filesize:
                    chunk = clientSocket.recv(1024)
                    if not chunk:
                        break
                    f.write(chunk)
                    received += len(chunk) #this block of code creates a new file with prefix downloaded_, 
                                        #receives the file in chunks, and writes it to disk.
            success_message = f"Downloaded {filename} successfully"
            print(success_message)
            log_message(success_message)
        else:
            print(response)  # Error message
            log_message(f"Download error: {response}")
    
    except Exception as e:
        error_message = f"Download error: {str(e)}"
        print(error_message)
        log_message(error_message)


clientSocket = socket(AF_INET, SOCK_STREAM)
clientSocket.connect((serverName, serverPort))#connects to the server
log_message(f"Connection with {clientSocket.getpeername()} established")

command = input("Enter command (LIST | UPLOAD filename (optional -o flag) | DOWNLOAD filename | EXIT): ").strip().upper()
#prompts the user for a command and turns it into uppercase(to make it case-insensitive)

if command == "EXIT":
    clientSocket.send(b"EXIT")
    log_message("Sent EXIT command")
    clientSocket.close() #closes the socket (it terminates the client)
    log_message("Connection closed")
    

elif command == "LIST":
    clientSocket.send(b"LIST")
    log_message("Sent LIST command")
    print("Available files:")
    files_list = clientSocket.recv(4096).decode() #asks the server for list of files, it then receives and prints it
    print(files_list)
    log_message("Received file list")

elif command.startswith("UPLOAD "):
    filename = command.split()[1]
    overwrite = False
    if len(command.split()) == 3 and command.split()[2] == "-o":
        overwrite = True
    upload_file(filename, clientSocket, overwrite) #extracts file name ftom the command and calls the upload function

elif command.startswith("DOWNLOAD "):
    filename = command.split()[1]
    download_file(filename, clientSocket) #extracts file name ftom the command and calls the download function

else:
    error_message = "Invalid command. Format:"
    print(error_message)
    print("LIST | UPLOAD filename | DOWNLOAD filename | EXIT") #prints usage info if the command doesn’t match any supported format
    log_message(error_message)

clientSocket.close()
log_message("Connection closed")