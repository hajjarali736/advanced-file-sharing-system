from socket import *

serverName = '127.0.0.1'  # Change this to the actual server IP
serverPort = 12001  # Must match the server's port

clientSocket = socket(AF_INET, SOCK_STREAM)
clientSocket.connect((serverName, serverPort))

while True:
    command = input("Enter command (LIST/UPLOAD filename/DOWNLOAD filename/EXIT): ").strip()
    
    if command.upper() == "EXIT":
        print("Closing connection.")
        clientSocket.close()
        break
    
    clientSocket.send(command.encode())  

    if command.upper() == "LIST":
        response = clientSocket.recv(4096).decode()
        print("Available files:", response)

    elif command.upper().startswith("UPLOAD "):
        filename = command.split(maxsplit=1)[1]
        try:
            file = open(filename, "rb")
            file_size = len(file.read())  #this is for us to get the file size 
            file.seek(0)

            clientSocket.send(f"{file_size}".encode())  #this is for us to receive the size
            ack = clientSocket.recv(1024).decode()

            if ack == "READY":
                while chunk:=file.read(1024):
                    clientSocket.send(chunk)
                print(f"Uploaded '{filename}' successfully.")
            else:
                print("Server refused upload.")

            file.close()
        except FileNotFoundError:
            print(f"File '{filename}' not found.")

    elif command.upper().startswith("DOWNLOAD "):
        response = clientSocket.recv(1024).decode()
        if response.startswith("SIZE"):
            file_size = int(response.split()[1])
            clientSocket.send("READY".encode())  #to acknowledge

            file = open(f"downloaded_{command.split(maxsplit=1)[1]}", "wb")
            received = 0

            while received < file_size:
                chunk = clientSocket.recv(1024)
                if not chunk:
                    break
                file.write(chunk)
                received += len(chunk)

            print(f"Downloaded file successfully.")
            file.close()
        else:
            print("Server response:", response)

    else:
        print("Invalid command.")
