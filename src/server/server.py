import socket
import threading
import os
import logging

# configure logging to write to logs.txt
logging.basicConfig(
    filename="logs.txt",      # log file name
    level=logging.INFO,       # log INFO and higher levels (WARNING, ERROR, etc.)
    format="%(asctime)s - %(message)s"  # log format
)

def log_message(message):
    logging.info(message)  # log the message with a timestamp

def handle_client(client_socket, addr):
    try:
        '''
            The client sends 3 kinds of commands:
            1. UPLOAD <filename> <filesize> <-o>: server receives file from client (programmed by Michael)
            2. DOWNLOAD <filename>: server sends file to client (programmed by Ali)
            3. LIST: server lists files to client (programmed by Michael)
        '''
        # if the client doesn't send anything in 5 seconds, close the socket
        log_message(f"Connection with {addr} established")
        client_socket.settimeout(5)  

        # get the command from the client
        command = client_socket.recv(1024).decode('utf-8')
        parts = command.split()

        # log the command
        log_message(f"{addr} issued the command {command}")

        # get the list of files (will need in UPLOAD and LIST)
        file_list = os.listdir("./files")

        if parts[0] == "UPLOAD":
            # remark: <-o> is an optional flag which means "overwrite"
            # ensure command formatted correctly
            if len(parts) < 3 or (len(parts) == 4 and parts[3] != "-o") or len(parts) > 4:
                client_socket.send("ERROR: Invalid arguments for the UPLOAD command".encode('utf-8'))
                log_message(f"ERROR: {addr} sent an invalid <filesize> argument")
                return

            filename = parts[1] # get <filename>
            try:
                file_size = int(parts[2]) # get <filesize> and convert to int
            except ValueError: # handle invalid <filesize>
                client_socket.send("ERROR: Invalid <filesize> argument".encode('utf-8'))
                log_message(f"Connection with {addr} established.\nCommand: {command}")
                return

            # if overwrite flag is not specified, avoid overwriting
            if (len(parts) == 3):
            # check if filename already exists in our list of files
                if filename in file_list:
                    name, ext = os.path.splitext(filename)  # split filename and extension
                    counter = 1
                    while True:
                        new_name = f"{name}({counter}){ext}"  # append counter before extension
                        if new_name not in file_list: # change filename to new_name to avoid overwriting
                            filename = new_name
                            break
                        counter += 1

            # receive chunks of 1024 bytes at a time, keep track of received amount
            received_size = 0
            # save file into "files" directory
            file_path = os.path.join("files", filename)

            try:
                with open(file_path, "wb") as f:
                    # loop until the full file size is received
                    while received_size < file_size:
                        chunk_size = min(1024, file_size - received_size)
                        chunk = client_socket.recv(chunk_size) # only send necessary amount
                        if not chunk:  # connection lost
                            raise ConnectionError("File transfer interrupted")  
                        # if chunk is complete, write it to file
                        f.write(chunk)
                        received_size += len(chunk) # dynamically update receieved amount

                # send transfer status to client
                if received_size == file_size:
                    client_socket.send(f"SUCCESS: File received as {filename}".encode('utf-8'))
                    log_message(f"SUCCESS: File received as {filename} from {addr}")
                else:
                    raise ConnectionError("File transfer incomplete")  

            except Exception as e:
                if os.path.exists(file_path):  # delete incomplete/corrupted file
                    os.remove(file_path)
                client_socket.send(f"ERROR: {str(e)}".encode('utf-8')) # send the error to client
                log_message(f"ERROR: File transfer with {addr} interrupted")


        elif parts[0] == "DOWNLOAD":
            '''ali's code'''
        
        elif parts[0] == "LIST":
            # send the client a list of files
            files = ""
            # format the list of files by numbering it
            for index, filename in enumerate(file_list, start=1):
                files += f"{index}. {filename}\n"
            client_socket.send(files.encode('utf-8'))
            log_message(f"File list successfully sent to {addr}")

        else:
            client_socket.send("ERROR: Command not recognized by server".encode('utf-8'))
            log_message(f"ERROR: {addr} sent unrecognized command")

    finally:
        # in all cases (even in case of sudden socket closure), close the client socket
        log_message(f"Closing connection with {addr}")
        client_socket.close()


# create a TCP socket that runs on localhost on port 8926
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(("localhost", 8926))
server_socket.listen(5)

print("Server is listening for incoming connections...")

while True:
    client_socket, addr = server_socket.accept()
    print(f"New connection from {addr}")

    # create a new thread for each client
    client_thread = threading.Thread(target=handle_client, args=(client_socket, addr,))
    client_thread.start()  # thread handles client while server listens to other connections
