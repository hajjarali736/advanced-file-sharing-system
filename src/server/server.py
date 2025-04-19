import socket
import threading
import os
import logging

# Function to calculate 16-bit checksum of a file
def calculate_checksum(filename):
    checksum = 0
    try:
        with open(filename, "rb") as f:
            while True:
                chunk = f.read(1024)
                if not chunk:
                    break
                # Sum up ASCII values of all bytes in the file
                checksum += sum(chunk)
        # Take modulo 65536 to get 16-bit checksum
        return checksum % 65536
    except Exception as e:
        log_message(f"Error calculating checksum: {str(e)}")
        return None

# configure logging to write to logs.txt
log_file_path = os.path.join(os.path.dirname(__file__), "logs.txt")

logging.basicConfig(
    filename=log_file_path,      # log file name
    level=logging.INFO,       # log INFO and higher levels (WARNING, ERROR, etc.)
    format="%(asctime)s - %(message)s"  # log format
)

def log_message(message):
    logging.info(message)  # log the message with a timestamp

def handle_client(client_socket, addr):
    try:
        '''
            The client sends 3 kinds of commands:
            1. UPLOAD <filename> <filesize> <checksum> <-o>: server receives file from client (programmed by Michael)
            2. DOWNLOAD <filename> [offset]: server sends file to client (programmed by Ali)
            3. LIST: server lists files to client (programmed by Michael)
            4. PAUSE: client requests to pause current download
        '''
        log_message(f"Connection with {addr} established")

        # get the command from the client
        command = client_socket.recv(1024).decode('utf-8')
        parts = command.split()

        # log the command
        log_message(f"{addr} issued the command {command}")

        # get the list of files (will need in UPLOAD and LIST)
        base_path = os.path.dirname(__file__)            # path to server.py
        files_path = os.path.join(base_path, "files")    # path to server/files
        file_list = os.listdir(files_path)

        if parts[0] == "UPLOAD":
            # remark: <-o> is an optional flag which means "overwrite"
            # ensure command formatted correctly
            if len(parts) < 4 or (len(parts) == 5 and parts[4] != "-o") or len(parts) > 5:
                client_socket.send("ERROR: Invalid arguments for the UPLOAD command".encode('utf-8'))
                log_message(f"ERROR: {addr} sent an invalid UPLOAD command")
                return

            filename = parts[1] # get <filename>
            try:
                file_size = int(parts[2]) # get <filesize> and convert to int
                expected_checksum = int(parts[3]) # get <checksum>
            except ValueError: # handle invalid <filesize> or <checksum>
                client_socket.send("ERROR: Invalid <filesize> or <checksum> argument".encode('utf-8'))
                log_message(f"ERROR: {addr} sent invalid <filesize> or <checksum>")
                return

            # if overwrite flag is not specified, avoid overwriting
            if (len(parts) == 4):
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

                # Verify checksum after receiving file
                actual_checksum = calculate_checksum(file_path)
                if actual_checksum == expected_checksum:
                    client_socket.send(f"SUCCESS: File received as {filename} (checksum verified)".encode('utf-8'))
                    log_message(f"SUCCESS: File received as {filename} from {addr} (checksum verified)")
                else:
                    raise ConnectionError("File checksum verification failed")

            except Exception as e:
                if os.path.exists(file_path):  # delete incomplete/corrupted file
                    os.remove(file_path)
                client_socket.send(f"ERROR: {str(e)}".encode('utf-8')) # send the error to client
                log_message(f"ERROR: File transfer with {addr} failed: {str(e)}")

        elif parts[0] == "DOWNLOAD":
            '''ali's code'''
            try:
                # ensure command formatted correctly
                if len(parts) < 2 or len(parts) > 3:
                    client_socket.send("ERROR: Invalid arguments for the DOWNLOAD command".encode('utf-8'))
                    log_message(f"ERROR: {addr} sent an invalid <filename> argument")
                    return

                filename = parts[1] # get <filename>
                offset = int(parts[2]) if len(parts) == 3 else 0 # get offset if provided
                file_path = os.path.join("files", filename)

                if not os.path.exists(file_path):
                    client_socket.send("ERROR: File not found".encode('utf-8'))
                    log_message(f"ERROR: {addr} requested non-existent file {filename}")
                    return

                filesize = os.path.getsize(file_path)
                if offset >= filesize:
                    client_socket.send("ERROR: Invalid offset".encode('utf-8'))
                    log_message(f"ERROR: {addr} sent invalid offset {offset}")
                    return

                checksum = calculate_checksum(file_path)
                if checksum is None:
                    client_socket.send("ERROR: Failed to calculate file checksum".encode('utf-8'))
                    log_message(f"ERROR: Failed to calculate checksum for {filename}")
                    return

                client_socket.send(f"filesize {filesize} {checksum}".encode('utf-8'))
                log_message(f"File size: {filesize} and checksum: {checksum} sent to {addr}")

                client_socket.settimeout(3)
                try:
                    start_signal = client_socket.recv(1024).decode('utf-8')
                    if start_signal != "START":
                        client_socket.send("ERROR: Invalid start signal".encode('utf-8'))
                        log_message(f"ERROR: {addr} sent an invalid start signal")
                        return
                except socket.timeout:
                    client_socket.send("ERROR: Timeout waiting for start signal".encode('utf-8'))
                    log_message(f"ERROR: {addr} timed out waiting for start signal")
                    return

                log_message(f"Client {addr} is ready. Starting file transfer from offset {offset}.")

                counter = 0
                total_sent = offset
                with open(file_path, "rb") as f:
                    f.seek(offset)  # seek to the requested offset
                    # send file in chunks of 1024 bytes
                    while True:
                        chunk = f.read(1024)
                        if not chunk:
                            break
                        #ensures that the full chunk is sent over the socket
                        client_socket.sendall(chunk)
                        total_sent += len(chunk)
                        log_message(f"File chunk {counter} sent to {addr} - Progress: {total_sent / filesize * 100:.2f}%")
                        counter += 1
                log_message(f"SUCCESS: File {filename} successfully sent to {addr}")
            
            except Exception as e:
                client_socket.send(f"ERROR: {str(e)}".encode('utf-8'))
                log_message(f"ERROR: File transfer with {addr} failed: {str(e)}")

        elif parts[0] == "PAUSE":
            log_message(f"Client {addr} requested pause")
            client_socket.send("PAUSE_ACK".encode('utf-8'))
            return

        elif parts[0] == "LIST":
            # send the client a list of files
            files = ""
            # format the list of files by numbering it
            for index, filename in enumerate(file_list, start=1):
                files += f"{index}. {filename}\n"
            client_socket.send(files.encode('utf-8'))
            log_message(f"File list successfully sent to {addr}")

        elif parts[0] == "EXIT":
            return

        else:
            client_socket.send("ERROR: Command not recognized by server".encode('utf-8'))
            log_message(f"ERROR: {addr} sent unrecognized command")

    finally:
        # in all cases (even in case of sudden socket closure), close the client socket
        log_message(f"Closing connection with {addr}")
        print(f"Connection with {addr} closed")
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
