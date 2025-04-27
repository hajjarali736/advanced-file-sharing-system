import socket
import threading
import os
import logging

import sqlite3
import hashlib


""" database functions"""

def initialize_db_from_file(sql_file_path):
    conn = connect_db()
    cursor = conn.cursor()

    with open(sql_file_path, 'r') as f:
        sql_script = f.read()

    cursor.executescript(sql_script)

    conn.commit()
    conn.close()


def connect_db():
    conn = sqlite3.connect('user_authentication.db')
    return conn

# Function to create the user table if it doesn't exist
def create_table():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS USER (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE,
                        password TEXT,
                        role TEXT CHECK(role IN ("user", "admin")) NOT NULL)''')
    conn.commit()
    conn.close()



# Function to hash passwords (help by chatgpt)
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Function to register a user (username, password, role)
def register(username, hashed_password, role="user"):
    conn = connect_db()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''INSERT INTO users (username, password_hash, role) 
                          VALUES (?, ?, ?)''', (username, hashed_password, role))
        conn.commit()
        print(f"User {username} registered successfully.")
        return True
    except sqlite3.IntegrityError:
        print("Username already exists.")
        return False
    finally:
        conn.close()

# Function to validate credentials (username, hashed_password)
def validate_credentials(username, received_hash):
    """Validate credentials with client-side hashing"""
    conn = connect_db()
    cursor = conn.cursor()
    
    # Get stored hash from database
    cursor.execute('''SELECT password_hash FROM users WHERE username = ?''', (username,))
    result = cursor.fetchone()
    
    conn.close()
    
    return result and result[0] == received_hash

def user_exists(username):
    """Check if a username exists in the database"""
    conn = connect_db()
    cursor = conn.cursor()
    
    cursor.execute('''SELECT username FROM users WHERE username = ?''', (username,))
    user = cursor.fetchone()
    
    conn.close()
    return user is not None  

def get_user_role(username):
    """Get the role of a user"""
    conn = connect_db()
    cursor = conn.cursor()
    
    cursor.execute('''SELECT role FROM users WHERE username = ?''', (username,))
    result = cursor.fetchone()
    
    conn.close()
    
    return result[0] if result else None

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
        login_message = client_socket.recv(1024).decode().strip()

        if login_message.startswith("LOGIN"):
            log_message(f"{addr} sent login attempt: {login_message}")
            parts = login_message.split()
            if len(parts) != 3:
                client_socket.send("ERROR: Invalid login format. Use LOGIN <username> <password>".encode())
                log_message(f"{addr} failed login: Invalid format")
                return
            
            username, password = parts[1], parts[2]
            # Check if the user exists in the database
            if not user_exists(username):
                client_socket.send("ERROR: User does not exist".encode())
                log_message(f"{addr} failed login: User {username} does not exist")
                return
            
            if not validate_credentials(username, password):
                client_socket.send("ERROR: Invalid credentials".encode())
                log_message(f"{addr} failed login: Invalid credentials for {username}")
                return
            
            role = get_user_role(username)
            client_socket.send(f"LOGIN_SUCCESS {role}".encode())
            log_message(f"{addr} authenticated as {username} successfully")

        elif login_message.startswith("REGISTER"):
            log_message(f"{addr} sent registration attempt: {login_message}")
            parts = login_message.split()
            if len(parts) != 3:
                client_socket.send("ERROR: Invalid registration format. Use REGISTER <username> <password>".encode())
                log_message(f"{addr} failed registration: Invalid format")
                return
            
            username, password = parts[1], parts[2]
            
            if register(username, password):
                client_socket.send("REGISTRATION_SUCCESS user".encode())
                log_message(f"{addr} registered as {username} with role User")
            else:
                client_socket.send("ERROR: Registration failed".encode())
                log_message(f"{addr} failed registration for {username}")

        else:
            client_socket.send("ERROR: You must login first using LOGIN <username> <password>".encode())
            log_message(f"{addr} failed to login: No LOGIN command")
            return

        # get the command from the client
        command = client_socket.recv(1024).decode('utf-8')
        parts = command.split()

        # log the command
        log_message(f"{addr} issued the command {command}")

        # get the list of files (will need in UPLOAD and LIST)
        base_path = os.path.dirname(__file__)            # path to server.py
        files_path = os.path.join(base_path, "files")    # path to server/files
        file_list = os.listdir(files_path)

        while len(parts) > 0 and parts[0] != "EXIT":
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
                # Ensure the file is saved in the correct directory relative to server.py
                file_path = os.path.join(files_path, filename)

                try:
                    with open(file_path, "wb") as f:
                        # Loop until the full file size is received
                        while received_size < file_size:
                            chunk_size = min(1024, file_size - received_size)
                            chunk = client_socket.recv(chunk_size)  # Only receive the necessary amount
                            if not chunk:  # Connection lost
                                raise ConnectionError("File transfer interrupted")
                            # Write the received chunk to the file
                            f.write(chunk)
                            received_size += len(chunk)  # Dynamically update the received amount

                    # Verify checksum after receiving the file
                    actual_checksum = calculate_checksum(file_path)
                    if actual_checksum == expected_checksum:
                        client_socket.send(f"SUCCESS: File received as {filename} (checksum verified)".encode('utf-8'))
                        log_message(f"SUCCESS: File received as {filename} from {addr} (checksum verified)")
                    else:
                        raise ConnectionError("File checksum verification failed")

                except Exception as e:
                    if os.path.exists(file_path):  # Delete incomplete/corrupted file
                        os.remove(file_path)
                    client_socket.send(f"ERROR: {str(e)}".encode('utf-8'))  # Send the error to the client
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

                    #if not os.path.exists(file_path):
                    # Perform case-insensitive file matching
                    matched_file = next((f for f in file_list if f.lower() == filename.lower()), None)
                    if not matched_file:
                        client_socket.send("ERROR: File not found".encode('utf-8'))
                        log_message(f"ERROR: {addr} requested non-existent file {filename}")
                        return

                    file_path = os.path.join(files_path, matched_file)

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
                    
                    #Ranim's code
                    with open(file_path,"rb") as f:
                        f.seek(offset)
                        total_sent=offset
                        counter=0

                        while total_sent<filesize:
                            chunk=f.read(1024)
                            if not chunk:
                                break

                            client_socket.sendall(chunk)
                            total_sent+=len(chunk)
                            log_message(f"Sent chunk {counter} to {addr}. Progress: {total_sent/filesize*100:.2f}%")
                            counter+=1

                            #now lets see what the client responds with, we'll give them 30 seconds max, else we terminate
                            client_socket.settimeout(30)
                            try:
                                response = client_socket.recv(1024).decode().strip().upper()
                            except socket.timeout:
                                log_message(f"Timeout:No response from {addr} after chunk {counter}. Aborting this transfer.")
                                return
                            #if the cliet replies with a continue it'll send the next chumk
                            while response != "CONTINUE":
                                if response == "PAUSE":
                                    log_message(f"Download paused by{addr}. Waiting up to 30 seconds to resume..")
                                    client_socket.settimeout(30)
                                elif response == "STOP":
                                    log_message(f"Client{addr} stopped the download.")
                                    return
                                try:
                                    response = client_socket.recv(1024).decode().strip().upper()
                                except socket.timeout:
                                    log_message(f"Timeout:No response from {addr} after chunk {counter}. Aborting this transfer.")
                                    return

                            if response == "CONTINUE":
                                log_message(f"Client {addr} requested to continue download after chunk {counter}.")
                                continue

                    log_message(f"SUCCESS: File {filename} successfully sent to {addr}")
                
                except Exception as e:
                    client_socket.send(f"ERROR: {str(e)}".encode('utf-8'))
                    log_message(f"ERROR: File transfer with {addr} failed: {str(e)}")

            elif parts[0] == "LIST":
                # send the client a list of files
                files = ""
                # format the list of files by numbering it
                for index, filename in enumerate(file_list, start=1):
                    files += f"{index}. {filename}\n"
                client_socket.send(files.encode('utf-8'))
                log_message(f"File list successfully sent to {addr}")
            
            elif parts[0]=="DELETE":
                if (role!="admin"):
                    client_socket.send("ERROR: Only admin users can delete files".encode())
                    log_message(f"Unauthorized Delete attempt by {username}from{addr}")
                    return 
                
                if (len(parts)!=2):
                    client_socket.send("ERROR: DELETE command requires a filename".encode())
                    return 
                
                filename=parts[1]
                # Get the absolute path to the "files" directory at the project root
                file_path = os.path.join(os.path.dirname(__file__), "files", filename)

                print(f"Attempting to delete file: {file_path}")

                if (os.path.exists(file_path)):
                    os.remove(file_path)
                    client_socket.send(f"SUCCESS: Deleted {filename}".encode())
                    log_message(f"Admin {username} deleted file {filename}")

                else:
                    client_socket.send("ERROR: File not found".encode())

            elif parts[0] == "EXIT":
                return

            else:
                client_socket.send("ERROR: Command not recognized by server".encode('utf-8'))
                log_message(f"ERROR: {addr} sent unrecognized command")

            command = client_socket.recv(1024).decode('utf-8')
            parts = command.split()
            file_list = os.listdir(files_path)


            # log the command
            log_message(f"{addr} issued the command {command}")

    finally:
        # in all cases (even in case of sudden socket closure), close the client socket
        log_message(f"Closing connection with {addr}")
        print(f"Connection with {addr} closed")
        client_socket.close()

# create a TCP socket that runs on localhost on port 8926
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(("localhost", 8926))
server_socket.listen(5)

sql_file_path = os.path.join(os.path.dirname(__file__), '..', '..', 'files', 'Database.sql')
initialize_db_from_file(sql_file_path)

print("Server is listening for incoming connections...")
create_table()
while True:
    client_socket, addr = server_socket.accept()
    print(f"New connection from {addr}")

    # create a new thread for each client
    client_thread = threading.Thread(target=handle_client, args=(client_socket, addr,))
    client_thread.start()  # thread handles client while server listens to other connections
