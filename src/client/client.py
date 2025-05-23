from socket import *
import os
import logging
from time import sleep
import hashlib

serverName = '127.0.0.1'
serverPort = 8926  
log_file_path = os.path.join(os.path.dirname(__file__), "logs.txt")

# Global variable to track download state
download_state = None
download_stopped = False
connection_closed = False

# Function  to hash password before sending it to server
def hash_password(password):
    """Client-side password hashing"""
    return hashlib.sha256(password.encode()).hexdigest()



# function to calculate 16-bit checksum of a file
def calculate_checksum(filename):
    checksum = 0
    try:
        with open(filename, "rb") as f:
            while True:
                chunk = f.read(1024)
                if not chunk:
                    break
                # sum up ASCII values of all bytes in the file
                checksum += sum(chunk)
        # take modulo 65536 to get 16-bit checksum
        return checksum % 65536
    except Exception as e:
        log_message(f"Error calculating checksum: {str(e)}")
        return None

logging.basicConfig(
    filename=log_file_path,      # log file name
    level=logging.INFO,       # log INFO and higher levels (WARNING, ERROR, etc.)
    format="%(asctime)s - %(message)s"  # log format
)

def log_message(message):
    logging.info(message)  # log the message with a timestamp

def upload_file(filename, clientSocket, overwrite):
    try:
        # Ensure the file path is relative to the directory of client.py
        file_path = os.path.join(os.path.dirname(__file__), filename)
        filesize = os.path.getsize(file_path) # automates file size by getting size and inform the server
                                        #how much data it should expect(bytes).
        # Calculate checksum before sending
        checksum = calculate_checksum(file_path)
        if checksum is None:
            error_message = "Failed to calculate checksum"
            print(error_message)
            log_message(error_message)
            return

        log_message(f"Preparing to upload {filename} of size {filesize} bytes with checksum {checksum}")
        if overwrite:
            clientSocket.send(f"UPLOAD {filename} {filesize} {checksum} -o".encode())
        else:
            clientSocket.send(f"UPLOAD {filename} {filesize} {checksum}".encode())
        
        with open(file_path, "rb") as f:
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

def save_download_state(filename, offset, total_size, save_path=None):
    """Save the current download state"""
    global download_state
    download_state = {
        "filename": filename,
        "offset": offset,
        "total_size": total_size,
        "save_path": save_path
    }
    log_message(f"Saved download state for {filename} at offset {offset}")

def load_download_state():
    """Load the current download state"""
    global download_state
    return download_state

def clear_download_state():
    """Clear the download state"""
    global download_state
    download_state = None
    log_message("Cleared download state")




def download_file(filename, clientSocket, resume=False):
    global download_stopped
    global connection_closed
    # Ensure the file path is relative to the directory of client.py
    temp_filename = f"{filename}.part"
    file_path = os.path.join(os.path.dirname(__file__), filename)
    temp_path = os.path.join(os.path.dirname(__file__), temp_filename)
    try:
        if resume:
            print(f"resume command: DOWNLOAD {filename} resume")
            if os.path.exists(temp_path):
                offset = os.path.getsize(temp_path)
            else:
                print("no temp file found")
                return
            clientSocket.send(f"DOWNLOAD {filename} resume".encode())
            
        else:
            offset=0#Ranim: I added this to make sure that the offset is defined when not resuming
            #that is, without it, offset would only be defined in the "resume==True" branch
            log_message(f"Requesting download for {filename}")
            clientSocket.send(f"DOWNLOAD {filename}".encode())
        
        response = clientSocket.recv(1024).decode()
        
        if response.startswith("filesize"):
            # Parse filesize and checksum from response
            parts = response.split()
            filesize = int(parts[1])
            expected_checksum = int(parts[2])
            server_offset = int(parts[3]) if len(parts) >= 4 else 0 
            if server_offset != offset:
                print(f"Server offset {server_offset} does not match local offset {offset}")
                return
            log_message(f"File size received: {filesize} bytes, expected checksum: {expected_checksum}")
            
            if not resume:
                save_download_state(filename, 0, filesize, file_path)
            
            clientSocket.send("START".encode())
            
            mode = "ab" if resume else "wb"
            #RANIM: im gonna implement the download logic here:
            received = offset
            with open(temp_path, mode) as f:
                received = offset if resume else 0
                while received < filesize:
                    chunk = clientSocket.recv(1024)
                    if not chunk:
                        break
                    f.write(chunk)
                    received += len(chunk) #this block of code creates a new file with prefix downloaded_, 
                                        #receives the file in chunks, and writes it to disk.                 
                    save_download_state(filename, received, filesize)
                    print(f"Received {received}/{filesize} bytes")
                    print(f"Download progress: {received/float(filesize)*100:.2f}%")

                    action = input("Enter action: CONTINUE/PAUSE/STOP: ").strip().upper()

                    while action != "CONTINUE":
                        if action == "PAUSE":
                            try:
                                clientSocket.send(b"PAUSE")
                            except Exception as e:
                                connection_closed = True
                                print("Connection closed by server.")
                                return
                            print("Download paused. Resume download using CONTINUE.")
                            log_message("Download paused by user.")

                        elif action == "STOP":
                            try:
                                clientSocket.send(b"STOP")
                            except Exception as e:
                                connection_closed = True
                                print("Connection closed by server.")
                                return
                            print("Download stopped by user.")
                            log_message("Download stopped by user.")
                            clientSocket.close()
                            download_stopped = True
                            return
                        
                        elif action != "CONTINUE":
                            print("Invalid action. Please enter CONTINUE to resume download.")
                            log_message("Invalid action entered by user.")
                        
                        action = input("Enter action: CONTINUE/PAUSE/STOP: ").strip().upper()

                    if connection_closed:
                        print("Connection closed by server.")
                        return
                    
                    if action == "CONTINUE":
                        clientSocket.send(b"CONTINUE")
                        continue

            # Verify checksum after download

            actual_checksum = calculate_checksum(temp_path)
            if actual_checksum == expected_checksum:
                os.rename(temp_path, file_path)
                success_message = f"Downloaded {filename} successfully (checksum verified)"
                print(success_message)
                log_message(success_message)
                clear_download_state()
            else:
                error_message = f"Checksum verification failed for {filename}. File may be corrupted."
                print(error_message)
                log_message(error_message)
                os.remove(file_path if file_path else filename)
                log_message(f"Deleted corrupted file: {filename}")
                clear_download_state()
        else:
            print(response)
            log_message(f"Download error: {response}")
    
    except Exception as e:
        error_message = f"Download error: {str(e)}"
        print(error_message)
        log_message(error_message)


def connect_to_server():
    client_socket = socket(AF_INET, SOCK_STREAM)
    client_socket.connect((serverName, serverPort))
    return client_socket


def login(username, password, client_socket):
    try:
        client_socket.send(f"LOGIN {username} {password}".encode())
        response = client_socket.recv(1024).decode()

        if response.startswith("LOGIN_SUCCESS"):
            role = response.split()[1]
            log_message(f"Login successful with role: {role}")
            return True, role
        else:
            log_message("Login failed")
            return False, None

    except Exception as e:
        log_message(f"Login error: {str(e)}")
        return False, None


def view_logs(client_socket):
    try:
        client_socket.send(f"VIEW_LOGS".encode())
        response = client_socket.recv(1024).decode()
        print("the server: " + response)
        if response.startswith("AUTHORIZED"):
            print("Authorized to view logs")
            client_socket.send("START".encode())    

            while True:
                chunk = client_socket.recv(1024)
                if not chunk:
                    break
                print(chunk.decode(),end="")
            print("\nLogs printed successfully.")
            log_message("Logs viewed successfully.")

        else:
            print("Unauthorized view logs attemnpt")
            log_message("Unauthorized view logs attemnpt")
            return
    except Exception as e:
        print(f"Error downloading logs: {str(e)}") 
        log_message(f"Error downloading logs: {str(e)}")

def main():
    clientSocket = socket(AF_INET, SOCK_STREAM)
    clientSocket.connect((serverName, serverPort))#connects to the server
    log_message(f"Connection with {clientSocket.getpeername()} established")

    #login logic:
    username = input("Username: ").strip()
    password = input("Password: ").strip()

    #hash the password before sending it to the server
    password = hash_password(password)
    choice = input("Login or Register (L/R): ").strip().upper()

    if choice == "R":
        clientSocket.send(f"REGISTER {username} {password}".encode())
        response = clientSocket.recv(1024).decode()

        if response.startswith("ERROR:"):
            print("Registration failed. Exiting..")
            log_message("Registration failed")
            clientSocket.close()
            exit()

        response = response.split()
        if response and response[0] == ("REGISTER_SUCCESS"):
            role = response[1]
            print("Registration successful!")
            log_message("Registration successful")
            if role == "admin":
                print("As an admin, you can also use: DELETE <filename>, VIEW_LOGS")
                log_message("Admin privileges granted")

    elif choice == "L":
        clientSocket.send(f"LOGIN {username} {password}".encode())
        response = clientSocket.recv(1024).decode()
        
        if response.startswith("ERROR:"):
            print("Login failed. Exiting..")
            log_message("Login failed")
            clientSocket.close()
            exit()

        response = response.split()
        if response and response[0] == ("LOGIN_SUCCESS"):
            role = response[1]
            print("Login successful!")
            log_message(f"Login successful with role: {role}")
            if role == "admin":
                print("As an admin, you can also use: DELETE <filename>, VIEW_LOGS")
                log_message("Admin privileges granted")
        

    command = input("Enter command (LIST | UPLOAD filename (optional -o flag) | DOWNLOAD filename | PAUSE | RESUME | DELETE filename | EXIT): ").strip()
    #prompts the user for a command and turns it into uppercase(to make it case-insensitive)
    while command != "EXIT" and not download_stopped and not connection_closed:
        if command == "LIST":
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
            if download_stopped or connection_closed:
                break

        elif command.startswith("RESUME"):
            print(command)
            filename = command.split()[1]
            download_file(filename, clientSocket, resume=True) 
            if download_stopped or connection_closed:
                break
            
        elif command.startswith("DELETE "):
            if (role!="admin"):
                print("ERROR: Only admin users can delete files.")
                log_message("Unauthorized delete attempt.")
            else:
                filename=command.split()[1]
                clientSocket.send(f"DELETE {filename}".encode())
                response=clientSocket.recv(1024).decode()
                print(response)
                log_message(f"Delete response: {response}")

        elif command.startswith("VIEW_LOGS"):
            view_logs(clientSocket)

        else:
            error_message = "Invalid command. Format:"
            print(error_message)
            print("LIST | UPLOAD filename | DOWNLOAD filename | EXIT") #prints usage info if the command doesn't match any supported format
            log_message(error_message)

        command = input("Enter command (LIST | UPLOAD filename (optional -o flag) | DOWNLOAD filename | DELETE filename | EXIT): ").strip()

    if command == "EXIT":
        clientSocket.send(b"EXIT")
        log_message("Sent EXIT command")

    clientSocket.close() #closes the socket (it terminates the client)
    log_message("Connection closed")


if __name__ == "__main__":
    main()