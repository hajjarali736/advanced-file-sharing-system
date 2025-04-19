from socket import *
import os
import logging

serverName = '127.0.0.1'
serverPort = 8926  
log_file_path = os.path.join(os.path.dirname(__file__), "logs.txt")

# Global variable to track download state
download_state = None

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
        # Calculate checksum before sending
        checksum = calculate_checksum(filename)
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

def save_download_state(filename, offset, total_size):
    """Save the current download state"""
    global download_state
    download_state = {
        "filename": filename,
        "offset": offset,
        "total_size": total_size
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
    try:
        if resume:
            state = load_download_state()
            if not state or state["filename"] != filename:
                print("No valid download state found for this file")
                return
            offset = state["offset"]
            total_size = state["total_size"]
            log_message(f"Resuming download of {filename} from offset {offset}")
            clientSocket.send(f"DOWNLOAD {filename} {offset}".encode())
        else:
            log_message(f"Requesting download for {filename}")
            clientSocket.send(f"DOWNLOAD {filename}".encode())
        
        response = clientSocket.recv(1024).decode() #receives its response(either confirmation+file size or error)
        
        if response.startswith("filesize"):
            # Parse filesize and checksum from response
            parts = response.split()
            filesize = int(parts[1])
            expected_checksum = int(parts[2])
            log_message(f"File size received: {filesize} bytes, expected checksum: {expected_checksum}")
            
            if not resume:
                save_download_state(filename, 0, filesize)
            
            clientSocket.send("START".encode())
            
            mode = "ab" if resume else "wb"
            with open(filename, mode) as f:
                received = offset if resume else 0
                while received < filesize:
                    chunk = clientSocket.recv(1024)
                    if not chunk:
                        break
                    f.write(chunk)
                    received += len(chunk) #this block of code creates a new file with prefix downloaded_, 
                                        #receives the file in chunks, and writes it to disk.
                    save_download_state(filename, received, filesize)
            # Verify checksum after download
            actual_checksum = calculate_checksum(filename)
            if actual_checksum == expected_checksum:
                success_message = f"Downloaded {filename} successfully (checksum verified)"
                print(success_message)
                log_message(success_message)
                clear_download_state()
            else:
                error_message = f"Checksum verification failed for {filename}. File may be corrupted."
                print(error_message)
                log_message(error_message)
                # Delete corrupted file
                os.remove(filename)
                log_message(f"Deleted corrupted file: {filename}")
                clear_download_state()
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

command = input("Enter command (LIST | UPLOAD filename (optional -o flag) | DOWNLOAD filename | PAUSE | RESUME | EXIT): ").strip().upper()
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

elif command == "PAUSE":
    state = load_download_state()
    if state:
        print(f"Download paused: {state['filename']} at {state['offset']}/{state['total_size']} bytes")
        clientSocket.send(b"PAUSE")
        log_message("Sent PAUSE command")
    else:
        print("No active download to pause")

elif command == "RESUME":
    state = load_download_state()
    if state:
        print(f"Resuming download: {state['filename']} from {state['offset']}/{state['total_size']} bytes")
        download_file(state['filename'], clientSocket, resume=True)
    else:
        print("No paused download to resume")

else:
    error_message = "Invalid command. Format:"
    print(error_message)
    print("LIST | UPLOAD filename | DOWNLOAD filename | PAUSE | RESUME | EXIT") #prints usage info if the command doesn't match any supported format
    log_message(error_message)

clientSocket.close()
log_message("Connection closed")