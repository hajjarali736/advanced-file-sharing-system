import socket



def handle_client_commands(client_socket):
    command = input("Enter command: ")
    parts = command.split()

    if parts[0] == "UPLOAD":
        ''' upload command ''''
        if len(parts) < 3 or (len(parts) == 4 and parts[3] != "-o") or len(parts) > 4:
            return

        overwrite = len(parts) == 4 and parts[3] == "-o"
        handle_upload(client_socket, parts[1], parts[2], overwrite)

    elif parts[0] == "DOWNLOAD":
        ''' download command ''''

        handle_download(client_socket. parts[1])

    elif parts[0] == "LIST":
        ''' list command ''''

        handle_list(client_socket)


def handle_upload(client_socket, filename, filesize, overwrite=False):
    ''' upload command ''''
    client_socket.send(f"UPLOAD {filename} {filesize} {overwrite ? -o : ''}".encode('utf-8'))

    try:

def handle_download(client_socket, filename):
    ''' download command ''''

def handle_list(client_socket):
    ''' list command ''''
    


def main():
    # create a TCP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("localhost", 8926))

    handle_client_commands(client_socket)

if __name__ == "__main__":
    main()

