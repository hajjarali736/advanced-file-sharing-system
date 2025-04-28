# Computer Networks File Sharing System

This is the first phase of the file sharing client server system for the computer networks course. The current progress made in this phase satisfies the connectivity requirements requested for the first phase. This README file is written by Michael Kolanjian.  
The file structure is broken down into **client** and **server** folders. The **server** folder contains all the files related to the server, while the **client** folder contains all the files related to the client, as well as some txt files for testing.

# How to Run:

Open the advanced-file-sharing-system directory, go to src/server/server.py and hit run, then go to src/client/client.py and hit run. This will cause the system to run on the terminal.
Remark: Please refer to the Technical Report instead of the below information since it is outdated.

## Team Members:

- Michael Kolanjian  
- Ranim Ibrahim  
- Ali El Hajjar  

## Resources Used:

We admit to working in reference to ChatGPT (for debugging and assistance when stuck) as well as the following GitHub project <https://github.com/nikhilroxtomar/Multithreaded-File-Transfer-using-TCP-Socket-in-Python>.  

## Progress Made:

In the first phase, we only focused on the below core requirements:  

### Client-Server Architecture:

- The server is always running, and supports multiple clients through multithreading.
- The clients have access to 4 commands: UPLOAD, DOWNLOAD, LIST, and EXIT.

### File Operations:

- Clients have access to 4 commands:
    - **UPLOAD**: The **UPLOAD** command has the *UPLOAD filename filesize -o* structure, where **filename** represents the name of the file, **filesize** represents the size of the file, and **-o** is an optional flag that when present asks the server to overwrite the file if it is present in its list of files. The **UPLOAD** command uploads a file from the client to the server. In case the file already exists and the client did not specify the overwrite **-o** flag, the file gets duplicated in the server's file list, with a counter representing the number of times the file is duplicated.

    - **DOWNLOAD**: The **DOWNLOAD** command has the *DOWNLOAD filename* structure, where **filename** represents the name of the file. The **DOWNLOAD** command downloads a file from the server to the client. In other words, the client requests a file from the server and saves it in its own file folder. The client does not handle duplicate files, and overwrites a file in case it is found in the client's files folder.

    - **LIST**: The **LIST** command has the *LIST* structure. The client requests the list of available files from the server.

    - **EXIT**: The **EXIT** command has the *EXIT* structure. The client informs the server that it is closing the connection, and closes the connection.

### Network Communication (Sockets):

- We made use of TCP sockets to ensure reliable file transfer between client and server.
- We implemented a custom file transfer protocol which works as such for each of the commands:
    - UPLOAD: After the TCP connection is established, the client issues the UPLOAD command, the server receives the command, processes it, and continues to receive the file in 1024 byte chunks from the client. At the end of the file transfer, the server sends a success message to the client informing the client of the name which the uploaded file is saved under, and the connection is closed.
    
    - DOWNLOAD: After the TCP connection is established, the client sends the DOWNLOAD command. The server receives the command, processes it, and in case of error sends an error message. If the command is valid, the server will send the client the file size. After the client receives the file size, the client sends a START signal to the server to signal that it is ready to begin receiving the file. When the server receives the START signal, it will begin sending the file in 1024 byte chunks. At the end of the transfer, the connection is closed.

    - LIST: After the TCP connection is established, the client sends the LIST command. The server receives the command, creates a string containing the list of available files in the server's file folder, sends this command to the client, and closes the connection.

    - EXIT: After the TCP connection is established, the client sends the EXIT command. The server receives the command and closes the connection.

### File Integrity Checking:

We have not yet implemented any file integrity checking yet.

### File Duplicates:

We have only implemented file duplication at the server side through the UPLOAD command. When the server receives a duplicate file, it checks for an overwrite **-o** flag which signals to the server to overwrite the duplicate file. If the overwrite flag is not present, the server will start a counter and loop across its files folder to assign a unique name for the duplicate file using the counter.  
For example: file.txt, file(1).txt, file(2).txt

### Logging System:

We have only implemented logging at the server side at the moment. The server logs connections, their closures, commands, errors, and command execution status. The server also logs the timestamps along with these messages.

## Split of Work:  

The work was split evenly on the three team members. Below is what each team member contributed to the project:  

### Michael's Contribution:

Michael has worked on implementing the server logging mechanism, the basic multithreaded server skeleton, and the UPLOAD and LIST commands. Michael thoroughly documented his code with descriptive line-by-line comments which highlight the functionality of his code. To avoid repetition, I will not repeat the explanation in the code comments.

### Ranim's Contribution:

Ranim has worked on implementing the whole client code. The following is an explanation from Ranim regarding the functionality of her code:  
This client side program uses socket programming to communicate with a server and provides three main functionalities: listing files, uploading files, downloading files, in addition to the option of exiting the application. Upon execution, the client enters a loop where it waits for the user to input a command. Depending on the command entered, the client establishes a TCP connection with the server running on 127.0.0.1 at port 8926. If the user enters LIST, the client sends the corresponding request and displays the list of available files received from the server. For the UPLOAD *filename* command, the client first checks if the specified file exists locally, sends the file name and its size to the server, and then transmits the file in binary chunks of 1024 bytes. When the user enters DOWNLOAD *filename*, the client requests the file, waits for the server to respond with the file size, acknowledges with a "START" message, and then begins receiving the file in chunks until the entire file is downloaded and saved locally with a "downloaded_" prefix. If the user types EXIT, the client closes the socket connection and exits the loop, ending the program. Each operation is wrapped in exception handling to catch and display any errors related to file I/O or network communication. Additionally, every command starts with a new connection and ends by closing it, making the client stateless between operations.

### Ali's Contribution:

Ali worked on testing the proper functionality and connectivity of the server and client, and worked on implementing the DOWNLOAD command in the server. His code first validates the structure of the DOWNLOAD command, and sends an error in case of invalidity. Then the server checks for the presence of the requested file, and sends a File not found error to the client in case it is not present. Then the server will send the file size to the client, and await for its START signal. Upon receiving the START signal, the server will send the file in 1024 byte chunks. The connection is closed at the end of the file transfer