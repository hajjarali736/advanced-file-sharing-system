import sys
import os

current_dir = os.path.dirname(__file__)
client_dir = os.path.abspath(os.path.join(current_dir, '..', '..', '..'))
sys.path.insert(0, client_dir)
from client import (
    upload_file,
    download_file,
    save_download_state,
    load_download_state,
    login,
    connect_to_server,
    clear_download_state,
    calculate_checksum,
    hash_password,
    log_message
)

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import socket
import hashlib
import logging
from pathlib import Path

# Server connection settings
SERVER_NAME = '127.0.0.1'
SERVER_PORT = 8926

# Global variables
download_state = None
is_downloading = False

class LoginWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("File Transfer Client - Login")
        self.geometry("500x400")
        self.configure(bg="#f0f0f0")
        self.resizable(False, False)
        
        self.create_widgets()
        
    def create_widgets(self):
        # Main frame
        main_frame = tk.Frame(self, bg="#f0f0f0", padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = tk.Label(main_frame, text="File Transfer Client", 
                              font=("Arial", 24, "bold"), bg="#f0f0f0")
        title_label.pack(pady=(0, 30))
        
        # Username
        username_label = tk.Label(main_frame, text="Username:", 
                                 font=("Arial", 12), bg="#f0f0f0", anchor="w")
        username_label.pack(fill=tk.X)
        
        self.username_entry = tk.Entry(main_frame, font=("Arial", 12), bd=2)
        self.username_entry.pack(fill=tk.X, pady=(0, 15))
        
        # Password
        password_label = tk.Label(main_frame, text="Password:", 
                                 font=("Arial", 12), bg="#f0f0f0", anchor="w")
        password_label.pack(fill=tk.X)
        
        self.password_entry = tk.Entry(main_frame, font=("Arial", 12), bd=2, show="•")
        self.password_entry.pack(fill=tk.X, pady=(0, 20))
        
        # Buttons
        buttons_frame = tk.Frame(main_frame, bg="#f0f0f0")
        buttons_frame.pack(fill=tk.X, pady=10)
        
        self.login_button = tk.Button(buttons_frame, text="Login", font=("Arial", 12),
                                     bg="#4CAF50", fg="white", width=10, command=self.login)
        self.login_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.register_button = tk.Button(buttons_frame, text="Register", font=("Arial", 12),
                                        bg="#2196F3", fg="white", width=10, command=self.register)
        self.register_button.pack(side=tk.LEFT)
        
        # Status
        self.status_label = tk.Label(main_frame, text="", font=("Arial", 10), 
                                    fg="red", bg="#f0f0f0")
        self.status_label.pack(pady=10)
    
    def login(self):
        """Handle login"""
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not username or not password:
            self.status_label.config(text="Please enter both username and password")
            return
        
        try:
            # Connect to server
            sock = connect_to_server()
            if not sock:
                self.status_label.config(text="Failed to connect to server")
                return
            
            # Hash the password before login
            hashed_password = hash_password(password)
            
            # Try to login
            success, role = login(username, hashed_password, sock)
            
            if success:
                messagebox.showinfo("Login Success", f"Welcome, {username}!")
                self.withdraw()  # Hide login window
                app = MainWindow(sock, username, role)
                app.protocol("WM_DELETE_WINDOW", lambda: self.on_main_close(app))
                app.mainloop()
            else:
                self.status_label.config(text="Login failed. Check credentials.")
                sock.close()
        
        except Exception as e:
            self.status_label.config(text=f"Error: {str(e)}")
            log_message(f"Login error: {str(e)}")
    
    def register(self):
        """Handle registration"""
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not username or not password:
            self.status_label.config(text="Please enter both username and password")
            return
        
        try:
            # Connect to server
            sock = connect_to_server()
            if not sock:
                self.status_label.config(text="Failed to connect to server")
                return
            
            # Hash the password
            hashed_password = hash_password(password)
            
            # Send register request
            sock.send(f"REGISTER {username} {hashed_password}".encode())
            response = sock.recv(1024).decode()
            
            if response.startswith("REGISTER_SUCCESS"):
                self.status_label.config(text="Registration successful! You can now login.", fg="green")
                log_message(f"Registration successful for user: {username}")
            else:
                self.status_label.config(text="Registration failed. Username may already exist.")
                log_message("Registration failed")
            
            sock.close()
        
        except Exception as e:
            self.status_label.config(text=f"Error: {str(e)}")
            log_message(f"Registration error: {str(e)}")
    
    def on_main_close(self, main_window):
        """Handle main window close"""
        main_window.destroy()
        self.deiconify()  # Show login window again

class LogViewerWindow(tk.Toplevel):
    def __init__(self, parent, logs_content):
        super().__init__(parent)
        self.title("Server Logs")
        self.geometry("800x600")
        self.configure(bg="white")
        
        # Create text widget
        self.text_widget = tk.Text(self, wrap=tk.WORD, font=("Courier", 10))
        self.text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Add scrollbar
        scrollbar = tk.Scrollbar(self.text_widget)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.text_widget.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.text_widget.yview)
        
        # Insert logs content
        self.text_widget.insert(tk.END, logs_content)
        self.text_widget.config(state=tk.DISABLED)  # Make read-only
        
        # Close button
        close_button = tk.Button(self, text="Close", command=self.destroy,
                               bg="#F44336", fg="white", font=("Arial", 10))
        close_button.pack(pady=10)

class MainWindow(tk.Toplevel):
    def __init__(self, client_socket, username, role):
        super().__init__()
        self.title(f"File Transfer Client - {username}")
        self.geometry("800x600")
        self.configure(bg="#f0f0f0")
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        
        self.client_socket = client_socket
        self.username = username
        self.role = role
        
        self.create_widgets()
        self.refresh_files()
    
    def create_widgets(self):
        # Main frame
        main_frame = tk.Frame(self, bg="#f0f0f0", padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # User info
        user_frame = tk.Frame(main_frame, bg="#f0f0f0")
        user_frame.pack(fill=tk.X, pady=(0, 10))
        
        user_label = tk.Label(user_frame, text=f"Logged in as: {self.username}", 
                             font=("Arial", 12, "bold"), bg="#f0f0f0")
        user_label.pack(side=tk.LEFT)
        
        if self.role == "admin":
            role_label = tk.Label(user_frame, text=" (Admin)", 
                                 font=("Arial", 12), bg="#f0f0f0")
            role_label.pack(side=tk.LEFT)
            
            # Add View Logs button for admin
            view_logs_button = tk.Button(user_frame, text="View Logs", 
                                       font=("Arial", 10), bg="#673AB7", fg="white",
                                       command=self.view_logs)
            view_logs_button.pack(side=tk.RIGHT)
        
        # Buttons
        buttons_frame = tk.Frame(main_frame, bg="#f0f0f0")
        buttons_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.refresh_button = tk.Button(buttons_frame, text="Refresh", font=("Arial", 10),
                                       bg="#2196F3", fg="white", command=self.refresh_files)
        self.refresh_button.pack(side=tk.LEFT, padx=(0, 5))
        
        self.upload_button = tk.Button(buttons_frame, text="Upload File", font=("Arial", 10),
                                      bg="#4CAF50", fg="white", command=self.upload_file)
        self.upload_button.pack(side=tk.LEFT, padx=5)
        
        self.download_button = tk.Button(buttons_frame, text="Download File", font=("Arial", 10),
                                        bg="#FF9800", fg="white", command=self.download_file)
        self.download_button.pack(side=tk.LEFT, padx=5)
        
        # Add Delete button for admin
        if self.role == "admin":
            self.delete_button = tk.Button(buttons_frame, text="Delete File", font=("Arial", 10),
                                         bg="#F44336", fg="white", command=self.delete_file)
            self.delete_button.pack(side=tk.LEFT, padx=5)
        
        self.pause_button = tk.Button(buttons_frame, text="Pause", font=("Arial", 10),
                                     bg="#9C27B0", fg="white", command=self.pause_transfer, state=tk.DISABLED)
        self.pause_button.pack(side=tk.LEFT, padx=5)
        
        self.resume_button = tk.Button(buttons_frame, text="Resume", font=("Arial", 10),
                                      bg="#009688", fg="white", command=self.resume_transfer, state=tk.DISABLED)
        self.resume_button.pack(side=tk.LEFT, padx=5)
        
        self.logout_button = tk.Button(buttons_frame, text="Logout", font=("Arial", 10),
                                      bg="#F44336", fg="white", command=self.logout)
        self.logout_button.pack(side=tk.LEFT, padx=5)
        
        # Files list frame
        files_frame = tk.LabelFrame(main_frame, text="Available Files", bg="#f0f0f0", padx=10, pady=10)
        files_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Files listbox with scrollbar
        self.files_listbox = tk.Listbox(files_frame, font=("Arial", 12), bd=2, 
                                       selectbackground="#2196F3", selectforeground="white")
        self.files_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = tk.Scrollbar(files_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.files_listbox.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.files_listbox.yview)
        
        # Progress frame
        progress_frame = tk.LabelFrame(main_frame, text="Transfer Progress", bg="#f0f0f0", padx=10, pady=10)
        progress_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_var.set(0)  # Initialize to 0
        
        self.progress_bar = ttk.Progressbar(progress_frame, orient=tk.HORIZONTAL, 
                                           length=100, mode='determinate', 
                                           variable=self.progress_var)
        self.progress_bar.pack(fill=tk.X, pady=(0, 5))
        
        # Progress percentage
        progress_info_frame = tk.Frame(progress_frame, bg="#f0f0f0")
        progress_info_frame.pack(fill=tk.X)
        
        self.progress_label = tk.Label(progress_info_frame, text="0%", 
                                      font=("Arial", 10), bg="#f0f0f0")
        self.progress_label.pack(side=tk.LEFT)
        
        # Status
        status_frame = tk.Frame(main_frame, bg="#f0f0f0")
        status_frame.pack(fill=tk.X)
        
        self.status_label = tk.Label(status_frame, text="Ready", 
                                    font=("Arial", 10), bg="#f0f0f0")
        self.status_label.pack(side=tk.LEFT)
    
    def update_progress_bar(self, progress):
        """Update the progress bar from any thread"""
        self.progress_var.set(progress)
        self.progress_label.config(text=f"{progress}%")
    
    def refresh_files(self):
        """Refresh the file list"""
        try:
            self.client_socket.send(b"LIST")
            data = self.client_socket.recv(4096).decode()
            
            # Clear listbox
            self.files_listbox.delete(0, tk.END)
            
            if not data.strip():
                messagebox.showinfo("Info", "No files on server.")
                return
            
            # Add files to listbox
            for line in data.splitlines():
                if line.strip():
                    self.files_listbox.insert(tk.END, line.strip())
            
            self.status_label.config(text="File list refreshed")
        
        except Exception as e:
            messagebox.showerror("Error", f"Could not fetch file list: {str(e)}")
            log_message(f"Error fetching file list: {str(e)}")
    
    def delete_file(self):
        """Delete a file from the server (admin only)"""
        if self.role != "admin":
            messagebox.showerror("Error", "Only administrators can delete files")
            log_message("Unauthorized delete attempt")
            return
        
        # Check if a file is selected
        selected = self.files_listbox.curselection()
        if not selected:
            messagebox.showinfo("Select File", "Please select a file to delete")
            return
        
        # Get filename
        filename_text = self.files_listbox.get(selected[0])
        if '. ' in filename_text:  # Format: "1. filename"
            filename = filename_text.split('. ', 1)[1].strip()
        elif ' | ' in filename_text:  # Format: "filename | size | date"
            filename = filename_text.split(' | ')[0].strip()
        else:
            filename = filename_text.strip()
        
        # Confirm deletion
        if not messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete {filename}?"):
            return
        
        try:
            # Send delete command
            self.client_socket.send(f"DELETE {filename}".encode())
            response = self.client_socket.recv(1024).decode()
            
            # Show response
            messagebox.showinfo("Delete Result", response)
            log_message(f"Delete response: {response}")
            
            # Refresh file list
            self.refresh_files()
        
        except Exception as e:
            error_message = f"Delete error: {str(e)}"
            messagebox.showerror("Error", error_message)
            log_message(error_message)
    
    def view_logs(self):
        """View server logs (admin only)"""
        if self.role != "admin":
            messagebox.showerror("Error", "Only administrators can view logs")
            return
        
        try:
            # Send view logs command
            self.client_socket.send(b"VIEW_LOGS")
            response = self.client_socket.recv(1024).decode()
            
            if response.startswith("AUTHORIZED"):
                # Send start command to begin receiving logs
                self.client_socket.send(b"START")
                
                # Receive logs content
                logs_content = ""
                while True:
                    chunk = self.client_socket.recv(1024)
                    if not chunk:
                        break
                    logs_content += chunk.decode()
                    
                    # Check if we've received all the logs
                    if logs_content.endswith("\n\n"):
                        break
                
                # Open logs viewer window
                LogViewerWindow(self, logs_content)
                log_message("Logs viewed successfully")
            else:
                messagebox.showerror("Error", "Unauthorized to view logs")
                log_message("Unauthorized view logs attempt")
        
        except Exception as e:
            error_message = f"Error viewing logs: {str(e)}"
            messagebox.showerror("Error", error_message)
            log_message(error_message)
    
    def upload_file(self):
        """Upload a file to the server"""
        # Select file
        file_path = filedialog.askopenfilename(title="Select File to Upload")
        if not file_path:
            return
        
        # Ask about overwrite
        overwrite = messagebox.askyesno("Overwrite", "Allow overwriting if file exists?")
        
        # Get filename
        filename = os.path.basename(file_path)
        
        # Reset progress bar
        self.progress_var.set(0)
        self.progress_label.config(text="0%")
        self.status_label.config(text=f"Preparing to upload {filename}...")
        
        # Start upload in a thread
        threading.Thread(target=self._upload_thread, 
                        args=(file_path, filename, overwrite), 
                        daemon=True).start()
    
    def _upload_thread(self, file_path, filename, overwrite):
        """Thread function for file upload"""
        try:
            # Get file size
            filesize = os.path.getsize(file_path)
            
            # Calculate checksum
            self.status_label.config(text=f"Calculating checksum for {filename}...")
            checksum = calculate_checksum(file_path)
            if checksum is None:
                messagebox.showerror("Error", "Failed to calculate checksum")
                return
            
            # Send upload command
            log_message(f"Preparing to upload {filename} of size {filesize} bytes with checksum {checksum}")
            if overwrite:
                self.client_socket.send(f"UPLOAD {filename} {filesize} {checksum} -o".encode())
            else:
                self.client_socket.send(f"UPLOAD {filename} {filesize} {checksum}".encode())
            
            # Send file data
            sent = 0
            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(1024)
                    if not chunk:
                        break
                    self.client_socket.send(chunk)
                    sent += len(chunk)
                    
                    # Update progress
                    progress = int((sent / filesize) * 100)
                    self.after(0, self.update_progress_bar, progress)
                    self.status_label.config(text=f"Uploading {filename}: {sent}/{filesize} bytes")
                    self.update_idletasks()  # Force UI update
            
            # Get response
            response = self.client_socket.recv(1024).decode()
            log_message(f"Upload response: {response}")
            
            # Update UI
            self.status_label.config(text=response)
            messagebox.showinfo("Upload Complete", response)
            
            # Refresh file list
            self.refresh_files()
        
        except Exception as e:
            error_message = f"Upload error: {str(e)}"
            self.status_label.config(text=error_message)
            messagebox.showerror("Upload Error", error_message)
            log_message(error_message)
    
    def download_file(self):
        """Download a file from the server directly to the application directory"""
        global is_downloading
        
        # Check if a file is selected
        selected = self.files_listbox.curselection()
        if not selected:
            messagebox.showinfo("Select File", "Please select a file to download")
            return
        
        # Get filename
        filename_text = self.files_listbox.get(selected[0])
        if '. ' in filename_text:  # Format: "1. filename"
            filename = filename_text.split('. ', 1)[1].strip()
        elif ' | ' in filename_text:  # Format: "filename | size | date"
            filename = filename_text.split(' | ')[0].strip()
        else:
            filename = filename_text.strip()
        
        # Set save path to current directory
        save_path = os.path.join(os.path.dirname(__file__), filename)
        
        # Check if file already exists
        if os.path.exists(save_path):
            if not messagebox.askyesno("File Exists", f"File {filename} already exists. Overwrite?"):
                return
        
        # Reset progress bar
        self.progress_var.set(0)
        self.progress_label.config(text="0%")
        self.status_label.config(text=f"Preparing to download {filename}...")
        
        # Enable pause button
        is_downloading = True
        self.pause_button.config(state=tk.NORMAL)
        self.resume_button.config(state=tk.DISABLED)
        
        # Start download in a thread
        threading.Thread(target=self._download_thread, 
                        args=(filename, save_path, False), 
                        daemon=True).start()
    
    def _download_thread(self, filename, save_path, resume=False):
        """Thread function for file download"""
        global is_downloading
        
        try:
            temp_path = f"{save_path}.part"
            
            if resume:
                state = load_download_state()
                if not state or state["filename"] != filename:
                    messagebox.showerror("Error", "No valid download state found")
                    is_downloading = False
                    self.pause_button.config(state=tk.DISABLED)
                    return
                
                offset = state["offset"]
                total_size = state["total_size"]
                log_message(f"Resuming download of {filename} from offset {offset}")
                
                self.client_socket.send(f"DOWNLOAD {filename} resume".encode())
                response = self.client_socket.recv(1024).decode()
                
                if not response.startswith("filesize"):
                    messagebox.showerror("Error", response)
                    is_downloading = False
                    self.pause_button.config(state=tk.DISABLED)
                    return
                
                # Parse response
                parts = response.split()
                filesize = int(parts[1])
                expected_checksum = int(parts[2])
                server_offset = int(parts[3]) if len(parts) >= 4 else 0
                
                if server_offset != offset:
                    messagebox.showerror("Error", f"Server offset {server_offset} does not match local offset {offset}")
                    is_downloading = False
                    self.pause_button.config(state=tk.DISABLED)
                    return
                
                self.client_socket.send(b"START")
                
                with open(temp_path, "ab") as f:
                    received = offset
                    while received < total_size and is_downloading:
                        chunk = self.client_socket.recv(1024)
                        if not chunk:
                            break
                        f.write(chunk)
                        received += len(chunk)
                        save_download_state(filename, received, total_size, save_path)

                        progress = int((received / total_size) * 100)
                        self.after(0, self.update_progress_bar, progress)
                        self.status_label.config(text=f"Resuming download of {filename}: {received}/{total_size} bytes")
                        self.update_idletasks()
                        
                        if is_downloading:
                            self.client_socket.send(b"CONTINUE")
                        else:
                            self.client_socket.send(b"PAUSE")
                            break
                    
                    if not is_downloading:
                        self.status_label.config(text=f"Download of {filename} paused")
                        return
                    
                    # Verify checksum
                    self.status_label.config(text=f"Verifying file integrity...")
                    actual_checksum = calculate_checksum(temp_path)
                    
                    if actual_checksum == expected_checksum:
                        os.rename(temp_path, save_path)
                        self.status_label.config(text=f"Downloaded {filename} successfully (checksum verified)")
                        messagebox.showinfo("Download Complete", f"Downloaded {filename} successfully")
                        clear_download_state()
                    else:
                        error_message = f"Checksum verification failed for {filename}. File may be corrupted."
                        self.status_label.config(text=error_message)
                        messagebox.showerror("Download Error", error_message)
                        if os.path.exists(temp_path):
                            os.remove(temp_path)
                        clear_download_state()
            else:
                # Start a new download
                self.client_socket.send(f"DOWNLOAD {filename}".encode())
                
                # Get response
                response = self.client_socket.recv(1024).decode()
                
                if not response.startswith("filesize"):
                    messagebox.showerror("Error", response)
                    is_downloading = False
                    self.pause_button.config(state=tk.DISABLED)
                    return
                
                # Parse file size and checksum
                parts = response.split()
                filesize = int(parts[1])
                expected_checksum = int(parts[2])
                log_message(f"File size received: {filesize} bytes, expected checksum: {expected_checksum}")
                
                # Save download state
                save_download_state(filename, 0, filesize, save_path)
                
                # Start download
                self.client_socket.send(b"START")
                
                with open(temp_path, "wb") as f:
                    received = 0
                    while received < filesize and is_downloading:
                        chunk = self.client_socket.recv(1024)
                        if not chunk:
                            break
                        f.write(chunk)
                        received += len(chunk)
                        save_download_state(filename, received, filesize, save_path)
                        
                        progress = int((received / filesize) * 100)
                        self.after(0, self.update_progress_bar, progress)
                        self.status_label.config(text=f"Downloading {filename}: {received}/{filesize} bytes")
                        self.update_idletasks()
                        
                        if is_downloading:
                            self.client_socket.send(b"CONTINUE")
                        else:
                            self.client_socket.send(b"PAUSE")
                            break
                    
                    if not is_downloading:
                        self.status_label.config(text=f"Download of {filename} paused")
                        return
                    
                    # Verify checksum
                    self.status_label.config(text="Verifying file integrity...")
                    actual_checksum = calculate_checksum(temp_path)
                    
                    if actual_checksum == expected_checksum:
                        os.rename(temp_path, save_path)
                        self.status_label.config(text=f"Downloaded {filename} successfully (checksum verified)")
                        messagebox.showinfo("Download Complete", f"Downloaded {filename} successfully")
                        log_message(f"Downloaded {filename} successfully (checksum verified)")
                        clear_download_state()
                    else:
                        error_message = f"Checksum verification failed for {filename}. File may be corrupted."
                        self.status_label.config(text=error_message)
                        messagebox.showerror("Download Error", error_message)
                        log_message(error_message)
                        if os.path.exists(temp_path):
                            os.remove(temp_path)
                        log_message(f"Deleted corrupted file: {filename}")
                        clear_download_state()
            
            # Reset download state
            is_downloading = False
            self.pause_button.config(state=tk.DISABLED)
            self.resume_button.config(state=tk.DISABLED)
        
        except Exception as e:
            error_message = f"Download error: {str(e)}"
            self.status_label.config(text=error_message)
            messagebox.showerror("Download Error", error_message)
            log_message(error_message)
            is_downloading = False
            self.pause_button.config(state=tk.DISABLED)
            self.resume_button.config(state=tk.DISABLED)
    
    def pause_transfer(self):
        """Pause the current download"""
        global is_downloading
        
        if is_downloading:
            is_downloading = False
            self.status_label.config(text="Pausing download...")
            self.pause_button.config(state=tk.DISABLED)
            self.resume_button.config(state=tk.NORMAL)
    
    def resume_transfer(self):
        """Resume the paused download"""
        global is_downloading
        
        state = load_download_state()
        if state:
            is_downloading = True
            self.pause_button.config(state=tk.NORMAL)
            self.resume_button.config(state=tk.DISABLED)
            
            # Update progress bar to current state
            if state["total_size"] > 0:
                progress = int((state["offset"] / state["total_size"]) * 100)
                self.after(0, self.update_progress_bar, progress)
            
            try:
                log_message("Resuming download...")
                threading.Thread(target=self._download_thread, 
                                args=(state["filename"], state["save_path"], True), 
                                daemon=True).start()
            except Exception as e:
                self.status_label.config(text=f"Resume error: {str(e)}")
                is_downloading = False
                self.pause_button.config(state=tk.DISABLED)
        else:
            messagebox.showinfo("No Download", "No paused download to resume")
    
    def logout(self):
        """Logout and close the window"""
        try:
            self.client_socket.send(b"EXIT")
            log_message("Sent EXIT command")
            self.client_socket.close()
        except:
            pass
        
        self.destroy()
    
    def on_close(self):
        """Handle window close"""
        self.logout()

if __name__ == "__main__":
    app = LoginWindow()
    app.mainloop()