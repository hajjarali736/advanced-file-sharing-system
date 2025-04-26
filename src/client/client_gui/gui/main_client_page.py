import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import tkinter.filedialog as fd
import threading
import socket
import os

class MainClientPage(ttk.Window):
    def __init__(self, client_socket):
        super().__init__(themename="cyborg")  # Futuristic dark theme
        self.title("File Sharing Client - Main")
        self.geometry("900x600")
        self.resizable(False, False)

        self.client_socket = client_socket
        self.downloading = False

        self.create_widgets()
        self.fetch_server_files()

    def create_widgets(self):
        # Top Button Bar
        button_frame = ttk.Frame(self)
        button_frame.pack(pady=10)

        self.upload_btn = ttk.Button(button_frame, text="Upload File", bootstyle="primary", command=self.upload_file)
        self.upload_btn.grid(row=0, column=0, padx=10)

        self.download_btn = ttk.Button(button_frame, text="Download Selected", bootstyle="success", command=self.download_selected_file)
        self.download_btn.grid(row=0, column=1, padx=10)

        self.refresh_btn = ttk.Button(button_frame, text="Refresh", bootstyle="info", command=self.fetch_server_files)
        self.refresh_btn.grid(row=0, column=2, padx=10)

        self.pause_btn = ttk.Button(button_frame, text="Pause Download", bootstyle="warning", command=self.pause_download, state=DISABLED)
        self.pause_btn.grid(row=0, column=3, padx=10)

        self.resume_btn = ttk.Button(button_frame, text="Resume Download", bootstyle="secondary", command=self.resume_download, state=DISABLED)
        self.resume_btn.grid(row=0, column=4, padx=10)

        self.logout_btn = ttk.Button(button_frame, text="Logout", bootstyle="danger", command=self.logout)
        self.logout_btn.grid(row=0, column=5, padx=10)

        # Server Files List
        self.files_listbox = ttk.Listbox(self, width=80, height=20, bootstyle="info")
        self.files_listbox.pack(pady=20)

        # Download Progress Bar
        self.progress = ttk.Progressbar(self, bootstyle="success-striped", length=700, mode="determinate")
        self.progress.pack(pady=10)

        # Status Label
        self.status_label = ttk.Label(self, text="", font=("Poppins", 12), bootstyle="warning")
        self.status_label.pack()

    def fetch_server_files(self):
        try:
            self.client_socket.sendall(b"LIST")
            files = self.client_socket.recv(4096).decode()
            self.files_listbox.delete(0, END)
            for file in files.strip().split("\n"):
                self.files_listbox.insert(END, file)
            self.status_label.config(text="File list updated.")
        except Exception as e:
            self.status_label.config(text=f"Error fetching files: {str(e)}")

    def upload_file(self):
        filepath = fd.askopenfilename()
        if not filepath:
            return

        filename = os.path.basename(filepath)
        filesize = os.path.getsize(filepath)

        overwrite = messagebox.askyesno("Overwrite?", "Overwrite if file already exists on server?")
        command = f"UPLOAD {filename} {filesize} {self.calculate_checksum(filepath)}"
        if overwrite:
            command += " -o"

        try:
            self.client_socket.sendall(command.encode())
            with open(filepath, "rb") as f:
                while True:
                    chunk = f.read(1024)
                    if not chunk:
                        break
                    self.client_socket.sendall(chunk)

            response = self.client_socket.recv(1024).decode()
            self.status_label.config(text=response)
            self.fetch_server_files()

        except Exception as e:
            self.status_label.config(text=f"Upload failed: {str(e)}")

    def download_selected_file(self):
        selection = self.files_listbox.curselection()
        if not selection:
            messagebox.showwarning("No file selected", "Please select a file to download.")
            return

        filename = self.files_listbox.get(selection[0]).split(". ", 1)[-1]

        try:
            self.client_socket.sendall(f"DOWNLOAD {filename}".encode())
            response = self.client_socket.recv(1024).decode()

            if response.startswith("filesize"):
                parts = response.split()
                filesize = int(parts[1])
                checksum = int(parts[2])

                self.client_socket.sendall(b"START")

                save_path = os.path.join(os.getcwd(), filename)

                self.downloading = True
                self.pause_btn.config(state=NORMAL)
                self.resume_btn.config(state=DISABLED)
                threading.Thread(target=self.receive_file, args=(save_path, filesize, checksum)).start()
            else:
                self.status_label.config(text=response)

        except Exception as e:
            self.status_label.config(text=f"Download failed: {str(e)}")

    def receive_file(self, save_path, filesize, expected_checksum):
        received = 0
        with open(save_path, "wb") as f:
            while received < filesize:
                if not self.downloading:
                    break
                chunk = self.client_socket.recv(1024)
                if not chunk:
                    break
                f.write(chunk)
                received += len(chunk)
                progress = (received / filesize) * 100
                self.progress['value'] = progress
                self.update_idletasks()

        # After download
        actual_checksum = self.calculate_checksum(save_path)
        if actual_checksum == expected_checksum:
            self.status_label.config(text="Download complete! File verified.")
        else:
            self.status_label.config(text="Download complete but checksum mismatch!")

        self.pause_btn.config(state=DISABLED)
        self.resume_btn.config(state=DISABLED)

    def pause_download(self):
        if self.downloading:
            self.client_socket.sendall(b"PAUSE")
            self.downloading = False
            self.status_label.config(text="Download paused.")
            self.pause_btn.config(state=DISABLED)
            self.resume_btn.config(state=NORMAL)

    def resume_download(self):
        if not self.downloading:
            self.client_socket.sendall(b"CONTINUE")
            self.downloading = True
            self.status_label.config(text="Resuming download...")
            self.pause_btn.config(state=NORMAL)
            self.resume_btn.config(state=DISABLED)

    def logout(self):
        try:
            self.client_socket.sendall(b"EXIT")
            self.client_socket.close()
            self.destroy()
        except:
            self.destroy()

    def calculate_checksum(self, filename):
        checksum = 0
        try:
            with open(filename, "rb") as f:
                while True:
                    chunk = f.read(1024)
                    if not chunk:
                        break
                    checksum += sum(chunk)
            return checksum % 65536
        except:
            return 0
