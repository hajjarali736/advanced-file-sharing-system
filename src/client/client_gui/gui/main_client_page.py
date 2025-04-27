import queue
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import tkinter as tk
from tkinter import messagebox, filedialog
import threading
import os
import client
from client import (
    upload_file,
    download_file,
    save_download_state,
    load_download_state
)

class MainClientPage(ttk.Window):
    def __init__(self, client_socket, username, role):
        super().__init__(themename="cyborg")
        self.report_callback_exception = lambda exc, val, tb: None

        self.title(f"Client – {username} ({role})")
        self.geometry("900x600")
        self.resizable(False, False)

        self.client_socket = client_socket
        self.queue = queue.Queue()
        self.download_thread = None
        self.download_paused = False
        self.active_download = None

        self.create_widgets()
        self.fetch_server_files()

        self.after(100, self._process_queue)

    def _process_queue(self):
        try:
            while True:
                evt = self.queue.get_nowait()
                kind = evt[0]
                if kind == "progress":
                    _, current, total = evt
                    self.progress['value'] = (current / total) * 100
                    self.update_idletasks()
                elif kind == "done":
                    messagebox.showinfo("Download Completed", "The file was downloaded successfully!")
                    self.progress['value'] = 0
                    self.pause_btn.config(state=DISABLED)
                    self.resume_btn.config(state=DISABLED)
                elif kind == "error":
                    _, err = evt
                    messagebox.showerror("Download Failed", f"Error: {err}")
                    self.progress['value'] = 0
                    self.pause_btn.config(state=DISABLED)
                    self.resume_btn.config(state=DISABLED)
                self.queue.task_done()
        except queue.Empty:
            pass
        finally:
            self.after(100, self._process_queue)

    def create_widgets(self):
        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=10)

        ttk.Button(btn_frame, text="Upload File", bootstyle="primary", command=self.upload_file).grid(row=0, column=0, padx=5)
        ttk.Button(btn_frame, text="Download Selected", bootstyle="success", command=self.download_selected_file).grid(row=0, column=1, padx=5)
        ttk.Button(btn_frame, text="Refresh", bootstyle="info", command=self.fetch_server_files).grid(row=0, column=2, padx=5)
        self.pause_btn = ttk.Button(btn_frame, text="Pause", bootstyle="warning", command=self.pause_download, state=DISABLED)
        self.pause_btn.grid(row=0, column=3, padx=5)
        self.resume_btn = ttk.Button(btn_frame, text="Resume", bootstyle="secondary", command=self.resume_download, state=DISABLED)
        self.resume_btn.grid(row=0, column=4, padx=5)
        ttk.Button(btn_frame, text="Logout", bootstyle="danger", command=self.logout).grid(row=0, column=5, padx=5)

        self.files_listbox = tk.Listbox(self, width=80, height=20)
        self.files_listbox.pack(pady=10)

        self.progress = ttk.Progressbar(self, bootstyle="success-striped", length=700, mode="determinate", maximum=100)
        self.progress.pack(pady=10, padx=20)

    def fetch_server_files(self):
        try:
            self.client_socket.sendall(b"LIST")
            data = self.client_socket.recv(4096).decode()
            self.files_listbox.delete(0, tk.END)
            if data.strip():
                for line in data.splitlines():
                    self.files_listbox.insert(tk.END, line.strip())
            else:
                messagebox.showinfo("Info", "No files on server.")
        except Exception as e:
            messagebox.showerror("Error", f"Could not fetch list: {e}")

    def download_selected_file(self):
        sel = self.files_listbox.curselection()
        if not sel:
            messagebox.showwarning("Select", "Please select a file first.")
            return
        filename = self.files_listbox.get(sel[0]).split(". ")[-1]
        save_path = filedialog.asksaveasfilename(initialfile=filename)
        if not save_path:
            return

        self.pause_btn.config(state=NORMAL)
        self.resume_btn.config(state=DISABLED)
        self.active_download = filename

        def worker():
            try:
                download_file(
                    filename=filename,
                    clientSocket=self.client_socket,
                    gui_callback=lambda c, t: self.queue.put(("progress", c, t)),
                    save_path=save_path
                )
                self.queue.put(("done",))
            except Exception as e:
                self.queue.put(("error", str(e)))

        self.download_thread = threading.Thread(target=worker, daemon=True)
        self.download_thread.start()

    def pause_download(self):
        if self.download_thread and self.download_thread.is_alive():
            try:
                self.client_socket.sendall(b"PAUSE")
                self.pause_btn.config(state=DISABLED)
                self.resume_btn.config(state=NORMAL)
                messagebox.showinfo("Paused", "Download paused. You can resume later.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to pause: {e}")

    def resume_download(self):
        state = load_download_state()
        if not state or state["filename"] != self.active_download:
            messagebox.showwarning("Nothing to resume", "No paused download found.")
            return

        self.pause_btn.config(state=NORMAL)
        self.resume_btn.config(state=DISABLED)

        def worker():
            try:
                download_file(
                    filename=state["filename"],
                    clientSocket=self.client_socket,
                    resume=True,
                    gui_callback=lambda c, t: self.queue.put(("progress", c, t)),
                    save_path=state["save_path"]
                )
                self.queue.put(("done",))
            except Exception as e:
                self.queue.put(("error", str(e)))

        self.download_thread = threading.Thread(target=worker, daemon=True)
        self.download_thread.start()

    def upload_file(self):
        path = filedialog.askopenfilename()
        if not path:
            return
        fname = os.path.basename(path)
        overwrite = messagebox.askyesno("Overwrite?", "Overwrite if exists?")
        def worker():
            try:
                upload_file(fname, self.client_socket, overwrite)
                self.fetch_server_files()
                messagebox.showinfo("Done", f"{fname} uploaded.")
            except Exception as e:
                messagebox.showerror("Error", f"Upload failed: {e}")
        threading.Thread(target=worker, daemon=True).start()

    def logout(self):
        try:
            self.client_socket.sendall(b"EXIT")
            self.client_socket.close()
        finally:
            self.destroy()