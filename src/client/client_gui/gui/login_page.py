import sys
import os
import tkinter.messagebox as messagebox
import ttkbootstrap as ttk
from ttkbootstrap.constants import *

# Adjust sys.path to locate client.py if needed
current_dir = os.path.dirname(__file__)
client_dir = os.path.abspath(os.path.join(current_dir, '..', '..', '..'))
sys.path.insert(0, client_dir)
import client
from main_client_page import MainClientPage

class LoginRegisterPage(ttk.Window):
    def __init__(self):
        super().__init__(themename="cyborg")
        self.title("File Sharing Client - Login/Register")
        self.geometry("600x650")
        self.resizable(False, False)
        self.active_tab = "Login"
        self.create_widgets()

    def create_widgets(self):
        # Title
        ttk.Label(self, text="Welcome", font=("Poppins", 28), bootstyle="info").pack(pady=20)
        # Tabs
        frm = ttk.Frame(self); frm.pack()
        self.login_btn = ttk.Button(frm, text="Login", width=15, bootstyle="info-outline",
                                    command=lambda: self.switch_tab("Login"))
        self.login_btn.grid(row=0, column=0, padx=10)
        self.register_btn = ttk.Button(frm, text="Register", width=15, bootstyle="secondary-outline",
                                       command=lambda: self.switch_tab("Register"))
        self.register_btn.grid(row=0, column=1, padx=10)
        # Form
        frm2 = ttk.Frame(self); frm2.pack(pady=30)
        ttk.Label(frm2, text="Username", font=("Poppins", 14)).grid(row=0, column=0, pady=10, sticky="w")
        self.username_entry = ttk.Entry(frm2, font=("Poppins", 14), width=30); self.username_entry.grid(row=1, column=0, pady=5)
        ttk.Label(frm2, text="Password", font=("Poppins", 14)).grid(row=2, column=0, pady=10, sticky="w")
        self.password_entry = ttk.Entry(frm2, show="*", font=("Poppins", 14), width=30); self.password_entry.grid(row=3, column=0, pady=5)
        self.submit_btn = ttk.Button(self, text="Login", bootstyle="success", width=20, command=self.submit_action)
        self.submit_btn.pack(pady=20)
        self.status_label = ttk.Label(self, text="", font=("Poppins", 12), bootstyle="danger"); self.status_label.pack()

    def switch_tab(self, tab):
        self.active_tab = tab
        if tab == "Login":
            self.login_btn.configure(bootstyle="info-outline"); self.register_btn.configure(bootstyle="secondary-outline")
            self.submit_btn.configure(text="Login", bootstyle="success")
        else:
            self.register_btn.configure(bootstyle="info-outline"); self.login_btn.configure(bootstyle="secondary-outline")
            self.submit_btn.configure(text="Register", bootstyle="secondary")
        self.status_label.config(text="")

    def submit_action(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username or not password:
            self.status_label.config(text="Please enter both username and password.")
            return
        try:
            sock = client.connect_to_server()
            success, role = client.login(username, password, sock)
            if success:
                messagebox.showinfo("Login Success", f"Welcome, {username}!")
                self.destroy()
                MainClientPage(sock, username, role).mainloop()
            else:
                self.status_label.config(text="Login failed. Check credentials.")
                sock.close()
        except Exception as e:
            self.status_label.config(text=f"Connection error: {e}")

if __name__ == "__main__":
    LoginRegisterPage().mainloop()

