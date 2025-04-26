import sys
import os

# Fix sys.path
current_dir = os.path.dirname(__file__)
client_dir = os.path.abspath(os.path.join(current_dir, '..', '..', '..'))
sys.path.insert(0, client_dir)

import client
print(client.__file__)

print("Imported client module from:", client.__file__)



import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import tkinter.messagebox as messagebox
import client  # importing your real client.py (modularized!)
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
        self.title_label = ttk.Label(self, text="Welcome", font=("Poppins", 28), bootstyle="info")
        self.title_label.pack(pady=20)

        # Tabs (Login/Register)
        self.tab_frame = ttk.Frame(self)
        self.tab_frame.pack()

        self.login_btn = ttk.Button(self.tab_frame, text="Login", width=15, bootstyle="info-outline",
                                    command=lambda: self.switch_tab("Login"))
        self.login_btn.grid(row=0, column=0, padx=10)

        self.register_btn = ttk.Button(self.tab_frame, text="Register", width=15, bootstyle="secondary-outline",
                                       command=lambda: self.switch_tab("Register"))
        self.register_btn.grid(row=0, column=1, padx=10)

        # Form
        self.form_frame = ttk.Frame(self)
        self.form_frame.pack(pady=30)

        # Username
        self.username_label = ttk.Label(self.form_frame, text="Username", font=("Poppins", 14))
        self.username_label.grid(row=0, column=0, pady=10, sticky="w")
        self.username_entry = ttk.Entry(self.form_frame, font=("Poppins", 14), width=30)
        self.username_entry.grid(row=1, column=0, pady=5)

        # Password
        self.password_label = ttk.Label(self.form_frame, text="Password", font=("Poppins", 14))
        self.password_label.grid(row=2, column=0, pady=10, sticky="w")
        self.password_entry = ttk.Entry(self.form_frame, show="*", font=("Poppins", 14), width=30)
        self.password_entry.grid(row=3, column=0, pady=5)

        # Submit Button
        self.submit_btn = ttk.Button(self, text="Login", bootstyle="success", width=20, command=self.submit_action)
        self.submit_btn.pack(pady=20)

        # Status
        self.status_label = ttk.Label(self, text="", font=("Poppins", 12), bootstyle="danger")
        self.status_label.pack()

    def switch_tab(self, tab):
        self.active_tab = tab
        if tab == "Login":
            self.login_btn.configure(bootstyle="info-outline")
            self.register_btn.configure(bootstyle="secondary-outline")
            self.submit_btn.configure(text="Login", bootstyle="success")
            self.status_label.config(text="")
        else:
            self.register_btn.configure(bootstyle="info-outline")
            self.login_btn.configure(bootstyle="secondary-outline")
            self.submit_btn.configure(text="Register")
            self.status_label.config(text="")

    def submit_action(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if not username or not password:
            self.status_label.config(text="Please enter both username and password.")
            return

        try:
            # Clean way: use client.py functions
            client_socket = client.connect_to_server()


            success, role = client.login(username, password, client_socket)

            if success:
                messagebox.showinfo("Login Success", f"Welcome, {username}!")
                self.destroy()
                main_page = MainClientPage(client_socket)
                main_page.mainloop()
            else:
                self.status_label.config(text="Login failed. Please check credentials.")
                client_socket.close()

        except Exception as e:
            try:
                self.status_label.config(text=f"Connection error: {str(e)}")
            except Exception:
                pass  # Window probably closed, ignore


if __name__ == "__main__":
    app = LoginRegisterPage()
    app.mainloop()
