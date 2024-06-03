import tkinter as tk
from tkinter import messagebox
import random
from cryptography.fernet import Fernet
import base64
import os

class EncryptionManager:
    def __init__(self, master_password):
        self.key = self.generate_key(master_password)
        self.fernet = Fernet(self.key)

    def generate_key(self, password):
        password = password.encode()
        key = base64.urlsafe_b64encode(password.ljust(32)[:32])
        return key

    def encrypt(self, plaintext):
        return self.fernet.encrypt(plaintext.encode()).decode()

    def decrypt(self, ciphertext):
        return self.fernet.decrypt(ciphertext.encode()).decode()

class PasswordManager:
    def __init__(self, master_password):
        self.encryption_manager = EncryptionManager(master_password)
        self.file_path = "passwords.txt"

    def save_password(self, site, username, password):
        encrypted_password = self.encryption_manager.encrypt(password)
        with open(self.file_path, "a") as file:
            file.write(f"{site},{username},{encrypted_password}\n")

    def load_passwords(self):
        passwords = []
        if os.path.exists(self.file_path):
            with open(self.file_path, "r") as file:
                for line in file:
                    site, username, encrypted_password = line.strip().split(",")
                    try:
                        decrypted_password = self.encryption_manager.decrypt(encrypted_password)
                        passwords.append((site, username, decrypted_password))
                    except:
                        passwords.append((site, username, "Invalid Master Password"))
        return passwords

    def delete_password(self, site, username):
        passwords = self.load_passwords()
        with open(self.file_path, "w") as file:
            for s, u, p in passwords:
                if not (s == site and u == username):
                    encrypted_password = self.encryption_manager.encrypt(p)
                    file.write(f"{s},{u},{encrypted_password}\n")

class GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")

        self.password_manager = None

        tk.Label(root, text="Master Password:").grid(row=0, column=0, padx=5, pady=5)
        self.master_password_entry = tk.Entry(root, show="*")
        self.master_password_entry.grid(row=0, column=1, padx=5, pady=5)
        tk.Button(root, text="Set Master Password", command=self.set_master_password).grid(row=0, column=2, padx=5, pady=5)

        tk.Label(root, text="Website:").grid(row=1, column=0, padx=5, pady=5)
        self.site_entry = tk.Entry(root)
        self.site_entry.grid(row=1, column=1, padx=5, pady=5)

        tk.Label(root, text="Username:").grid(row=2, column=0, padx=5, pady=5)
        self.username_entry = tk.Entry(root)
        self.username_entry.grid(row=2, column=1, padx=5, pady=5)

        tk.Label(root, text="Password Length:").grid(row=3, column=0, padx=5, pady=5)
        self.length_entry = tk.Entry(root)
        self.length_entry.grid(row=3, column=1, padx=5, pady=5)

        self.password_entry = tk.Entry(root)
        self.password_entry.grid(row=4, column=1, padx=5, pady=5)

        tk.Button(root, text="Generate Password", command=self.generate_password).grid(row=4, column=0, padx=5, pady=5)
        tk.Button(root, text="Save Password", command=self.save_password).grid(row=5, column=0, padx=5, pady=5)
        tk.Button(root, text="Show Stored Passwords", command=self.show_passwords).grid(row=5, column=1, padx=5, pady=5)

    def set_master_password(self):
        master_password = self.master_password_entry.get()
        if master_password:
            self.password_manager = PasswordManager(master_password)
            messagebox.showinfo("Info", "Master password set successfully!")
        else:
            messagebox.showwarning("Warning", "Master password cannot be empty")

    def generate_password(self):
        length = self.get_password_length()
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
        password = "".join(random.choice(chars) for _ in range(length))
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)

    def save_password(self):
        if not self.password_manager:
            messagebox.showwarning("Warning", "Please set the master password first")
            return

        site = self.site_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()

        if site and username and password:
            self.password_manager.save_password(site, username, password)

            self.site_entry.delete(0, tk.END)
            self.username_entry.delete(0, tk.END)
            self.password_entry.delete(0, tk.END)
            messagebox.showinfo("Info", "Password saved successfully!")
        else:
            messagebox.showwarning("Warning", "Please fill out all fields")

    def show_passwords(self):
        if not self.password_manager:
            messagebox.showwarning("Warning", "Please set the master password first")
            return

        passwords = self.password_manager.load_passwords()

        show_window = tk.Toplevel(self.root)
        show_window.title("Stored Passwords")

        for i, (site, username, decrypted_password) in enumerate(passwords):
            tk.Label(show_window, text=site).grid(row=i, column=0, padx=5, pady=5)
            tk.Label(show_window, text=username).grid(row=i, column=1, padx=5, pady=5)
            tk.Label(show_window, text=decrypted_password).grid(row=i, column=2, padx=5, pady=5)
            tk.Button(show_window, text="Copy", command=lambda p=decrypted_password: self.copy_to_clipboard(p)).grid(row=i, column=3, padx=5, pady=5)
            tk.Button(show_window, text="Delete", command=lambda s=site, u=username: self.delete_password(s, u)).grid(row=i, column=4, padx=5, pady=5)

    def delete_password(self, site, username):
        if messagebox.askyesno("Delete Password", f"Are you sure you want to delete the password for {username} on {site}?"):
            self.password_manager.delete_password(site, username)
            messagebox.showinfo("Info", "Password deleted successfully!")
            self.show_passwords()

    def get_password_length(self):
        try:
            length = int(self.length_entry.get())
        except ValueError:
            length = 12  # default length if not specified
        return length

    def copy_to_clipboard(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        messagebox.showinfo("Info", "Password copied to clipboard")

def main():
    root = tk.Tk()
    gui = GUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
