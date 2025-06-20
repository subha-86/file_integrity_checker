import os
import json
import hashlib
import smtplib
import time
import threading
from email.message import EmailMessage
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# ---------- GLOBALS ----------
USER_EMAIL = None
USER_PASSWORD = None
HASH_FILE = "hashes.json"

# ---------- HASHING ----------
def generate_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

def hash_all_files(folder_path):
    file_hashes = {}
    for root, dirs, files in os.walk(folder_path):
        for name in files:
            full_path = os.path.join(root, name)
            try:
                file_hashes[full_path] = generate_hash(full_path)
            except Exception as e:
                print(f"[ERROR] Could not hash {full_path}: {e}")
    with open(HASH_FILE, "w") as f:
        json.dump(file_hashes, f, indent=4)
    return file_hashes

# ---------- EMAIL ----------
def get_email_credentials_gui(root):
    global USER_EMAIL, USER_PASSWORD

    def submit_credentials():
        nonlocal email_window
        USER_EMAIL = email_entry.get().strip()
        USER_PASSWORD = password_entry.get().strip()
        email_window.destroy()

    if USER_EMAIL and USER_PASSWORD:
        return

    email_window = tk.Toplevel(root)
    email_window.title("Enter Gmail Credentials")
    email_window.geometry("300x180")
    email_window.grab_set()

    ttk.Label(email_window, text="Gmail Address:").pack(pady=(10, 2))
    email_entry = ttk.Entry(email_window, width=30)
    email_entry.pack()

    ttk.Label(email_window, text="App Password:").pack(pady=(10, 2))
    password_entry = ttk.Entry(email_window, width=30, show="*")
    password_entry.pack()

    ttk.Button(email_window, text="Submit", command=submit_credentials).pack(pady=15)
    email_window.wait_window()

def send_email(subject, body, root):
    get_email_credentials_gui(root)

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = USER_EMAIL
    msg["To"] = USER_EMAIL
    msg.set_content(body)

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(USER_EMAIL, USER_PASSWORD)
            smtp.send_message(msg)
        print("[EMAIL] Sent:", subject)
    except Exception as e:
        print(f"[EMAIL ERROR] {e}")
        messagebox.showerror("Email Error", f"Could not send alert:\n{e}")

# ---------- VERIFY ----------
def verify_integrity(root):
    if not os.path.exists(HASH_FILE):
        print("[ERROR] hashes.json not found.")
        return

    with open(HASH_FILE, "r") as f:
        original_hashes = json.load(f)

    modified_files = []

    for path, original_hash in original_hashes.items():
        if not os.path.exists(path):
            modified_files.append(f"{path} (Missing)")
            continue
        current_hash = generate_hash(path)
        if current_hash != original_hash:
            modified_files.append(f"{path} (Modified)")

    if modified_files:
        alert = " The following files were modified or deleted:\n\n" + "\n".join(modified_files)
        send_email("File Integrity Alert", alert, root)

# ---------- WATCHDOG ----------
class IntegrityMonitor(FileSystemEventHandler):
    def __init__(self, root):
        self.root = root

    def on_modified(self, event):
        if not event.is_directory:
            verify_integrity(self.root)

    def on_deleted(self, event):
        if not event.is_directory:
            verify_integrity(self.root)

def start_watch(path_to_watch, root):
    event_handler = IntegrityMonitor(root)
    observer = Observer()
    observer.schedule(event_handler, path=path_to_watch, recursive=True)
    observer.start()
    print(f"[WATCHDOG] Monitoring '{path_to_watch}'")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# ---------- GUI ----------
def gui_app():
    def select_folder():
        folder = filedialog.askdirectory()
        folder_path.set(folder)
        status_label.config(text=f"Selected: {folder}", foreground="blue")

    def generate_and_send_hashes():
        path = folder_path.get()
        if not path:
            messagebox.showwarning("No folder", "Please select a folder.")
            return
        hashes = hash_all_files(path)
        body = f"🛡️ File Hash Report for: {path}\n\n"
        for file, hash_val in hashes.items():
            body += f"{file}\n→ {hash_val}\n\n"
        send_email("🛡️ File Hash Report", body, root)
        status_label.config(text="Hashes emailed.", foreground="green")

    def start_monitoring():
        path = folder_path.get()
        if not path:
            messagebox.showwarning("No folder", "Please select a folder.")
            return
        status_label.config(text=f" Monitoring {path}", foreground="purple")
        threading.Thread(target=start_watch, args=(path, root), daemon=True).start()

    global root
    root = tk.Tk()
    root.title(" File Hash Reporter + Monitor")
    root.geometry("520x300")
    root.resizable(False, False)

    style = ttk.Style(root)
    style.theme_use("clam")

    frame = ttk.Frame(root, padding=20)
    frame.pack(expand=True)

    folder_path = tk.StringVar()

    ttk.Label(frame, text="File Hash Reporter & Monitor", font=("Helvetica", 16, "bold")).pack(pady=(0, 15))

    ttk.Entry(frame, textvariable=folder_path, width=50).pack()
    ttk.Button(frame, text="Browse Folder", command=select_folder).pack(pady=5)
    ttk.Button(frame, text="Send Hash Report Now", command=generate_and_send_hashes).pack(pady=5)
    ttk.Button(frame, text="Start Integrity Monitor", command=start_monitoring).pack(pady=10)

    global status_label
    status_label = ttk.Label(frame, text="", font=("Arial", 10))
    status_label.pack(pady=(10, 0))

    root.mainloop()

# ---------- RUN ----------
if __name__ == "__main__":
    gui_app()
