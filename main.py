import os
import pickle
import threading
import subprocess
import psutil
import logging
import math
import tkinter as tk
from tkinter import ttk
import ttkbootstrap as ttkb
from ttkbootstrap.constants import *
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from googleapiclient.http import MediaFileUpload
from scanner_utils import scan_and_delete
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Google Drive API scope
SCOPES = ['https://www.googleapis.com/auth/drive.file']
HANDLE_EXE_PATH = os.path.join(os.getcwd(), "handle.exe")

# Logging setup
logging.basicConfig(filename='anti_ransomware.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# ------------------ Google Drive Authentication -------------------
def authenticate_drive():
    creds = None
    script_dir = os.path.dirname(os.path.abspath(__file__))
    credentials_path = os.path.join(script_dir, 'client_secret.json')
    token_path = os.path.join(script_dir, 'token.pickle')

    if not os.path.exists(credentials_path):
        messagebox.showerror("Missing File", f"client_secret.json not found at:\n{credentials_path}")
        return None

    if os.path.exists(token_path):
        with open(token_path, 'rb') as token:
            creds = pickle.load(token)

    try:
        if creds and creds.valid:
            pass
        elif creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            raise Exception("Invalid or missing credentials")
    except Exception as e:
        if os.path.exists(token_path):
            os.remove(token_path)
        flow = InstalledAppFlow.from_client_secrets_file(credentials_path, SCOPES)
        creds = flow.run_local_server(port=0)
        with open(token_path, 'wb') as token:
            pickle.dump(creds, token)

    return build('drive', 'v3', credentials=creds)

# ------------------ Upload and Scan Logic -------------------
def create_drive_folder(service, folder_name, parent_id=None):
    metadata = {'name': folder_name, 'mimeType': 'application/vnd.google-apps.folder'}
    if parent_id:
        metadata['parents'] = [parent_id]
    folder = service.files().create(body=metadata, fields='id').execute()
    return folder.get('id')

def upload_file(service, filepath, folder_id, progress_callback=None):
    try:
        file_metadata = {'name': os.path.basename(filepath), 'parents': [folder_id]}
        media = MediaFileUpload(filepath, resumable=True)
        request = service.files().create(body=file_metadata, media_body=media, fields='id')

        response = None
        while response is None:
            status, response = request.next_chunk()
            if status and progress_callback:
                root.after(0, lambda: progress_callback(int(status.progress() * 100)))

        if progress_callback:
            root.after(0, lambda: progress_callback(100))

        logging.info(f"Uploaded: {filepath}")
        return response.get('id')
    except Exception as e:
        logging.error(f"Upload Error: {str(e)}")
        root.after(0, lambda: messagebox.showerror("Upload Error", f"Failed to upload:\n{filepath}\n\n{str(e)}"))
        return None

def upload_folder(service, folder_path, parent_folder_id, progress_callback=None):
    folder_id_map = {folder_path: parent_folder_id}
    total_files = sum(len(files) for _, _, files in os.walk(folder_path))
    uploaded_files = [0]

    for root_dir, dirs, files in os.walk(folder_path):
        parent_id = folder_id_map.get(os.path.dirname(root_dir), parent_folder_id)

        if root_dir not in folder_id_map:
            folder_metadata = {
                'name': os.path.basename(root_dir),
                'mimeType': 'application/vnd.google-apps.folder',
                'parents': [parent_id]
            }
            folder = service.files().create(body=folder_metadata, fields='id').execute()
            folder_id_map[root_dir] = folder.get('id')

        for file_name in files:
            file_path = os.path.join(root_dir, file_name)

            def inner_progress(pct):
                overall = int(((uploaded_files[0] + pct / 100) / total_files) * 100)
                root.after(0, lambda: update_progress(overall))

            upload_file(service, file_path, folder_id_map[root_dir], progress_callback=inner_progress)
            uploaded_files[0] += 1

def update_progress(value):
    progress_bar.configure(value=value)
    progress_label.config(text=f"{value}%")
    progress_bar.update_idletasks()

def upload_selected_folder():
    folder = filedialog.askdirectory(title="Select a folder to upload")
    if not folder:
        return

    threading.Thread(target=upload_folder_task, args=(folder,), daemon=True).start()

def upload_folder_task(folder):
    try:
        update_progress(0)
        service = authenticate_drive()
        if not service:
            return
        backup_root_id = create_drive_folder(service, "RansomwareBackup")
        top_folder_id = create_drive_folder(service, os.path.basename(folder), backup_root_id)
        upload_folder(service, folder, top_folder_id)
        update_progress(100)
        root.after(0, lambda: messagebox.showinfo("Success", "Folder uploaded successfully!"))
    except Exception as e:
        logging.error(f"Folder Upload Error: {str(e)}")
        root.after(0, lambda: messagebox.showerror("Upload Error", str(e)))

def upload_selected_file():
    file = filedialog.askopenfilename(title="Select a file to upload")
    if not file:
        return

    threading.Thread(target=upload_file_task, args=(file,), daemon=True).start()

def upload_file_task(file):
    try:
        update_progress(0)
        service = authenticate_drive()
        if not service:
            return
        folder_id = create_drive_folder(service, "RansomwareBackup")

        def file_progress(pct):
            update_progress(pct)

        upload_file(service, file, folder_id, progress_callback=file_progress)
        update_progress(100)
        root.after(0, lambda: messagebox.showinfo("Success", "File uploaded successfully!"))
    except Exception as e:
        logging.error(f"File Upload Error: {str(e)}")
        root.after(0, lambda: messagebox.showerror("Upload Error", str(e)))

# ------------------ Scanner -------------------
def run_scan():
    file_path = filedialog.askopenfilename(title="Select a file to scan")
    if not file_path:
        return
    threading.Thread(target=perform_scan, args=(file_path,), daemon=True).start()

def perform_scan(file_path):
    try:
        abs_path = os.path.abspath(file_path)
        result = scan_and_delete(abs_path)
        logging.info(f"Scan Result: {result}")

        # Insert the result once
        if "Threat detected" in result:
            threats_text.insert(tk.END, f"{abs_path}: {result}\n")
            threats_text.see(tk.END)

            # Show threat popup
            if messagebox.askyesno("Threat Found", f"{result}\n\nDelete this file?"):
                os.remove(abs_path)
                messagebox.showinfo("Deleted", f"Deleted:\n{abs_path}")
        else:
            threats_text.insert(tk.END, f"{abs_path}: ✅ No threats detected.\n")
            threats_text.see(tk.END)

            # Show safe scan popup
            messagebox.showinfo("Scan Complete", f"No threats found in:\n{abs_path}")

    except Exception as e:
        logging.error(f"Scan Error: {str(e)}")
        messagebox.showerror("Scan Error", f"Error during scan:\n{str(e)}")
# ------------------ Real-Time Encryption Detection -------------------
def calculate_entropy(filepath):
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        if not data:
            return 0
        byte_count = [0] * 256
        for byte in data:
            byte_count[byte] += 1
        entropy = -sum((count / len(data)) * math.log2(count / len(data))
                       for count in byte_count if count != 0)
        return entropy
    except Exception:
        return 0

class EncryptionDetectorHandler(FileSystemEventHandler):
    def __init__(self, gui_callback):
        self.gui_callback = gui_callback

    def on_created(self, event):
        if not event.is_directory:
            self.check_file(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.check_file(event.src_path)

    def check_file(self, filepath):
        suspicious_exts = ['.enc', '.encrypted', '.locked', '.locky', '.aes', '.wnry', '.xyz']
        safe_exts = ['.docx', '.xlsx', '.pptx', '.pdf']
        _, ext = os.path.splitext(filepath)

        if ext.lower() in safe_exts:
            return

        entropy = calculate_entropy(filepath)

        if ext.lower() in suspicious_exts and entropy > 7.5:
            self.gui_callback(filepath, entropy)

def start_encryption_monitor(path_to_watch, gui_callback):
    handler = EncryptionDetectorHandler(gui_callback)
    observer = Observer()
    observer.schedule(handler, path=path_to_watch, recursive=True)
    observer.start()
    return observer

def encryption_alert(filepath, entropy):
    msg = f"⚠️ Possible ransomware activity detected!\n\nFile: {filepath}\nEntropy: {entropy:.2f}\n\nDelete it?"

    logging.warning(f"Suspicious file: {filepath} | Entropy: {entropy}")
    threats_text.insert(tk.END, f"[ENCRYPTION WARNING] {filepath} (Entropy: {entropy:.2f})\n")
    threats_text.see(tk.END)

    if messagebox.askyesno("Ransomware Alert", msg):
        try:
            os.remove(filepath)
            messagebox.showinfo("Deleted", f"File deleted: {filepath}")
        except Exception as e:
            messagebox.showerror("Error", f"Could not delete:\n{str(e)}")


def view_logs():
    LOG_FILE = "logs_history.json"

    if not os.path.exists(LOG_FILE):
        messagebox.showinfo("No Logs", "No logs found.")
        return

    try:
        with open(LOG_FILE, "r", encoding="utf-8") as file:
            logs = json.load(file)
    except json.JSONDecodeError:
        messagebox.showerror("Error", "Failed to read or parse the log file.")
        return

    # Create a new window to show logs
    log_window = tk.Toplevel()
    log_window.title("Logs History")
    log_window.geometry("800x450")
    log_window.configure(bg="#f8f9fa")

    # Frame for Treeview and Scrollbar
    frame = tk.Frame(log_window)
    frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    # Create Treeview
    columns = ("Time", "Event", "Detail")
    tree = ttk.Treeview(frame, columns=columns, show="headings")

    # Define headings and column widths
    tree.heading("Time", text="Timestamp")
    tree.heading("Event", text="Event Type")
    tree.heading("Detail", text="Detail")
    tree.column("Time", width=180, anchor="center")
    tree.column("Event", width=140, anchor="center")
    tree.column("Detail", width=460, anchor="w")

    # Add vertical scrollbar
    vsb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=vsb.set)
    vsb.pack(side="right", fill="y")
    tree.pack(fill=tk.BOTH, expand=True)

    # Insert log entries
    for log in logs:
        timestamp = log.get("timestamp", "N/A")
        event_type = log.get("event_type", "N/A")
        detail = log.get("detail", "N/A")
        tree.insert("", tk.END, values=(timestamp, event_type, detail))

# ------------------ GUI Setup -------------------
# ... (Imports and utility functions unchanged)



class AntiRansomwareApp(ttkb.Window):
    def __init__(self):
        super().__init__(themename="superhero")
        self.title("Anti-Ransomware Security Solution")
        self.geometry("1000x700")
        self.minsize(800, 600)

        # Load background image
        bg_path = "background.jpg"
        if os.path.exists(bg_path):
            bg_img = Image.open(bg_path).resize((1000, 700), Image.Resampling.LANCZOS)

            self.bg_photo = ImageTk.PhotoImage(bg_img)
        else:
            self.bg_photo = None

        self.frames = {}
        for F in (MainPage, ScanPage, BackupPage, ThreatsPage):
            page_name = F.__name__
            frame = F(parent=self, controller=self)
            self.frames[page_name] = frame
            frame.grid(row=0, column=0, sticky="nsew")
            self.grid_rowconfigure(0, weight=1)
            self.grid_columnconfigure(0, weight=1)

        self.show_frame("MainPage")


    def show_frame(self, page_name):
        frame = self.frames[page_name]
        frame.tkraise()


# -- Common frame styling function --
def style_common_frame(self):
    self.configure(style="Custom.TFrame")
    style = ttkb.Style()
    style.configure("Custom.TFrame", background="#f8f9fa")


class MainPage(ttkb.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        if controller.bg_photo:
         bg_label = ttkb.Label(self, image=controller.bg_photo)
         bg_label.place(x=0, y=0, relwidth=1, relheight=1)
         bg_label.lower()  # Push to background

        style_common_frame(self)

        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        top_frame = ttkb.Frame(self, padding=10, style="Custom.TFrame")
        top_frame.grid(row=0, column=0, sticky="ew")

        logo_path = "D:/AntiRansomware Project/logo.png"
        if os.path.exists(logo_path):
            logo_img = ImageTk.PhotoImage(Image.open(logo_path).resize((90, 50)))
            logo_label = ttkb.Label(top_frame, image=logo_img, background="#f8f9fa")
            logo_label.pack(side=LEFT, padx=10)
            self.logo_img = logo_img

        title_label = ttkb.Label(top_frame, text="Anti-Ransomware Security Solution",
                                 font=("Arial", 24, "bold"),
                                 background="#f8f9fa", foreground="black")
        title_label.pack(side=LEFT, padx=10)

        center_frame = ttkb.Frame(self, padding=10, style="Custom.TFrame")
        center_frame.grid(row=1, column=0, sticky="nsew")

        button_container = ttkb.Frame(center_frame, style="Custom.TFrame")
        button_container.pack(expand=True)

        button_width = 30

        ttkb.Button(button_container, text="⚠ Threat Logs",
                    command=lambda: controller.show_frame("ThreatsPage"),
                    bootstyle="warning-outline", width=button_width).pack(pady=20, fill=X)

        ttkb.Button(button_container, text="🔎 Scan Now",
                    command=lambda: controller.show_frame("ScanPage"),
                    bootstyle="primary-outline", width=button_width).pack(pady=20, fill=X)

        ttkb.Button(button_container, text="💾 Backup Data",
                    command=lambda: controller.show_frame("BackupPage"),
                  bootstyle="success-outline", width=button_width).pack(pady=20, fill=X)

        # Log button section — moved inside __init__
              # Log Button Frame
        log_button_frame = ttkb.Frame(self, style="Custom.TFrame")
        log_button_frame.grid(row=3, column=0)
       
        # Footer Label
        footer_label = ttkb.Label(self, text="Stay Safe from Ransomware. Backup, Scan, and Monitor!",
                                  font=("Arial", 16),
                                  background="#f8f9fa", foreground="black")
        footer_label.grid(row=4, column=0, pady=10)

class ScanPage(ttkb.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        
        if controller.bg_photo:
            bg_label = ttkb.Label(self, image=controller.bg_photo)
            bg_label.place(x=0, y=0, relwidth=1, relheight=1)
            bg_label.lower()
        
        style = ttkb.Style()
        style.configure("Transparent.TFrame", background="")
        style_common_frame(self)

        self.grid_rowconfigure(0, weight=0)
        self.grid_rowconfigure(1, weight=0)
        self.grid_rowconfigure(2, weight=0)
        self.grid_rowconfigure(3, weight=1)
        self.grid_rowconfigure(4, weight=0)
        self.grid_columnconfigure(0, weight=1)

        # 🔙 Top-left Back Arrow Button
        style = ttkb.Style()
        style.configure("Big.TButton", font=("Times New Roman", 24, "bold"))
        arrow_btn = ttkb.Button(self,text="🡄",width=2,command=lambda: controller.show_frame("MainPage"),bootstyle=SECONDARY) 
        arrow_btn.place(x=10, y=10)
        

        # Title
        ttkb.Label(self, text="🔎 Scan Files", font=("Arial", 24, "bold"),
                   background="#f8f9fa", foreground="black").grid(row=0, column=0, pady=20, sticky="n")

        # Instruction
        ttkb.Label(self, text="Select a file and scan for ransomware threats.",
                   font=("Arial", 16), anchor="center").grid(row=1, column=0, pady=100, sticky="n", columnspan=2)

        # Scan Button
        ttkb.Button(self, text="Select and Scan a File", 
                    command=run_scan, bootstyle=SUCCESS, width=25, padding=10).grid(row=2, column=0, pady=60, padx=20, sticky="n", columnspan=2)

        # Spacer Frame
        ttkb.Frame(self).grid(row=3, column=0, pady=50)

        # Back to Main Menu Button (Bottom)
        ttkb.Button(self, text="⬅ Back to Main Menu",
                    command=lambda: controller.show_frame("MainPage"),
                    bootstyle=SECONDARY, width=25, padding=10).grid(row=4, column=0, pady=20, padx=20, sticky="n", columnspan=2)


class BackupPage(ttkb.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        if controller.bg_photo:
         bg_label = ttkb.Label(self, image=controller.bg_photo)
         bg_label.place(x=0, y=0, relwidth=1, relheight=1)
         bg_label.lower()  # Push to background

        style_common_frame(self)

        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # 🔙 Top-left Back Arrow Button
        style = ttkb.Style()
        style.configure("Big.TButton", font=("Times New Roman", 24, "bold"))
        arrow_btn = ttkb.Button(self,text="🡄",width=2,command=lambda: controller.show_frame("MainPage"),bootstyle=SECONDARY) 
        arrow_btn.place(x=10, y=10)
        


        ttkb.Label(self, text="💾 Backup Data to Google Drive", font=("Arial", 22, "bold"),
                   background="#f8f9fa", foreground="black").grid(row=0, column=0, pady=80)

        backup_card = ttkb.Frame(self, bootstyle=PRIMARY, padding=10)
        backup_card.grid(row=1, column=0, pady=30, padx=40, sticky="n")

        ttkb.Label(backup_card, text="Backup your important files and folders to Google Drive.", font=("Arial", 14)).pack(pady=20)

        ttkb.Button(backup_card, text="⬆ Backup Folder", command=upload_selected_folder, bootstyle=INFO).pack(pady=20)
        ttkb.Button(backup_card, text="📄 Backup File", command=upload_selected_file, bootstyle=INFO).pack(pady=20)

        global progress_bar, progress_label
        progress_bar = ttkb.Progressbar(self, orient="horizontal", length=500, mode="determinate")
        progress_bar.grid(row=2, column=0, pady=20)
        progress_label = ttkb.Label(self, text="0%", font=("Arial", 12, "bold"),
                                    background="#087070")
        progress_label.grid(row=3, column=0)

        ttkb.Button(self, text="⬅ Back to Main Menu",
                    command=lambda: controller.show_frame("MainPage"),
                    bootstyle=SECONDARY).grid(row=4, column=0, pady=20)


class ThreatsPage(ttkb.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        if controller.bg_photo:
         bg_label = ttkb.Label(self, image=controller.bg_photo)
         bg_label.place(x=0, y=0, relwidth=1, relheight=1)
         bg_label.lower()  # Push to background

        style_common_frame(self)

        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # 🔙 Top-left Back Arrow Button
        style = ttkb.Style()
        style.configure("Big.TButton", font=("Times New Roman", 24, "bold"))
        arrow_btn = ttkb.Button(self,text="🡄",width=2,command=lambda: controller.show_frame("MainPage"),bootstyle=SECONDARY) 
        arrow_btn.place(x=10, y=10)
        


        ttkb.Label(self, text="⚠ Threats History", font=("Arial", 22, "bold"),
                   background="#f8f9fa", foreground="black").grid(row=0, column=0, pady=20)

        threat_card = ttkb.Frame(self, bootstyle=DANGER, padding=10)
        threat_card.grid(row=1, column=0, padx=20, pady=10, sticky="nsew")

        # Add Scrollbar
        global threats_text
        scrollbar = ttkb.Scrollbar(threat_card)
        scrollbar.pack(side=RIGHT, fill=Y)

        threats_text = tk.Text(threat_card, height=20, bg="#1f1f1f", fg="white", font=("Consolas", 11), yscrollcommand=scrollbar.set)
        threats_text.pack(fill=BOTH, expand=True)
        scrollbar.config(command=threats_text.yview)

        ttkb.Button(self, text="⬅ Back to Main Menu",
                    command=lambda: controller.show_frame("MainPage"),
                    bootstyle=SECONDARY).grid(row=2, column=0, pady=20)


if __name__ == "__main__":
    root = AntiRansomwareApp()
    root.mainloop()