import tkinter as tk
from tkinter import Label, Button, Frame, Text, filedialog, messagebox
from PIL import Image, ImageTk
import os

# Function to scan a selected file
def run_scan():
    file_path = filedialog.askopenfilename(title="Select a file to scan")
    
    if not file_path:  # If no file selected, do nothing
        return
    
    status_label.config(text="🔴 Scanning... Please wait", fg="red")
    root.after(2000, lambda: check_file(file_path))  # Simulating scan delay

# Function to check file status (Simulated Logic)
def check_file(file_path):
    # Simple check: If file name contains 'test', flag as suspicious
    if "test" in os.path.basename(file_path).lower():
        scan_result = f"⚠ Suspicious file detected: {os.path.basename(file_path)}"
        status_label.config(text=scan_result, fg="orange")
        threats_text.insert(tk.END, f"{scan_result}\n")
    else:
        status_label.config(text="🟢 Scan Complete: No Threats Detected", fg="green")

# Function to simulate backup process
def start_backup():
    messagebox.showinfo("Backup", "Backup started successfully!")

# Create main window
root = tk.Tk()
root.title("Anti-Ransomware Security Solution")
root.geometry("750x500")  # Increased UI size
root.configure(bg="#0F1A2C")  # Dark background

# Load and display the existing logo
logo_path = "D:/AntiRansomware Project/logo.png"
try:
    original_logo = Image.open(logo_path)
    original_logo = original_logo.resize((100, 60))  # Adjusted size
    logo_img = ImageTk.PhotoImage(original_logo)
    logo_label = Label(root, image=logo_img, bg="#0F1A2C")
    logo_label.place(x=20, y=10)
except Exception as e:
    messagebox.showerror("Error", f"Logo file not found: {e}")

# Title Label
title_label = Label(root, text="Anti-Ransomware Security Solution", fg="white", bg="#0F1A2C", font=("Arial", 16, "bold"))
title_label.pack(pady=10)

# Status Label
status_label = Label(root, text="🟢 Current Status: No Threats Detected", fg="green", bg="#0F1A2C", font=("Arial", 12, "bold"))
status_label.pack()

# Scan Button
scan_button = Button(root, text="🔍 Scan Now", fg="white", bg="#007BFF", font=("Arial", 12, "bold"), width=20, height=2, command=run_scan)
scan_button.pack(pady=10)

# Threats History Section
threats_frame = Frame(root, bg="#1E2A3A", width=650, height=120)
threats_frame.pack(pady=10)

threats_label = Label(threats_frame, text="⚠ Threats History", fg="white", bg="#1E2A3A", font=("Arial", 12, "bold"))
threats_label.pack(anchor="w", padx=10, pady=5)

threats_text = Text(threats_frame, bg="#2C3E50", fg="white", width=75, height=5, font=("Arial", 10))
threats_text.pack(padx=10, pady=5)

# Backup Section
backup_frame = Frame(root, bg="#1E2A3A", width=650, height=100)
backup_frame.pack(pady=10)

backup_label = Label(backup_frame, text="💾 Backup Your Data", fg="white", bg="#1E2A3A", font=("Arial", 12, "bold"))
backup_label.pack(anchor="w", padx=10, pady=5)

backup_button = Button(root, text="⬆ Start Backup", fg="white", bg="#007BFF", font=("Arial", 12, "bold"), width=20, height=2, command=start_backup)
backup_button.pack(pady=10)

# Run the application
root.mainloop()
