import os
import psutil
import time
import subprocess
import hashlib
import re
import tkinter as tk
from tkinter import scrolledtext, messagebox
import platform
import threading


# Hash checker for known bad files
def file_hash(file_path):
    hasher = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            hasher.update(f.read())
        return hasher.hexdigest()
    except (PermissionError, OSError):
        return None


# Advanced process scan
def check_processes(nuke=False):
    output.delete('1.0', tk.END)
    output.insert(tk.END, "Ripping through processes like a chainsaw...\n")
    suspicious = []
    for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'memory_info', 'num_threads']):
        pid = proc.info['pid']
        name = proc.info['name'].lower()
        cmdline = ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else ''
        mem = proc.info['memory_info'].rss / 1024 / 1024  # MB
        threads = proc.info['num_threads']
        if ('python' in name or 'keylog' in cmdline or 'pynput' in cmdline or
                'bash' in cmdline or mem > 100 or threads > 20):
            output.insert(tk.END,
                          f"Caught a rat! PID: {pid}, Name: {name}, Command: {cmdline}, Mem: {mem:.2f}MB, Threads: {threads}\n")
            suspicious.append(pid)

    if nuke and suspicious:
        output.insert(tk.END, "\nNuking these bastards...\n")
        for pid in suspicious:
            try:
                os.kill(pid, 9)
                output.insert(tk.END, f"Process {pid} obliterated.\n")
            except Exception as e:
                output.insert(tk.END, f"Couldn’t kill {pid}: {e}\n")


# File scan with threading
def check_files_thread(nuke):
    def scan():
        output.delete('1.0', tk.END)
        output.insert(tk.END, "Clawing through files—any spies are toast...\n")
        suspicious_dirs = ["/sdcard", "/data/data/com.termux/files/home",
                           "/data/local/tmp"] if platform.system() != "Windows" else ["C:\\Users", "C:\\Temp"]
        keywords = ["keylog", "spy", "hack", "log.txt"]
        known_bad_hashes = ["e80b5017098950fc58aad83c8c14978e"]
        bad_files = []
        file_count = 0
        max_files = 5000  # Limit to prevent overload

        for dir_path in suspicious_dirs:
            if not os.path.exists(dir_path) or not os.access(dir_path, os.R_OK):
                output.insert(tk.END, f"Skipping {dir_path}: No access or doesn’t exist.\n")
                continue
            for root, _, files in os.walk(dir_path):
                for file in files:
                    file_count += 1
                    if file_count > max_files:
                        output.insert(tk.END, f"Hit max file limit ({max_files}). Stopping scan.\n")
                        break
                    if any(keyword in file.lower() for keyword in keywords):
                        full_path = os.path.join(root, file)
                        output.insert(tk.END, f"Flagged file: {full_path}\n")
                        filehash = file_hash(full_path)
                        if filehash and filehash in known_bad_hashes:
                            output.insert(tk.END, f"Known bad file confirmed: {full_path}, Hash: {filehash}\n")
                        bad_files.append(full_path)
                    if file_count % 100 == 0:  # Update GUI every 100 files
                        output.insert(tk.END, f"Scanned {file_count} files...\n")
                        root.update_idletasks()  # Keep GUI responsive
                if file_count > max_files:
                    break

        if nuke and bad_files:
            output.insert(tk.END, "\nTorching these fuckers...\n")
            for file in bad_files:
                try:
                    os.remove(file)
                    output.insert(tk.END, f"File {file} wiped clean.\n")
                except Exception as e:
                    output.insert(tk.END, f"Couldn’t delete {file}: {e}\n")
        output.insert(tk.END, "File scan complete.\n")

    # Run scan in a separate thread
    thread = threading.Thread(target=scan)
    thread.start()


# Network scan—works on both Windows and Linux
def check_network(nuke=False):
    output.delete('1.0', tk.END)
    output.insert(tk.END, "Sniffing the wires for leeches...\n")
    is_windows = platform.system() == "Windows"
    try:
        cmd = ['netstat', '-ano'] if is_windows else ['netstat', '-tuln']
        result = subprocess.check_output(cmd, text=True, timeout=10)
        suspicious_ports = [4444, 1337, 31337]

        for line in result.splitlines():
            if is_windows:
                match = re.search(r':(\d+)\s+.*\s+(\d+)$', line)
                if match:
                    port = int(match.group(1))
                    pid = match.group(2)
                    if port in suspicious_ports:
                        output.insert(tk.END, f"Red alert! Suspicious connection on port {port}, PID: {pid}\n")
                        if nuke:
                            output.insert(tk.END, f"Dropping the hammer—killing PID {pid}...\n")
                            try:
                                subprocess.run(['taskkill', '/PID', pid, '/F'], text=True)
                                output.insert(tk.END, f"Process {pid} forcefully terminated.\n")
                            except Exception as e:
                                output.insert(tk.END, f"Couldn’t kill PID {pid}: {e}\n")
            else:
                match = re.search(r':(\d+)\s+.*LISTEN', line)
                if match:
                    port = int(match.group(1))
                    if port in suspicious_ports:
                        output.insert(tk.END, f"Red alert! Suspicious connection on port {port}\n")
                        if nuke:
                            output.insert(tk.END, "Dropping the hammer—shutting down network shit...\n")
                            try:
                                os.kill(
                                    int(subprocess.check_output(['lsof', '-t', '-i', f':{port}'], text=True).strip()),
                                    9)
                                output.insert(tk.END, f"Process on port {port} obliterated.\n")
                            except Exception as e:
                                output.insert(tk.END, f"Couldn’t kill process on port {port}: {e}\n")
    except Exception as e:
        output.insert(tk.END, f"Network scan choked: {e}\n")


# GUI Setup
root = tk.Tk()
root.title("Code Monarch")
root.geometry("800x600")
root.configure(bg="#1a1a1a")

header = tk.Label(root, text="Code Monarch: Device Gutting System", font=("Courier", 16, "bold"), fg="#ff3333",
                  bg="#1a1a1a")
header.pack(pady=10)

output = scrolledtext.ScrolledText(root, width=90, height=25, font=("Courier", 10), bg="#0d0d0d", fg="#ff6666",
                                   insertbackground="#ff3333")
output.pack(pady=10)

nuke_var = tk.BooleanVar()
nuke_check = tk.Checkbutton(root, text="Nuke Mode", variable=nuke_var, font=("Courier", 12), fg="#ff3333", bg="#1a1a1a",
                            selectcolor="#0d0d0d")
nuke_check.pack(pady=5)

btn_frame = tk.Frame(root, bg="#1a1a1a")
btn_frame.pack(pady=10)

process_btn = tk.Button(btn_frame, text="Scan Processes", command=lambda: check_processes(nuke_var.get()),
                        font=("Courier", 12), fg="#ff3333", bg="#0d0d0d", activebackground="#ff6666")
process_btn.grid(row=0, column=0, padx=5)

file_btn = tk.Button(btn_frame, text="Scan Files", command=lambda: check_files_thread(nuke_var.get()),
                     font=("Courier", 12), fg="#ff3333", bg="#0d0d0d", activebackground="#ff6666")
file_btn.grid(row=0, column=1, padx=5)

network_btn = tk.Button(btn_frame, text="Scan Network", command=lambda: check_network(nuke_var.get()),
                        font=("Courier", 12), fg="#ff3333", bg="#0d0d0d", activebackground="#ff6666")
network_btn.grid(row=0, column=2, padx=5)

output.insert(tk.END,
              "Code Monarch’s back, sharper and deadlier. Let’s gut this device and burn any fuckers hiding inside.\n")

root.mainloop()