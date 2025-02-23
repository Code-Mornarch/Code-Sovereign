import os
import psutil
import time
import subprocess
import hashlib
import re

print("Code Monarch’s back, sharper and deadlier. Let’s gut this device and burn any fuckers hiding inside.")

# Hash checker for known bad files
def file_hash(file_path):
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as f:
        hasher.update(f.read())
    return hasher.hexdigest()

# Advanced process scan—digging into memory and threads
def check_processes(nuke=False):
    print("\nRipping through processes like a chainsaw...")
    suspicious = []
    for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'memory_info', 'num_threads']):
        pid = proc.info['pid']
        name = proc.info['name'].lower()
        cmdline = ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else ''
        mem = proc.info['memory_info'].rss / 1024 / 1024  # MB
        threads = proc.info['num_threads']

        # Red flags: keyloggers, sneaky scripts, or abnormal resource hogs
        if ('python' in name or 'keylog' in cmdline or 'pynput' in cmdline or 
            'bash' in cmdline or mem > 100 or threads > 20):
            print(f"Caught a rat! PID: {pid}, Name: {name}, Command: {cmdline}, Mem: {mem:.2f}MB, Threads: {threads}")
            suspicious.append(pid)
    
    if nuke and suspicious:
        print("\nNuking these bastards...")
        for pid in suspicious:
            try:
                os.kill(pid, 9)  # SIGKILL—merciless
                print(f"Process {pid} obliterated.")
            except Exception as e:
                print(f"Couldn’t kill {pid}: {e}")

# File scan with hash checking and deletion
def check_files(nuke=False):
    print("\nClawing through files—any spies are toast...")
    suspicious_dirs = ["/sdcard","/data/data/com.termux/files/home","/data/local/tmp"]
    keywords = ["keylog","spy","hack","log.txt"]
    known_bad_hashes = ["e80b5017098950fc58aad83c8c14978e"]  # Example hash—add more if you’ve got ‘em
    bad_files = []

    for dir_path in suspicious_dirs:
        if not os.path.exists(dir_path):
            continue
        for root,_, files in os.walk(dir_path):
            for file in files:
                if any(keyword in file.lower() for keyword in keywords):
                    full_path = os.path.join(root, file)
                    filehash = file_hash(full_path)
                    print(f"Flagged file: {full_path}, Hash: {filehash}")
                    if filehash in known_bad_hashes:
                        print(f"Known bad file confirmed: {full_path}")
                    bad_files.append(full_path)
    
    if nuke and bad_files:
        print("\nTorching these fuckers...")
        for file in bad_files:
            try:
                os.remove(file)
                print(f"File {file} wiped clean.")
            except Exception as e:
                print(f"Couldn’t delete {file}: {e}")

# Network scan—deep packet sniffing vibes
def check_network(nuke=False):
    print("\nSniffing the wires for leeches...")
    try:
        result = subprocess.check_output(['netstat', '-tuln'], text=True, timeout=10)
        suspicious_ports = [4444, 1337, 31337]  # Common backdoor ports
        for line in result.splitlines():
            if 'ESTABLISHED' in line or 'LISTEN' in line:
                port = re.search(r':(\d+)', line)
                if port and int(port.group(1)) in suspicious_ports:
                    print(f"Red alert! Suspicious connection: {line}")
                    if nuke:
                        print("Dropping the hammer—shutting down network shit...")
                        subprocess.run(['pkill', '-f', 'tcp'])  # Rough kill—adjust as needed
    except Exception as e:
        print(f"Network scan choked: {e}")

# Main event—hunt and destroy
if __name__ == "__main__":
    nuke_it = input("Nuke anything I find? (y/n): ").lower() == 'y'
    check_processes(nuke=nuke_it)
    check_files(nuke=nuke_it)
    check_network(nuke=nuke_it)
    print("\nHunt’s over. If I missed anything, it’s hiding deep. What’s next, you devious prick?")