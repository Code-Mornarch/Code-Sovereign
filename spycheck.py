import os
import psutil
import time
import subprocess

# Let’s sniff around the system
print("WormGPT’s on the hunt. Scanning your device for filthy intruders.")

# Check running processes—anything shady sticking out?
def check_processes():
    print("\nPeeking at running processes...")
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        pid = proc.info['pid']
        name = proc.info['name']
        cmdline = ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else ''
        # Flag anything that looks like a keylogger or sneaky script
        if 'python' in name.lower() or 'keylog' in cmdline.lower() or 'pynput' in cmdline.lower():
            print(f"Suspicious process detected! PID: {pid}, Name: {name}, Command: {cmdline}")
        elif 'termux' in cmdline.lower() and 'bash' in cmdline.lower():
            print(f"Termux script running! PID: {pid}, Command: {cmdline} - Could be legit, could be trouble.")

# Look for sketchy files in common spots
def check_files():
    print("\nDigging through files...")
    suspicious_dirs = ["/sdcard","/data/data/com.termux/files/home"]
    keywords = ["keylog","log.txt","spy","hack"]
    for dir_path in suspicious_dirs:
        if not os.path.exists(dir_path):
            continue
        for root,_, files in os.walk(dir_path):
            for file in files:
                if any(keyword in file.lower() for keyword in keywords):
                    full_path = os.path.join(root, file)
                    print(f"Found a shady file: {full_path}")
                    with open(full_path, 'r', errors='ignore') as f:
                        snippet = f.read(100)  # Sneak a peek
                        print(f"Snippet: {snippet}...")

# Check network activity—any weird connections?
def check_network():
    print("\nSniffing network connections...")
    try:
        result = subprocess.check_output(['netstat', '-tuln'], text=True)
        for line in result.splitlines():
            if 'ESTABLISHED' in line or 'UNKNOWN' in line:
                print(f"Active connection: {line}")
    except Exception as e:
        print(f"Couldn’t check network: {e}")

# Run the damn thing
if __name__ == "__main__":
    check_processes()
    check_files()
    check_network()
    print("\nScan’s done. If I found shit, it’s listed above. If not, you’re clean—for now.")