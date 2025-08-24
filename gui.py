import tkinter as tk  
import os
from tkinter import messagebox  #For showing GUI librarry
from modules import (
    password_cracker,
    port_scanner,
    subdomain_enum,
    api_tester,
    encrypt_decrypt,
    file_automation,
    keylogger_monitor,
    credential_manager
)

def open_password_cracker():
    win = tk.Toplevel() #Create a new window on top of the main app.
    win.title("Password Cracker") 
    tk.Label(win, text="Enter SHA-256 Hash: ", width=40).pack(pady=15)
    hash_entry = tk.Entry(win)
    hash_entry.pack()
    tk.Label(win, text="Wordlist path: ", width=40).pack(pady=15)
    path_entry = tk.Entry(win)
    path_entry.pack()
    #This function is triggered when the "Crack" button is clicked.
    def crack():
        hash_val = hash_entry.get()
        path = path_entry.get()
        #Calls crack_sha-256() function from the password_cracker module.
        result = password_cracker.crack_sha256(hash_val, path)
        messagebox.showinfo("Result: ", f"Password:{result or 'Not found'}")

    tk.Button(win, text="Crack", command=crack, width=20).pack(pady=15)

def open_subdomain_enum():
    win = tk.Toplevel()
    win.title("Subdomain Enumerator")
    tk.Label(win, text="Enter Domain: ", width=40).pack(pady=10)
    domain_entry = tk.Entry(win)
    domain_entry.pack()
    tk.Label(win, text="Wordlist path: ", width=40).pack(pady=15)
    wordlist_entry = tk.Entry(win)
    wordlist_entry.pack()

    def enum():
        domain = domain_entry.get()
        path = wordlist_entry.get()
        results = subdomain_enum.enumerate_subdomain(domain, path)
        result_text = "\n".join([f"{sub} --> {ip}" for sub,ip in results])
        messagebox.showinfo("Results", result_text or "No subdomains found")
#         if results :
#             for sub, ip in results:
#                 messagebox.showinfo(f"{sub}--> {ip}\n")
#         else:
#             messagebox.showerror("No Subdomain Found. \n")
    tk.Button(win, text="Enumerate", command=enum, width=40).pack(pady=15)


#This function opens a new popup window for the port scanner.
def open_port_scanner():
    win = tk.Toplevel()
    win.title("Port Scanner")
    tk.Label(win, text="Target IP: ", width=40).pack(pady=15) #ask for the IP address to scan.
    ip_entry = tk.Entry(win)
    ip_entry.pack()
    #This function is called when the scan button is pressed.
    def scan():
        ip = ip_entry.get()
        #Calls scan_ports() from the port_scanner module.
        open_ports = port_scanner.scan_ports(ip)
        messagebox.showinfo("Open Ports: ",f"{open_ports}") #Display the open ports in a pop-up.

    tk.Button(win, text="Scan", command=scan, width=20).pack(pady=15)

#This is the API Tester GUI
def open_api_tester():
    win = tk.Toplevel()
    win.title("API Teaster")

    tk.Label(win, text="URL: ", width=40).pack(pady=15)
    url_entry =tk.Entry(win)
    url_entry.pack()
    tk.Label(win, text="Method (GET/POST): ", width=40).pack(pady=15)
    method_entry = tk.Entry(win)
    method_entry.pack()
    
    def test_api():
        url = url_entry.get()
        method = method_entry.get()
        status, response = api_tester.test_api(method, url)
        messagebox.showinfo("API Result", f"Status: {status}\n Response: {response}")
    
    tk.Button(win, text="Test API", command=test_api, width=40).pack(pady=15)

#This is a Encrypt/Decrypt GUI
def open_encrypt_decrypt():
    win = tk.Toplevel()
    win.title("Encrypt / Decrypt")

    tk.Label(win, text="Message:").pack()
    msg_entry = tk.Entry(win, width=50)
    msg_entry.pack()

    tk.Label(win, text="Encryption Key:").pack()
    key_entry = tk.Entry(win, width=70)
    key_entry.pack()

    tk.Label(win, text="Encrypted Message:").pack()
    encrypted_entry = tk.Entry(win, width=70)
    encrypted_entry.pack()

    def generate_new_key():
        key = encrypt_decrypt.generate_key()
        key_entry.delete(0, tk.END)
        key_entry.insert(0, key.decode())

    def encrypt_msg():
        message = msg_entry.get()
        key = key_entry.get().encode()

        try:
            encrypted = encrypt_decrypt.encrypt_message(key, message)
            encrypted_entry.delete(0, tk.END)
            encrypted_entry.insert(0, encrypted.decode())
            win.clipboard_clear()
            win.clipboard_append(encrypted.decode())
            messagebox.showinfo("Success", "Message encrypted and copied to clipboard!")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed:\n{e}")

    def decrypt_msg():
        encrypted = encrypted_entry.get()
        key = key_entry.get().encode()

        try:
            decrypted = encrypt_decrypt.decrypt_message(key, encrypted.encode())
            messagebox.showinfo("Decrypted", f"Decrypted message:\n{decrypted}")
        except Exception:
            messagebox.showerror("Error", "Decryption failed. Invalid key or message.")

    # Buttons
    tk.Button(win, text="Generate Key", command=generate_new_key).pack(pady=2)
    tk.Button(win, text="Encrypt & Copy", command=encrypt_msg).pack(pady=2)
    tk.Button(win, text="Decrypt", command=decrypt_msg).pack(pady=2)

#File Automation GUI
def open_file_automation():
    win = tk.Toplevel()
    win.title("File Automation")

    tk.Label(win, text="Directory:", width=40).pack(pady=15)
    dir_entry = tk.Entry(win)
    dir_entry.pack()

    tk.Label(win, text="Prefix (for renaming):", width=40).pack(pady=15)
    prefix_entry = tk.Entry(win)
    prefix_entry.pack()

    def rename():
        file_automation.rename_files(dir_entry.get(), prefix_entry.get())
        messagebox.showinfo("Done", "Files renamed")

    def delete_tmp():
        file_automation.delete_temp_files(dir_entry.get())
        messagebox.showinfo("Done", ".tmp files deleted")

    tk.Button(win, text="Rename Files", command=rename, width=40).pack(pady=15)
    tk.Button(win, text="Delete .tmp Files", command=delete_tmp, width=40).pack(pady=15)

#Keylogger Monitoring
def open_keylogger():
    win = tk.Toplevel()
    win.title("Keylogger Monitor")

    tk.Label(win, text="Duration (sec):", width=40).pack(pady=15)
    duration_entry = tk.Entry(win)
    duration_entry.insert(0, "30")
    duration_entry.pack()

    def start_logger():
        duration = int(duration_entry.get())
        keylogger_monitor.start_keylogger(duration)
        messagebox.showinfo("Started", f"Keylogger running for {duration} seconds.")

    tk.Button(win, text="Start Keylogger", command=start_logger, width=40).pack(pady=15)

#Credential Manager
def open_credential_manager():
    win = tk.Toplevel()
    win.title("Credential Manager")

    tk.Label(win, text="Service:", width=40).pack(pady=15)
    service_entry = tk.Entry(win)
    service_entry.pack()

    tk.Label(win, text="Username:", width=40).pack(pady=15)
    user_entry = tk.Entry(win)
    user_entry.pack()

    tk.Label(win, text="Password:", width=40).pack(pady=15)
    pass_entry = tk.Entry(win, show="*")
    pass_entry.pack()

    KEY_FILE = "data/secret.key"

    # Ensure consistent encryption key
    if not os.path.exists(KEY_FILE):
        key = encrypt_decrypt.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    else:
        with open(KEY_FILE, "rb") as f:
            key = f.read()

    def save():
        credential_manager.save_credentials(
            service_entry.get(), user_entry.get(), pass_entry.get(), key
        )
        messagebox.showinfo("Saved", "Credentials stored.")

    def retrieve():
        result = credential_manager.get_credentials(service_entry.get(), key)
        if result:
            messagebox.showinfo("Credentials", f"Username: {result[0]}\nPassword: {result[1]}")
        else:
            messagebox.showerror("Error", "Service not found or wrong key.")

    tk.Button(win, text="Save", command=save, width=40).pack(pady=15)
    tk.Button(win, text="Retrieve", command=retrieve, width=40).pack(pady=15)

#Main Window
root = tk.Tk()
root.geometry("800x500")
root.title("CYBERSECURITY TOOLKIT")

tk.Button(root, text="1.Password Cracker", command=open_password_cracker, width=40).pack(pady=15)
tk.Button(root, text="2.Subdomain Enumerator", command=open_subdomain_enum, width=40).pack(pady=15)
tk.Button(root, text="3.Port Scanner", command=open_port_scanner, width=40).pack(pady=15)
tk.Button(root, text="4.API Tester", command=open_api_tester, width=40).pack(pady=15)
tk.Button(root, text="5.Encryption and Decryption", command=open_encrypt_decrypt, width=40).pack(pady=15)
tk.Button(root, text="6.File Automation", command=open_file_automation, width=40).pack(pady=15)
tk.Button(root, text="7.Keylogger Monitor", command=open_keylogger, width=40).pack(pady=15)
tk.Button(root, text="8.Credential Manager", command=open_credential_manager, width=40).pack(pady=15)

root.mainloop()