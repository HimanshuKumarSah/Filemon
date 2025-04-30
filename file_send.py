import os
import socket
import threading
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

server_socket = None

def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print("RSA key pair generated and saved.")

def encrypt_file(input_file, output_file, public_key_path):
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    with open(input_file, "rb") as f:
        data = f.read()

    chunk_size = 190
    encrypted_chunks = [
        public_key.encrypt(
            data[i:i + chunk_size],
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        ) for i in range(0, len(data), chunk_size)
    ]

    with open(output_file, "wb") as f:
        for chunk in encrypted_chunks:
            f.write(chunk)

    print(f"File '{input_file}' encrypted and saved as '{output_file}'.")

def decrypt_file(encrypted_file, output_file, private_key_path):
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    with open(encrypted_file, "rb") as f:
        encrypted_data = f.read()

    chunk_size = 256
    decrypted_chunks = [
        private_key.decrypt(
            encrypted_data[i:i + chunk_size],
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        ) for i in range(0, len(encrypted_data), chunk_size)
    ]

    with open(output_file, "wb") as f:
        for chunk in decrypted_chunks:
            f.write(chunk)

    print(f"Encrypted file '{encrypted_file}' decrypted and saved as '{output_file}'.")

# === Network Functions ===
def start_file_server(host='0.0.0.0', port=9999):
    def handle_client():
        global server_socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((host, port))
        server_socket.listen(1)
        print(f"[*] Listening on {host}:{port}")

        try:
            client_socket, addr = server_socket.accept()
            print(f"[*] Accepted connection from {addr[0]}:{addr[1]}")

            with open("received_encrypted_file.bin", "wb") as f:
                while True:
                    data = client_socket.recv(4096)
                    if not data:
                        break
                    f.write(data)

            print("[*] File received and saved as 'received_encrypted_file.bin'")
            client_socket.close()
        except Exception as e:
            print(f"[*] Server stopped: {e}")

        server_socket.close()

    threading.Thread(target=handle_client, daemon=True).start()


def send_file_to_server(file_path, server_ip, port=9999):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((server_ip, port))

    with open(file_path, "rb") as f:
        while True:
            data = f.read(4096)
            if not data:
                break
            client.sendall(data)

    client.close()
    print(f"[*] File '{file_path}' sent to {server_ip}:{port}")

def get_local_ip():
    try:
        # This doesn't actually connect, just picks an appropriate local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
    except Exception:
        ip = "Unavailable"
    return ip

# === GUI ===
def create_gui():
    root = tk.Tk()
    root.title("Secure File Transfer App")
    root.configure(bg="black")
    root.resizable(False, False)

    frame = tk.Frame(root, bg="black", padx=20, pady=20)
    frame.pack()
    
    # Custom button style
    def styled_button(master, text, command, row, col, colspan=1, width=15):
        btn = tk.Button(
            master, text=text, command=command, width=width,
            bg="black", fg="lime", activebackground="black", activeforeground="lime",
            relief="flat", borderwidth=2, highlightthickness=2,
            highlightbackground="green", highlightcolor="lime"
        )
        btn.grid(row=row, column=col, columnspan=colspan, padx=5, pady=5)
        return btn


    title = tk.Label(frame, text="🔐 Secure File Transfer", font=("Consolas", 18, "bold"), fg="lime", bg="black")
    title.grid(row=0, column=0, columnspan=4, pady=(0, 20))

    # File selection
    tk.Label(frame, text="Select File:", fg="lime", bg="black").grid(row=1, column=0, sticky="e", padx=5, pady=5)
    file_path = tk.StringVar()
    tk.Entry(frame, textvariable=file_path, width=40, bg="black", fg="lime", insertbackground="green").grid(row=1, column=1, padx=5, pady=5)
    styled_button(frame, "Browse", lambda: file_path.set(filedialog.askopenfilename()), row=1, col=2)

    # Receiver IP
    tk.Label(frame, text="Receiver IP:", fg="lime", bg="black").grid(row=2, column=0, sticky="e", padx=5, pady=5)
    server_ip = tk.StringVar()
    tk.Entry(frame, textvariable=server_ip, width=40, bg="black", fg="lime", insertbackground="green").grid(row=2, column=1, columnspan=2, padx=5, pady=5)

    # Public Key Path
    tk.Label(frame, text="Public Key (if encrypting):", fg="lime", bg="black").grid(row=3, column=0, sticky="e", padx=5, pady=5)
    public_key = tk.StringVar()
    tk.Entry(frame, textvariable=public_key, width=40, bg="black", fg="lime", insertbackground="green").grid(row=3, column=1, padx=5, pady=5)
    styled_button(frame, "Generate RSA Key", generate_keys, row=3, col=2)

    # Encryption toggle
    enable_encryption = tk.BooleanVar(value=True)
    tk.Checkbutton(frame, text="Enable Encryption", variable=enable_encryption,
                   bg="black", fg="green", selectcolor="black",
                   activebackground="black", activeforeground="lime").grid(row=4, column=1, pady=(10, 10))

    # Show Local IP
    local_ip = get_local_ip()
    tk.Label(root, text=f"🖧 Your IP: {local_ip}", fg="green", font=("Consolas", 10, "bold"), bg="black").pack(pady=5)

    # Button Actions
    def send_file():
        if not file_path.get() or not server_ip.get():
            messagebox.showerror("Error", "File path and Receiver IP are required.")
            return
        if enable_encryption.get():
            if not public_key.get():
                messagebox.showerror("Error", "Public key path required when encryption is enabled.")
                return
            encrypt_file(file_path.get(), "temp_encrypted.bin", public_key.get())
            send_file_to_server("temp_encrypted.bin", server_ip.get())
        else:
            send_file_to_server(file_path.get(), server_ip.get())

    def receive_file():
        start_file_server()
        messagebox.showinfo("Receiver", "Receiver is now listening for incoming files.")

    def decrypt_selected_file():
        enc_file = filedialog.askopenfilename(title="Select Encrypted File")
        if not enc_file:
            return
        priv_key_path = filedialog.askopenfilename(title="Select Private Key")
        if not priv_key_path:
            return
        save_path = filedialog.asksaveasfilename(defaultextension=".bin", title="Save Decrypted File As (Include file extension in name as well)")
        if not save_path:
            return
        try:
            decrypt_file(enc_file, save_path, priv_key_path)
            messagebox.showinfo("Success", f"File decrypted and saved to:\n{save_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed:\n{str(e)}")

    # Buttons
    styled_button(frame, "Send File", send_file, row=5, col=0)
    styled_button(frame, "Start Receiver", receive_file, row=5, col=1)
    styled_button(frame, "Decrypt File", decrypt_selected_file, row=5, col=2)

    # Proper app exit
    def on_close():
        global server_socket
        if server_socket:
            try:
                temp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                temp_sock.connect(('127.0.0.1', 9999))
                temp_sock.close()
            except:
                pass
            try:
                server_socket.close()
            except:
                pass
        root.destroy()
        os._exit(0)

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()

if __name__ == "__main__":
    create_gui()