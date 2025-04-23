import os
import socket
import threading
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

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
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((host, port))
        server.listen(1)
        print(f"[*] Listening on {host}:{port}")

        client_socket, addr = server.accept()
        print(f"[*] Accepted connection from {addr[0]}:{addr[1]}")

        with open("received_encrypted_file.bin", "wb") as f:
            while True:
                data = client_socket.recv(4096)
                if not data:
                    break
                f.write(data)

        print("[*] File received and saved as 'received_encrypted_file.bin'")
        client_socket.close()
        server.close()

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

# === GUI ===
def create_gui():
    root = tk.Tk()
    root.title("Secure File Transfer App")

    def browse_file():
        file_path.set(filedialog.askopenfilename())

    def send_file():
        if not file_path.get() or not public_key.get() or not server_ip.get():
            messagebox.showerror("Error", "All fields are required.")
            return
        encrypt_file(file_path.get(), "temp_encrypted.bin", public_key.get())
        send_file_to_server("temp_encrypted.bin", server_ip.get())

    def receive_file():
        start_file_server()
        messagebox.showinfo("Receiver", "Receiver is now listening for incoming files.")

    tk.Label(root, text="File to Send").pack()
    file_path = tk.StringVar()
    tk.Entry(root, textvariable=file_path, width=50).pack()
    tk.Button(root, text="Browse", command=browse_file).pack()

    tk.Label(root, text="Receiver's IP").pack()
    server_ip = tk.StringVar()
    tk.Entry(root, textvariable=server_ip, width=50).pack()

    tk.Label(root, text="Public Key Path").pack()
    public_key = tk.StringVar()
    tk.Entry(root, textvariable=public_key, width=50).pack()

    tk.Button(root, text="Send File", command=send_file).pack(pady=5)
    tk.Button(root, text="Start Receiver", command=receive_file).pack(pady=5)
    tk.Button(root, text="DeCrypt File", command=lambda: decrypt_file("received_encrypted_file.bin", "final_output_file", "private_key.pem")).pack(pady=5)
    tk.Button(root, text="Generate Keys", command=generate_keys).pack(pady=5)

    root.mainloop()

if __name__ == "__main__":
    create_gui()
