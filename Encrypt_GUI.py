import tkinter as tk
from tkinter import messagebox, filedialog
from tkinter import ttk
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

def switch_to_encrypt_view():
    for widget in root.winfo_children():
        widget.destroy()

    root.geometry("600x400")

    # Plaintext Input
    plaintext_label = tk.Label(root, text="Enter Plaintext to Encrypt:")
    plaintext_label.pack(pady=10)

    global plaintext_entry
    plaintext_entry = tk.Text(root, height=5, width=50)
    plaintext_entry.pack(pady=5)

    # Passphrase Input
    passphrase_label = tk.Label(root, text="Enter Passphrase:")
    passphrase_label.pack(pady=10)

    global passphrase_entry
    passphrase_entry = tk.Entry(root, show="*")
    passphrase_entry.pack(pady=5)

    # Encrypt Data Button
    encrypt_button = tk.Button(root, text="Encrypt Data", command=encrypt_data)
    encrypt_button.pack(pady=10)

def switch_to_initial_view():
    for widget in root.winfo_children():
        widget.destroy()

    root.geometry("400x250")

    # Key Length Selection
    key_length_label = tk.Label(root, text="Select Key Length:")
    key_length_label.pack(pady=10)

    key_length_var.set(key_length_options[0])
    key_length_dropdown = ttk.Combobox(root, textvariable=key_length_var, values=key_length_options)
    key_length_dropdown.current(0)
    key_length_dropdown.pack(pady=5)

    # Public Exponent Selection
    public_exponent_label = tk.Label(root, text="Select Public Exponent:")
    public_exponent_label.pack(pady=10)

    public_exponent_var.set(public_exponent_options[0])
    public_exponent_dropdown = ttk.Combobox(root, textvariable=public_exponent_var, values=public_exponent_options)
    public_exponent_dropdown.current(0)
    public_exponent_dropdown.pack(pady=5)

    # Generate Keys Button
    generate_button = tk.Button(root, text="Generate RSA Keys", command=generate_keys)
    generate_button.pack(pady=20)

def generate_keys():
    try:
        key_length = int(key_length_var.get())
        public_exponent = int(public_exponent_var.get())
        
        if public_exponent not in [3, 65537]:
            raise ValueError("Invalid public exponent. Choose one of [3, 65537].")
        
        private_key = rsa.generate_private_key(
            public_exponent=public_exponent,
            key_size=key_length,
            backend=default_backend()
        )
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        with open('private_key.priv', 'wb') as priv_file:
            priv_file.write(private_pem)
        
        with open('public_key.pub', 'wb') as pub_file:
            pub_file.write(public_pem)
        
        messagebox.showinfo("Success", "RSA keys generated and saved to files.")
        switch_to_encrypt_view()
        
    except ValueError as ve:
        messagebox.showerror("Error", str(ve))
    except Exception as e:
        messagebox.showerror("Error", "An error occurred during key generation.")

# Encrypt data using AES and passphrase
def encrypt_data():
    try:
        plaintext = plaintext_entry.get("1.0", tk.END).encode()
        passphrase = passphrase_entry.get().encode()

        if not passphrase:
            raise ValueError("Passphrase cannot be empty.")

        rsa_public_key_path = filedialog.askopenfilename(title="Select RSA Public Key", filetypes=(("Public Key files", "*.pub"),))
        
        if not rsa_public_key_path:
            raise ValueError("RSA public key file not selected.")

        with open(rsa_public_key_path, 'rb') as key_file:
            rsa_public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())

        # Derive AES key from passphrase
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'salt',  # Using a constant salt for simplicity
            iterations=100000,
            backend=default_backend()
        )
        aes_key = kdf.derive(passphrase)

        iv = os.urandom(16)  # 16 bytes for AES
        
        # Pad plaintext
        padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        
        # Encrypt plaintext with AES
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Encrypt AES key with RSA public key
        encrypted_aes_key = rsa_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        with open('encrypted_data.bin', 'wb') as enc_file:
            enc_file.write(ciphertext)
        
        with open('encrypted_aes_key.bin', 'wb') as key_file:
            key_file.write(encrypted_aes_key)
        
        with open('iv.bin', 'wb') as iv_file:
            iv_file.write(iv)
        
        messagebox.showinfo("Success", "Data encrypted and saved to files.")
        
    except ValueError as ve:
        messagebox.showerror("Error", str(ve))
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred during encryption: {str(e)}")

# Create the main window
root = tk.Tk()
root.title("RSA Key Generation and AES Encryption Tool")

# Set initial window size
root.geometry("400x250")

# Get the screen width and height
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()

# Calculate the position to center the window
position_top = int(screen_height / 2 - 250 / 2)
position_right = int(screen_width / 2 - 400 / 2)

# Set the geometry of the window to center it
root.geometry(f'400x250+{position_right}+{position_top}')

# Make the window resizable
root.resizable(True, True)

# Key Length Selection
key_length_label = tk.Label(root, text="Select Key Length:")
key_length_label.pack(pady=10)

key_length_var = tk.StringVar()
key_length_options = [2048, 3072, 4096, 8192]
key_length_dropdown = ttk.Combobox(root, textvariable=key_length_var, values=key_length_options)
key_length_dropdown.current(0)
key_length_dropdown.pack(pady=5)

# Public Exponent Selection
public_exponent_label = tk.Label(root, text="Select Public Exponent:")
public_exponent_label.pack(pady=10)

public_exponent_var = tk.StringVar()
public_exponent_options = [3, 65537]
public_exponent_dropdown = ttk.Combobox(root, textvariable=public_exponent_var, values=public_exponent_options)
public_exponent_dropdown.current(0)
public_exponent_dropdown.pack(pady=5)

# Generate Keys Button
generate_button = tk.Button(root, text="Generate RSA Keys", command=generate_keys)
generate_button.pack(pady=20)

# Run the GUI loop
root.mainloop()
