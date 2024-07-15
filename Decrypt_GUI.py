import tkinter as tk
from tkinter import messagebox, filedialog
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def decrypt_data():
    try:
        passphrase = passphrase_entry.get().encode()

        if not passphrase:
            raise ValueError("Passphrase cannot be empty.")

        rsa_private_key_path = filedialog.askopenfilename(title="Select RSA Private Key", filetypes=(("Private Key files", "*.priv"),))
        if not rsa_private_key_path:
            raise ValueError("RSA private key file not selected.")

        encrypted_aes_key_path = filedialog.askopenfilename(title="Select Encrypted AES Key", filetypes=(("Encrypted Key files", "*.bin"),))
        if not encrypted_aes_key_path:
            raise ValueError("Encrypted AES key file not selected.")

        iv_path = filedialog.askopenfilename(title="Select IV File", filetypes=(("IV files", "*.bin"),))
        if not iv_path:
            raise ValueError("IV file not selected.")

        encrypted_data_path = filedialog.askopenfilename(title="Select Encrypted Data File", filetypes=(("Encrypted Data files", "*.bin"),))
        if not encrypted_data_path:
            raise ValueError("Encrypted data file not selected.")

        with open(rsa_private_key_path, 'rb') as key_file:
            rsa_private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())

        with open(encrypted_aes_key_path, 'rb') as key_file:
            encrypted_aes_key = key_file.read()

        with open(iv_path, 'rb') as iv_file:
            iv = iv_file.read()

        with open(encrypted_data_path, 'rb') as enc_file:
            ciphertext = enc_file.read()

        # Decrypt AES key with RSA private key
        aes_key = rsa_private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Derive AES key from passphrase
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'salt',  # Using a constant salt for simplicity
            iterations=100000,
            backend=default_backend()
        )
        derived_aes_key = kdf.derive(passphrase)

        if derived_aes_key != aes_key:
            raise ValueError("Incorrect passphrase.")

        # Decrypt ciphertext
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Unpad decrypted data
        unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_data) + unpadder.finalize()
        
        messagebox.showinfo("Success", f"Decrypted data:\n{plaintext.decode()}")
        
    except ValueError as ve:
        messagebox.showerror("Error", str(ve))
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred during decryption: {str(e)}")

# Create the main window
root = tk.Tk()
root.title("AES Decryption Tool")

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

# Passphrase Input
passphrase_label = tk.Label(root, text="Enter Passphrase:")
passphrase_label.pack(pady=10)

global passphrase_entry
passphrase_entry = tk.Entry(root, show="*")
passphrase_entry.pack(pady=5)

# Decrypt Data Button
decrypt_button = tk.Button(root, text="Decrypt Data", command=decrypt_data)
decrypt_button.pack(pady=20)

# Run the GUI loop
root.mainloop()
