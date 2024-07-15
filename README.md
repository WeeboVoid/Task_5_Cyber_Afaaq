# RSA and AES Encryption/Decryption Tool

## Overview
This repository contains two Python GUI programs for RSA key generation, AES encryption, and decryption of plaintext using the `cryptography` library. The programs allow users to generate RSA key pairs, encrypt data using AES with a passphrase, and decrypt the data using the RSA private key and passphrase.

## Program 1: Encryption

### Steps for Encryption
1. **Generate RSA Keys**:
   - Select the RSA key length.
   - Generate an RSA private key and derive the public key from it.
   - Save the private key in a file named `private_key.priv`.
   - Save the public key in a file named `public_key.pub`.

2. **Encrypt Data**:
   - Enter the plaintext to be encrypted.
   - Enter a passphrase.
   - Select the RSA public key file to be used for encrypting the AES key.
   - Derive an AES key from the passphrase using PBKDF2HMAC with a constant salt.
   - Generate a random initialization vector (IV) for AES encryption.
   - Encrypt the plaintext using AES in CBC mode with the derived AES key and IV.
   - Encrypt the derived AES key using the RSA public key.
   - Save the encrypted data in a file named `encrypted_data.bin`.
   - Save the encrypted AES key in a file named `encrypted_aes_key.bin`.
   - Save the IV in a file named `iv.bin`.

### Libraries Used
- **tkinter**:
  Used for GUI functionalities.

- **cryptography.hazmat.primitives**:
  - **asymmetric.rsa**:
    - `generate_private_key()`: Generates an RSA private key.
  - **serialization**:
    - `private_bytes()`: Serializes the private key.
    - `public_bytes()`: Serializes the public key.
    - `load_pem_private_key()`: Loads a PEM-formatted private key.
    - `load_pem_public_key()`: Loads a PEM-formatted public key.
  - **padding**:
    - `PKCS7`: Provides PKCS7 padding for block ciphers.
  - **ciphers**:
    - `Cipher()`: Creates a new cipher object for encryption or decryption.
    - **algorithms**:
      - `AES()`: Specifies the AES algorithm.
    - **modes**:
      - `CBC()`: Specifies the CBC mode for AES.

### Functionalities
1. **switch_to_encrypt_view()**: Switches the GUI to the encrypt view.
2. **switch_to_initial_view()**: Switches the GUI to the initial view.
3. **generate_keys()**: Generates RSA keys and saves them to files.
4. **encrypt_data()**: Encrypts data with AES, encrypts the AES key with the RSA public key, and saves the files.

## Program 2: Decrypt Data Using AES with RSA Private Key and Passphrase

### Steps for Decryption
1. **Decrypt Data**:
   - Enter the passphrase.
   - Select the RSA private key file to be used for decrypting the AES key.
   - Select the encrypted AES key file.
   - Select the IV file.
   - Select the encrypted data file.
   - Decrypt the AES key using the RSA private key.
   - Verify the passphrase by deriving the AES key and comparing it to the decrypted AES key.
   - Decrypt the encrypted data using AES in CBC mode with the derived AES key and IV.
   - Display the decrypted plaintext data.

### Libraries Used
- **tkinter**:
  - `tk.Tk()`: Creates the main application window.
  - `messagebox`: Provides a set of dialogs to show messages.
  - `filedialog`: Provides a set of dialogs to open or save files.

- **cryptography.hazmat.backends**:
  - `default_backend()`: Provides the default backend for cryptographic operations.

- **cryptography.hazmat.primitives**:
  - **asymmetric.rsa**:
    - `load_pem_private_key()`: Loads a PEM-formatted private key.
  - **serialization**:
    - `load_pem_private_key()`: Loads a PEM-formatted private key.
  - **hashes**:
    - `SHA256`: Specifies the SHA-256 hash algorithm.
  - **padding**:
    - `PKCS7`: Provides PKCS7 padding for block ciphers.
  - **ciphers**:
    - `Cipher()`: Creates a new cipher object for encryption or decryption.
    - **algorithms**:
      - `AES()`: Specifies the AES algorithm.
    - **modes**:
      - `CBC()`: Specifies the CBC mode for AES.
  - **kdf.pbkdf2**:
    - `PBKDF2HMAC()`: Derives a key using PBKDF2 HMAC.

### Functionalities
1. **decrypt_data()**: Decrypts the AES key using the RSA private key, verifies the passphrase, decrypts the data using the AES key, and displays the decrypted data.

## Usage
1. **Program 1**:
   - Run the program.
   - Generate RSA keys by selecting the key length.
   - Encrypt data by entering the plaintext, passphrase, and selecting the RSA public key file.

2. **Program 2**:
   - Run the program.
   - Decrypt data by entering the passphrase, selecting the RSA private key file, encrypted AES key file, IV file, and encrypted data file.

## Important Notes
- I have used ChatGPT to implement most of the GUI elements and modified it after.
- The passphrase is used to derive the AES key using PBKDF2HMAC with a constant salt.
- The AES key is encrypted using the RSA public key and stored separately.
- The IV used for AES encryption is stored separately.
- During decryption, the passphrase is verified by deriving the AES key and comparing it to the decrypted AES key.
- Proper error handling is implemented to ensure that incorrect passphrases or missing files result in appropriate error messages.
