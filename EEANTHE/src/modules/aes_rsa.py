from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import pandas as pd
import csv

# ------------------- RSA KEY GENERATION -------------------

def generate_rsa_keypair(output_file="aes_rsa_private.pem"):
    """Generate RSA key pair and save the private key to a file."""
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open(output_file, "wb") as f:
        f.write(private_key)

    print(f"RSA key pair generated and private key saved to '{output_file}'.")
    return public_key

# ------------------- AES + RSA ENCRYPTION -------------------

def aes_rsa_encryption(get_csv_path, write_to_nfc, output_file="aes_rsa_private.pem"):
    """Encrypt CSV data with AES and RSA, then write to NFC."""
    csv_file = get_csv_path()
    if not csv_file:
        return

    df = pd.read_csv(csv_file)
    first_row = df.iloc[0].tolist()
    plaintext = ",".join(map(str, first_row))

    aes_key = get_random_bytes(16)  # Generate AES key (16 bytes)

    public_key = generate_rsa_keypair(output_file)
    public_key_obj = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(public_key_obj)

    enc_aes_key = cipher_rsa.encrypt(aes_key)  # Encrypt AES key with RSA

    cipher_aes = AES.new(aes_key, AES.MODE_OCB)
    ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext.encode())

    print("Writing ciphertext to NFC card...")
    write_to_nfc(ciphertext)
    print("Ciphertext successfully written to NFC!")

    enc_file_path = "aes_rsa_encrypted.bin"
    with open(enc_file_path, "wb") as f:
        f.write(enc_aes_key)  # RSA-encrypted AES key (256 bytes)
        f.write(cipher_aes.nonce)  # AES nonce (15 bytes)
        f.write(tag)  # AES authentication tag (16 bytes)

    return ciphertext

# ------------------- AES + RSA DECRYPTION -------------------

def aes_rsa_decryption(get_csv_path, read_from_nfc, input_file="aes_rsa_private.pem", output_csv="decrypted_aes_rsa_data.csv"):
    """Decrypt data from NFC and restore original CSV format using AES-RSA hybrid approach."""
    try:
        with open(input_file, "rb") as f:
            rsa_private_key = RSA.import_key(f.read())

        ciphertext = read_from_nfc()

        if not ciphertext:
            print("Error: No ciphertext found on NFC card.")
            return

        enc_file_path = "aes_rsa_encrypted.bin"
        with open(enc_file_path, "rb") as f:
            enc_aes_key = f.read(256)  # RSA-encrypted AES key
            nonce = f.read(15)  # AES nonce
            tag = f.read(16)  # AES authentication tag

        cipher_rsa = PKCS1_OAEP.new(rsa_private_key)
        aes_key = cipher_rsa.decrypt(enc_aes_key)  # Decrypt AES key

        cipher_aes = AES.new(aes_key, AES.MODE_OCB, nonce=nonce)
        plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag).decode()

        decrypted_data = plaintext.split(",")

        csv_file = get_csv_path()
        if not csv_file:
            return

        df = pd.read_csv(csv_file)
        headers = df.columns.tolist()

        if len(headers) != len(decrypted_data):
            decrypted_data = decrypted_data[:len(headers)]

        with open(output_csv, "w", newline="") as csvfile:
            csv_writer = csv.writer(csvfile, quoting=csv.QUOTE_ALL)
            csv_writer.writerow(headers)
            csv_writer.writerow(decrypted_data)

        print(f"Decrypted data saved to '{output_csv}'.")

        return plaintext

    except ValueError as e:
        print(f"Decryption failed: {e}")
    except FileNotFoundError:
        print(f"Error: File '{input_file}' not found.")
