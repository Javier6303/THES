from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import pandas as pd
import csv
import os

def aes_encryption(get_csv_path, write_to_nfc, output_file="aes_encrypted.bin"):
    """Encrypts CSV data with AES and writes to NFC."""
    csv_file = get_csv_path()
    if not csv_file:
        return None  # Return None if no CSV file is found

    df = pd.read_csv(csv_file)
    first_row = df.iloc[0].tolist()
    data = ",".join(map(str, first_row))
    aes_key = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_OCB)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())

    write_to_nfc(ciphertext)
    print("AES Encryption completed and written to NFC.")

    # Save the encryption components to a file
    with open(output_file, "wb") as f:
        f.write(aes_key)
        f.write(tag)
        f.write(cipher.nonce)

    return ciphertext  # Return the actual encrypted data for performance measurement


def aes_decryption(get_csv_path, read_from_nfc, output_file="decrypted_aes.csv", input_file="aes_encrypted.bin"):
    """Reads encrypted data from NFC, decrypts with AES, and restores the original CSV format."""
    print("Reading ciphertext from NFC card...")
    ciphertext = read_from_nfc()

    if not ciphertext:
        print("Error: No data read from NFC.")
        return None

    try:
        with open(input_file, "rb") as f:
            aes_key = f.read(16)
            tag = f.read(16)
            nonce = f.read(15)

        if len(ciphertext) == 0:
            raise ValueError("No ciphertext found on NFC card.")

        cipher = AES.new(aes_key, AES.MODE_OCB, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag).decode()
        
        decrypted_data = plaintext.split(",")  # Convert plaintext back to list format

        csv_file = get_csv_path()
        if not csv_file:
            return None  # Return None if CSV file is missing

        df = pd.read_csv(csv_file)
        headers = df.columns.tolist()

        # Ensure the decrypted data matches the CSV header length
        if len(headers) != len(decrypted_data):
            decrypted_data = decrypted_data[:len(headers)]

        output_path = os.path.join(os.getcwd(), output_file)
        with open(output_path, "w", newline="") as csvfile:
            csv_writer = csv.writer(csvfile, quoting=csv.QUOTE_ALL)
            csv_writer.writerow(headers)
            csv_writer.writerow(decrypted_data)

        print(f"Decrypted data saved to '{output_path}'.")

        return plaintext.encode()  # Return the decrypted plaintext as bytes for throughput calculation

    except ValueError as e:
        print(f"Decryption failed: {e}")
    except FileNotFoundError:
        print(f"Error: File '{input_file}' not found.")
    
    return None
