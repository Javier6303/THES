from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import pandas as pd
import csv
import os
from modules.db_manager import save_key, load_key, load_patient

def aes_encryption(patient_id, write_to_nfc, key_name="aes_key"):
    """Encrypts CSV data with AES and writes to NFC."""
    patient = load_patient(patient_id)
    if not patient:
        print(f"No patient found with ID: {patient_id}")
        return None

    # Remove MongoDB-specific fields (like _id)
    patient.pop("_id", None)

    # Convert patient dict to comma-separated string
    data = ",".join(str(value) for value in patient.values())
    
    aes_key = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_OCB)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())

    write_to_nfc(ciphertext)
    print("AES Encryption completed and written to NFC.")

    # Save the encryption components to a file
    save_key(key_name, aes_key + tag + cipher.nonce)

    return ciphertext  # Return the actual encrypted data for performance measurement


def aes_decryption(get_csv_path, read_from_nfc, key_name="aes_key", output_file="decrypted_aes.csv"):
    """Reads encrypted data from NFC, retrieves AES key from MongoDB, decrypts, and restores the CSV format."""
    print("Reading ciphertext from NFC card...")
    ciphertext = read_from_nfc()

    if not ciphertext:
        print("Error: No data read from NFC.")
        return None

    try:
        key_data = load_key(key_name)  # Retrieve key, tag, and nonce from MongoDB
        if not key_data:
            print(f"Error: No key found in MongoDB for '{key_name}'.")
            return None

        aes_key, tag, nonce = key_data[:16], key_data[16:32], key_data[32:]

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
        print(f"Error: CSV file not found.")

    return None

    
    
