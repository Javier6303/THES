from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import pandas as pd
import csv
import os
from modules.db_manager import save_key, load_key, load_patient

def generate_aes_keys():
    """Generate AES key and return it in a dict format."""
    aes_key = get_random_bytes(32)  # 128-bit key
    return {
        "aes_key": aes_key
    }

def aes_encryption(patient, write_to_nfc, key_name="aes_key", preloaded_keys=None):
    """Encrypts CSV data with AES and writes to NFC."""

    # Remove MongoDB-specific fields (like _id)
    patient.pop("_id", None)

    # Convert patient dict to comma-separated string
    data = ",".join(str(value) for value in patient.values())
    
    if preloaded_keys and key_name in preloaded_keys:
        aes_key = preloaded_keys[key_name]
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())

    write_to_nfc(ciphertext)
    print("AES Encryption completed and written to NFC.")

    # Save the encryption components to a file
    key_bytes = aes_key + tag + cipher.nonce
    return ciphertext, {key_name: key_bytes}  # Return the actual encrypted data for performance measurement


def aes_decryption(get_csv_path, read_from_nfc, patient_id, preloaded_keys=None, key_name="aes_key", output_file="decrypted_aes.csv"):
    """Decrypts AES encrypted data using the patient's key from MongoDB."""
    print("Reading ciphertext from NFC card...")
    ciphertext = read_from_nfc()

    if not ciphertext:
        print("Error: No data read from NFC.")
        return None

    try:
        # Load the AES key specific to the patient
        # Use preloaded_keys if available
        if preloaded_keys and key_name in preloaded_keys:
            key_data = preloaded_keys[key_name]
        # else:
        #     # fallback for manual calls without preloaded keys
        #     from modules.db_manager import load_key
        #     key_data = load_key(key_name, patient_id)

        if not key_data:
            print(f"Error: No key found in MongoDB for '{key_name}' and Patient ID '{patient_id}'.")
            return None

        aes_key, tag, nonce = key_data[:32], key_data[32:48], key_data[48:]

        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag).decode()

        return plaintext

    except ValueError as e:
        print(f"Decryption failed: {e}")
    except FileNotFoundError:
        print("Error: CSV file not found.")

    return None


# aes_key, tag, nonce = key_data[:32], key_data[32:48], key_data[48:] FOR 32 KEY SIZE
    
