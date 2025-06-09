from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import pandas as pd
import csv
from modules.db_manager import save_key, load_key, load_patient  # Import MongoDB functions


# ------------------- RSA KEY GENERATION -------------------

def generate_rsa_keypair():
    """Generate a new RSA key pair and save it in MongoDB."""
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    return private_key, public_key


# ------------------- AES + RSA ENCRYPTION -------------------

def aes_rsa_encryption(patient, write_to_nfc, key_name="aes_rsa_key"):
    """Encrypt CSV data with AES and RSA, then write to NFC."""

    patient.pop("_id", None)  # Remove internal MongoDB ID
    plaintext = ",".join(str(value) for value in patient.values())

    # Generate AES key for session
    aes_key = get_random_bytes(16)

    # Generate new RSA key pair for this encryption session
    private_key, public_key = generate_rsa_keypair()
    public_key_obj = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(public_key_obj)

    # Encrypt the AES key with RSA
    enc_aes_key = cipher_rsa.encrypt(aes_key)

    # Encrypt the plaintext using AES
    cipher_aes = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext.encode())

    # Write encrypted data to NFC
    print("Writing ciphertext to NFC card...")
    write_to_nfc(ciphertext)
    print("Ciphertext successfully written to NFC!")

    # Store encrypted AES key, nonce, and tag separately
    key_dict = {
        f"{key_name}_private": private_key,
        f"{key_name}_public": public_key,
        f"{key_name}_enc_aes_key": enc_aes_key,
        f"{key_name}_aes_nonce": cipher_aes.nonce,
        f"{key_name}_aes_tag": tag,
    }

    return ciphertext, key_dict  # Return encrypted data for performance metrics


# ------------------- AES + RSA DECRYPTION -------------------

def aes_rsa_decryption(get_csv_path, read_from_nfc, patient_id, preloaded_keys=None, key_name="aes_rsa_key", output_csv="decrypted_aes_rsa_data.csv"):
    """Decrypt data from NFC and restore the original CSV format using AES-RSA hybrid encryption."""
    try:

        if preloaded_keys:
            private_key_data = preloaded_keys.get(f"{key_name}_private", None)
            enc_aes_key = preloaded_keys.get(f"{key_name}_enc_aes_key", None)
            nonce = preloaded_keys.get(f"{key_name}_aes_nonce", None)
            tag = preloaded_keys.get(f"{key_name}_aes_tag", None)
            

        rsa_private_key = RSA.import_key(private_key_data)

        # Read encrypted ciphertext from NFC
        ciphertext = read_from_nfc()
        if not ciphertext:
            print("Error: No ciphertext found on NFC card.")
            return None


        # Decrypt AES key using RSA
        cipher_rsa = PKCS1_OAEP.new(rsa_private_key)
        aes_key = cipher_rsa.decrypt(enc_aes_key)

        # Decrypt the ciphertext using AES
        cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag).decode()

        return plaintext

    except ValueError as e:
        print(f"Decryption failed: {e}")
    return None
