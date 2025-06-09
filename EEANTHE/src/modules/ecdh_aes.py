from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from Crypto.Cipher import AES
import base64
import pandas as pd
import csv
from modules.db_manager import save_key, load_key, load_patient  # Import MongoDB functions

# ------------------- ECC KEY GENERATION -------------------

def generate_ecdh_key_pair():
    """Generate ECC Private-Public Key Pair and store in MongoDB."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    # Save private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Save public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_key, public_key, private_pem, public_pem

# ------------------- ECDH + AES-GCM ENCRYPTION -------------------

def ecdh_aes_encryption(patient, write_to_nfc, key_name="ecdh_key"):
    """Encrypt CSV data using ECDH for key derivation and AES-GCM for encryption."""
    # Remove MongoDB-specific fields (like _id)
    patient.pop("_id", None)

    # Convert patient dict to comma-separated string
    plaintext = ",".join(str(value) for value in patient.values()).encode()

    # Generate a new ECC key pair for each session
    private_key, public_key, private_pem, public_pem = generate_ecdh_key_pair()

    # Generate an ephemeral key pair
    ephemeral_private_key = ec.generate_private_key(ec.SECP256R1())
    ephemeral_public_key = ephemeral_private_key.public_key()

    # Compute shared secret
    shared_secret = ephemeral_private_key.exchange(ec.ECDH(), public_key)

    # Derive a 256-bit AES key using HKDF
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=16,  # 256-bit key
        salt=None,
        info=b"ecdh-aes-gcm-key"
    ).derive(shared_secret)

    # Generate a random nonce for AES-GCM
    nonce = AES.new(aes_key, AES.MODE_GCM).nonce

    # Encrypt using AES-GCM
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    print("Writing ciphertext to NFC card...")
    write_to_nfc(ciphertext)
    print("Ciphertext successfully written to NFC!")

    # Save ephemeral public key, AES-GCM nonce, and tag in MongoDB
    ephemeral_public_pem = ephemeral_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


    return ciphertext, {
        f"{key_name}_private": private_pem,
        f"{key_name}_public": public_pem,
        f"{key_name}_ephemeral": ephemeral_public_pem,
        f"{key_name}_nonce": nonce,
        f"{key_name}_tag": tag
    }

# ------------------- ECDH + AES-GCM DECRYPTION -------------------

def ecdh_aes_decryption(get_csv_path, read_from_nfc, patient_id, preloaded_keys=None, key_name="ecdh_key", output_file="decrypted_ecdh_aes_data.csv"):
    """Decrypt data from NFC using ECDH for key derivation and AES-GCM for decryption."""
    try:
        if preloaded_keys:
            private_key_data = preloaded_keys.get(f"{key_name}_private")
            ephemeral_public_key_data = preloaded_keys.get(f"{key_name}_ephemeral")
            nonce = preloaded_keys.get(f"{key_name}_nonce")
            tag = preloaded_keys.get(f"{key_name}_tag")

            if not private_key_data or not ephemeral_public_key_data or not nonce or not tag:
                print(f"Error: Preloaded keys missing for '{key_name}'.")
                return None

            private_key = serialization.load_pem_private_key(private_key_data, password=None)
            ephemeral_public_key = serialization.load_pem_public_key(ephemeral_public_key_data)

        # Read ciphertext from NFC
        ciphertext = read_from_nfc()
        if not ciphertext:
            print("Error: No ciphertext found on NFC card.")
            return None

        # Compute shared secret
        shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public_key)

        # Derive AES key using HKDF
        aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=16,  # 256-bit key
            salt=None,
            info=b"ecdh-aes-gcm-key"
        ).derive(shared_secret)

        # Decrypt using AES-GCM
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag).decode()

        return plaintext

    except Exception as e:
        print(f"Decryption failed: {e}")
