from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Random import get_random_bytes
import base64
import pandas as pd
import csv
from modules.db_manager import save_key, load_key, load_patient  # Import MongoDB functions

# ------------------- ECC KEY GENERATION -------------------

def generate_ecc_key_pair(key_name="ecc_key"):
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

    # Generate an ephemeral key pair
    ephemeral_private_key = ec.generate_private_key(ec.SECP256R1())
    ephemeral_public_key = ephemeral_private_key.public_key()

    return {
        f"{key_name}_private": private_pem,
        f"{key_name}_public": public_pem,
        f"{key_name}_ephemeral_pub": ephemeral_public_key,
        f"{key_name}_ephemeral_priv": ephemeral_private_key
    }

# ------------------- ECC + XOR ENCRYPTION -------------------

def ecc_xor_encryption(patient, write_to_nfc, preloaded_keys=None, key_name="ecc_key"):
    """Encrypt CSV data using ECC XOR encryption and write to NFC."""

    # Remove MongoDB-specific fields (like _id)
    patient.pop("_id", None)

    # Convert patient dict to comma-separated string
    plaintext = ",".join(str(value) for value in patient.values())
    plaintext_bytes = plaintext.encode()

    private_pem = preloaded_keys.get(f"{key_name}_private")
    public_pem = preloaded_keys.get(f"{key_name}_public")
    ephemeral_public_key = preloaded_keys.get(f"{key_name}_ephemeral_pub")
    ephemeral_private_key = preloaded_keys.get(f"{key_name}_ephemeral_priv")

    # Load the public key
    public_key = serialization.load_pem_public_key(public_pem)

    # Compute shared secret
    shared_secret = ephemeral_private_key.exchange(ec.ECDH(), public_key)

    # Derive key
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 16 bytes = 128-bit key (use 32 for 256-bit)
        salt=None,
        info=b"ecc-xor-keystream"
    ).derive(shared_secret)

    # Create a CTR-based keystream generator
    nonce = get_random_bytes(8)  
    ctr = Counter.new(64, prefix=nonce)
    stream_cipher = AES.new(derived_key, AES.MODE_CTR, counter=ctr)

    # Encrypt using XOR
    keystream = stream_cipher.encrypt(b'\x00' * len(plaintext_bytes))
    encrypted_bytes = bytes(a ^ b for a, b in zip(plaintext_bytes, keystream))
    encrypted_text = base64.b64encode(encrypted_bytes).decode()

    print("Writing ciphertext to NFC card...")
    write_to_nfc(encrypted_text.encode("utf-8"))
    print("Ciphertext successfully written to NFC!")

    # Save ephemeral public key in MongoDB
    ephemeral_public_pem = ephemeral_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return encrypted_text, {
        f"{key_name}_private": private_pem,
        f"{key_name}_public": public_pem,
        f"{key_name}_ephemeral": ephemeral_public_pem,
        f"{key_name}_nonce": nonce
    }

# ------------------- ECC + XOR DECRYPTION -------------------

def ecc_xor_decryption(get_csv_path, read_from_nfc, patient_id, preloaded_keys=None, key_name="ecc_key", output_file="decrypted_ecc_data.csv"):
    """Decrypt data from NFC using ECC XOR encryption and restore CSV format."""
    try:
        # Retrieve private key from MongoDB
        if preloaded_keys:
            private_key_data = preloaded_keys.get(f"{key_name}_private")
            ephemeral_public_key_data = preloaded_keys.get(f"{key_name}_ephemeral")
            nonce = preloaded_keys.get(f"{key_name}_nonce")

            if not private_key_data or not ephemeral_public_key_data:
                print(f"Error: Preloaded ECC keys missing for '{key_name}'.")
                return None

            private_key = serialization.load_pem_private_key(private_key_data, password=None)
            ephemeral_public_key = serialization.load_pem_public_key(ephemeral_public_key_data)

        # Read ciphertext from NFC
        encrypted_text = read_from_nfc().decode("utf-8")
        if not encrypted_text:
            print("Error: No ciphertext found on NFC card.")
            return None

        # Compute shared secret
        shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public_key)

        # Derive key
        encrypted_bytes = base64.b64decode(encrypted_text)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # or 32 if you used 256-bit in encryption
            salt=None,
            info=b"ecc-xor-keystream"
        ).derive(shared_secret)

        ctr = Counter.new(64, prefix=nonce)
        stream_cipher = AES.new(derived_key, AES.MODE_CTR, counter=ctr)

        keystream = stream_cipher.encrypt(b'\x00' * len(encrypted_bytes))

        # Decrypt using XOR
        decrypted_bytes = bytes(a ^ b for a, b in zip(encrypted_bytes, keystream))
        decrypted_text = decrypted_bytes.decode()

        return decrypted_text

    except Exception as e:
        print(f"Decryption failed: {e}")
