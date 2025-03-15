from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from Crypto.Cipher import AES
import base64
import pandas as pd
import csv
from modules.db_manager import save_key, load_key, load_patient  # Import MongoDB functions

# ------------------- ECC KEY GENERATION -------------------

def generate_ecdh_key_pair(key_name="ecdh_key"):
    """Generate ECC Private-Public Key Pair and store in MongoDB."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    # Save private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    save_key(f"{key_name}_private", private_pem)

    # Save public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    save_key(f"{key_name}_public", public_pem)

    print(f"New ECC Key Pair generated & stored in MongoDB: {key_name}")

    return private_key, public_key

# ------------------- ECDH + AES-GCM ENCRYPTION -------------------

def ecdh_aes_encryption(patient_id, write_to_nfc, key_name="ecdh_key"):
    """Encrypt CSV data using ECDH for key derivation and AES-GCM for encryption."""
    patient = load_patient(patient_id)
    if not patient:
        print(f"No patient found with ID: {patient_id}")
        return None

    # Remove MongoDB-specific fields (like _id)
    patient.pop("_id", None)

    # Convert patient dict to comma-separated string
    plaintext = ",".join(str(value) for value in patient.values()).encode()

    # Generate a new ECC key pair for each session
    private_key, public_key = generate_ecdh_key_pair(key_name)

    # Generate an ephemeral key pair
    ephemeral_private_key = ec.generate_private_key(ec.SECP256R1())
    ephemeral_public_key = ephemeral_private_key.public_key()

    # Compute shared secret
    shared_secret = ephemeral_private_key.exchange(ec.ECDH(), public_key)

    # Derive a 256-bit AES key using HKDF
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit key
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
    save_key(f"{key_name}_ephemeral", ephemeral_public_pem)
    save_key(f"{key_name}_nonce", nonce)
    save_key(f"{key_name}_tag", tag)

    print(f"Ephemeral Public Key, Nonce, and Tag saved in MongoDB for '{key_name}'.")

    return ciphertext

# ------------------- ECDH + AES-GCM DECRYPTION -------------------

def ecdh_aes_decryption(get_csv_path, read_from_nfc, key_name="ecdh_key", output_file="decrypted_ecdh_aes_data.csv"):
    """Decrypt data from NFC using ECDH for key derivation and AES-GCM for decryption."""
    try:
        # Retrieve private key from MongoDB
        private_key_data = load_key(f"{key_name}_private")
        if not private_key_data:
            print(f"Error: ECC Private Key '{key_name}_private' not found in MongoDB.")
            return None
        private_key = serialization.load_pem_private_key(private_key_data, password=None)

        # Retrieve ephemeral public key from MongoDB
        ephemeral_public_key_data = load_key(f"{key_name}_ephemeral")
        if not ephemeral_public_key_data:
            print(f"Error: ECC Ephemeral Public Key '{key_name}_ephemeral' not found in MongoDB.")
            return None
        ephemeral_public_key = serialization.load_pem_public_key(ephemeral_public_key_data)

        # Retrieve nonce and tag from MongoDB
        nonce = load_key(f"{key_name}_nonce")
        tag = load_key(f"{key_name}_tag")
        if not nonce or not tag:
            print("Error: AES-GCM Nonce or Tag not found in MongoDB.")
            return None

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
            length=32,  # 256-bit key
            salt=None,
            info=b"ecdh-aes-gcm-key"
        ).derive(shared_secret)

        # Decrypt using AES-GCM
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag).decode()

        decrypted_data = plaintext.split(",")

        csv_file = get_csv_path()
        if not csv_file:
            return None

        df = pd.read_csv(csv_file)
        headers = df.columns.tolist()

        if len(headers) != len(decrypted_data):
            decrypted_data = decrypted_data[:len(headers)]

        with open(output_file, "w", newline="") as csvfile:
            csv_writer = csv.writer(csvfile, quoting=csv.QUOTE_ALL)
            csv_writer.writerow(headers)
            csv_writer.writerow(decrypted_data)

        print(f"Decrypted data saved to '{output_file}'.")

        return plaintext

    except Exception as e:
        print(f"Decryption failed: {e}")
