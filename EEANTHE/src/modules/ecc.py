from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
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
    save_key(f"{key_name}_private", private_pem)

    # Save public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    save_key(f"{key_name}_public", public_pem)

    print(f"New ECC Key Pair generated & stored in MongoDB: {key_name}")

    return private_key, public_key

# ------------------- ECC + XOR ENCRYPTION -------------------

def ecc_xor_encryption(patient_id, write_to_nfc, key_name="ecc_key"):
    """Encrypt CSV data using ECC XOR encryption and write to NFC."""
    patient = load_patient(patient_id)
    if not patient:
        print(f"No patient found with ID: {patient_id}")
        return None

    # Remove MongoDB-specific fields (like _id)
    patient.pop("_id", None)

    # Convert patient dict to comma-separated string
    plaintext = ",".join(str(value) for value in patient.values())

    # Generate a new ECC key pair for each session
    private_key, public_key = generate_ecc_key_pair(key_name)

    # Generate an ephemeral key pair
    ephemeral_private_key = ec.generate_private_key(ec.SECP256R1())
    ephemeral_public_key = ephemeral_private_key.public_key()

    # Compute shared secret
    shared_secret = ephemeral_private_key.exchange(ec.ECDH(), public_key)

    # Derive key
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=len(plaintext),
        salt=None,
        info=b"ecc-xor-key"
    ).derive(shared_secret)

    # Encrypt using XOR
    encrypted_bytes = bytes(a ^ b for a, b in zip(plaintext.encode(), derived_key))
    encrypted_text = base64.b64encode(encrypted_bytes).decode()

    print("Writing ciphertext to NFC card...")
    write_to_nfc(encrypted_text.encode("utf-8"))
    print("Ciphertext successfully written to NFC!")

    # Save ephemeral public key in MongoDB
    ephemeral_public_pem = ephemeral_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    save_key(f"{key_name}_ephemeral", ephemeral_public_pem)

    print(f"Ephemeral Public Key saved in MongoDB for '{key_name}'.")

    return encrypted_text

# ------------------- ECC + XOR DECRYPTION -------------------

def ecc_xor_decryption(get_csv_path, read_from_nfc, key_name="ecc_key", output_file="decrypted_ecc_data.csv"):
    """Decrypt data from NFC using ECC XOR encryption and restore CSV format."""
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
            length=len(encrypted_bytes),
            salt=None,
            info=b"ecc-xor-key"
        ).derive(shared_secret)

        # Decrypt using XOR
        decrypted_bytes = bytes(a ^ b for a, b in zip(encrypted_bytes, derived_key))
        decrypted_text = decrypted_bytes.decode()

        decrypted_data = decrypted_text.split(",")

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

        return decrypted_text

    except Exception as e:
        print(f"Decryption failed: {e}")
