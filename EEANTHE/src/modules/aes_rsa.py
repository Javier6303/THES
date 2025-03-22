from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import pandas as pd
import csv
from modules.db_manager import save_key, load_key, load_patient  # Import MongoDB functions


# ------------------- RSA KEY GENERATION -------------------

def generate_rsa_keypair(patient_id, key_name="aes_rsa_key"):
    """Generate a new RSA key pair and save it in MongoDB."""
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    save_key(f"{key_name}_private", private_key, patient_id)
    save_key(f"{key_name}_public", public_key,  patient_id)

    print("New RSA Key Pair Generated & Stored in MongoDB.")
    return public_key


# ------------------- AES + RSA ENCRYPTION -------------------

def aes_rsa_encryption(patient_id, write_to_nfc, key_name="aes_rsa_key"):
    """Encrypt CSV data with AES and RSA, then write to NFC."""
    patient = load_patient(patient_id)
    if not patient:
        print(f"No patient found with ID: {patient_id}")
        return None

    patient.pop("_id", None)  # Remove internal MongoDB ID
    plaintext = ",".join(str(value) for value in patient.values())

    # Generate AES key for session
    aes_key = get_random_bytes(16)

    # Generate new RSA key pair for this encryption session
    public_key = generate_rsa_keypair(patient_id, key_name)
    public_key_obj = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(public_key_obj)

    # Encrypt the AES key with RSA
    enc_aes_key = cipher_rsa.encrypt(aes_key)

    # Encrypt the plaintext using AES
    cipher_aes = AES.new(aes_key, AES.MODE_OCB)
    ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext.encode())

    # Write encrypted data to NFC
    print("Writing ciphertext to NFC card...")
    write_to_nfc(ciphertext)
    print("Ciphertext successfully written to NFC!")

    # Store encrypted AES key, nonce, and tag separately
    save_key(f"{key_name}_enc_aes_key", enc_aes_key, patient_id)  # Store encrypted AES key (256 bytes)
    save_key(f"{key_name}_aes_nonce", cipher_aes.nonce, patient_id)  # Store AES nonce (15 bytes)
    save_key(f"{key_name}_aes_tag", tag, patient_id)  # Store AES authentication tag (16 bytes)

    return ciphertext  # Return encrypted data for performance metrics


# ------------------- AES + RSA DECRYPTION -------------------

def aes_rsa_decryption(get_csv_path, read_from_nfc, patient_id, key_name="aes_rsa_key", output_csv="decrypted_aes_rsa_data.csv"):
    """Decrypt data from NFC and restore the original CSV format using AES-RSA hybrid encryption."""
    try:
        # Retrieve private RSA key from MongoDB
        private_key_data = load_key(f"{key_name}_private", patient_id)
        if not private_key_data:
            print(f"Error: No private key found in MongoDB for '{key_name}'.")
            return None

        rsa_private_key = RSA.import_key(private_key_data)

        # Read encrypted ciphertext from NFC
        ciphertext = read_from_nfc()
        if not ciphertext:
            print("Error: No ciphertext found on NFC card.")
            return None

        # Retrieve encrypted AES key, nonce, and tag from MongoDB
        enc_aes_key = load_key(f"{key_name}_enc_aes_key", patient_id)
        nonce = load_key(f"{key_name}_aes_nonce", patient_id)
        tag = load_key(f"{key_name}_aes_tag", patient_id)

        if not enc_aes_key or not nonce or not tag:
            print(f"Error: AES key components missing in MongoDB for '{key_name}'.")
            return None

        # Decrypt AES key using RSA
        cipher_rsa = PKCS1_OAEP.new(rsa_private_key)
        aes_key = cipher_rsa.decrypt(enc_aes_key)

        # Decrypt the ciphertext using AES
        cipher_aes = AES.new(aes_key, AES.MODE_OCB, nonce=nonce)
        plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag).decode()

        decrypted_data = plaintext.split(",")

        # Read CSV headers
        csv_file = get_csv_path()
        if not csv_file:
            return None  # No CSV file, exit early

        df = pd.read_csv(csv_file)
        headers = df.columns.tolist()

        # Ensure decrypted data matches the header count
        if len(headers) != len(decrypted_data):
            decrypted_data = decrypted_data[:len(headers)]

        # Save decrypted data to CSV
        with open(output_csv, "w", newline="") as csvfile:
            csv_writer = csv.writer(csvfile, quoting=csv.QUOTE_ALL)
            csv_writer.writerow(headers)
            csv_writer.writerow(decrypted_data)

        print(f"Decrypted data saved to '{output_csv}'.")
        return plaintext.encode()  # Return decrypted data for performance tracking

    except ValueError as e:
        print(f"Decryption failed: {e}")
    return None
