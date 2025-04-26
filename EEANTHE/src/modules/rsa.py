from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import pandas as pd
import csv
from modules.db_manager import save_key, load_key, load_patient  # Import MongoDB functions


# ------------------- RSA ENCRYPTION -------------------

def generate_rsa_keypair(patient_id, key_name="rsa_key"):
    """Generate RSA key pair and save the private key to a file."""
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    save_key(f"{key_name}_private", private_key, patient_id)
    save_key(f"{key_name}_public", public_key, patient_id)
    
    return public_key

def rsa_encryption(patient_id, write_to_nfc, key_name="rsa_key"):
    """Encrypt CSV data and store ciphertext on NFC using RSA."""
    patient = load_patient(patient_id)
    if not patient:
        print(f"No patient found with ID: {patient_id}")
        return None

    patient.pop("_id", None)  # Remove MongoDB internal ID if present
    data = ",".join(str(value) for value in patient.values()).encode()

    public_key_data = generate_rsa_keypair(patient_id, key_name)
    public_key = RSA.import_key(public_key_data)
    cipher = PKCS1_OAEP.new(public_key)

    max_length = (public_key.size_in_bits() // 8) - 42  # 42 bytes overhead for OAEP
    if len(data) > max_length:
        print(f"Error: Patient data too large for RSA encryption. Limit is {max_length} bytes.")
        return None
    
    ciphertext = cipher.encrypt(data)

    print("Writing ciphertext to NFC card...")
    write_to_nfc(ciphertext)
    print("Ciphertext successfully written to NFC!")

    return ciphertext

# ------------------- RSA DECRYPTION -------------------

def rsa_decryption(get_csv_path, read_from_nfc, patient_id, preloaded_keys=None, key_name="rsa_key", output_csv="decrypted_rsa_data.csv"):
    """Decrypt data from NFC and restore original CSV format using RSA with keys from MongoDB."""
    try:
        if preloaded_keys:
            private_key_data = preloaded_keys.get(f"{key_name}_private", None)
            
        if not private_key_data:
            print(f"Error: No private key found in MongoDB for '{key_name}'.")
            return None

        private_key = RSA.import_key(private_key_data)

        ciphertext = read_from_nfc()

        if not ciphertext:
            print("Error: No ciphertext found on NFC card.")
            return None

        plaintext = PKCS1_OAEP.new(private_key).decrypt(ciphertext).decode()

        decrypted_data = plaintext.split(",")

        csv_file = get_csv_path()
        if not csv_file:
            return None

        df = pd.read_csv(csv_file)
        headers = df.columns.tolist()

        if len(headers) != len(decrypted_data):
            decrypted_data = decrypted_data[:len(headers)]

        with open(output_csv, "w", newline="") as csvfile:
            csv_writer = csv.writer(csvfile, quoting=csv.QUOTE_ALL)
            csv_writer.writerow(headers)
            csv_writer.writerow(decrypted_data)

        print(f"Decrypted data saved to '{output_csv}'.")

        return plaintext.encode()  # Return plaintext as bytes for throughput calculation

    except ValueError as e:
        print(f"Decryption failed: {e}")
    return None

