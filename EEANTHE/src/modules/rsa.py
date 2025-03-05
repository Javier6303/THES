from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import pandas as pd
import csv
from modules.db_manager import save_key, load_key  # Import MongoDB functions


# ------------------- RSA ENCRYPTION -------------------

def generate_rsa_keypair(key_name="rsa_key"):
    """Generate RSA key pair and save the private key to a file."""
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    save_key(f"{key_name}_private", private_key)
    save_key(f"{key_name}_public", public_key)
    
    return public_key

def rsa_encryption(get_csv_path, write_to_nfc, key_name="rsa_key"):
    """Encrypt CSV data and store ciphertext on NFC using RSA."""
    csv_file = get_csv_path()
    if not csv_file:
        return

    df = pd.read_csv(csv_file)
    first_row = df.iloc[0].tolist()
    data = ",".join(map(str, first_row)).encode()

    
    public_key_data = generate_rsa_keypair(key_name)

    public_key = RSA.import_key(public_key_data)
    cipher = PKCS1_OAEP.new(public_key)

    ciphertext = cipher.encrypt(data)

    print("Writing ciphertext to NFC card...")
    write_to_nfc(ciphertext)
    print("Ciphertext successfully written to NFC!")

    return ciphertext

# ------------------- RSA DECRYPTION -------------------

def rsa_decryption(get_csv_path, read_from_nfc, key_name="rsa_key", output_csv="decrypted_rsa_data.csv"):
    """Decrypt data from NFC and restore original CSV format using RSA with keys from MongoDB."""
    try:
        private_key_data = load_key(f"{key_name}_private")
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

