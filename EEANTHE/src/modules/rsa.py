from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import pandas as pd
import csv

# ------------------- RSA ENCRYPTION -------------------

def generate_rsa_keypair(output_file="rsa_private.pem"):
    """Generate RSA key pair and save the private key to a file."""
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open(output_file, "wb") as f:
        f.write(private_key)

    print(f"RSA key pair generated and private key saved to '{output_file}'.")
    return public_key

def rsa_encryption(get_csv_path, write_to_nfc, output_file="rsa_private.pem"):
    """Encrypt CSV data and store ciphertext on NFC using RSA."""
    csv_file = get_csv_path()
    if not csv_file:
        return

    df = pd.read_csv(csv_file)
    first_row = df.iloc[0].tolist()
    data = ",".join(map(str, first_row)).encode()

    public_key = generate_rsa_keypair(output_file)
    public_key_obj = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(public_key_obj)

    ciphertext = cipher.encrypt(data)

    print("Writing ciphertext to NFC card...")
    write_to_nfc(ciphertext)
    print("Ciphertext successfully written to NFC!")

    return ciphertext

# ------------------- RSA DECRYPTION -------------------

def rsa_decryption(get_csv_path, read_from_nfc, input_file="rsa_private.pem", output_csv="decrypted_rsa_data.csv"):
    """Decrypt data from NFC and restore original CSV format using RSA."""
    try:
        with open(input_file, "rb") as f:
            private_key = RSA.import_key(f.read())

        ciphertext = read_from_nfc()

        if not ciphertext:
            print("Error: No ciphertext found on NFC card.")
            return

        plaintext = PKCS1_OAEP.new(private_key).decrypt(ciphertext).decode()

        decrypted_data = plaintext.split(",")

        csv_file = get_csv_path()
        if not csv_file:
            return

        df = pd.read_csv(csv_file)
        headers = df.columns.tolist()

        if len(headers) != len(decrypted_data):
            decrypted_data = decrypted_data[:len(headers)]

        with open(output_csv, "w", newline="") as csvfile:
            csv_writer = csv.writer(csvfile, quoting=csv.QUOTE_ALL)
            csv_writer.writerow(headers)
            csv_writer.writerow(decrypted_data)

        print(f"Decrypted data saved to '{output_csv}'.")

        return plaintext

    except ValueError as e:
        print(f"Decryption failed: {e}")
    except FileNotFoundError:
        print(f"Error: File '{input_file}' not found.")
