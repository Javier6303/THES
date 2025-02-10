from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from smartcard.System import readers
import csv
import sys
import pandas as pd
import os

# ------------------- FILE LOCATION FIX -------------------

def get_csv_path():
    """Locate sample_patient_data.csv dynamically anywhere in the project."""
    project_root = os.path.dirname(os.path.abspath(__file__))  # Get the script's directory
    csv_path = os.path.join(project_root, "..", "sample_patient_data.csv")  # Move up one level

    if not os.path.exists(csv_path):
        print(f"Error: CSV file '{csv_path}' not found. Ensure it's in the project root directory!")
        return None

    return csv_path

# ------------------- NFC FUNCTIONS -------------------

def write_to_nfc_card_as_ndef(ciphertext):
    """Writes RSA-encrypted ciphertext to NFC as an NDEF record."""
    try:
        r = readers()
        if not r:
            print("No NFC readers found.")
            return

        reader = r[0]
        connection = reader.createConnection()
        connection.connect()

        print(f"NFC card detected using: {reader}")

        # Build NDEF message
        language_code = "en"
        language_code_length = len(language_code)
        ciphertext_length = len(ciphertext)

        ndef_message = [
            0x03,
            ciphertext_length + 7,
            0xD1,
            0x01,
            ciphertext_length + 3,
            0x54,
            language_code_length,
        ] + list(language_code.encode("utf-8")) + list(ciphertext) + [0xFE]

        while len(ndef_message) % 4 != 0:
            ndef_message.append(0x00)

        print(f"Writing NDEF message with length: {len(ndef_message)} bytes")

        page = 4
        for i in range(0, len(ndef_message), 4):
            chunk = ndef_message[i:i+4]
            WRITE_COMMAND = [0xFF, 0xD6, 0x00, page, 0x04] + list(chunk)
            response, sw1, sw2 = connection.transmit(WRITE_COMMAND)
            if sw1 == 0x90 and sw2 == 0x00:
                print(f"Successfully wrote to page {page}: {chunk}")
                page += 1
            else:
                print(f"Failed to write to page {page}. SW1: {sw1}, SW2: {sw2}")
                break

        print("Write operation complete.")

    except Exception as e:
        print(f"Error writing to NFC: {e}")

def read_from_nfc_card():
    """Reads RSA-encrypted text from NFC."""
    try:
        r = readers()
        if not r:
            print("No NFC readers found.")
            sys.exit(1)

        reader = r[0]
        connection = reader.createConnection()
        connection.connect()

        print(f"NFC card detected using: {reader}")

        nfc_data = b""
        for page in range(4, 225):
            READ_COMMAND = [0xFF, 0xB0, 0x00, page, 0x04]
            response, sw1, sw2 = connection.transmit(READ_COMMAND)
            if sw1 == 0x90 and sw2 == 0x00:
                nfc_data += bytes(response)
            else:
                print(f"Failed to read page {page}. SW1: {sw1}, SW2: {sw2}")
                break

        nfc_data = nfc_data.rstrip(b'\x00')
        print("Successfully read data from NFC card.")

        return extract_ciphertext(nfc_data)

    except Exception as e:
        print(f"Error reading from NFC: {e}")
        sys.exit(1)

def extract_ciphertext(nfc_data):
    """Extract ciphertext from NFC card following RSA-style parsing."""
    if len(nfc_data) < 10:
        raise ValueError("Invalid NFC data length.")

    if nfc_data[0] != 0x03:
        raise ValueError("Invalid NDEF message format.")

    index = 2
    while index < len(nfc_data) and nfc_data[index] != 0x54:
        index += 1

    if index >= len(nfc_data) - 1:
        raise ValueError("Ciphertext not found in NFC data!")

    language_code_length = nfc_data[index + 1]
    ciphertext_start = index + 2 + language_code_length
    ciphertext = nfc_data[ciphertext_start:]

    if ciphertext.endswith(b'\xFE'):
        ciphertext = ciphertext[:-1]

    print(f"Ciphertext Length Extracted: {len(ciphertext)} bytes")

    return ciphertext

# ------------------- RSA ENCRYPTION -------------------

def generate_rsa_keypair():
    """Generate RSA key pair and save private key to a file."""
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open("rsa_private.pem", "wb") as f:
        f.write(private_key)

    print("RSA key pair generated and private key saved to 'rsa_private.pem'.")
    return public_key

def rsa_encrypt(output_file="rsa_private.pem"):
    """Encrypt CSV data and store ciphertext on NFC."""
    csv_file = get_csv_path()
    if not csv_file:
        return  # Exit if CSV file is missing

    df = pd.read_csv(csv_file)
    headers = df.columns.tolist()
    first_row = df.iloc[0].tolist()

    data = ",".join(map(str, first_row)).encode()

    public_key = generate_rsa_keypair()
    public_key_obj = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(public_key_obj)
    ciphertext = cipher.encrypt(data)

    print(f"Ciphertext length after encryption: {len(ciphertext)} bytes")

    print("Writing ciphertext to NFC card...")
    write_to_nfc_card_as_ndef(ciphertext)
    print("Ciphertext successfully written to NFC!")

    return headers, ciphertext

# ------------------- RSA DECRYPTION -------------------

def rsa_decrypt(output_csv="decrypted_rsa_data.csv"):
    """Decrypt data from NFC and restore original CSV format using stored RSA private key."""
    try:
        with open("rsa_private.pem", "rb") as f:
            private_key = RSA.import_key(f.read())

        ciphertext = read_from_nfc_card()
        plaintext = PKCS1_OAEP.new(private_key).decrypt(ciphertext).decode()
        print("Decryption successful!")

        decrypted_data = plaintext.split(",")

        csv_file = get_csv_path()
        if not csv_file:
            return  # Exit if CSV file is missing

        df = pd.read_csv(csv_file)
        headers = df.columns.tolist()

        if len(headers) != len(decrypted_data):
            decrypted_data = decrypted_data[:len(headers)]

        with open(output_csv, "w", newline="") as csvfile:
            csv_writer = csv.writer(csvfile, quoting=csv.QUOTE_ALL)
            csv_writer.writerow(headers)
            csv_writer.writerow(decrypted_data)

        print(f"Decrypted data saved to '{output_csv}'.")

    except ValueError as e:
        print(f"Decryption failed: {e}")
        sys.exit(1)

# ------------------- MAIN FUNCTION -------------------

def main():
    operation = input("Enter operation ('encryption' or 'decryption'): ").strip().lower()

    if operation == "encryption":
        rsa_encrypt()

    elif operation == "decryption":
        rsa_decrypt()

    else:
        print("Invalid operation. Please enter 'encryption' or 'decryption'.")

if __name__ == "__main__":
    main()
