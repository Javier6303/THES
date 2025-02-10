from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import os
import csv
import sys
import pandas as pd
from smartcard.System import readers

# ------------------- FILE LOCATION FIX -------------------

def get_csv_path():
    """Locate sample_patient_data.csv dynamically in the project root."""
    project_root = os.path.dirname(os.path.abspath(__file__))  # Get current script's directory
    csv_path = os.path.join(project_root, "..", "sample_patient_data.csv")  # Move up one level

    if not os.path.exists(csv_path):
        print(f"Error: CSV file '{csv_path}' not found. Ensure it's in the project directory!")
        return None

    return csv_path

def get_file_path(filename):
    """Get absolute path for files inside the current working directory."""
    return os.path.join(os.getcwd(), filename)

# ------------------- AES + RSA ENCRYPTION -------------------

def generate_rsa_keypair():
    """Generate RSA key pair and save private key in the current directory."""
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    private_key_path = get_file_path("aes_rsa_private.pem")
    with open(private_key_path, "wb") as f:
        f.write(private_key)

    print(f"RSA key pair generated and private key saved to '{private_key_path}'.")
    return public_key  # Return only public key

def encrypt_with_rsa_aes(plaintext, rsa_public_key):
    """Encrypt plaintext using AES and encrypt the AES key with RSA."""
    aes_key = get_random_bytes(16)  # Generate AES key (16 bytes)

    cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
    enc_aes_key = cipher_rsa.encrypt(aes_key)  # Encrypt AES key with RSA

    cipher_aes = AES.new(aes_key, AES.MODE_OCB)
    ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext.encode())  # Encrypt with AES

    enc_file_path = get_file_path("aes_rsa_encrypted.bin")
    with open(enc_file_path, "wb") as f:
        f.write(enc_aes_key)  # RSA-encrypted AES key (256 bytes)
        f.write(cipher_aes.nonce)  # AES nonce (15 bytes)
        f.write(tag)  # AES authentication tag (16 bytes)

    return ciphertext

def decrypt_with_rsa_aes(ciphertext):
    """Decrypt ciphertext using stored RSA private key to unlock AES key."""
    private_key_path = get_file_path("aes_rsa_private.pem")
    enc_file_path = get_file_path("aes_rsa_encrypted.bin")

    try:
        with open(private_key_path, "rb") as f:
            rsa_private_key = RSA.import_key(f.read())
    except FileNotFoundError:
        print(f"Error: Private key file '{private_key_path}' not found.")
        return None

    with open(enc_file_path, "rb") as f:
        enc_aes_key = f.read(256)  # RSA-encrypted AES key
        nonce = f.read(15)  # AES nonce
        tag = f.read(16)  # AES authentication tag

    cipher_rsa = PKCS1_OAEP.new(rsa_private_key)
    aes_key = cipher_rsa.decrypt(enc_aes_key)  # Decrypt AES key

    cipher_aes = AES.new(aes_key, AES.MODE_OCB, nonce=nonce)
    decrypted_text = cipher_aes.decrypt_and_verify(ciphertext, tag).decode()

    return decrypted_text

# ------------------- NFC FUNCTIONALITIES -------------------

def write_to_nfc_card_as_ndef(ciphertext):
    """Writes AES-encrypted ciphertext to NFC as an NDEF record."""
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
            chunk = ndef_message[i:i + 4]
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
    """Reads encrypted text from NFC and extracts ciphertext."""
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
        for page in range(4, 225):  # Read until max writable memory
            READ_COMMAND = [0xFF, 0xB0, 0x00, page, 0x04]
            response, sw1, sw2 = connection.transmit(READ_COMMAND)
            if sw1 == 0x90 and sw2 == 0x00:
                nfc_data += bytes(response)
            else:
                print(f"Failed to read page {page}. SW1: {sw1}, SW2: {sw2}")
                break

        nfc_data = nfc_data.rstrip(b'\x00')
        print("Successfully read data from NFC card.")

        return parse_ndef_message(nfc_data)

    except Exception as e:
        print(f"Error reading from NFC: {e}")
        sys.exit(1)

def parse_ndef_message(nfc_data):
    """Parse NDEF message and extract ciphertext."""
    print(f"Raw NDEF Data (Hex): {nfc_data.hex()}")

    if nfc_data[0] != 0x03:
        raise ValueError("Invalid NDEF message format.")

    payload_length = nfc_data[1]
    language_code_length = nfc_data[6]
    ciphertext_start = 7 + language_code_length
    ciphertext_end = ciphertext_start + (payload_length - (3 + language_code_length))
    ciphertext = nfc_data[ciphertext_start:ciphertext_end]

    if ciphertext.endswith(b'\xFE'):
        ciphertext = ciphertext[:-1]

    print(f"Extracted Ciphertext (Hex): {ciphertext.hex()}")
    return ciphertext

# ------------------- MAIN FUNCTION -------------------

def encrypt_csv():
    """Encrypt CSV data and store ciphertext on NFC."""
    csv_file = get_csv_path()
    if not csv_file:
        return

    df = pd.read_csv(csv_file)
    headers = df.columns.tolist()
    first_row = df.iloc[0].tolist()

    plaintext = ",".join(map(str, first_row))
    public_key = generate_rsa_keypair()
    ciphertext = encrypt_with_rsa_aes(plaintext, RSA.import_key(public_key))

    print("Writing ciphertext to NFC...")
    write_to_nfc_card_as_ndef(ciphertext)

    return headers, ciphertext

def decrypt_csv(output_file="aes_rsa_decrypted_data.csv"):
    """Decrypt data from NFC and restore original CSV format."""
    ciphertext = read_from_nfc_card()
    plaintext = decrypt_with_rsa_aes(ciphertext)

    if plaintext is None:
        print("Error: Decryption failed.")
        return

    decrypted_data = plaintext.split(",")  # Convert plaintext back to list format

    csv_file = get_csv_path()
    if not csv_file:
        return  # Exit if CSV file is missing

    df = pd.read_csv(csv_file)
    headers = df.columns.tolist()

    # Ensure we only write the correct number of columns
    if len(headers) != len(decrypted_data):
        decrypted_data = decrypted_data[:len(headers)]

    # Save decrypted data to CSV
    output_path = get_file_path(output_file)
    with open(output_path, "w", newline="") as csvfile:
        csv_writer = csv.writer(csvfile, quoting=csv.QUOTE_ALL)
        csv_writer.writerow(headers)
        csv_writer.writerow(decrypted_data)



def main():
    operation = input("Enter operation ('encryption' or 'decryption'): ").strip().lower()

    if operation == "encryption":
        encrypt_csv()
    elif operation == "decryption":
        decrypt_csv(output_file="aes_rsa_decrypted_data.csv")  # Now writes to a file
    else:
        print("Invalid operation.")


if __name__ == "__main__":
    main()
