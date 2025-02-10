from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
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
        print(f"Error: {e}")

def parse_ndef_message(nfc_data):
    """Parse NDEF message and extract ciphertext."""
    print(f"Raw NDEF data: {nfc_data.hex()}")

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

def read_from_nfc_card():
    """Reads encrypted text from NFC."""
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
        for page in range(4, 222):
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
        print(f"Error: {e}")
        sys.exit(1)

# ------------------- AES ENCRYPTION -------------------

def aes_encryption_with_ndef(output_file="encrypted.bin"):
    csv_file = get_csv_path()
    if not csv_file:
        return  # Exit if CSV file is missing

    df = pd.read_csv(csv_file)
    headers = df.columns.tolist()
    first_row = df.iloc[0].tolist()

    data = ",".join(map(str, first_row))

    aes_key = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_OCB)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())

    with open(output_file, "wb") as f:
        f.write(aes_key)
        f.write(tag)
        f.write(cipher.nonce)

    print(f"AES key, tag, and nonce saved to '{output_file}'.")

    print("Writing ciphertext to NFC card as NDEF record...")
    write_to_nfc_card_as_ndef(ciphertext)
    print("Ciphertext successfully written to NFC as NDEF Text Record!")

    return headers, aes_key, tag, cipher.nonce, ciphertext

# ------------------- AES DECRYPTION -------------------

def aes_decryption_from_nfc(input_file="encrypted.bin", output_csv="decrypted_aes_data.csv"):
    try:
        with open(input_file, "rb") as f:
            aes_key = f.read(16)
            tag = f.read(16)
            nonce = f.read(15)

        print("Reading ciphertext from NFC card...")
        ciphertext = read_from_nfc_card()

        print(f"Ciphertext length: {len(ciphertext)} bytes")
        if len(ciphertext) == 0:
            raise ValueError("No ciphertext found on NFC card.")

        cipher = AES.new(aes_key, AES.MODE_OCB, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag).decode()
        print("Decryption successful!")

        decrypted_data = plaintext.split(",")
        print(f"Decrypted data: {decrypted_data}")

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

        return decrypted_data

    except ValueError as e:
        print(f"Decryption failed: {e}")
        sys.exit(1)
    except FileNotFoundError:
        print(f"Error: File '{input_file}' not found.")
        sys.exit(1)

# ------------------- MAIN FUNCTION -------------------

def main():
    global headers

    operation = input("Enter operation ('encryption' or 'decryption'): ").strip().lower()

    if operation == "encryption":
        headers, aes_key, tag, nonce, ciphertext = aes_encryption_with_ndef(output_file="encrypted.bin")

    elif operation == "decryption":
        if 'headers' not in globals():
            csv_file = get_csv_path()
            if csv_file:
                df = pd.read_csv(csv_file)
                headers = df.columns.tolist()

        aes_decryption_from_nfc(input_file="encrypted.bin", output_csv="decrypted_aes_data.csv")

    else:
        print("Invalid operation. Please enter 'encryption' or 'decryption'.")

if __name__ == "__main__":
    main()
