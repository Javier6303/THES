import numpy as np
import csv
import sys
import pandas as pd
import os
from smartcard.System import readers

# ------------------- DYNAMIC FILE PATH -------------------

def get_csv_path():
    """Locate sample_patient_data.csv dynamically anywhere in the project."""
    project_root = os.path.dirname(os.path.abspath(__file__))  # Get the script's directory
    csv_path = os.path.join(project_root, "..", "sample_patient_data.csv")  # Move up one level

    if not os.path.exists(csv_path):
        print(f"Error: CSV file '{csv_path}' not found. Ensure it's in the project root directory!")
        return None

    return csv_path

# ------------------- CUSTOM ALPHABET -------------------

CUSTOM_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789,|.@#$/:-_()[]{}!?%&+=*\"' "
ALPHABET_SIZE = len(CUSTOM_ALPHABET)

def char_to_index(char):
    """Convert character to index based on CUSTOM_ALPHABET."""
    return CUSTOM_ALPHABET.index(char) if char in CUSTOM_ALPHABET else CUSTOM_ALPHABET.index(" ")

def index_to_char(index):
    """Convert index back to a character in CUSTOM_ALPHABET."""
    return CUSTOM_ALPHABET[index % ALPHABET_SIZE]

def text_to_numbers(text):
    """Convert text to a list of numbers based on CUSTOM_ALPHABET."""
    return [char_to_index(c) for c in text]

def numbers_to_text(numbers):
    """Convert a list of numbers back to text using CUSTOM_ALPHABET."""
    return "".join(index_to_char(n) for n in numbers)

# ------------------- HILL CIPHER FUNCTIONS -------------------

def hill_encrypt(plaintext, key_matrix):
    """Encrypts plaintext using Hill Cipher."""
    indexes = text_to_numbers(plaintext)

    while len(indexes) % len(key_matrix) != 0:
        indexes.append(char_to_index(" "))  # Pad with space

    ciphertext_indexes = []
    for i in range(0, len(indexes), len(key_matrix)):
        chunk = indexes[i:i + len(key_matrix)]
        encrypted_chunk = np.dot(key_matrix, chunk) % ALPHABET_SIZE
        ciphertext_indexes.extend(encrypted_chunk)

    return numbers_to_text(ciphertext_indexes)

def hill_decrypt(ciphertext, key_matrix_inv):
    """Decrypts ciphertext using Hill Cipher."""
    indexes = text_to_numbers(ciphertext)

    decrypted_indexes = []
    for i in range(0, len(indexes), len(key_matrix_inv)):
        chunk = indexes[i:i + len(key_matrix_inv)]
        decrypted_chunk = np.dot(key_matrix_inv, chunk) % ALPHABET_SIZE
        decrypted_indexes.extend(decrypted_chunk)

    return numbers_to_text(decrypted_indexes).strip()

def mod_inverse_matrix(matrix, mod=ALPHABET_SIZE):
    """Finds the modular inverse of a matrix under mod ALPHABET_SIZE."""
    det = int(np.round(np.linalg.det(matrix)))
    det_inv = pow(det, -1, mod)
    matrix_inv = np.round(det_inv * np.linalg.det(matrix) * np.linalg.inv(matrix)).astype(int) % mod
    return matrix_inv

# ------------------- NFC FUNCTIONALITIES -------------------

def write_to_nfc_card_as_ndef(ciphertext):
    """Writes encrypted text to NFC as an NDEF record."""
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
        ] + list(language_code.encode("utf-8")) + list(ciphertext.encode("utf-8")) + [0xFE]

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
    """Reads encrypted text from NFC and extracts ciphertext properly."""
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

        return parse_ndef_message(nfc_data)

    except Exception as e:
        print(f"Error reading from NFC: {e}")
        sys.exit(1)

def parse_ndef_message(nfc_data):
    """Parse NDEF message (same parsing method as AES)."""
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
    return ciphertext.decode("utf-8")

# ------------------- MAIN FUNCTION -------------------

def encrypt_csv(key_matrix):
    """Encrypts CSV and writes ciphertext to NFC."""
    csv_file = get_csv_path()
    if not csv_file:
        return

    df = pd.read_csv(csv_file)
    headers = df.columns.tolist()
    first_row = df.iloc[0].tolist()

    plaintext = ",".join(map(str, first_row))
    ciphertext = hill_encrypt(plaintext, key_matrix)

    print("Writing ciphertext to NFC...")
    write_to_nfc_card_as_ndef(ciphertext)

    return headers, ciphertext

def decrypt_csv(key_matrix_inv, output_file="decrypted_hill_data.csv"):
    """Reads ciphertext from NFC and restores original CSV format."""
    ciphertext = read_from_nfc_card()
    plaintext = hill_decrypt(ciphertext, key_matrix_inv)
    decrypted_data = plaintext.split(",")

    csv_file = get_csv_path()
    if not csv_file:
        return

    df = pd.read_csv(csv_file)
    headers = df.columns.tolist()

    if len(headers) != len(decrypted_data):
        decrypted_data = decrypted_data[:len(headers)]

    with open(output_file, "w", newline="") as csvfile:
        csv_writer = csv.writer(csvfile, quoting=csv.QUOTE_ALL)
        csv_writer.writerow(headers)
        csv_writer.writerow(decrypted_data)

    print(f"Decrypted data saved to '{output_file}'.")

def main():
    key_matrix = np.array([[3, 3], [2, 5]])
    key_matrix_inv = mod_inverse_matrix(key_matrix)

    operation = input("Enter operation ('encryption' or 'decryption'): ").strip().lower()

    if operation == "encryption":
        encrypt_csv(key_matrix)

    elif operation == "decryption":
        decrypt_csv(key_matrix_inv)

    else:
        print("Invalid operation.")

if __name__ == "__main__":
    main()
