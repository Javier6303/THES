import os
import sys
from pathlib import Path
from dotenv import load_dotenv
from modules.aes_ndef import aes_encryption, aes_decryption
from modules.aes_rsa import encrypt_with_rsa_aes, decrypt_with_rsa_aes
from smartcard.System import readers

# ------------------- ENVIRONMENT CONFIGURATION -------------------
SHOULD_DOTENV = os.getenv("SHOULD_DOTENV", "true").lower() == "true"
if SHOULD_DOTENV:
    script_path = Path(os.path.realpath(__file__))
    env_path = script_path.parent.joinpath("configs", ".env")
    load_dotenv(env_path)

CONNECTION_STR = os.getenv("CONNECTION_STR", "")
CONFIG_PATH = os.getenv("CONFIG_PATH", "")
PAT = os.getenv("PAT", "")

# ------------------- NFC FUNCTIONALITIES -------------------
def write_to_nfc_card_as_ndef(ciphertext):
    try:
        r = readers()
        if not r:
            print("No NFC readers found.")
            return
        
        reader = r[0]
        connection = reader.createConnection()
        connection.connect()

        print(f"NFC card detected using: {reader}")

        #Build NDEF message
        ndef_message = [0x03, len(ciphertext) + 7, 0xD1, 0x01, len(ciphertext) + 3, 0x54, 2] + list("en".encode()) + list(ciphertext) + [0xFE]
        while len(ndef_message) % 4 != 0:
            ndef_message.append(0x00)

        page = 4
        for i in range(0, len(ndef_message), 4):
            chunk = ndef_message[i:i + 4]
            WRITE_COMMAND = [0xFF, 0xD6, 0x00, page, 0x04] + chunk
            response, sw1, sw2 = connection.transmit(WRITE_COMMAND)
            if sw1 != 0x90 or sw2 != 0x00:
                print(f"Failed to write to page {page}. SW1: {sw1}, SW2: {sw2}")
                break
            page += 1

        print("Write operation complete.")
    except Exception as e:
        print(f"Error writing to NFC: {e}")

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
                break

        return nfc_data.rstrip(b'\x00')
    except Exception as e:
        print(f"Error reading from NFC: {e}")
        sys.exit(1)

# ------------------- MAIN PROGRAM -------------------
def main():
    print("Select Encryption Method:")
    print("1. AES-NDEF")
    print("2. AES-RSA")

    choice = input("Enter choice (1 or 2): ").strip()

    if choice == "1":
        operation = input("Enter operation ('encryption' or 'decryption'): ").strip().lower()
        if operation == "encryption":
            aes_encryption(lambda:CONFIG_PATH, write_to_nfc_card_as_ndef)
        elif operation == "decryption":
            aes_decryption(read_from_nfc_card)
        else:
            print("Invalid operation.")

    elif choice == "2":
        operation = input("Enter operation ('encryption' or 'decryption'): ").strip().lower()
        if operation == "encryption":
            encrypt_with_rsa_aes(lambda:CONFIG_PATH, write_to_nfc_card_as_ndef)
        elif operation == "decryption":
            decrypt_with_rsa_aes(read_from_nfc_card)
        else:
            print("Invalid operation.")
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
