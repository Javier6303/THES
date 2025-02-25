import os
import sys
import tracemalloc
import time
import logging
from pathlib import Path
from dotenv import load_dotenv
from modules.aes_ndef import aes_encryption, aes_decryption
from modules.aes_rsa import aes_rsa_encryption, aes_rsa_decryption
from modules.rsa import rsa_encryption, rsa_decryption
from modules.hill_cipher import hill_cipher_encryption, hill_cipher_decryption
from modules.ecc import ecc_xor_encryption, ecc_xor_decryption

from smartcard.System import readers

# ------------------- LOGGER CONFIGURATION -------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("encryption.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

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
            logger.error("No NFC readers found.")
            return
        
        reader = r[0]
        connection = reader.createConnection()
        connection.connect()

        logger.info(f"NFC card detected using: {reader}")

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
                logger.error(f"Failed to write to page {page}. SW1: {sw1}, SW2: {sw2}")
                break
            page += 1

        logger.info("Write operation complete.")
    except Exception as e:
        logger.exception(f"Error writing to NFC: {e}")

def parse_ndef_message(nfc_data, asymmetric_mode=False):
    """Parse NDEF message and extract ciphertext."""
    print(f"Raw NDEF data: {nfc_data.hex()}")

    if len(nfc_data) < 10:
        raise ValueError("Invalid NFC data length.")

    if nfc_data[0] != 0x03:
        raise ValueError("Invalid NDEF message format.")

    if asymmetric_mode:
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

    else:
        payload_length = nfc_data[1]
        language_code_length = nfc_data[6]
        ciphertext_start = 7 + language_code_length
        ciphertext_end = ciphertext_start + (payload_length - (3 + language_code_length))
        ciphertext = nfc_data[ciphertext_start:ciphertext_end]

        if ciphertext.endswith(b'\xFE'):
            ciphertext = ciphertext[:-1]

    print(f"Extracted Ciphertext (Hex): {ciphertext.hex()}")
    return ciphertext

def read_from_nfc_card(asymmetric_mode=False):
    """Reads encrypted text from NFC."""
    try:
        r = readers()
        if not r:
            logger.error("No NFC readers found.")
            sys.exit(1)

        reader = r[0]
        connection = reader.createConnection()
        connection.connect()

        logger.info(f"NFC card detected using: {reader}")

        nfc_data = b""
        for page in range(4, 222):
            READ_COMMAND = [0xFF, 0xB0, 0x00, page, 0x04]
            response, sw1, sw2 = connection.transmit(READ_COMMAND)
            if sw1 == 0x90 and sw2 == 0x00:
                nfc_data += bytes(response)
            else:
                logger.error(f"Failed to read page {page}. SW1: {sw1}, SW2: {sw2}")
                break

        nfc_data = nfc_data.rstrip(b'\x00')
        logger.info("Successfully read data from NFC card.")

        return parse_ndef_message(nfc_data, asymmetric_mode=asymmetric_mode)

    except Exception as e:
        logger.exception(f"Error reading from NFC: {e}")
        sys.exit(1)

def measure_performance(operation, encryption_func, decryption_func, config_func, nfc_write_func, nfc_read_func):
    metrics = {}

    if operation == "1":  # Encryption
        print("Starting Encryption...")
        tracemalloc.start()
        start_time = time.time()

        # Execute the encryption function
        encrypted_data = encryption_func(config_func, nfc_write_func)

        encryption_time = time.time() - start_time
        current, peak = tracemalloc.get_traced_memory()  # Get current and peak memory usage
        tracemalloc.stop()

        # Calculate data size based on the actual encrypted data
        data_size = len(encrypted_data.encode()) if isinstance(encrypted_data, str) else len(encrypted_data) if encrypted_data else 0

        metrics["encryption_latency"] = encryption_time
        metrics["encryption_throughput"] = data_size / encryption_time if encryption_time > 0 else 0
        metrics["encryption_memory_usage"] = {"current": current, "peak": peak}

        print(f"Encryption data: {encrypted_data}")
        logger.info(f"Encryption completed. Time: {encryption_time}s, Memory Usage: {peak / 1024:.2f} KB")

    elif operation == "2":  # Decryption
        print("Starting Decryption...")
        tracemalloc.start()
        start_time = time.time()

        # Execute the decryption function
        decrypted_data = decryption_func(config_func, nfc_read_func)

        decryption_time = time.time() - start_time
        current, peak = tracemalloc.get_traced_memory()  # Get current and peak memory usage
        tracemalloc.stop()

        # Calculate data size based on the actual decrypted data
        data_size = len(decrypted_data.encode()) if isinstance(decrypted_data, str) else len(decrypted_data) if decrypted_data else 0

        metrics["decryption_latency"] = decryption_time
        metrics["decryption_throughput"] = data_size / decryption_time if decryption_time > 0 else 0
        metrics["decryption_memory_usage"] = {"current": current, "peak": peak}

        print(f"Decryption data: {decrypted_data}")
        logger.info(f"Decryption completed. Time: {decryption_time}s, Memory Usage: {peak / 1024:.2f} KB")

    logger.info("Performance Metrics: %s", metrics)
    print("Performance Metrics:", metrics)
    return metrics

# ------------------- MAIN PROGRAM -------------------
def main():
    logger.info("STARTING PROGRAM...") #removev nalang this one if ever

    print("SELECT ENCRYPTION METHOD:")
    print("1. AES")
    print("2. RSA")
    print("3. AES-RSA")
    print("4. Hill Cipher")
    print("5. ECC")

    choice = input("Enter choice (1, 2, 3, 4, or 5): ").strip()

    if choice in {"1", "2", "3", "4", "5"}:
        print("\nSelect Operation:")
        print("1. Encryption")
        print("2. Decryption")
        operation = input("Enter operation (1 or 2): ").strip()

        if operation == "1":
            if choice == "1":
                aes_encryption(lambda: CONFIG_PATH, write_to_nfc_card_as_ndef)
            elif choice == "2":
                rsa_encryption(lambda: CONFIG_PATH, write_to_nfc_card_as_ndef)
            elif choice == "3":
                aes_rsa_encryption(lambda: CONFIG_PATH, write_to_nfc_card_as_ndef)
            elif choice == "4":
                hill_cipher_encryption(lambda: CONFIG_PATH, write_to_nfc_card_as_ndef)
            elif choice == "5":
                ecc_xor_encryption(lambda: CONFIG_PATH, write_to_nfc_card_as_ndef)
            else:
                print("Invalid choice for encryption.")

        elif operation == "2":
            if choice == "1":
                aes_decryption(lambda: CONFIG_PATH, read_from_nfc_card)
            elif choice == "2":
                rsa_decryption(lambda: CONFIG_PATH, lambda: read_from_nfc_card(asymmetric_mode=True))
            elif choice == "3":
                aes_rsa_decryption(lambda: CONFIG_PATH, read_from_nfc_card)
            elif choice == "4":
                hill_cipher_decryption(lambda: CONFIG_PATH, read_from_nfc_card)
            elif choice == "5":
                ecc_xor_decryption(lambda: CONFIG_PATH, lambda: read_from_nfc_card(asymmetric_mode=True))
            else:
                print("Invalid choice for decryption.")
        else:
            print("Invalid operation. Choose 1 for Encryption or 2 for Decryption.")
    else:
        print("Invalid encryption method choice. Choose a number between 1 and 5.")

if __name__ == "__main__":
    main()

