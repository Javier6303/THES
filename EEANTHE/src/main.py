import os
import sys
import tracemalloc
import time
import logging
import csv
import psutil
from pathlib import Path
from dotenv import load_dotenv
from modules.aes_ndef import aes_encryption, aes_decryption
from modules.aes_rsa import aes_rsa_encryption, aes_rsa_decryption
from modules.rsa import rsa_encryption, rsa_decryption
from modules.hill_cipher import hill_cipher_encryption, hill_cipher_decryption
from modules.ecc import ecc_xor_encryption, ecc_xor_decryption
from modules.ecdh_aes import ecdh_aes_encryption, ecdh_aes_decryption
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
        for page in range(4, 225):
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


def save_metrics_to_csv(metrics, operation):
    """Append encryption or decryption metrics to a CSV file."""
    csv_file = "metrics_log.csv"
    file_exists = os.path.isfile(csv_file)

    fieldnames = ["operation", "latency", "throughput", "memory_usage", "data_size_bytes"]

    if operation == "1":
        row = {
            "operation": "encryption",
            "latency": metrics["encryption_latency"],
            "throughput": metrics["encryption_throughput"],
            "memory_usage": str(metrics["encryption_memory_usage"]),
            "data_size_bytes": metrics["data_size_bytes"]
        }
    else:
        row = {
            "operation": "decryption",
            "latency": metrics["decryption_latency"],
            "throughput": metrics["decryption_throughput"],
            "memory_usage": str(metrics["decryption_memory_usage"]),
            "data_size_bytes": metrics["data_size_bytes"]
        }

    with open(csv_file, mode="a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)

def measure_performance(operation, encryption_func, decryption_func, patient_id, config_func,  nfc_write_func, nfc_read_func, asymmetric=False):
    metrics = {}

    decryption_keys = {
        "aes_decryption": ["aes_key"],
        "rsa_decryption": ["rsa_key_private"],
        "aes_rsa_decryption": ["aes_rsa_key_private", "aes_rsa_key_enc_aes_key", "aes_rsa_key_aes_nonce", "aes_rsa_key_aes_tag"],
        "hill_cipher_decryption": ["hill_cipher_key"],
        "ecc_xor_decryption": ["ecc_key_private", "ecc_key_ephemeral"],
        "ecdh_aes_decryption": ["ecdh_key_private", "ecdh_key_ephemeral", "ecdh_key_nonce", "ecdh_key_tag"],
    }

    if operation == "1":  # Encryption
        print("Starting Encryption...")
        tracemalloc.start()

        process = psutil.Process(os.getpid())
        process.cpu_percent(interval=None)
        start_time = time.time()

        # Execute the encryption function
        encrypted_data = encryption_func(patient_id, nfc_write_func)

        end_time = time.time()
        encryption_time = end_time - start_time
        cpu_usage = process.cpu_percent(interval=None)
        current, peak = tracemalloc.get_traced_memory()  # Get current and peak memory usage
        tracemalloc.stop()

        # Calculate data size based on the actual encrypted data
        data_size = len(encrypted_data.encode()) if isinstance(encrypted_data, str) else len(encrypted_data) if encrypted_data else 0

        metrics["encryption_latency"] = f"{encryption_time:.6f} s"
        metrics["encryption_throughput"] = f"{(data_size / encryption_time) / 1024:.6f} KB/s" if encryption_time > 0 else "0 KB/s"
        metrics["encryption_memory_usage"] = {
            "current": f"{current / 1024:.6f} KB",
            "peak": f"{peak / 1024:.6f} KB"
        }
        metrics["encryption_cpu_usage"] = f"{cpu_usage:.2f} %"
        metrics["data_size_bytes"] = data_size
        metrics["encryption_data"] = encrypted_data
        logger.info(f"Encryption completed. Time: {encryption_time:.6f}s, Memory Usage: {peak / 1024:.6f} KB")

        save_metrics_to_csv(metrics, operation)

    elif operation == "2":  # Decryption
        print("Starting Decryption...")

        from modules.db_manager import load_key

        # Load all necessary keys BEFORE timing
        key_list = decryption_keys.get(decryption_func.__name__, [])
        preloaded_keys = {}

        for key_name in key_list:
            key_data = load_key(key_name, patient_id)
            preloaded_keys[key_name] = key_data

        tracemalloc.start()

        process = psutil.Process(os.getpid())
        process.cpu_percent(interval=None)
        start_time = time.time()

        # Execute the decryption function
        decrypted_data = decryption_func(config_func, lambda: nfc_read_func(asymmetric_mode=asymmetric), patient_id, preloaded_keys=preloaded_keys)

        end_time = time.time()
        decryption_time = end_time - start_time
        cpu_usage = process.cpu_percent(interval=None)
        current, peak = tracemalloc.get_traced_memory()  # Get current and peak memory usage
        tracemalloc.stop()

        # Calculate data size based on the actual decrypted data
        data_size = len(decrypted_data.encode()) if isinstance(decrypted_data, str) else len(decrypted_data) if decrypted_data else 0

        metrics["decryption_latency"] = f"{decryption_time:.6f} s"
        metrics["decryption_throughput"] = f"{(data_size / decryption_time) / 1024:.6f} KB/s" if decryption_time > 0 else "0 KB/s"
        metrics["decryption_memory_usage"] = {
            "current": f"{current / 1024:.6f} KB",
            "peak": f"{peak / 1024:.6f} KB"
        }
        metrics["decryption_cpu_usage"] = f"{cpu_usage:.2f} %"
        metrics["data_size_bytes"] = data_size
        metrics["decryption_data"] = decrypted_data

        print(f"Decryption data: {decrypted_data}")
        logger.info(f"Decryption completed. Time: {decryption_time:.6f}s, Memory Usage: {peak / 1024:.6f} KB")

        save_metrics_to_csv(metrics, operation)

    logger.info("Performance Metrics: %s", metrics)

    return metrics



# ------------------- MAIN PROGRAM -------------------
def main():
    logger.info("STARTING PROGRAM...") #removev nalang this one if ever

    print("SELECT ENCRYPTION METHOD:")
    print("1. AES")
    print("2. RSA")
    print("3. AES-RSA")
    print("4. Hill Cipher")
    print("5. ECC XOR")
    print("6. ECDH + AES-GCM")

    choice = input("Enter Chosen method: ").strip()

    encryption_methods = {
        "1": (aes_encryption, aes_decryption),
        "2": (rsa_encryption, rsa_decryption),
        "3": (aes_rsa_encryption, aes_rsa_decryption),
        "4": (hill_cipher_encryption, hill_cipher_decryption),
        "5": (ecc_xor_encryption, ecc_xor_decryption),
        "6": (ecdh_aes_encryption, ecdh_aes_decryption)
    }

    if choice in encryption_methods:
        encryption_func, decryption_func = encryption_methods[choice]

        print("SELECT OPERATION:")
        print("1. Encryption")
        print("2. Decryption")
        operation = input("Enter operation: ").strip()

        # RSA and ECC are asymmetric
        asymmetric = choice in {"1", "2", "3", "4", "5", "6"}  

        if operation in {"1", "2"}:
            patient_id = input("Enter patient ID: ").strip()
            measure_performance(operation, encryption_func, decryption_func, patient_id, lambda: CONFIG_PATH, write_to_nfc_card_as_ndef, read_from_nfc_card, asymmetric=asymmetric)
        else:
            print("Invalid operation. Choose 1 for Encryption or 2 for Decryption.")

    else:
        print("Invalid encryption method choice. Choose a number between 1 and 5.")

if __name__ == "__main__":
    main()
