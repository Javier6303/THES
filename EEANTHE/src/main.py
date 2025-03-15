import os
import sys
import tracemalloc
import time
import logging
import csv
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

CONFIG_PATH = os.getenv("CONFIG_PATH", "")

# ------------------- NFC FUNCTIONALITIES -------------------
def write_to_nfc_card_as_ndef(ciphertext):
    """Writes encrypted data to NFC card."""
    try:
        r = readers()
        if not r:
            logger.error("No NFC readers found.")
            return False

        reader = r[0]
        connection = reader.createConnection()
        connection.connect()

        logger.info(f"NFC card detected using: {reader}")

        # Build NDEF message
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
                return False
            page += 1

        logger.info("Write operation complete.")
        return True
    except Exception as e:
        logger.exception(f"Error writing to NFC: {e}")
        return False

def read_from_nfc_card(asymmetric_mode=False):
    """Reads encrypted text from NFC card."""
    try:
        r = readers()
        if not r:
            logger.error("No NFC readers found.")
            return None

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
        return nfc_data
    except Exception as e:
        logger.exception(f"Error reading from NFC: {e}")
        return None

# ------------------- PERFORMANCE MEASUREMENT -------------------
def measure_performance(operation, encryption_func, decryption_func, nfc_write_func, nfc_read_func, asymmetric=False):
    metrics = {}

    if operation == "1":  # Encryption
        tracemalloc.start()
        start_time = time.time()
        encrypted_data = encryption_func(lambda: CONFIG_PATH, nfc_write_func)
        encryption_time = time.time() - start_time
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        metrics["encryption_latency"] = f"{encryption_time:.6f} s"
        metrics["encryption_memory_usage"] = f"{peak / 1024:.6f} KB"
        logger.info(f"Encryption completed in {encryption_time:.6f}s, Peak Memory: {peak / 1024:.6f} KB")
    
    elif operation == "2":  # Decryption
        tracemalloc.start()
        start_time = time.time()
        decrypted_data = decryption_func(lambda: CONFIG_PATH, lambda: nfc_read_func(asymmetric_mode=asymmetric))
        decryption_time = time.time() - start_time
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        metrics["decryption_latency"] = f"{decryption_time:.6f} s"
        metrics["decryption_memory_usage"] = f"{peak / 1024:.6f} KB"
        logger.info(f"Decryption completed in {decryption_time:.6f}s, Peak Memory: {peak / 1024:.6f} KB")
    
    logger.info("Performance Metrics: %s", metrics)
    return metrics
