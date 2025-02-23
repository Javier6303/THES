from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from smartcard.System import readers
import base64
import os
import csv
import pandas as pd
import sys
import time
import tracemalloc

# ------------------- FILE LOCATION -------------------

def get_csv_path():
    """Locate sample_patient_data.csv in the same directory."""
    script_dir = os.path.dirname(os.path.abspath(__file__))  # Get script location
    csv_path = os.path.join(script_dir, "..", "sample_patient_data.csv")  # Assume it's in the same folder

    if not os.path.exists(csv_path):
        print(f"Error: CSV file '{csv_path}' not found. Ensure it's in the same directory.")
        return None

    return csv_path

def get_file_path(filename):
    """Get absolute path for storing key and encrypted files."""
    return os.path.join(os.getcwd(), filename)

# ------------------- NFC FUNCTIONS -------------------

def write_to_nfc_card_as_ndef(ciphertext):
    """Writes XOR-encrypted ciphertext to NFC as an NDEF record."""
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
        ndef_message = [0x03, len(ciphertext) + 7, 0xD1, 0x01, len(ciphertext) + 3, 0x54, len(language_code)] \
                     + list(language_code.encode("utf-8")) + list(ciphertext) + [0xFE]

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

# ------------------- ECC + XOR ENCRYPTION -------------------

def generate_ecc_key_pair():
    """Generate ECC Private-Public Key Pair and save the private key."""
    private_key = ec.generate_private_key(ec.SECP256R1())

    private_key_path = get_file_path("ecc_private.pem")
    with open(private_key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    print(f"ECC private key saved to '{private_key_path}'.")
    return private_key, private_key.public_key()

def ecc_xor_encrypt(public_key, plaintext):
    """Encrypts data using ECC key exchange and XOR."""
    ephemeral_private_key = ec.generate_private_key(ec.SECP256R1())
    ephemeral_public_key = ephemeral_private_key.public_key()

    shared_secret = ephemeral_private_key.exchange(ec.ECDH(), public_key)

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=len(plaintext),
        salt=None,
        info=b"ecc-xor-key"
    ).derive(shared_secret)

    data_size = len(plaintext.encode())

    # Start memory and time measurement
    tracemalloc.start()
    start_time = time.perf_counter()
    encrypted_bytes = bytes(a ^ b for a, b in zip(plaintext.encode(), derived_key))

    # Stop time measurement
    end_time = time.perf_counter()
    encryption_time = end_time - start_time

    # Measure memory usage
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # Calculate throughput
    encryption_throughput = data_size / encryption_time

    # Display performance metrics
    print("\n[ENCRYPTION METRICS]")
    print(f"Data Size: {data_size} bytes")
    print(f"Encryption Time: {encryption_time:.8f} seconds")
    print(f"Encryption Throughput: {encryption_throughput:.10f} bytes/second")
    print(f"Memory Usage: {current / 1024:.10f} KB; Peak: {peak / 1024:.10f} MB")

    # Save ephemeral public key
    ephemeral_public_path = get_file_path("ecc_ephemeral_public.pem")
    with open(ephemeral_public_path, "wb") as f:
        f.write(ephemeral_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print(f" Ephemeral public key saved to '{ephemeral_public_path}'.")


    return base64.b64encode(encrypted_bytes).decode()

# ------------------- ECC + XOR DECRYPTION -------------------

def ecc_xor_decrypt(encrypted_text):
    """Decrypts XOR-encrypted data using ECC key exchange."""
    private_key_path = get_file_path("ecc_private.pem")
    ephemeral_public_path = get_file_path("ecc_ephemeral_public.pem")

    # Load keys from files
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    with open(ephemeral_public_path, "rb") as f:
        ephemeral_public_key = serialization.load_pem_public_key(f.read())

    shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public_key)

    data_size = len(encrypted_text)

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=len(encrypted_text),
        salt=None,
        info=b"ecc-xor-key"
    ).derive(shared_secret)

    # Start memory and time measurement
    tracemalloc.start()
    start_time = time.perf_counter()

    decrypted_bytes = bytes(a ^ b for a, b in zip(base64.b64decode(encrypted_text), derived_key))
    decrypted_text = decrypted_bytes.decode()

    # Stop time measurement
    end_time = time.perf_counter()
    decryption_time = end_time - start_time

    # Measure memory usage
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # Calculate throughput
    decryption_throughput = data_size / decryption_time

    # Display performance metrics
    print("\n[DECRYPTION METRICS]")
    print(f"Data Size: {data_size} bytes")
    print(f"Decryption Time: {decryption_time:.8f} seconds")
    print(f"Decryption Throughput: {decryption_throughput:.10f} bytes/second")
    print(f"Memory Usage: {current / 1024:.10f} KB; Peak: {peak / 1024:.10f} MB")

    return decrypted_text

# ------------------- MAIN FUNCTION -------------------

def main():
    operation = input("Enter operation ('encryption' or 'decryption'): ").strip().lower()

    if operation == "encryption":
        csv_path = get_csv_path()
        if not csv_path:
            return

        df = pd.read_csv(csv_path)
        headers = df.columns.tolist()
        first_row = df.iloc[0].tolist()
        plaintext = ",".join(map(str, first_row))

        private_key, public_key = generate_ecc_key_pair()
        encrypted_text = ecc_xor_encrypt(public_key, plaintext)

        write_to_nfc_card_as_ndef(encrypted_text.encode())


    elif operation == "decryption":

        encrypted_from_nfc = read_from_nfc_card().decode()

        decrypted_text = ecc_xor_decrypt(encrypted_from_nfc)

        print(f"\nDecrypted Patient Data: {decrypted_text}")

        csv_path = get_csv_path()

        if not csv_path:
            return

        df = pd.read_csv(csv_path)

        headers = df.columns.tolist()

        output_csv = "decrypted_patient_data.csv"

        with open(output_csv, "w", newline="") as csvfile:

            csv_writer = csv.writer(csvfile, quoting=csv.QUOTE_ALL)

            csv_writer.writerow(headers)  # Write headers

            csv_writer.writerow(decrypted_text.split(","))  # Write decrypted row

        print(f"\nDecrypted data saved to '{output_csv}'.")

    else:
        print("Invalid operation. Choose 'encryption' or 'decryption'.")

if __name__ == "__main__":
    main()
