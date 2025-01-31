from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from smartcard.System import readers
import csv
import sys
import pandas as pd


# Function: Generate RSA Key Pair
def generate_rsa_keypair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    print("RSA key pair generated.")
    print(f"Private Key Length: {len(private_key)} bytes")
    print(f"Public Key Length: {len(public_key)} bytes")

    return private_key, public_key


# Function: Write to NFC Card as NDEF Record
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

        # Build NDEF Text Record
        language_code = "en"
        language_code_length = len(language_code)
        ciphertext_length = len(ciphertext)

        ndef_message = [
            0x03,  # NDEF TLV type
            ciphertext_length + 7,  # Length of NDEF payload
            0xD1,  # NDEF record header
            0x01,  # Type length (1 byte, for "T" type)
            ciphertext_length + 3,  # Payload length
            0x54,  # Type field ("T" for Text)
            language_code_length,  # Status byte (language code length)
        ] + list(language_code.encode("utf-8")) + list(ciphertext) + [0xFE]  # Terminator TLV

        while len(ndef_message) % 4 != 0:
            ndef_message.append(0x00)

        print(f"Writing NDEF message with length: {len(ndef_message)} bytes")

        # Write the NDEF message to NFC card
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


# Function: Read Full NFC Memory and Extract Ciphertext
def read_from_nfc_card():
    try:
        r = readers()
        if not r:
            print("No NFC readers found.")
            sys.exit(1)

        reader = r[0]
        connection = reader.createConnection()
        connection.connect()

        print(f"NFC card detected using: {reader}")

        # Read the entire NFC memory (from Address 4 to your max E1)
        nfc_data = b""
        for page in range(4, 225):  # Read until your card's limit (E1 = 225)
            READ_COMMAND = [0xFF, 0xB0, 0x00, page, 0x04]
            response, sw1, sw2 = connection.transmit(READ_COMMAND)
            if sw1 == 0x90 and sw2 == 0x00:
                nfc_data += bytes(response)
            else:
                print(f"Failed to read page {page}. SW1: {sw1}, SW2: {sw2}")
                break

        # Remove padding
        nfc_data = nfc_data.rstrip(b'\x00')
        print("Successfully read data from NFC card.")

        # Parse and extract only ciphertext
        return extract_ciphertext(nfc_data)

    except Exception as e:
        print(f"Error reading from NFC: {e}")
        sys.exit(1)




# Function: Extract Ciphertext from NFC Data
def extract_ciphertext(nfc_data):

    if len(nfc_data) < 10:
        raise ValueError("Invalid NFC data length.")

    # Ensure the data contains an NDEF record
    if nfc_data[0] != 0x03:
        raise ValueError("Invalid NDEF message format.")

    # Locate start of actual ciphertext (skip metadata dynamically)
    index = 2  # Start after NDEF type
    while index < len(nfc_data) and nfc_data[index] != 0x54:  # Find 'T' record (0x54)
        index += 1

    if index >= len(nfc_data) - 1:
        raise ValueError("Ciphertext not found in NFC data!")

    # Move past language code length
    language_code_length = nfc_data[index + 1]
    ciphertext_start = index + 2 + language_code_length  # Actual ciphertext start
    ciphertext = nfc_data[ciphertext_start:]

    # Strip padding & NDEF terminator (0xFE) if present
    if ciphertext.endswith(b'\xFE'):
        ciphertext = ciphertext[:-1]

    print(f"Ciphertext Length Extracted: {len(ciphertext)} bytes")

    return ciphertext



# Function: RSA Encryption
def rsa_encrypt(csv_file, output_file="rsa_private.pem"):
    df = pd.read_csv(csv_file)
    headers = df.columns.tolist()
    first_row = df.iloc[0].tolist()

    data = ",".join(map(str, first_row)).encode()

    private_key, public_key = generate_rsa_keypair()

    public_key_obj = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(public_key_obj)
    ciphertext = cipher.encrypt(data)

    print(f"Ciphertext length after encryption: {len(ciphertext)} bytes")

    with open(output_file, "wb") as priv_file:
        priv_file.write(private_key)

    print("Private key saved to 'rsa_private.pem'.")

    print("Writing ciphertext to NFC card...")
    write_to_nfc_card_as_ndef(ciphertext)
    print("Ciphertext successfully written to NFC!")

    return headers, private_key, ciphertext


# Function: RSA Decryption
def rsa_decrypt(input_file="rsa_private.pem", output_csv="decrypted_rsa_data.csv"):
    try:
        with open(input_file, "rb") as priv_file:
            private_key = RSA.import_key(priv_file.read())

        print("Reading ciphertext from NFC card...")
        ciphertext = read_from_nfc_card()

        print(f"Ciphertext length from NFC: {len(ciphertext)} bytes")

        expected_length = private_key.size_in_bytes()
        if len(ciphertext) != expected_length:
            print(f"Error: Expected {expected_length} bytes, got {len(ciphertext)} bytes.")
            raise ValueError("Ciphertext length mismatch.")

        cipher = PKCS1_OAEP.new(private_key)
        plaintext = cipher.decrypt(ciphertext).decode()
        print("Decryption successful!")

        # Convert plaintext back into a list (CSV format)
        decrypted_data = plaintext.split(",")

        # Read headers from CSV file
        csv_file = "sample_patient_data.csv"
        df = pd.read_csv(csv_file)
        headers = df.columns.tolist()

        # Debugging: Print extracted data
        print(f"Decrypted Data: {decrypted_data}")
        print(f"Expected Columns: {len(headers)}, Extracted Columns: {len(decrypted_data)}")

        # Ensure the decrypted data length matches headers
        if len(headers) != len(decrypted_data):
            print(f"Error: Header/Data Mismatch ({len(headers)} headers vs {len(decrypted_data)} values)")
            decrypted_data = decrypted_data[:len(headers)]  # Trim excess if necessary

        # Write decrypted data into CSV
        with open(output_csv, "w", newline="") as csvfile:
            csv_writer = csv.writer(csvfile, quoting=csv.QUOTE_ALL)
            csv_writer.writerow(headers)
            csv_writer.writerow(decrypted_data)

        print(f"Decrypted data saved to '{output_csv}'.")

        return decrypted_data

    except ValueError as e:
        print(f"Decryption failed: {e}")
        sys.exit(1)


# Main Function
def main():
    operation = input("Enter operation ('encryption' or 'decryption'): ").strip().lower()

    if operation == "encryption":
        rsa_encrypt("sample_patient_data.csv")

    elif operation == "decryption":
        rsa_decrypt()

    else:
        print("Invalid operation.")


if __name__ == "__main__":
    main()
