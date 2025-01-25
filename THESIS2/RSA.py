from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from smartcard.System import readers
import sys


# Function: Generate RSA Key Pair
def generate_rsa_keypair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    print("RSA key pair generated.")
    return private_key, public_key


# Function: Write to NFC Card
def write_to_nfc_card(ciphertext):
    try:
        # Get the list of available readers
        r = readers()
        if not r:
            print("No NFC readers found.")
            return

        # Select the first reader
        reader = r[0]
        connection = reader.createConnection()
        connection.connect()

        print(f"NFC card detected using: {reader}")

        # Write ciphertext to NFC card
        message_bytes = ciphertext
        while len(message_bytes) % 4 != 0:  # Pad to align with 4-byte NFC pages
            message_bytes += b'\x00'

        page = 4  # Start writing at Address 04
        for i in range(0, len(message_bytes), 4):
            chunk = message_bytes[i:i+4]
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


# Function: Read from NFC Card
def read_from_nfc_card():
    try:
        # Get the list of available readers
        r = readers()
        if not r:
            print("No NFC readers found.")
            sys.exit(1)

        # Select the first reader
        reader = r[0]
        connection = reader.createConnection()
        connection.connect()

        print(f"NFC card detected using: {reader}")

        # Read raw data from NFC card
        nfc_data = b""
        for page in range(4, 222):  # Adjust range based on expected ciphertext size
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
        return nfc_data

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


# Function: RSA Encryption
def rsa_encrypt(data):
    # Generate a new RSA key pair
    private_key, public_key = generate_rsa_keypair()

    # Encrypt the data with the public key
    public_key_obj = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(public_key_obj)
    ciphertext = cipher.encrypt(data)

    # Write the ciphertext to the NFC card
    print("Writing ciphertext to NFC card...")
    write_to_nfc_card(ciphertext)

    # Save private key to file for decryption
    with open("rsa_private.pem", "wb") as priv_file:
        priv_file.write(private_key)
    print("Private key saved to 'rsa_private.pem'.")

    print(f"Original ciphertext length: {len(ciphertext)} bytes")

    return ciphertext


# Function: RSA Decryption
def rsa_decrypt():
    # Read the private key from the file
    with open("rsa_private.pem", "rb") as priv_file:
        private_key = RSA.import_key(priv_file.read())

    # Read the ciphertext from the NFC card
    print("Reading ciphertext from NFC card...")
    ciphertext = read_from_nfc_card()

    # Strip any padding or terminator bytes added during NFC writing
    ciphertext = ciphertext.rstrip(b'\x00')
    print(f"Ciphertext length from NFC: {len(ciphertext)} bytes")

    # Validate ciphertext length for RSA decryption
    expected_length = private_key.size_in_bytes()  # e.g., 256 bytes for 2048-bit RSA
    if len(ciphertext) != expected_length:
        print(f"Error: Ciphertext length mismatch. Expected {expected_length} bytes, got {len(ciphertext)} bytes.")
        print("Ensure the ciphertext is fully written and read from the NFC card.")
        raise ValueError("Ciphertext length mismatch.")

    # Decrypt the data with the private key
    cipher = PKCS1_OAEP.new(private_key)
    plaintext = cipher.decrypt(ciphertext)

    # Save decrypted data to a file named "decrypted_rsa.txt"
    with open("decrypted_rsa.txt", "w") as output_file:
        output_file.write(plaintext.decode())
    print("Decrypted plaintext saved to 'decrypted_rsa.txt'.")

    return plaintext


# Main Function
def main():
    # Prompt user for operation
    operation = input("Enter operation ('encryption' or 'decryption'): ").strip().lower()

    if operation == "encryption":
        # Read plaintext data from the user
        plaintext = input("Enter the plaintext to encrypt: ").strip().encode()

        # Encrypt the data and write it to NFC
        rsa_encrypt(plaintext)

    elif operation == "decryption":
        # Read ciphertext from NFC and decrypt it
        plaintext = rsa_decrypt()
        print("Decrypted Data:", plaintext.decode())

    else:
        print("Invalid operation. Please enter 'encryption' or 'decryption'.")


if __name__ == "__main__":
    main()
