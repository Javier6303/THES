# Import necessary libraries
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import nfc
import time
import csv


def load_private_key(file_path):
    # Load the RSA private key from a file to use for decryption

    with open(file_path, "rb") as f:
        private_key = RSA.import_key(f.read())  # Load and return the private key
    return private_key


def rsa_decrypt(encrypted_data, private_key):
    # Decrypt the RSA encrypted data using OAEP padding

    rsa_cipher = PKCS1_OAEP.new(private_key)
    decrypted_data = rsa_cipher.decrypt(encrypted_data)  # Decrypt the data
    return decrypted_data


def wait_for_nfc_tag():
    # Wait for an NFC tag to be tapped

    clf = nfc.ContactlessFrontend('usb')  # Open NFC reader connection
    tag = None
    while not tag:
        # Wait for NFC tag to be tapped
        clf.close()
        return tag


def read_from_nfc(nfc_tag):
    # Read the encrypted data from the NFC card

    # Simulating NFC tag read for now
    encrypted_data = nfc_tag.ndef.message
    return encrypted_data


def write_to_csv(file_path, decrypted_data):
    # Write the decrypted patient data to a CSV file

    with open(file_path, 'w', newline='') as file:
        writer = csv.writer(file)
        # Write decrypted data as a row


def status_message(success):
    # Show message indicating if decryption was successful or not

    if success:
        print("Decryption and write to CSV successful!")
    else:
        print("Decryption failed.")


def rsa_decrypt_process(private_key_file, csv_file_path):
    # Decrypt RSA data from NFC and write it to CSV

    private_key = load_private_key(private_key_file)  # Load RSA private key

    nfc_tag = wait_for_nfc_tag()  # Wait for NFC tag to be tapped
    encrypted_data = read_from_nfc(nfc_tag)  # Read encrypted data from NFC tag

    start_time = time.time()  # Record start time for decryption
    decrypted_data = rsa_decrypt(encrypted_data, private_key)  # Decrypt the data
    decryption_time = time.time() - start_time  # Calculate decryption time

    print(f"Decryption time: {decryption_time} seconds")

    write_to_csv(csv_file_path, decrypted_data)  # Write decrypted data to CSV

    status_message(True)  # Display status message


def main():
    private_key_file = "private.pem"
    csv_file_path = 'decrypted_data.csv'
    rsa_decrypt_process(private_key_file)


main()  # Run main function
