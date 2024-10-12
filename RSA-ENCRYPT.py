from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import time
import nfc

key = RSA.generate(2048)
private_key = key.export_key()
with open("private.pem", "wb") as f:
    f.write(private_key)

public_key = key.publickey().export_key()
with open("receiver.pem", "wb") as f:
    f.write(public_key)

def load_public_key(file_path):
    # Load the RSA public key from a file to use for encryption

    with open(file_path, "rb") as f:
        public_key = RSA.import_key(f.read())
    return public_key


def rsa_encrypt(data, public_key):
    # Encrypt the data using RSA and OAEP padding

    rsa_cipher = PKCS1_OAEP.new(public_key)  # Initialize RSA cipher with OAEP padding
    encrypted_data = rsa_cipher.encrypt(data.encode())  # Encrypt the data
    return encrypted_data


def wait_for_nfc_tag():
    # Wait for the NFC tag to be tapped and return the tag reference.

    clf = nfc.ContactlessFrontend('usb')  # Open NFC reader connection
    tag = None
    while not tag:
    # Wait for NFC tag tap
        clf.close()



def write_to_nfc(nfc_tag, encrypted_data):
    # Write the RSA encrypted data onto the NFC card

    nfc_tag.ndef.message = encrypted_data  # Write encrypted data to NFC tag


def status_message(success):
    # Display a message indicating whether the write was successful or not.

    if success:
        print("Data written to NFC tag successfully!")
    else:
        print("Failed to write data to NFC tag.")



def rsa_encrypt_process(data, public_key_file):
    # Perform RSA encryption and write the encrypted data to the NFC card

    public_key = load_public_key(public_key_file)  # Load the RSA public key

    start_time = time.time()  # Record start time for encryption
    encrypted_data = rsa_encrypt(data, public_key)  # Encrypt the data using RSA
    encryption_time = time.time() - start_time  # Calculate encryption time

    print(encryption_time)

    nfc_tag = wait_for_nfc_tag()  # Wait for NFC tag
    write_to_nfc(nfc_tag, encrypted_data)  # Write encrypted data to NFC tag

    status_message()


def main():
    data = 'patient data from CSV'
    public_key_file = 'receiver.pem'
    rsa_encrypt_process(data, public_key_file)


main()