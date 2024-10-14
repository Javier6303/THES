from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import nfc
import time
import csv

Define function to generate RSA keys:
    Generate a new RSA key pair.
    Save the private key to a file ('private.pem').
    Save the public key to a separate file ('public.pem').

Define function to load RSA key:
    - If public key is needed, load it from specified file ('public.pem').
    - If private key is needed, load it from specified file ('private.pem').
    Return the corresponding RSA key.

Define function to perform RSA encryption:
    Take the data and RSA public key as parameters.
    Use RSA to encrypt the data.
    Return the encrypted data.

Define function to perform RSA decryption:
    Take the encrypted data and RSA private key as parameters.
    Use RSA to decrypt the data.
    If the decryption is successful, return the decrypted data.

Define function to handle NFC tag interaction:
    Set up NFC reader and wait for a tag to be tapped.
    Depending on the operation (encryption or decryption):
        - For encryption: Write the RSA encrypted data to the NFC tag.
        - For decryption: Read the encrypted data from the NFC tag.
    Close the connection.

Define function to write decrypted data to a file:
    Take the decrypted data and write it into a CSV file.

Define main function:
    Ask the user to choose whether to generate RSA keys, perform encryption, or perform decryption.

    If key generation is chosen:
        Generate RSA keys and save them to pem files.

    If encryption is chosen:
        Load the public key from a file.
        Prepare the data to be encrypted.
        Encrypt the data using the RSA public key and measure the time taken, memory utilization, and througput.
        Wait for the NFC tag to be tapped.
        Write the encrypted data to the NFC tag.      

    If decryption is chosen:
        Load the private key from a file.
        Wait for the NFC tag to be tapped.
        Read the encrypted data from the NFC tag.
        Decrypt the data using the RSA private key and measure the time taken, memory utilization, and througput.
        Write the decrypted data to a CSV file.
      

main
