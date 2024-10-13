# Import necessary libraries
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import nfc
import time

Define function to read patient data from a file:
    Open the specified file (CSV) and retrieve its content.
    Return file content.

Define function to generate RSA keys:
    Generate a new RSA key pair.
    Save the private key to a file named 'private.pem'.
    Save the public key to a file named 'public.pem'.

Define function to load RSA key:
    If public key is needed, load it from 'public.pem'.
    If private key is needed, load it from 'private.pem'.
    Return the corresponding RSA key.

Define function to perform RSA+AES hybrid encryption:
    Take the plaintext data and the RSA public key as parameters.
    Generate a random 16-byte AES session key.
    Encrypt the AES session key with the RSA public key.
    Encrypt the data with the AES cipher.
    Save the RSA-encrypted AES session key, AES nonce, and AES tag to a binary file.
    Return the encrypted data.

Define function to perform RSA+AES hybrid decryption:
    Read the RSA-encrypted AES session key, AES nonce, and AES tag from the binary file.
    Take the RSA private key and ciphertext as parameters.
    Decrypt the AES session key with the RSA private key.
    Decrypt the AES ciphertext and verify its integrity with the tag.
    If the decryption is successful, return  decrypted data.

Define function to handle NFC tag interaction:
    Set up an NFC reader and wait for a tag to be tapped.
    Once the NFC tag is detected, establish a connection.
    If the operation is encryption, write the encrypted data to NFC tag.
    If the operation is decryption, read the encrypted data from NFC tag.
    Close the connection.

Define function to write decrypted data to a file:
    Take the decrypted data as a parameter.
    Open a CSV file in write mode.
    Write the decrypted data into the CSV file.

Define main function:
    Ask the user to choose whether to generate RSA keys, perform encryption, or perform decryption.
    
    If the choice is key generation:
        Generate RSA keys and save them to 'pem' files.

    If the choice is encryption:
        Load the RSA public key from 'public.pem'.
        Read the data from the CSV file.
        Perform RSA+AES hybrid encryption.
        Measure the time taken for encryption.
        Write the RSA-encrypted AES session key, AES nonce, and AES tag to a binary file.
        Write the AES-encrypted ciphertext to the NFC tag.
        Display a success or failure message.

    If the choice is decryption:
        Load the RSA private key from 'private.pem'.
        Read the RSA-encrypted AES session key, AES nonce, and AES tag from the binary file.
        Read the AES-encrypted ciphertext from the NFC tag.
        Perform RSA+AES hybrid decryption.
        Measure the time taken for decryption.
        If decryption is successful, write the decrypted data to a CSV file.
        Display a success or failure message.

main()
