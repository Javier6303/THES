# Import necessary libraries
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import time
import nfc
import csv 

Define function to read patient data from a file:
    Open the specified file (CSV) and retrieve its content.
    Return file content.

Define function to generate AES encryption key:
    Create a random 16-byte key for AES encryption.
    Save the key in bin file to be used later for decryption.
    Return AES key.

Define function to perform AES encryption:
    Take data and AES key as parameters.
    Encrypt the data using AES in OCB mode.
    Generate a tag and nonce during encryption for integrity verification.
    Save the encrypted data, the tag, and the nonce in a file.
    Return the encrypted data.

Define function to perform AES decryption:
    Take encrypted data, the AES key, nonce, and tag as parameters.
    Decrypt the data using the AES key and verify its integrity with the tag.
    If the decryption is successful, return the decrypted data.
    If decryption fails, display an error message.

Define function to handle NFC tag interaction:
    Set up NFC reader and wait for tag to be tapped.
    Once the NFC tag is detected, establish a connection.
    Depending on the operation:
        - For encryption: Write the encrypted data to the NFC tag.
        - For decryption: Read the encrypted data from the NFC tag.
    Close the connection.

Define function to write decrypted data to a file:
    Take the decrypted data and write it into a CSV file.

Define main function:
    Ask the user to choose whether to perform encryption or decryption. (testing purposes only)
    
    If encryption:
        Read the data from the CSV file.
        Generate an AES key.
        Encrypt the data and measure the time taken.
        Wait for the NFC tag and write the encrypted data to the NFC tag.
        Display a success or failure message.
    
    If decryption:
        Read the AES key from bin file.
        Wait for the NFC tag and read the encrypted data from it.
        Decrypt the data and measure the time taken.
        Write the decrypted data to a CSV file.
        Display a success or failure message.

main
