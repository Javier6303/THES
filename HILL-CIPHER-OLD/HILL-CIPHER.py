https://github.com/D-ENCODER/KRYPTOR

# Import necessary libraries
import numpy as np
import nfc
import csv
import time


Define function to read patient data from a file:
    Open the specified file (CSV) and retrieve its content.
    Return file content.

Define function to generate or load a key matrix for Hill cipher:
    Define a key matrix of integers, e.g., 2x2 or 3x3
    Ensure the matrix is invertible modulo 26
    Save the key matrix to a file, or load if it already exists
    Return key matrix
    
Define function to convert letters to numbers:
    Get text as parameters                              
    Convert each letter to a corresponding number (A=0, B=1, ..., Z=25)
    Return the list of numbers

Define function to convert numbers to letters:
    Get numbers as parameters                               
    Convert each number back to a letter (0=A, 1=B, ..., 25=Z)
    Return the string

Define function to perform Hill cipher encryption:
    Get plaintext and key matrix as parameters                                            
    Convert plaintext to numbers and pad if needed
    Reshape numbers into vectors and multiply by key matrix, mod 26
    Convert the result back to letters 
    Return the ciphertext
   
Define function to perform Hill cipher decryption:
    Get ciphertext and key matrix as parameters 
    Calculate the inverse of the key matrix mod 26
    Convert ciphertext to numbers and reshape into vectors
    Multiply by the inverse matrix mod 26 and convert back to letters
    Return the plaintext
    
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
    Ask user whether to encrypt or decrypt
                                                           
    Load or generate key matrix

    If encryption:
      Read the data from the CSV file.
      Encrypt the data and measure the time taken, memory utilization, and througput.                                                     
      Wait for the NFC tag and write the encrypted data to the NFC tag.
      Display a success or failure message.

    If decryption:
      Wait for the NFC tag and read the encrypted data from it.
      Decrypt the data and measure the time taken, memory utilization, and througput.
      Write the decrypted data to a CSV file.
      Display a success or failure message.
                                                           
 main()
