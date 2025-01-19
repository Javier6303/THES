Import Libraries:
import numpy as np
import nfc, csv, time

Function: Read Data
  Input: file_path
  Open file_path as file
  data ← file content
  Return: data

Function: Generate and Save Key Matrix
  key_matrix ← Define integer matrix (e.g., 2x2 or 3x3)
  Ensure key_matrix is invertible modulo 26
  Save key_matrix to key_file
  Return: key_matrix

Function: Load Key Matrix
  If key_file exists:
    Load key_matrix from key_file

Function: Convert Letters to Numbers
  Input: text
  numbers ← Convert each letter in text to a number (A=0, B=1, ..., Z=25)
  Return: numbers

Function: Convert Numbers to Letters
  Input: numbers
  text ← Convert each number in numbers back to a letter (0=A, 1=B, ..., 25=Z)
  Return: text

Function: Hill Cipher Encryption
  Input: plaintext, key_matrix
  numbers ← Convert plaintext to numbers and pad if needed
  vectors ← Reshape numbers into vectors of size matching key_matrix
  encrypted_vectors ← Multiply each vector by key_matrix, then mod 26
  ciphertext ← Convert encrypted_vectors back to letters
  Return: ciphertext

Function: Hill Cipher Decryption
  Input: ciphertext, key_matrix
  inverse_key_matrix ← Calculate the inverse of key_matrix mod 26
  numbers ← Convert ciphertext to numbers and reshape into vectors
  decrypted_vectors ← Multiply each vector by inverse_key_matrix, then mod 26
  plaintext ← Convert decrypted_vectors back to letters
  Return: plaintext

Function: NFC Tag Interaction
  Set up NFC reader
  Wait for NFC tag
  If operation = encryption:
    Write ciphertext to NFC tag
  If operation = decryption:
    Read ciphertext from NFC tag
  Close NFC connection

  Function: Write Decrypted Data
  Input: decrypted_data
  Open output_file.csv for writing
  Write decrypted_data to output_file.csv

Main Function
operation ← Prompt user: "Encrypt or Decrypt?"
key_matrix ← Generate or Load Key Matrix
If operation = encryption:
  data ← Read data from data_file.csv
  key_matrix ← Generate and Save Key Matrix
  ciphertext ← Encrypt data with key_matrix
  Measure encryption_time, memory_usage, throughput
  Write ciphertext to NFC tag
If operation = decryption:
  ciphertext ← Read data from NFC tag
  key_matrix ← Load Key Matrix
  decrypted_data ← Decrypt ciphertext with key_matrix
  Measure decryption_time, memory_usage, throughput
  Write decrypted_data to output_file.csv

Execute Main Function

