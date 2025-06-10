import numpy as np
import pandas as pd
import csv
from modules.db_manager import save_key, load_key, load_patient  # Import MongoDB functions

# ------------------- CUSTOM ALPHABET -------------------

CUSTOM_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789,|.@#$/:-_()[]{}!?%&+=*\"' "
ALPHABET_SIZE = len(CUSTOM_ALPHABET)
HILL_MATRIX_SIZE = 6


def char_to_index(char):
    """Convert character to index based on CUSTOM_ALPHABET."""
    return CUSTOM_ALPHABET.index(char) if char in CUSTOM_ALPHABET else CUSTOM_ALPHABET.index(" ")

def index_to_char(index):
    """Convert index back to a character in CUSTOM_ALPHABET."""
    return CUSTOM_ALPHABET[index % ALPHABET_SIZE]

def text_to_numbers(text):
    """Convert text to a list of numbers based on CUSTOM_ALPHABET."""
    return [char_to_index(c) for c in text]

def numbers_to_text(numbers):
    """Convert a list of numbers back to text using CUSTOM_ALPHABET."""
    return "".join(index_to_char(n) for n in numbers)


# ------------------- HILL CIPHER FUNCTIONS -------------------

def mod_inverse_matrix(matrix, mod=ALPHABET_SIZE):
    """Finds the modular inverse of a matrix under mod ALPHABET_SIZE."""
    det = int(np.round(np.linalg.det(matrix)))
    det_inv = pow(det, -1, mod)
    matrix_inv = np.round(det_inv * np.linalg.det(matrix) * np.linalg.inv(matrix)).astype(int) % mod
    return matrix_inv 

def hill_encrypt(plaintext, key_matrix):
    """Encrypts plaintext using Hill Cipher."""
    indexes = text_to_numbers(plaintext)
    n = HILL_MATRIX_SIZE  # block size

    while len(indexes) % n != 0:
        indexes.append(char_to_index(" "))  # Pad with space

    ciphertext_indexes = []
    for i in range(0, len(indexes), n):
        chunk = np.array(indexes[i:i + n])
        encrypted_chunk = np.dot(key_matrix, chunk) % ALPHABET_SIZE
        ciphertext_indexes.extend(encrypted_chunk)

    return numbers_to_text(ciphertext_indexes)

def hill_decrypt(ciphertext, key_matrix_inv):
    """Decrypts ciphertext using Hill Cipher."""
    indexes = text_to_numbers(ciphertext)
    n = HILL_MATRIX_SIZE

    decrypted_indexes = []
    for i in range(0, len(indexes), n):
        chunk = np.array(indexes[i:i + n])
        decrypted_chunk = np.dot(key_matrix_inv, chunk) % ALPHABET_SIZE
        decrypted_indexes.extend(decrypted_chunk)

    return numbers_to_text(decrypted_indexes).strip()

def generate_hill_cipher_key(key_name="hill_cipher_key"):
    """Generate Hill Cipher key matrix and return it as a dict."""
    n = HILL_MATRIX_SIZE  # 4x4 matrix for AES-128 level

    while True:
        matrix = np.random.randint(0, ALPHABET_SIZE, (n, n), dtype=np.int32)
        try:
            det = int(np.round(np.linalg.det(matrix)))
            if det != 0 and pow(det, -1, ALPHABET_SIZE):  # Ensure invertibility mod ALPHABET_SIZE
                break
        except ValueError:
            continue  # Try again if modular inverse doesn't exist

    return {key_name: matrix.tobytes()}

# ------------------- HILL CIPHER ENCRYPTION -------------------

def hill_cipher_encryption(patient, write_to_nfc, preloaded_keys=None, key_name="hill_cipher_key"):
    """Encrypt CSV data using Hill Cipher and write to NFC."""

    # Remove MongoDB-specific fields (like _id)
    patient.pop("_id", None)

    # Convert patient dict to comma-separated string
    plaintext = ",".join(str(value) for value in patient.values())

    # Retrieve the key matrix from MongoDB or generate a new one
    key_matrix = None
    key_bytes = preloaded_keys.get(key_name)
    key_matrix = np.frombuffer(key_bytes, dtype=np.int32).reshape(HILL_MATRIX_SIZE, HILL_MATRIX_SIZE)
    
    ciphertext = hill_encrypt(plaintext, key_matrix)

    print("Writing ciphertext to NFC card...")
    write_to_nfc(ciphertext.encode("utf-8"))
    print("Ciphertext successfully written to NFC!")

    return ciphertext, {key_name: key_bytes}


# ------------------- HILL CIPHER DECRYPTION -------------------

def hill_cipher_decryption(get_csv_path, read_from_nfc, patient_id, preloaded_keys=None, key_name="hill_cipher_key", output_file="decrypted_hill_data.csv"):
    """Decrypt data from NFC using Hill Cipher and restore CSV format."""
    key_matrix = None
    if preloaded_keys:
        key_data = preloaded_keys.get(key_name)
        if key_data:
            key_matrix = np.frombuffer(key_data, dtype=np.int32).reshape(HILL_MATRIX_SIZE, HILL_MATRIX_SIZE)
        else:
            print(f"Error: Preloaded Hill Cipher key '{key_name}' not found.")
            return None
        
    if key_matrix is None:
        print(f"Error: No Hill Cipher key found in MongoDB for '{key_name}'.")
        return None

    key_matrix_inv = mod_inverse_matrix(key_matrix)

    ciphertext = read_from_nfc().decode("utf-8")

    if not ciphertext:
        print("Error: No ciphertext found on NFC card.")
        return None

    plaintext = hill_decrypt(ciphertext, key_matrix_inv)

    return plaintext
