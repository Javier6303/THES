import numpy as np
import pandas as pd
import csv
from modules.db_manager import save_key, load_key, load_patient  # Import MongoDB functions

# ------------------- CUSTOM ALPHABET -------------------

CUSTOM_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789,|.@#$/:-_()[]{}!?%&+=*\"' "
ALPHABET_SIZE = len(CUSTOM_ALPHABET)

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

def generate_hill_cipher_key(patient_id, key_name="hill_cipher_key"):
    """Generate and store a new key matrix in MongoDB."""
    key_matrix = np.array([[3, 3], [2, 5]])  # Example 2x2 key matrix
    save_key(key_name, key_matrix.tobytes(), patient_id)  # Store as bytes
    print(f"New Hill Cipher Key Matrix stored in MongoDB: {key_name}")

def get_hill_cipher_key(patient_id, key_name="hill_cipher_key"):
    """Retrieve Hill Cipher key matrix from MongoDB."""
    key_data = load_key(key_name, patient_id)
    if key_data:
        return np.frombuffer(key_data, dtype=int).reshape(2, 2)  # Convert back to numpy array
    print(f"Error: Hill Cipher Key '{key_name}' not found in MongoDB.")
    return None

def hill_encrypt(plaintext, key_matrix):
    """Encrypts plaintext using Hill Cipher."""
    indexes = text_to_numbers(plaintext)

    while len(indexes) % len(key_matrix) != 0:
        indexes.append(char_to_index(" "))  # Pad with space

    ciphertext_indexes = []
    for i in range(0, len(indexes), len(key_matrix)):
        chunk = indexes[i:i + len(key_matrix)]
        encrypted_chunk = np.dot(key_matrix, chunk) % ALPHABET_SIZE
        ciphertext_indexes.extend(encrypted_chunk)

    return numbers_to_text(ciphertext_indexes)

def hill_decrypt(ciphertext, key_matrix_inv):
    """Decrypts ciphertext using Hill Cipher."""
    indexes = text_to_numbers(ciphertext)

    decrypted_indexes = []
    for i in range(0, len(indexes), len(key_matrix_inv)):
        chunk = indexes[i:i + len(key_matrix_inv)]
        decrypted_chunk = np.dot(key_matrix_inv, chunk) % ALPHABET_SIZE
        decrypted_indexes.extend(decrypted_chunk)

    return numbers_to_text(decrypted_indexes).strip()


# ------------------- HILL CIPHER ENCRYPTION -------------------

def hill_cipher_encryption(patient_id, write_to_nfc, key_name="hill_cipher_key"):
    """Encrypt CSV data using Hill Cipher and write to NFC."""
    patient = load_patient(patient_id)
    if not patient:
        print(f"No patient found with ID: {patient_id}")
        return None

    # Remove MongoDB-specific fields (like _id)
    patient.pop("_id", None)

    # Convert patient dict to comma-separated string
    plaintext = ",".join(str(value) for value in patient.values())

    # Retrieve the key matrix from MongoDB or generate a new one
    key_matrix = get_hill_cipher_key(patient_id, key_name)
    if key_matrix is None:
        generate_hill_cipher_key(patient_id, key_name)
        key_matrix = get_hill_cipher_key(patient_id, key_name)

    ciphertext = hill_encrypt(plaintext, key_matrix)

    print("Writing ciphertext to NFC card...")
    write_to_nfc(ciphertext.encode("utf-8"))
    print("Ciphertext successfully written to NFC!")

    return ciphertext


# ------------------- HILL CIPHER DECRYPTION -------------------

def hill_cipher_decryption(get_csv_path, read_from_nfc, patient_id, preloaded_keys=None, key_name="hill_cipher_key", output_file="decrypted_hill_data.csv"):
    """Decrypt data from NFC using Hill Cipher and restore CSV format."""
    if preloaded_keys:
        key_data = preloaded_keys.get(key_name)
        if key_data:
            key_matrix = np.frombuffer(key_data, dtype=int).reshape(2, 2)
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
    decrypted_data = plaintext.split(",")

    csv_file = get_csv_path()
    if not csv_file:
        return None

    df = pd.read_csv(csv_file)
    headers = df.columns.tolist()

    if len(headers) != len(decrypted_data):
        decrypted_data = decrypted_data[:len(headers)]

    with open(output_file, "w", newline="") as csvfile:
        csv_writer = csv.writer(csvfile, quoting=csv.QUOTE_ALL)
        csv_writer.writerow(headers)
        csv_writer.writerow(decrypted_data)

    print(f"Decrypted data saved to '{output_file}'.")

    return plaintext
