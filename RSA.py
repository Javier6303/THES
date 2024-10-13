# Import necessary libraries for RSA encryption/decryption, file handling, and NFC interaction.

Initialize necessary libraries for RSA encryption/decryption and NFC communication.

Define function to generate RSA keys:
    - Generate a new RSA key pair (2048 bits).
    - Save the private key to a file (e.g., 'private.pem').
    - Save the public key to a separate file (e.g., 'receiver.pem').
    - Return a message indicating the keys have been successfully generated.

Define function to load RSA key:
    - If public key is needed for encryption, load it from a specified file (e.g., 'receiver.pem').
    - If private key is needed for decryption, load it from a different file (e.g., 'private.pem').
    - Return the corresponding RSA key for use in encryption or decryption.

Define function to perform RSA encryption:
    Take the data and RSA public key as input.
    Use RSA with OAEP padding to securely encrypt the data.
    Return the encrypted data.

Define function to perform RSA decryption:
    Take the encrypted data and RSA private key as input.
    Use RSA with OAEP padding to decrypt the data.
    If the decryption is successful, return the decrypted data.
    If decryption fails, display an error message.

Define function to handle NFC tag interaction:
    Set up NFC reader and wait for a tag to be tapped.
    Depending on the operation (encryption or decryption):
        - For encryption: Write only the RSA encrypted data to the NFC tag.
        - For decryption: Read the encrypted data from the NFC tag.
    Close the NFC connection after the operation is completed.

Define function to write decrypted data to a file:
    Take the decrypted data and write it into a CSV file or any specified file format.

Define function to display status messages:
    Display a message indicating success or failure of the encryption or decryption process.

Define main function:
    Ask the user to choose whether to generate RSA keys, perform encryption, or perform decryption.

    If key generation is chosen:
        Generate RSA keys (public and private) and save them to files.
        Display a success message for key generation.

    If encryption is chosen:
        Load the public key from a file.
        Prepare the data to be encrypted.
        Encrypt the data using the RSA public key and measure the time taken.
        Wait for the NFC tag to be tapped.
        Write only the encrypted data to the NFC tag.
        Display a success or failure message based on the outcome.

    If decryption is chosen:
        Load the private key from a file.
        Wait for the NFC tag to be tapped.
        Read the encrypted data from the NFC tag.
        Decrypt the data using the RSA private key and measure the time taken.
        Write the decrypted data to a CSV file.
        Display a success or failure message based on the outcome.

Execute the main function to start the process.
