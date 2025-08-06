# THES

## Environment Setup

- **Python 3.10 or higher**
- **Virtual Environment set-up**
  1. Open a terminal in your project folder.
  2. Create a virtual environment (name it `venv`):
     ```bash
     python -m venv venv
     ```
  3. Activate the virtual environment:
     - **Windows (Command Prompt)**:
       ```bash
       venv\Scripts\activate
       ```
     - **Windows (PowerShell)**:
       ```bash
       .\venv\Scripts\Activate.ps1
       ```
  4. Install all required libraries:
     ```bash
     pip install -r requirements.txt
     ```

- **Python Libraries**  
  *Note: Can also be installed through `pip -r install requirements.txt`*  
  - python-dotenv  
  - pyscard  
  - pandas  
  - pycryptodome  
  - cryptography  
  - numpy  
  - pymongo  
  - gmpy2  
  - datetime  
  - psutil  

## Running the Program

1. Ensure that all necessary packages are installed as mentioned previously, and that the program and its source codes are run in a virtual environment.  
2. Make sure to adjust the IP address for the `MongoDB_URI` in the `gui.py` and `db_manager.py` source codes.  
3. Update the `.env` file to match the system path where patient_data_headers.csv is located.
4. Run the program by using the following command:  
   ```bash
   & .venv/Scripts/python.exe path/to/your/script.py
5. A GUI window will then appear, which allows the user to input the patient data and select an encryption algorithm, encrypt, and write to the NFC card, or decrypt the patient data written on the NFC card.
6. The output for both encryption and decryption will be displayed in the GUI and will also be saved in both a CSV file (metrics_log) and a .log file (metrics_result.log), as seen in the images below. Additionally, another CSV file (e.g., decrypted_aes for AES     decryption) containing the decrypted data is produced during each decryption, depending on the algorithm used.
