import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import logging
import os
from dotenv import load_dotenv
from pymongo import MongoClient
from base64 import b64encode
from smartcard.System import readers
from smartcard.util import toHexString
from modules.aes_ndef import aes_encryption, aes_decryption
from modules.aes_rsa import aes_rsa_encryption, aes_rsa_decryption
from modules.rsa import rsa_encryption, rsa_decryption
from modules.hill_cipher import hill_cipher_encryption, hill_cipher_decryption
from modules.ecc import ecc_xor_encryption, ecc_xor_decryption
from modules.ecdh_aes import ecdh_aes_encryption, ecdh_aes_decryption
from main import measure_performance, CONFIG_PATH, write_to_nfc_card_as_ndef, read_from_nfc_card
from modules.db_manager import save_new_patient, update_patient
from modules.email import send_email
from datetime import timedelta
import datetime 



# ----------------- LOGGER -----------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ----------------- LOAD ENV -----------------
load_dotenv()
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME = "encryption_db"
PATIENTS_COLLECTION = "patients"

# ----------------- CONNECT TO MONGO -----------------
client = MongoClient(MONGO_URI)
db = client[DB_NAME]
patients_collection = db[PATIENTS_COLLECTION]


# ----------------- GUI CLASS -----------------
class EncryptionGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Patient Encryption System")
        self.root.geometry("800x1000")

        # ----- Notebook Tabs -----
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True)

        self.operations_frame = ttk.Frame(self.notebook)
        self.metrics_frame = ttk.Frame(self.notebook)
        self.info_frame = ttk.Frame(self.notebook)

        self.notebook.add(self.operations_frame, text="Patient Operations")
        self.notebook.add(self.metrics_frame, text="Metrics")
        self.notebook.add(self.info_frame, text="Information")

        # ----- NFC Info Tab -----
        ttk.Button(self.info_frame, text="Read NFC Card Info", command=self.read_nfc_info).pack(pady=10)
        self.info_display = scrolledtext.ScrolledText(self.info_frame, width=100, height=30, state="disabled")
        self.info_display.pack(padx=10, pady=10)

        # ----- Patient Type (Operations Tab) -----
        ttk.Label(self.operations_frame, text="Select Patient Type:").pack(pady=5)

        initial_patient_type = self.check_nfc_card_has_data()
        patient_type_values = [initial_patient_type] if initial_patient_type else ["New Patient", "Existing Patient"]

        self.patient_type = ttk.Combobox(self.operations_frame, values=patient_type_values, state="readonly")
        self.patient_type.pack(pady=5)
        if initial_patient_type:
            self.patient_type.set(initial_patient_type)

        self.patient_type.bind("<<ComboboxSelected>>", self.render_form)

        # Form container and field definitions
        self.form_frame = ttk.Frame(self.operations_frame)
        self.form_frame.pack(pady=10)

        self.entries = {}
        self.patient_fields = [
            "Name", "Age", "Sex", "Address", "Contact Number", "Email", "Birthday", "Height",
            "Blood Pressure", "Blood Type", "History of Medical Illnesses", "Last Appointment Date","Next Appointment Date",
            "Doctor's Notes"
        ]

        # ----- Metrics Tab -----
        self.metrics_display = scrolledtext.ScrolledText(self.metrics_frame, width=100, height=30, state="disabled")
        self.metrics_display.pack(padx=10, pady=10)

        # Auto-render form based on card data
        if initial_patient_type:
            self.render_form()


    def render_form(self, event=None):
        # Clear current form
        for widget in self.form_frame.winfo_children():
            widget.destroy()

        self.entries.clear()
        selected_type = self.patient_type.get()

        if selected_type == "New Patient":
            # Clear previous
            self.entries.clear()

            # Form fields
            for field in self.patient_fields:
                ttk.Label(self.form_frame, text=field + ":").pack(pady=2)
                
                if field == "Last Appointment Date":
                    # Set the default value of 'Last Appointment Date' to today's date
                    last_appointment_date = datetime.date.today().strftime("%Y-%m-%d")  # Format it as YYYY-MM-DD
                    entry = ttk.Entry(self.form_frame)
                    entry.insert(0, last_appointment_date)  # Insert today's date into the entry field
                    entry.pack()
                    self.entries[field] = entry

                elif field == "Doctor's Notes":
                    text_widget = tk.Text(self.form_frame, height=7)
                    text_widget.pack(fill="both", expand=True, padx=10, pady=5)
                    self.entries[field] = text_widget
                else:
                    entry = ttk.Entry(self.form_frame)
                    entry.pack()
                    self.entries[field] = entry

            # Encryption label + dropdown
            ttk.Label(self.form_frame, text="Select Algorithm For Encryption:").pack(pady=5)
            self.encryption_choice = ttk.Combobox(self.form_frame, values=[
                "AES", "RSA", "AES-RSA", "Hill Cipher", "ECC XOR", "ECDH-AES"
            ], state="readonly")
            self.encryption_choice.pack()

            # Save button
            self.action_btn = ttk.Button(self.form_frame, text="Save & Encrypt", command=self.save_and_encrypt)
            self.action_btn.pack(pady=10)


        elif selected_type == "Existing Patient":
            # Clear previous
            self.entries.clear()

            # Patient ID
            ttk.Label(self.form_frame, text="Patient ID:").pack(pady=2)
            self.patient_id_entry = ttk.Entry(self.form_frame)
            self.patient_id_entry.pack()

            # Encryption label + dropdown
            ttk.Label(self.form_frame, text="Select Algorithm Used During Encryption:").pack(pady=5)
            self.encryption_choice = ttk.Combobox(self.form_frame, values=[
                "AES", "RSA", "AES-RSA", "Hill Cipher", "ECC XOR", "ECDH-AES"
            ], state="readonly")
            self.encryption_choice.pack()

            # Decrypt button
            self.decrypt_btn = ttk.Button(self.form_frame, text="Decrypt NFC Data", command=self.decrypt_existing_patient)
            self.decrypt_btn.pack(pady=10)

            

    def save_and_encrypt(self):
        method = self.encryption_choice.get()
        if not method:
            messagebox.showerror("Error", "Please select an encryption method.")
            return

        patient_data = {
            field: (
                self.entries[field].get("1.0", tk.END).strip()
                if isinstance(self.entries[field], tk.Text)
                else self.entries[field].get().strip()
            )
            for field in self.patient_fields
        }

        if any(not value for value in patient_data.values()):
            messagebox.showerror("Error", "All fields must be filled.")
            return

        patient_id = save_new_patient(patient_data)

        encryption_func = {
            "AES": aes_encryption,
            "RSA": rsa_encryption,
            "AES-RSA": aes_rsa_encryption,
            "Hill Cipher": hill_cipher_encryption,
            "ECC XOR": ecc_xor_encryption,
            "ECDH-AES": ecdh_aes_encryption
        }.get(method)

        try:

            metrics = {
                "plaintext_data": ",".join(str(v) for v in patient_data.values()) # joined as a single string for display
            }
            encryption_metrics = measure_performance(
                operation="1",
                encryption_func=encryption_func,
                decryption_func=None,  # not needed for encryption
                patient_id=patient_id,
                config_func=lambda: CONFIG_PATH,
                nfc_write_func=write_to_nfc_card_as_ndef,
                nfc_read_func=read_from_nfc_card,
                asymmetric=True  # all your algorithms use asymmetric_mode=True now
            )

            metrics.update(encryption_metrics)

            messagebox.showinfo("Success", f"Patient data saved and encrypted to NFC.\nID: {patient_id}")
            self.display_metrics(metrics, "encryption")

        except Exception as e:
            messagebox.showerror("Error", str(e))

        # --- Send appointment email after successful encryption ---
        try:
            email = patient_data["Email"]
            next_appointment = patient_data["Next Appointment Date"]

            subject = f"Your Next Appointment (Patient ID: {patient_id})"
            body = f"Dear {patient_data['Name']},\n\nYour next appointment is scheduled for: {next_appointment}.\n\nThank you."

            send_email(email, subject, body)
        except Exception as e:
            print(f"Failed to send appointment email: {e}")

        
        
    def decrypt_existing_patient(self):
        method = self.encryption_choice.get()
        if not method:
            messagebox.showerror("Error", "Please select an algorithm used.")
            return
        
        patient_id = self.patient_id_entry.get().strip()

        decryption_func = {
            "AES": aes_decryption,
            "RSA": rsa_decryption,
            "AES-RSA": aes_rsa_decryption,
            "Hill Cipher": hill_cipher_decryption,
            "ECC XOR": ecc_xor_decryption,
            "ECDH-AES": ecdh_aes_decryption
        }.get(method)

        try:
            metrics = measure_performance(
                operation="2",
                encryption_func=None,  # not needed for decryption
                decryption_func=decryption_func,
                patient_id=patient_id,  # not needed in current design
                config_func=lambda: CONFIG_PATH,
                nfc_write_func=write_to_nfc_card_as_ndef,  # still required by the function signature
                nfc_read_func=read_from_nfc_card,
                asymmetric=True
            )

            self.display_metrics(metrics, "decryption")
            decrypted_text = metrics.get("decryption_data", None)
            # Display decrypted text (split and display)
            if isinstance(decrypted_text, bytes):
                decrypted_text = decrypted_text.decode()

            decrypted_fields = decrypted_text.split(",")
            for widget in self.form_frame.winfo_children():
                widget.destroy()

            ttk.Label(self.form_frame, text="Patient ID:").pack(pady=2)
            self.patient_id_entry = ttk.Entry(self.form_frame)
            self.patient_id_entry.insert(0, decrypted_fields[-1])
            self.patient_id_entry.pack()

            for i, field in enumerate(self.patient_fields):
                ttk.Label(self.form_frame, text=field + ":").pack(pady=2)
                value = decrypted_fields[i] if i < len(decrypted_fields) else ""

                if field == "Doctor's Notes":
                    text_widget = tk.Text(self.form_frame, height=7)
                    text_widget.insert("1.0", value)
                    text_widget.pack(fill="both", expand=True, padx=10, pady=5)
                    self.entries[field] = text_widget
                else:
                    entry = ttk.Entry(self.form_frame)
                    entry.insert(0, value)
                    entry.pack()
                    self.entries[field] = entry

            ttk.Label(self.form_frame, text="Select Algorithm Used During Encryption:").pack(pady=5)
            self.encryption_choice = ttk.Combobox(self.form_frame, values=[
                "AES", "RSA", "AES-RSA", "Hill Cipher", "ECC XOR", "ECDH-AES"
            ], state="readonly")
            self.encryption_choice.pack()
            
            # Add Update & Encrypt button
            self.update_btn = ttk.Button(self.form_frame, text="Update & Encrypt", command=self.update_and_encrypt)
            self.update_btn.pack(pady=15)

              
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))

    def update_and_encrypt(self):
        try:
            # Make sure the encryption dropdown exists
            if not hasattr(self, 'encryption_choice') or not self.encryption_choice.winfo_exists():
                messagebox.showerror("Error", "Encryption method selector is unavailable.")
                return

            method = self.encryption_choice.get()
            patient_id = self.patient_id_entry.get().strip()

            if not method or not patient_id:
                messagebox.showerror("Error", "Please provide patient ID and select an encryption method.")
                return

            updated_data = {
                field: (
                    self.entries[field].get("1.0", tk.END).strip()
                    if isinstance(self.entries[field], tk.Text)
                    else self.entries[field].get().strip()
                )
                for field in self.patient_fields
            }
            if any(not value for value in updated_data.values()):
                messagebox.showerror("Error", "All fields must be filled.")
                return

            success = update_patient(patient_id, updated_data)
            if not success:
                messagebox.showerror("Error", f"Patient ID '{patient_id}' not found.")
                return

            encryption_func = {
                "AES": aes_encryption,
                "RSA": rsa_encryption,
                "AES-RSA": aes_rsa_encryption,
                "Hill Cipher": hill_cipher_encryption,
                "ECC XOR": ecc_xor_encryption,
                "ECDH-AES": ecdh_aes_encryption
            }.get(method)

            metrics = {
                "plaintext_data": ",".join(str(v) for v in updated_data.values())
            }

            encryption_metrics = measure_performance(
                operation="1",
                encryption_func=encryption_func,
                decryption_func=None,
                patient_id=patient_id,
                config_func=lambda: CONFIG_PATH,
                nfc_write_func=write_to_nfc_card_as_ndef,
                nfc_read_func=read_from_nfc_card,
                asymmetric=True
            )

            metrics.update(encryption_metrics)

            self.display_metrics(metrics, "encryption")
            messagebox.showinfo("Success", f"Patient {patient_id} updated and re-encrypted.")

        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))

        # --- Send appointment email after successful encryption ---
        try:
            email = updated_data["Email"]
            next_appointment = updated_data["Next Appointment Date"]
            subject = f"Your Next Appointment (Patient ID: {patient_id})"
            body = f"Dear {updated_data['Name']},\n\nYour next appointment is scheduled for: {next_appointment}.\n\nThank you."

            send_email(email, subject, body)
        except Exception as e:
            print(f"Failed to send updated appointment email: {e}")

            
    def display_metrics(self, metrics, operation):
        self.metrics_display.configure(state="normal")
        self.metrics_display.insert(tk.END, f"\n--- {operation.upper()} METRICS ---\n")

        for key, value in metrics.items():
            if isinstance(value, dict):
                for subkey, subval in value.items():
                    self.metrics_display.insert(tk.END, f"{subkey.capitalize()}: {subval}\n")

            elif key == "plaintext_data":
                self.metrics_display.insert(tk.END, "Plaintext data (before encryption):\n")
                split_data = value.split(",")
                for i, field in enumerate(self.patient_fields):
                    val = split_data[i] if i < len(split_data) else "<missing>"
                    self.metrics_display.insert(tk.END, f"{field}: {val}\n")
                    
            elif key in ("encryption_data", "decryption_data"):
                # Show encoded form
                if isinstance(value, bytes):
                    try:
                        hexed = value.hex()
                        self.metrics_display.insert(tk.END, f"{key.replace('_', ' ').capitalize()} (Hex):\n{hexed}\n")

                        # Show readable decrypted string if applicable
                        if key == "decryption_data":
                            try:
                                decoded_text = value.decode()
                                self.metrics_display.insert(tk.END, f"{key.replace('_', ' ').capitalize()} (Text):\n{decoded_text}\n")
                            except Exception:
                                self.metrics_display.insert(tk.END, f"{key.replace('_', ' ').capitalize()} (Text): <Unreadable or binary>\n")
                    except Exception:
                        self.metrics_display.insert(tk.END, f"{key.replace('_', ' ').capitalize()}: <Binary data>\n")

                else:
                    self.metrics_display.insert(tk.END, f"{key.replace('_', ' ').capitalize()}: {value}\n")

            else:
                self.metrics_display.insert(tk.END, f"{key.replace('_', ' ').capitalize()}: {value}\n")

        self.metrics_display.insert(tk.END, "\n")
        self.metrics_display.configure(state="disabled")


    def read_nfc_info(self):
        try:
            r = readers()
            if not r:
                messagebox.showerror("NFC Error", "No NFC readers found.")
                return

            reader = r[0]
            connection = reader.createConnection()
            connection.connect()

            atr = connection.getATR()
            atr_hex = toHexString(atr)

            # Try getting UID from page 0 (common for NTAG cards)
            get_uid_cmd = [0xFF, 0xCA, 0x00, 0x00, 0x00]
            uid, sw1, sw2 = connection.transmit(get_uid_cmd)
            uid_str = toHexString(uid) if sw1 == 0x90 and sw2 == 0x00 else "Unavailable"
            
            # Read raw NDEF pages (4–225)
            nfc_data = b""
            pages_read = 0
            for page in range(4, 225):
                READ_COMMAND = [0xFF, 0xB0, 0x00, page, 0x04]
                response, sw1, sw2 = connection.transmit(READ_COMMAND)
                if sw1 == 0x90 and sw2 == 0x00:
                    nfc_data += bytes(response)
                    pages_read += 1
                else:
                    break

            nfc_data = nfc_data.rstrip(b'\x00')

            # Parse text from NDEF payload
            record = "Unavailable"
            if nfc_data and nfc_data[0] == 0x03:
                try:
                    index = 2
                    while index < len(nfc_data) and nfc_data[index] != 0x54:
                        index += 1

                    language_code_length = nfc_data[index + 1]
                    text_start = index + 2 + language_code_length
                    text_end = nfc_data.find(b'\xFE')  # End of NDEF message
                    record_data = nfc_data[text_start:text_end]
                    record = record_data.decode(errors='replace')  # Even if it's encrypted

                except Exception as parse_err:
                    record = f"Error parsing record: {parse_err}"

            memory_bytes = pages_read * 4
            info = [
                f"Reader: {reader}",
                f"ATR: {atr_hex}",
                f"UID: {uid_str}",
                f"Memory Pages: {pages_read} (4 bytes each) = {memory_bytes} bytes",  # can be calculated from read loop if needed
                f"RECORD 1: Text (en) = {record}"
            ]

            self.info_display.configure(state="normal")
            self.info_display.delete("1.0", tk.END)
            for line in info:
                self.info_display.insert(tk.END, line + "\n")
            self.info_display.configure(state="disabled")

        except Exception as e:
            messagebox.showerror("NFC Error", str(e))
    
    def check_nfc_card_has_data(self):
        try:
            r = readers()
            if not r:
                return None

            reader = r[0]
            connection = reader.createConnection()
            connection.connect()

            nfc_data = b""
            for page in range(4, 225):
                READ_COMMAND = [0xFF, 0xB0, 0x00, page, 0x04]
                response, sw1, sw2 = connection.transmit(READ_COMMAND)
                if sw1 == 0x90 and sw2 == 0x00:
                    nfc_data += bytes(response)
                else:
                    break

            nfc_data = nfc_data.rstrip(b"\x00")
            if nfc_data and b'\x03' in nfc_data:
                return "Existing Patient"
            return "New Patient"

        except Exception as e:
            print("NFC check failed:", e)
            return None


# ----------------- LAUNCH -----------------
if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionGUI(root)
    root.mainloop()
