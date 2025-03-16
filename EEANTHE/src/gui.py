import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import logging
import os
from dotenv import load_dotenv
from pymongo import MongoClient
from base64 import b64encode
from modules.aes_ndef import aes_encryption, aes_decryption
from modules.aes_rsa import aes_rsa_encryption, aes_rsa_decryption
from modules.rsa import rsa_encryption, rsa_decryption
from modules.hill_cipher import hill_cipher_encryption, hill_cipher_decryption
from modules.ecc import ecc_xor_encryption, ecc_xor_decryption
from modules.ecdh_aes import ecdh_aes_encryption, ecdh_aes_decryption
from main import measure_performance, CONFIG_PATH, write_to_nfc_card_as_ndef, read_from_nfc_card
from modules.db_manager import save_new_patient, update_patient

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

        # -------------------- Create Notebook --------------------
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True)

        # --- Tab 1: Patient Operations ---
        self.operations_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.operations_frame, text="Patient Operations")

        # --- Tab 2: Metrics ---
        self.metrics_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.metrics_frame, text="Metrics")

        # -------------------- Frame inside Patient Operations tab --------------------
        ttk.Label(self.operations_frame, text="Select Patient Type:").pack(pady=5)
        self.patient_type = ttk.Combobox(self.operations_frame, values=["New Patient", "Existing Patient"], state="readonly")
        self.patient_type.pack(pady=5)
        self.patient_type.bind("<<ComboboxSelected>>", self.render_form)

        # Form frame inside operations tab
        self.form_frame = ttk.Frame(self.operations_frame)
        self.form_frame.pack(pady=10)

        # Shared patient fields
        self.patient_fields = [
            "Name", "Age", "Sex", "Address", "Contact Number", "Email", "Birthday", "Height",
            "Blood Pressure", "Blood Type", "Allergies", "History of Medical Illnesses",
            "Doctor's Notes", "Last Appointment Date"
        ]
        self.entries = {}

        # Encryption algorithm selector
        self.encryption_choice = ttk.Combobox(self.operations_frame, values=[
            "AES", "RSA", "AES-RSA", "Hill Cipher", "ECC XOR", "ECDH-AES"
        ], state="readonly")
        self.encryption_choice.pack(pady=5)

        # Save button (only for new patients)
        self.action_btn = ttk.Button(self.operations_frame, text="Save & Encrypt", command=self.save_and_encrypt)
        self.action_btn.pack(pady=10)

        # -------------------- Metrics Tab --------------------
        self.metrics_display = scrolledtext.ScrolledText(self.metrics_frame, width=100, height=30, state="disabled")
        self.metrics_display.pack(padx=10, pady=10)

    def render_form(self, event=None):
        # Clear current form
        for widget in self.form_frame.winfo_children():
            widget.destroy()

        self.entries.clear()
        selected_type = self.patient_type.get()

        if selected_type == "New Patient":
            # Show fields directly
            for field in self.patient_fields:
                ttk.Label(self.form_frame, text=field + ":").pack(pady=2)
                entry = ttk.Entry(self.form_frame)
                entry.pack()
                self.entries[field] = entry

            ttk.Label(self.form_frame, text="Select Algorithm For Encryption:").pack(pady=5)

            # Only show Save & Encrypt for New Patient
            self.action_btn.config(text="Save & Encrypt", command=self.save_and_encrypt)
            self.action_btn.pack(pady=10)

        elif selected_type == "Existing Patient":
            # Hide Save & Encrypt (if it was packed before)
            self.action_btn.pack_forget()

            # Patient ID field
            ttk.Label(self.form_frame, text="Patient ID:").pack(pady=2)
            self.patient_id_entry = ttk.Entry(self.form_frame)
            self.patient_id_entry.pack()

            # Algorithm dropdown
            ttk.Label(self.form_frame, text="Select Algorithm Used During Encryption:").pack(pady=5)
            self.encryption_choice.pack()

            # Decrypt button only for now
            self.decrypt_btn = ttk.Button(self.form_frame, text="Decrypt NFC Data", command=self.decrypt_existing_patient)
            self.decrypt_btn.pack(pady=10)

    def save_and_encrypt(self):
        method = self.encryption_choice.get()
        if not method:
            messagebox.showerror("Error", "Please select an encryption method.")
            return

        patient_data = {field: self.entries[field].get().strip() for field in self.patient_fields}
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
            metrics = measure_performance(
                operation="1",
                encryption_func=encryption_func,
                decryption_func=None,  # not needed for encryption
                patient_id=patient_id,
                config_func=lambda: CONFIG_PATH,
                nfc_write_func=write_to_nfc_card_as_ndef,
                nfc_read_func=read_from_nfc_card,
                asymmetric=True  # all your algorithms use asymmetric_mode=True now
            )

            messagebox.showinfo("Success", f"Patient data saved and encrypted to NFC.\nID: {patient_id}")
            self.display_metrics(metrics, "encryption")

        except Exception as e:
            messagebox.showerror("Error", str(e))

        
        
    def decrypt_existing_patient(self):
        method = self.encryption_choice.get()
        if not method:
            messagebox.showerror("Error", "Please select an algorithm used.")
            return

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
                patient_id=None,  # not needed in current design
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
                entry = ttk.Entry(self.form_frame)
                entry.insert(0, decrypted_fields[i] if i < len(decrypted_fields) else "")
                entry.pack()
                self.entries[field] = entry

            # Add Update & Encrypt button
            self.update_btn = ttk.Button(self.form_frame, text="Update & Encrypt", command=self.update_and_encrypt)
            self.update_btn.pack(pady=15)

                
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))

    def update_and_encrypt(self):
        method = self.encryption_choice.get()
        patient_id = self.patient_id_entry.get().strip()

        if not method or not patient_id:
            messagebox.showerror("Error", "Please provide patient ID and select an encryption method.")
            return

        updated_data = {field: self.entries[field].get().strip() for field in self.patient_fields}
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

        try:
            metrics = measure_performance(
                operation="1",
                encryption_func=encryption_func,
                decryption_func=None,
                patient_id=patient_id,
                config_func=lambda: CONFIG_PATH,
                nfc_write_func=write_to_nfc_card_as_ndef,
                nfc_read_func=read_from_nfc_card,
                asymmetric=True
            )
            self.display_metrics(metrics, "encryption")
            messagebox.showinfo("Success", f"Patient {patient_id} updated and re-encrypted.")
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))

    

    def display_metrics(self, metrics, operation):
        self.metrics_display.configure(state="normal")
        self.metrics_display.insert(tk.END, f"\n--- {operation.upper()} METRICS ---\n")
        for key, value in metrics.items():
            if isinstance(value, dict):
                for subkey, subval in value.items():
                    self.metrics_display.insert(tk.END, f"{subkey.capitalize()}: {subval}\n")
            else:
                self.metrics_display.insert(tk.END, f"{key.replace('_', ' ').capitalize()}: {value}\n")
        self.metrics_display.insert(tk.END, "\n")
        self.metrics_display.configure(state="disabled")

# ----------------- LAUNCH -----------------
if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionGUI(root)
    root.mainloop()
