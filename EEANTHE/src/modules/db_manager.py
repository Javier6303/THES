from pymongo import MongoClient
import os
from dotenv import load_dotenv
from base64 import b64encode, b64decode
from Crypto.PublicKey import RSA  # Import RSA for correct handling

# Load environment variables
load_dotenv()

# Update MongoDB details
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME = "encryption_db"
COLLECTION_NAME = "keys"

# Connect to MongoDB
try:
    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    collection = db[COLLECTION_NAME]
    print("Connected to MongoDB successfully.")
except Exception as e:
    print(f"Error connecting to MongoDB: {e}")

def save_key(key_name, key_data):
    """Save a key to MongoDB (Base64 Encoded)."""
    key_encoded = b64encode(key_data).decode()  # Convert bytes to Base64 string
    collection.update_one(
        {"key_name": key_name}, 
        {"$set": {"key_data": key_encoded}}, 
        upsert=True
    )
    print(f"Key '{key_name}' saved to MongoDB.")


def load_key(key_name):
    """Retrieve a key from MongoDB."""
    key_entry = collection.find_one({"key_name": key_name})
    if key_entry:
        print(f"Key '{key_name}' loaded from MongoDB.")
        return b64decode(key_entry["key_data"])  # Convert back from base64
    print(f"Key '{key_name}' not found in MongoDB.")
    return None

def load_patient(patient_id):
    """Retrieve patient document by patient_id."""
    return db["patients"].find_one({"patient_id": patient_id})

def generate_next_patient_id():
    """Auto-generates the next patient ID like 'P001', 'P002'..."""
    last_patient = db["patients"].find().sort("patient_id", -1).limit(1)
    last = list(last_patient)
    if last:
        last_id = int(last[0]["patient_id"][1:])
        return f"P{last_id + 1:03d}"
    return "P001"

def save_new_patient(data):
    """Insert new patient into MongoDB and return assigned patient_id."""
    patient_id = generate_next_patient_id()
    data["patient_id"] = patient_id
    db["patients"].insert_one(data)
    print(f"New patient saved with ID: {patient_id}")
    return patient_id

def update_patient(patient_id, updated_data):
    """Update an existing patient in MongoDB using patient_id."""
    result = db["patients"].update_one(
        {"patient_id": patient_id},
        {"$set": updated_data}
    )
    if result.matched_count > 0:
        if result.modified_count == 0:
            print(f"Patient {patient_id} was found, but no fields changed.")
        else:
            print(f"Patient {patient_id} updated.")
        return True
    else:
        print(f"Patient ID '{patient_id}' not found.")
        return False
