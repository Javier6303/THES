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
