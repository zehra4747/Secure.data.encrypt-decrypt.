import streamlit as st
import hashlib
import os
import json
import time
from cryptography.fernet import Fernet

# --- Key Management ---
KEY_FILE = "secret.key"

def load_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    else:
        with open(KEY_FILE, "rb") as f:
            key = f.read()
    return key

cipher = Fernet(load_key())

# --- Data Storage ---
DATA_FILE = "data.json"

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

# Initialize session state
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "is_logged_in" not in st.session_state:
    st.session_state.is_logged_in = True

stored_data = load_data()

# --- Helpers ---
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# --- UI Begins ---
st.title("🔐 Secure Data Encryption App")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.radio("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("This app securely **stores and retrieves your data** using encryption and passkeys.")

elif choice == "Store Data":
    st.subheader("📥 Store Data")
    label = st.text_input("Label for your data (e.g., 'Note1'):")
    plain_text = st.text_area("Enter your data:")
    passkey = st.text_input("Set a Passkey:", type="password")

    if st.button("Encrypt and Store"):
        if label and plain_text and passkey:
            encrypted = encrypt_data(plain_text)
            hashed_pass = hash_passkey(passkey)
            stored_data[label] = {"encrypted_text": encrypted, "passkey": hashed_pass}
            save_data(stored_data)
            st.success("✅ Data encrypted and saved!")
        else:
            st.error("⚠️ All fields are required.")

elif choice == "Retrieve Data":
    st.subheader("🔎 Retrieve Data")

    if not st.session_state.is_logged_in:
        st.warning("🔒 Please reauthorize to continue.")
        st.stop()

    label = st.text_input("Enter Label of Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if label in stored_data:
            correct_hash = stored_data[label]["passkey"]
            encrypted_text = stored_data[label]["encrypted_text"]

            if hash_passkey(passkey) == correct_hash:
                result = decrypt_data(encrypted_text)
                st.success(f"✅ Decrypted Data:\n\n{result}")
                st.session_state.failed_attempts = 0
            else:
                st.session_state.failed_attempts += 1
                attempts_left = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts left: {attempts_left}")
                if st.session_state.failed_attempts >= 3:
                    st.session_state.is_logged_in = False
                    st.warning("🚫 Too many attempts. Please login again.")
        else:
            st.error("⚠️ Label not found!")

elif choice == "Login":
    st.subheader("🔐 Reauthorization")
    master_pass = st.text_input("Enter Master Password (hint: admin123)", type="password")

    if st.button("Login"):
        if master_pass == "admin123":
            st.session_state.failed_attempts = 0
            st.session_state.is_logged_in = True
            st.success("✅ Reauthorized successfully.")
        else:
            st.error("❌ Wrong master password.")