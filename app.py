import streamlit as st
import hashlib

# Initialize session state
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}  # {"id_1": {"text": ..., "passkey": ...}}

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

# Function to hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# UI Title
st.title("🔐 Simple Passkey-Protected Storage")

# Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome to Simple Data Vault")
    st.write("Store your data with a passkey — no encryption, just protection.")

elif choice == "Store Data":
    st.subheader("📂 Store Data")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            data_id = f"id_{len(st.session_state.stored_data) + 1}"
            st.session_state.stored_data[data_id] = {"text": user_data, "passkey": hashed_passkey}
            st.success(f"✅ Data stored! Your Data ID: `{data_id}`")
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Data")
    data_id = st.text_input("Enter Data ID:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Retrieve"):
        if data_id and passkey:
            hashed_passkey = hash_passkey(passkey)
            data = st.session_state.stored_data.get(data_id)

            if data:
                if data["passkey"] == hashed_passkey:
                    st.session_state.failed_attempts = 0
                    st.success(f"✅ Your Data: {data['text']}")
                else:
                    st.session_state.failed_attempts += 1
                    attempts_left = 3 - st.session_state.failed_attempts
                    st.error(f"❌ Incorrect passkey! Attempts left: {attempts_left}")
                    if st.session_state.failed_attempts >= 3:
                        st.warning("🔒 Too many failed attempts. Redirecting to login...")
                        st.experimental_rerun()
            else:
                st.error("❌ Data ID not found.")
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Login":
    st.subheader("🔑 Admin Login")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":
            st.session_state.failed_attempts = 0
            st.success("✅ Logged in! Redirecting to Retrieve Data...")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect master password!")


