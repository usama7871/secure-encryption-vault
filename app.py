import streamlit as st
import hashlib
import json
import os
import time
import uuid
import base64
import io
import mimetypes
from pathlib import Path
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PIL import Image

# ============ Configuration ============
CONFIG = {
    "MAX_LOGIN_ATTEMPTS": 3,
    "LOCKOUT_TIME_SECONDS": 300,  # 5 minutes
    "DATA_DIRECTORY": "secure_data",
    "VAULT_FILE": "vault.json",
    "SALT_FILE": "salt.key",
    "SESSION_TIMEOUT": 600,  # 10 minutes of inactivity
    "MAX_FILE_SIZE_MB": 25,  # Maximum file size in MB
    "SUPPORTED_EXTENSIONS": {
        "Images": [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp"],
        "Documents": [".pdf", ".doc", ".docx", ".txt", ".rtf", ".odt", ".xlsx", ".csv"],
        "Videos": [".mp4", ".mov", ".avi", ".mkv", ".webm"],
        "Audio": [".mp3", ".wav", ".ogg", ".flac", ".aac"],
    }
}

# ============ Initialize App State ============
def initialize_app():
    """Initialize session state and application folders"""
    # Session variables
    if 'login_attempts' not in st.session_state:
        st.session_state.login_attempts = 0
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'last_attempt' not in st.session_state:
        st.session_state.last_attempt = time.time()
    if 'last_activity' not in st.session_state:
        st.session_state.last_activity = time.time()
    if 'user_id' not in st.session_state:
        st.session_state.user_id = None
    if 'file_upload_type' not in st.session_state:
        st.session_state.file_upload_type = "Text"
    
    # Create secure data directory if it doesn't exist
    data_dir = Path(CONFIG["DATA_DIRECTORY"])
    data_dir.mkdir(exist_ok=True)
    
    # Generate a salt for the application if it doesn't exist
    salt_path = data_dir / CONFIG["SALT_FILE"]
    if not salt_path.exists():
        with open(salt_path, "wb") as f:
            f.write(os.urandom(16))

# ============ Security Functions ============
def get_salt():
    """Get the application salt"""
    salt_path = Path(CONFIG["DATA_DIRECTORY"]) / CONFIG["SALT_FILE"]
    with open(salt_path, "rb") as f:
        return f.read()

def derive_key(password, salt=None):
    """Derive a key from password using PBKDF2"""
    if salt is None:
        salt = get_salt()
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def hash_password(password):
    """Create a secure hash of the password with salt"""
    salt = get_salt()
    return hashlib.pbkdf2_hmac(
        'sha256', 
        password.encode(), 
        salt, 
        iterations=100000
    ).hex()

def create_cipher(password):
    """Create a Fernet cipher based on a password"""
    key = derive_key(password)
    return Fernet(key)

def encrypt_text(text, password):
    """Encrypt text using the provided password"""
    cipher = create_cipher(password)
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text, password):
    """Decrypt text using the provided password"""
    try:
        cipher = create_cipher(password)
        return cipher.decrypt(encrypted_text.encode()).decode()
    except Exception as e:
        st.error(f"Decryption failed")
        return None

def encrypt_binary(data, password):
    """Encrypt binary data using the provided password"""
    cipher = create_cipher(password)
    return cipher.encrypt(data)

def decrypt_binary(encrypted_data, password):
    """Decrypt binary data using the provided password"""
    try:
        cipher = create_cipher(password)
        return cipher.decrypt(encrypted_data)
    except Exception as e:
        st.error(f"Decryption failed")
        return None

# ============ Data Management ============
def get_vault_path():
    """Get the path to the vault file"""
    return Path(CONFIG["DATA_DIRECTORY"]) / CONFIG["VAULT_FILE"]

def save_data(data_dict):
    """Save data to the vault file"""
    with open(get_vault_path(), "w") as f:
        json.dump(data_dict, f, indent=2)

def load_data():
    """Load data from the vault file"""
    try:
        vault_path = get_vault_path()
        if not vault_path.exists():
            return {}
        
        with open(vault_path, "r") as f:
            return json.load(f)
    except Exception as e:
        st.error(f"Error loading data: {e}")
        return {}

def update_activity():
    """Update the last activity timestamp"""
    st.session_state.last_activity = time.time()

def check_session_timeout():
    """Check if the session has timed out"""
    if st.session_state.authenticated:
        time_since_activity = time.time() - st.session_state.last_activity
        if time_since_activity > CONFIG["SESSION_TIMEOUT"]:
            st.session_state.authenticated = False
            return True
    return False

# ============ User Management ============
def get_users():
    """Get all registered users"""
    vault = load_data()
    return vault.get("users", {})

def create_user(username, password):
    """Create a new user"""
    users = get_users()
    
    # Check if username already exists
    if username in users:
        return False, "Username already exists"
    
    # Create a new user with hashed password
    user_id = str(uuid.uuid4())
    users[username] = {
        "id": user_id,
        "password_hash": hash_password(password),
        "created_at": datetime.now().isoformat(),
    }
    
    # Save updated users to vault
    vault = load_data()
    vault["users"] = users
    save_data(vault)
    
    return True, user_id

def authenticate_user(username, password):
    """Authenticate a user with username and password"""
    users = get_users()
    
    if username not in users:
        return False, "Invalid username or password"
    
    user = users[username]
    if user["password_hash"] != hash_password(password):
        return False, "Invalid username or password"
    
    return True, user["id"]

# ============ File Management ============
def identify_file_type(file):
    """Identify the file type from uploaded file"""
    filename = file.name.lower()
    _, ext = os.path.splitext(filename)
    
    for file_type, extensions in CONFIG["SUPPORTED_EXTENSIONS"].items():
        if ext in extensions:
            return file_type
    
    return "Unknown"

def get_file_icon(file_type):
    """Get appropriate icon for file type"""
    icons = {
        "Text": "📝",
        "Images": "🖼️",
        "Documents": "📄",
        "Videos": "🎬",
        "Audio": "🔊",
        "Unknown": "📎"
    }
    return icons.get(file_type, "📎")

# ============ Vault Management ============
def get_user_vault(user_id):
    """Get the vault data for a specific user"""
    vault = load_data()
    if "data" not in vault:
        vault["data"] = {}
    
    if user_id not in vault["data"]:
        vault["data"][user_id] = []
        save_data(vault)
    
    return vault["data"][user_id]

def save_to_vault(user_id, title, encrypted_data, encryption_key_hash, file_type="Text", file_metadata=None):
    """Save encrypted data to the user's vault"""
    vault = load_data()
    
    if "data" not in vault:
        vault["data"] = {}
    
    if user_id not in vault["data"]:
        vault["data"][user_id] = []
    
    # Create new entry
    entry = {
        "id": str(uuid.uuid4()),
        "title": title,
        "encrypted_data": encrypted_data if isinstance(encrypted_data, str) else base64.b64encode(encrypted_data).decode('ascii'),
        "key_hash": encryption_key_hash,
        "created_at": datetime.now().isoformat(),
        "file_type": file_type,
        "file_metadata": file_metadata or {}
    }
    
    vault["data"][user_id].append(entry)
    save_data(vault)
    return True

def delete_from_vault(user_id, entry_id):
    """Delete an entry from the user's vault"""
    vault = load_data()
    
    if "data" not in vault or user_id not in vault["data"]:
        return False
    
    # Filter out the entry to delete
    vault["data"][user_id] = [e for e in vault["data"][user_id] if e["id"] != entry_id]
    save_data(vault)
    return True

# ============ UI Components ============
def render_login_page():
    """Render the login page"""
    st.title("🔐 Secure Vault")
    
    # Check if account is locked out
    if time.time() - st.session_state.last_attempt < CONFIG["LOCKOUT_TIME_SECONDS"] and st.session_state.login_attempts >= CONFIG["MAX_LOGIN_ATTEMPTS"]:
        remaining = int(CONFIG["LOCKOUT_TIME_SECONDS"] - (time.time() - st.session_state.last_attempt))
        st.error(f"Too many failed attempts. Account locked for {remaining} seconds")
        st.progress(1 - remaining/CONFIG["LOCKOUT_TIME_SECONDS"])
        return
    
    tab1, tab2 = st.tabs(["Login", "Register"])
    
    with tab1:
        st.subheader("Login")
        username = st.text_input("Username", key="login_username")
        password = st.text_input("Password", type="password", key="login_password")
        
        col1, col2 = st.columns([1, 3])
        with col1:
            if st.button("Login", use_container_width=True):
                if not username or not password:
                    st.error("Please fill in all fields")
                    return
                
                success, result = authenticate_user(username, password)
                if success:
                    st.session_state.authenticated = True
                    st.session_state.user_id = result
                    st.session_state.login_attempts = 0
                    update_activity()
                    st.rerun()
                else:
                    st.session_state.login_attempts += 1
                    st.session_state.last_attempt = time.time()
                    remaining_attempts = CONFIG["MAX_LOGIN_ATTEMPTS"] - st.session_state.login_attempts
                    st.error(f"Authentication failed. Attempts remaining: {remaining_attempts}")

    with tab2:
        st.subheader("Register")
        new_username = st.text_input("Choose a username", key="register_username")
        new_password = st.text_input("Create a password", type="password", key="register_password")
        confirm_password = st.text_input("Confirm password", type="password", key="confirm_password")
        
        col1, col2 = st.columns([1, 3])
        with col1:
            if st.button("Register", use_container_width=True):
                if not new_username or not new_password or not confirm_password:
                    st.error("Please fill in all fields")
                    return
                
                if new_password != confirm_password:
                    st.error("Passwords do not match")
                    return
                
                if len(new_password) < 8:
                    st.error("Password must be at least 8 characters long")
                    return
                
                success, result = create_user(new_username, new_password)
                if success:
                    st.success("Registration successful! You can now log in.")
                else:
                    st.error(result)

def render_main_app():
    """Render the main application after login"""
    # Check for session timeout
    if check_session_timeout():
        st.error("Your session has expired. Please log in again.")
        st.rerun()
    
    update_activity()
    
    st.title("🔐 Secure Data Vault")
    
    # Sidebar navigation
    with st.sidebar:
        st.write(f"Last activity: {datetime.fromtimestamp(st.session_state.last_activity).strftime('%H:%M:%S')}")
        page = st.radio("Navigation", ["Store Data", "Retrieve Data", "File Browser"])
        
        if st.button("Logout", type="primary"):
            st.session_state.authenticated = False
            st.session_state.user_id = None
            st.rerun()
    
    if page == "Store Data":
        render_store_data_page()
    elif page == "Retrieve Data":
        render_retrieve_data_page()
    elif page == "File Browser":
        render_file_browser_page()

def render_store_data_page():
    """Render the page for storing data"""
    st.header("Store Sensitive Data")
    
    # Select data type to store
    data_type = st.radio("Select type of data to store:", 
                         ["Text", "File"], 
                         horizontal=True,
                         index=0 if st.session_state.file_upload_type == "Text" else 1)
    st.session_state.file_upload_type = data_type
    
    if data_type == "Text":
        render_text_upload_form()
    else:
        render_file_upload_form()

def render_text_upload_form():
    """Render the form for uploading text data"""
    with st.form("store_text_form"):
        title = st.text_input("Entry Title")
        data = st.text_area("Enter sensitive data:", height=200)
        key = st.text_input("Enter encryption key:", type="password", 
                            help="This key will be used to encrypt and decrypt your data")
        confirm_key = st.text_input("Confirm encryption key:", type="password")
        
        submit = st.form_submit_button("Encrypt & Store")
        
        if submit:
            if not title or not data or not key or not confirm_key:
                st.error("Please fill in all fields")
                return
            
            if key != confirm_key:
                st.error("Encryption keys do not match")
                return
            
            try:
                encrypted = encrypt_text(data, key)
                key_hash = hash_password(key)
                metadata = {"content_length": len(data)}
                save_to_vault(st.session_state.user_id, title, encrypted, key_hash, "Text", metadata)
                st.success("Data stored securely! ✅")
                
                # Show some details without exposing sensitive info
                st.info(f"Entry '{title}' created with {len(data)} characters of encrypted data")
            except Exception as e:
                st.error(f"Error storing data: {e}")

def render_file_upload_form():
    """Render the form for uploading file data"""
    with st.form("store_file_form"):
        title = st.text_input("File Title", help="A descriptive name for this file")
        
        uploaded_file = st.file_uploader("Upload a file", 
                                        type=sum(CONFIG["SUPPORTED_EXTENSIONS"].values(), []),
                                        help=f"Maximum file size: {CONFIG['MAX_FILE_SIZE_MB']}MB")
        
        key = st.text_input("Enter encryption key:", type="password", 
                           help="This key will be used to encrypt and decrypt your file")
        confirm_key = st.text_input("Confirm encryption key:", type="password")
        
        submit = st.form_submit_button("Encrypt & Store File")
        
        if submit:
            if not title or not uploaded_file or not key or not confirm_key:
                st.error("Please fill in all fields and upload a file")
                return
            
            if key != confirm_key:
                st.error("Encryption keys do not match")
                return
            
            try:
                # Check file size
                file_size_mb = uploaded_file.size / (1024 * 1024)
                if file_size_mb > CONFIG["MAX_FILE_SIZE_MB"]:
                    st.error(f"File too large. Maximum size is {CONFIG['MAX_FILE_SIZE_MB']}MB")
                    return
                
                # Read file content
                file_bytes = uploaded_file.getvalue()
                
                # Identify file type
                file_type = identify_file_type(uploaded_file)
                
                # Create metadata
                file_metadata = {
                    "filename": uploaded_file.name,
                    "size": uploaded_file.size,
                    "mime_type": uploaded_file.type or mimetypes.guess_type(uploaded_file.name)[0] or "application/octet-stream"
                }
                
                # Encrypt the file
                encrypted_data = encrypt_binary(file_bytes, key)
                key_hash = hash_password(key)
                
                # Save to vault
                save_to_vault(st.session_state.user_id, title, encrypted_data, key_hash, file_type, file_metadata)
                st.success(f"File '{uploaded_file.name}' encrypted and stored securely! ✅")
                st.info(f"File size: {file_size_mb:.2f}MB | Type: {file_type}")
                
            except Exception as e:
                st.error(f"Error storing file: {e}")

def render_retrieve_data_page():
    """Render the page for retrieving data"""
    st.header("Retrieve Data")
    
    user_vault = get_user_vault(st.session_state.user_id)
    
    if not user_vault:
        st.info("You don't have any stored data yet")
        st.button("Go to Store Data", on_click=lambda: st.session_state.update({"page": "Store Data"}))
        return
    
    # Sort entries by creation date, newest first
    sorted_entries = sorted(user_vault, key=lambda x: x.get("created_at", ""), reverse=True)
    
    # Create select box with entry titles and file type icons
    entry_titles = [f"{get_file_icon(e.get('file_type', 'Text'))} {e['title']} ({e['created_at'].split('T')[0]})" for e in sorted_entries]
    selected_index = st.selectbox("Select entry:", range(len(entry_titles)), format_func=lambda i: entry_titles[i])
    
    selected_entry = sorted_entries[selected_index]
    
    # Show file metadata if available
    file_type = selected_entry.get('file_type', 'Text')
    file_metadata = selected_entry.get('file_metadata', {})
    
    col1, col2 = st.columns(2)
    with col1:
        st.write(f"Type: {file_type}")
        st.write(f"Created: {selected_entry['created_at'].replace('T', ' ')}")
    
    with col2:
        if file_metadata:
            if "filename" in file_metadata:
                st.write(f"Original filename: {file_metadata['filename']}")
            if "size" in file_metadata:
                st.write(f"Size: {file_metadata['size'] / 1024:.2f} KB")
    
    with st.form(key=f"decrypt_form_{selected_entry['id']}"):
        key = st.text_input("Enter decryption key:", type="password")
        col1, col2, col3 = st.columns([1, 1, 1])
        
        with col1:
            decrypt_button = st.form_submit_button("Decrypt")
        
        with col3:
            delete_button = st.form_submit_button("Delete Entry", type="secondary")
        
        if decrypt_button:
            if not key:
                st.error("Please enter the decryption key")
                return
            
            if hash_password(key) != selected_entry["key_hash"]:
                st.error("Invalid decryption key")
                return
            
            try:
                if file_type == "Text":
                    decrypted = decrypt_text(selected_entry["encrypted_data"], key)
                    if decrypted:
                        st.success("Data decrypted successfully!")
                        st.text_area("Decrypted Data:", value=decrypted, height=200)
                        st.session_state.pop("decrypted_file", None)  # Clear previous file if any
                else:
                    encrypted_data = base64.b64decode(selected_entry["encrypted_data"])
                    decrypted_data = decrypt_binary(encrypted_data, key)
                    
                    if decrypted_data:
                        st.success("File decrypted successfully!")

                        mime_type = file_metadata.get('mime_type')
                        filename = file_metadata.get('filename', f"decrypted_{selected_entry['id']}")

                        # Store in session for download outside form
                        st.session_state["decrypted_file"] = {
                            "data": decrypted_data,
                            "filename": filename,
                            "mime_type": mime_type,
                            "file_type": file_type,
                        }

                        # Show preview
                        if file_type == "Images":
                            try:
                                image = Image.open(io.BytesIO(decrypted_data))
                                st.image(image, caption=filename)
                            except:
                                st.warning("Could not preview image, but you can download it below.")
                        elif file_type == "Videos":
                            st.video(decrypted_data, format=mime_type)
                        elif file_type == "Audio":
                            st.audio(decrypted_data, format=mime_type)

            except Exception as e:
                st.error(f"Error during decryption: {str(e)}")
        
        if delete_button:
            if st.session_state.get("confirm_delete") != selected_entry["id"]:
                st.session_state["confirm_delete"] = selected_entry["id"]
                st.warning("Click 'Delete Entry' again to confirm deletion")
                return
            
            if delete_from_vault(st.session_state.user_id, selected_entry["id"]):
                st.session_state.pop("confirm_delete", None)
                st.success("Entry deleted successfully!")
                time.sleep(1)
                st.rerun()
            else:
                st.error("Failed to delete entry")

    # ✅ Show download button OUTSIDE the form
    if "decrypted_file" in st.session_state:
        decrypted = st.session_state["decrypted_file"]
        st.download_button(
            label="Download File",
            data=decrypted["data"],
            file_name=decrypted["filename"],
            mime=decrypted["mime_type"],
        )    
    else:
                st.error("Failed to delete entry")

def render_file_browser_page():
    """Render the file browser page with filtering capabilities"""
    st.header("File Browser")
    
    user_vault = get_user_vault(st.session_state.user_id)
    
    if not user_vault:
        st.info("You don't have any stored data yet")
        st.button("Go to Store Data", on_click=lambda: st.session_state.update({"page": "Store Data"}))
        return
    
    # Filter options
    col1, col2 = st.columns(2)
    with col1:
        # Get unique file types
        file_types = ["All"] + list(set([entry.get("file_type", "Text") for entry in user_vault]))
        selected_type = st.selectbox("Filter by type:", file_types)
    
    with col2:
        search_term = st.text_input("Search by title:", "")
    
    # Apply filters
    filtered_entries = user_vault
    if selected_type != "All":
        filtered_entries = [e for e in filtered_entries if e.get("file_type") == selected_type]
    
    if search_term:
        filtered_entries = [e for e in filtered_entries if search_term.lower() in e["title"].lower()]
    
    # Sort by creation date
    filtered_entries = sorted(filtered_entries, key=lambda x: x.get("created_at", ""), reverse=True)
    
    # Show results
    st.subheader(f"Found {len(filtered_entries)} items")
    
    # Display grid of items
    cols = st.columns(3)
    for i, entry in enumerate(filtered_entries):
        file_type = entry.get("file_type", "Text")
        icon = get_file_icon(file_type)
        title = entry["title"]
        created = entry["created_at"].split("T")[0]
        
        with cols[i % 3]:
            st.markdown(f"""
            <div style="border:1px solid #ddd; padding:10px; margin:5px; border-radius:5px;">
                <h3>{icon} {title}</h3>
                <p>Type: {file_type}<br>Created: {created}</p>
            </div>
            """, unsafe_allow_html=True)
            
            if st.button(f"View {title}", key=f"view_{entry['id']}"):
                # Set session state to open this entry in retrieve page
                st.session_state["selected_entry_id"] = entry["id"]
                st.session_state["page"] = "Retrieve Data"
                st.rerun()

# ============ Additional Features ============
def get_file_stats():
    """Get statistics about stored files"""
    user_vault = get_user_vault(st.session_state.user_id)
    
    stats = {
        "total": len(user_vault),
        "by_type": {},
        "total_size": 0
    }
    
    for entry in user_vault:
        file_type = entry.get("file_type", "Text")
        stats["by_type"][file_type] = stats["by_type"].get(file_type, 0) + 1
        
        # Calculate size
        if file_type == "Text":
            # Approximate text size
            stats["total_size"] += len(entry.get("encrypted_data", ""))
        else:
            # Get actual file size from metadata
            metadata = entry.get("file_metadata", {})
            stats["total_size"] += metadata.get("size", 0)
    
    return stats

# ============ Main App ============
def main():
    # Initialize app state and data directories
    initialize_app()
    
    # Set page config
    st.set_page_config(
        page_title="Secure Vault",
        page_icon="🔐",
        layout="centered"
    )
    
    # Custom CSS for better appearance
    st.markdown("""
    <style>
    .stButton button {
        width: 100%;
    }
    .stProgress > div > div {
        background-color: red;
    }
    </style>
    """, unsafe_allow_html=True)
    
    # Display appropriate page based on authentication state
    if st.session_state.authenticated:
        render_main_app()
    else:
        render_login_page()

if __name__ == "__main__":
    main()