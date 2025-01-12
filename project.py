# Project. Top Secret Research Projects.
# Author: Asael, Josue

# Libraries.
from flask import Flask, request, redirect, session, url_for, render_template, send_file, flash
import os, base64, hashlib, json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Protocol.SecretSharing import Shamir
from io import BytesIO
import db_config # DB configuration.


# -------------------------------------------------------------------------------------------------- #
# Flask app.
app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'  # Folder for uploaded files.
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = 'asael'  # Secret key for the app.

# -------------------------------------------------------------------------------------------------- #
# MySQL configuration.
app.config['MYSQL_HOST'] = db_config.MYSQL_HOST
app.config['MYSQL_USER'] = db_config.MYSQL_USER
app.config['MYSQL_PASSWORD'] = db_config.MYSQL_PASSWORD
app.config['MYSQL_DATABASE'] = db_config.MYSQL_DATABASE

# -------------------------------------------------------------------------------------------------- #
# Create the folder if it doesn't exist.
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# -------------------------------------------------------------------------------------------------- #
# AES-128 key for encryption.

# Function to generate a key.
def generate_aes_key():
    # Generate a random key.
    aes_key = get_random_bytes(16)
    return aes_key

# Function to encrypt a file with AES mode CTR.
def encrypt_file_CTR(file_path):
    key = generate_aes_key()
    iv = get_random_bytes(8)
    cipher = AES.new(key, AES.MODE_CTR, nonce=iv)
    
    with open(file_path, 'rb') as f:
        file_data = f.read()
    encrypted_data = cipher.encrypt(file_data)
    
    # Encode the encrypted data in base64.
    encrypted_data_b64 = base64.b64encode(iv + encrypted_data)

    # Encode the key in base64.
    key_b64 = base64.b64encode(key)

    encrypted_file_path = file_path + '.enc'
    with open(encrypted_file_path, 'wb') as f:
        f.write(encrypted_data_b64)
    
    # Remove the original file.
    os.remove(file_path)

    return encrypted_file_path, key_b64

# Function to decrypt a file with AES mode CTR.
def decrypt_file_CTR(encrypted_data_b64, key):
    # Decode the base64 encoded data
    encrypted_data = base64.b64decode(encrypted_data_b64)
    #print(f'Encrypted data: {encrypted_data}')

    iv = encrypted_data[:8]
    encrypted_data = encrypted_data[8:]

    cipher = AES.new(key, AES.MODE_CTR, nonce=iv)
    decrypted_data = cipher.decrypt(encrypted_data)

    return decrypted_data
# -------------------------------------------------------------------------------------------------- #
# ECDSA key generation.

# Function to generate a key pair.
def generate_key_pair():
    private_key = ECC.generate(curve='P-256')
    public_key = private_key.public_key()

    private_key_pem = private_key.export_key(format='PEM')
    public_key_pem = public_key.export_key(format='PEM')
    
    # Encode keys to base64 format.
    private_key_b64 = base64.b64encode(private_key_pem.encode()).decode()    
    public_key_b64 = base64.b64encode(public_key_pem.encode()).decode()

    return private_key_b64, public_key_b64

# Function to sign a file.
def sign_file(file_path, private_key):
    # Decode the private key.
    #private_key_pem = base64.b64decode(private_key_b64)
    #private_key = ECC.import_key(private_key_pem)
    if hasattr(private_key, 'read'):
        private_key = private_key.read()
    private_key = ECC.import_key(private_key)
    
    signer = DSS.new(private_key, 'fips-186-3')

    with open (file_path, 'rb') as f:
        file_data = f.read()

    # Hash the file data.
    h = SHA256.new(file_data)

    # Sign the hash.
    signature = signer.sign(h)

    return signature

# Function to verify a signature.
def verify_signature(file_data, signature, public_key_b64):
    # Decode the public key.
    public_key_pem = base64.b64decode(public_key_b64)
    public_key = ECC.import_key(public_key_pem)
    verifier = DSS.new(public_key, 'fips-186-3')
    
    #with open (file_path, 'rb') as f:
    #    file_data = f.read()
    
    # Hash the file data.
    h = SHA256.new(file_data)
    
    # Verify the signature.
    try:
        verifier.verify(h, signature)
        return True
    except ValueError:
        return False
    
# -------------------------------------------------------------------------------------------------- #
# Shamir secret sharing.

# Dictionary to store master keys by team.
master_keys_by_team = {}

# Function to generate a secret key.
def generate_secret_key():
    # Generate a random key.
    secret_key = get_random_bytes(16)
    print(f'Secret key: {secret_key}')
    # Encode secret key in base64.
    secret_key = base64.b64encode(secret_key).decode()
    print(f'Secret key in base64: {secret_key}')
    return secret_key

# Function to split a secret key into shares.
def split_secret_key(secret_key, n, k):
    # Decode secret key in base64.
    secret_key = base64.b64decode(secret_key)
    # Split the secret key into shares.
    shares = Shamir.split(k, n, secret_key)
    # Encode shares in base64.
    shares_b64 = [(x, base64.b64encode(y).decode()) for x, y in shares]
    return shares_b64

# Function to reconstruct a secret key from shares.
def reconstruct_secret_key(shares):
    # Decode shares in base64.
    shares = [(x, base64.b64decode(y)) for x, y in shares]
    # Reconstruct the secret key.
    secret_key = Shamir.combine(shares)
    # Encode secret key in base64.
    secret_key = base64.b64encode(secret_key).decode()
    return secret_key

# Fucntion to assign shares to users.
def assign_master_key_shares_in_memory(master_key):
    global users_shares
    user_shares.clear()

    for team, users in active_users_by_team.items():
        num_active_users = len(users)
        print(f'Number of active users in team {team}: {num_active_users}')

        if num_active_users > 0:
            # Generate a master key for each team if it doesn't exist.
            if team not in master_keys_by_team:
                master_keys_by_team[team] = master_key
            master_key = master_keys_by_team[team]
            print(f'Master key for team {team}: {master_key}')

            # Generate shares for the master key.
            shares = split_secret_key(master_key, num_active_users, num_active_users - 1)
            print(f'Shares for team {team}: {shares}')

            # Assign shares to users.
            for i, user in enumerate(users):
                user_shares[user] = shares[i]
                print(f'Assigned share to user {user}: {shares[i]}')

# -------------------------------------------------------------------------------------------------- #
# Key wrapping.

# Function to generate a wrapped key.
def generate_wrapped_key():
    # Generate a random key.
    wrapped_key = get_random_bytes(16)
    # Encode wrapped key in base64.
    wrapped_key_b64 = base64.b64encode(wrapped_key).decode()
    return wrapped_key_b64

# Function to wrap a key.
def wrap_key(filename, key):
    # Decode the key in base64.
    key = base64.b64decode(key)
    print(f'Key: {key}')
    # Generate a wrapped key.
    wrapped_key = generate_wrapped_key()

    # Store the wrapped key in json.
    wrapped_keys_by_file[filename] = wrapped_key
    # Write the wrapped keys to a JSON file.
    with open('wrapped_keys.json', 'w') as json_file:
        json.dump(wrapped_keys_by_file, json_file, indent=4)
    # Decode the wrapped key in base64.
    wrapped_key = base64.b64decode(wrapped_key)
    print(f'Wrapped key: {wrapped_key}')
    # Generate iv.
    iv = get_random_bytes(8)
    # Wrap the key.
    cipher = AES.new(wrapped_key, AES.MODE_CTR, nonce=iv)
    wrapped_key = cipher.encrypt(key)
    # Concatenate iv with wrapped key.
    wrapped = iv + wrapped_key
    # Encode the wrapped key in base64.
    wrapped_key_b64 = base64.b64encode(wrapped).decode()
    return wrapped_key_b64

# Function to unwrap a key.
def unwrap_key(filename, wrapped_key_b64):
    # Load the wrapped keys from the JSON file.
    with open('wrapped_keys.json', 'r') as json_file:
        wrapped_keys_by_file = json.load(json_file)

    print(f'Wrapped Keys by file: {wrapped_keys_by_file}')
    # Get the wrapping key from wrapped_keys_by_file.
    wrapping_key_b64 = wrapped_keys_by_file[filename]
    print(f'Wrapping key: {wrapping_key_b64}')

    # Decode the wrapping key in base64.
    wrapping_key = base64.b64decode(wrapping_key_b64)

    # Decode the wrapped key in base64.
    wrapped_key = base64.b64decode(wrapped_key_b64)

    # Extract the iv from the wrapped key.
    iv = wrapped_key[:8]
    wrapped_key = wrapped_key[8:]

    # Decipher the wrapped key.
    cipher = AES.new(wrapping_key, AES.MODE_CTR, nonce=iv)
    decrypted_wrapped_key = cipher.decrypt(wrapped_key)
    print(f'Decrypted wrapped key: {decrypted_wrapped_key}')
    # Encode the decrypted wrapped key in base64.
    decrypted_wrapped_key_b64 = base64.b64encode(decrypted_wrapped_key).decode()
    return decrypted_wrapped_key_b64


# -------------------------------------------------------------------------------------------------- #
# List of active users by team.
active_users_by_team = {}

# Global dictionary to store user shares.
user_shares = {}

# JSON to store the wrapped keys by file.
wrapped_keys_by_file = {}

# -------------------------------------------------------------------------------------------------- #

# Route for registration.
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        team = request.form['team']
        # Hash the password for storage.
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        # Generate key pair for ECDSA.
        private_key, public_key = generate_key_pair()

        # Check if user exists in the database.
        user = db_config.get_user_from_db(username)

        if user:
            flash('User already exists. Choose a different username.')
            return redirect(url_for('register'))

        # Insert new user.
        db_config.save_user_in_db(username, hashed_password, public_key, team)

        
        # Decode the private key in base64.
        private_key = base64.b64decode(private_key)
        #print(f'Private key: {private_key}')

        # Create a BytesIO object for the private key.
        private_key_io = BytesIO(private_key)
        private_key_io.seek(0)

        # Send the private key file to the user.
        return send_file(private_key_io, as_attachment=True, download_name=f'{username}_private_key.pem')

    # Render the registration page.
    
    return render_template('register.html')

# Route for login.
@app.route('/login', methods=['GET', 'POST'])
def login():
    error_username = None
    error_password = None

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        # Search for the user in the database.
        user = db_config.get_user_from_db(username)

        # Verify if the user exists and the password is correct.
        if user is None:
            error_username = 'User does not exist.'
        elif user[2] != hashed_password:  # Assuming the password is in the third column.
            error_password = 'Incorrect password. Try again.'
        else:
            # If the user exists and the password is correct, set the session and redirect to the index page.
            session['username'] = user[1]
            flash('Login successful.', 'success')

            # Add the user to the list of active users.
            team = user[4]
            if team not in active_users_by_team:
                active_users_by_team[team] = []
            if username not in active_users_by_team[team]:
                active_users_by_team[team].append(username)
            print(f'Active users by team: {active_users_by_team}')

            # Generate shares for the master key if it doesn't exist.
            if team not in master_keys_by_team:
                master_key = generate_secret_key()
                master_keys_by_team[team] = master_key
                assign_master_key_shares_in_memory(master_key)
                print(f'Master key for team {team}: {master_key}')
            else:
                master_key = master_keys_by_team[team]
                assign_master_key_shares_in_memory(master_key)
                print(f'User shares: {user_shares}')

            return redirect(url_for('index'))

    # Render the login page with the error messages.
    return render_template('login.html', error_username=error_username, error_password=error_password)

# Route for logout.
@app.route('/logout')
def logout():
    # Get the username from the session.
    username = session['username']

    # Remove the user from the list of active users by team.
    user = db_config.get_user_from_db(username)
    team = user[4]
    if team in active_users_by_team and username in active_users_by_team[team]:
        active_users_by_team[team].remove(username)
    session.pop('username', None)
    print(f'Active users by team: {active_users_by_team}')

    flash('Logged out.')
    return redirect(url_for('login'))

# Main route (dashboard).
@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('register'))
    username = session['username']
    user = db_config.get_user_from_db(username)
    team = user[4]
    
    # Directory for the team's files.
    team_folder = os.path.join(app.config['UPLOAD_FOLDER'], team)
    if not os.path.exists(team_folder):
        os.makedirs(team_folder)

    # List files in the team's directory.
    files = [f for f in os.listdir(team_folder) if f.endswith('.sig')]
    return render_template('index.html', files=files)

# Upload route.
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files or 'private_key' not in request.files:
        return redirect(url_for('index'))
    
    file = request.files['file']
    private_key = request.files['private_key']

    if file.filename == '' or private_key.filename == '':
        return redirect(url_for('index'))
    
    if file:
        username = session.get('username')
        if not username:
            flash('User not authenticated.')
            return redirect(url_for('login'))
        
        user = db_config.get_user_from_db(username)
        team = user[4]

        # Directory for the team's files.
        team_folder = os.path.join(app.config['UPLOAD_FOLDER'], team)
        if not os.path.exists(team_folder):
            os.makedirs(team_folder)

        # Save the file in the team's directory.
        file_path = os.path.join(team_folder, file.filename)
        file.save(file_path)

        # Sign the file.
        signature = sign_file(file_path, private_key)
        # Encode signature in base64.
        signature_b64 = base64.b64encode(signature)

        # IF the file is signed, encrypt the file.
        if signature:
            # Encrypt the file with AES mode CTR.
            encrypted_file_path, key_b64 = encrypt_file_CTR(file_path)
            print('Key in base64:', key_b64)

            with open(encrypted_file_path, 'rb') as f:
                encrypted_file_data_b64 = f.read()
            
            # Concatenate encrypt file with signature.
            concatenated_file = encrypted_file_data_b64 + signature_b64
            
            # Filename with .sig extension.
            filename_sig = f'{file.filename}.sig'

            # Save the concatenated file.
            concatenated_file_path = os.path.join(team_folder, filename_sig)
            with open(concatenated_file_path, 'wb') as f:
                f.write(concatenated_file)

        # Remove the encrypted file.
        os.remove(encrypted_file_path)
        
        # Get only the username.
        user = user[1]

        # Wrap the key.
        wrapped_key = wrap_key(filename_sig, key_b64)
        print(f'Wrapped keys: {wrapped_keys_by_file}')

        # Save the files in the database.
        db_config.save_files_in_db(user, filename_sig, signature_b64, wrapped_key)
        
        flash(f'File {file.filename} uploaded, signed and encrypted successfully')
        return redirect(url_for('index'))

# Route for downloading a file.
@app.route('/download/<filename>')
def download_file(filename):
    print(f'File selected for download: {filename}')
    
    username = session['username']
    if not username:
        flash('User not authenticated.')
        return redirect(url_for('login'))
    
    user = db_config.get_user_from_db(username)
    team = user[4]

    if team not in active_users_by_team or len(active_users_by_team[team]) < len(user_shares) - 1:
        flash('All team members except one must be logged in to download the file.')
        print('All team members except one must be logged in to download the file.')
        return redirect(url_for('index'))
    
    # Reconstruct the master key.
    shares = [user_shares[username] for username in active_users_by_team[team]]
    print(f'Shares reconstructed for team {team}: {shares}')
    master_key = reconstruct_secret_key(shares)
    print(f'Master key reconstructed: {master_key}')

    # Get the specific file from the database based on the filename.
    file_record = db_config.get_file_from_db_by_filename(filename)
    print(f'File record: {file_record}')
    
    # Get the signature from the file record.
    signature_b64 = file_record[3]
    # Convert signature_b64 to bytes.
    signature_b64 = signature_b64.encode()
    print(f'Signature: {signature_b64}')
    
    # Get the path of the concatenated file.
    concatenated_file_path = os.path.join(app.config['UPLOAD_FOLDER'], team, filename)
    print(f'Concatenated file path: {concatenated_file_path}')
    
    # Read the concatenated file.
    with open(concatenated_file_path, 'rb') as f:
        concatenated_file_data_b64 = f.read()
    
    # Compare the signature with the concatenated file data.
    if signature_b64 in concatenated_file_data_b64:
        print('Signature found in the concatenated file data.')
        # Separate the encrypted file data from the signature.
        encrypted_file_data_b64 = concatenated_file_data_b64[:-len(signature_b64)]
        
        # Get the key from the database.
        wrapped_key_b64 = file_record[4]
        # Convert key_b64 to bytes.
        wrapped_key_b64 = wrapped_key_b64.encode()
        print(f'Wrapped Key (base64): {wrapped_key_b64}')
        
        # Unwrap the key.
        key_b64 = unwrap_key(filename, wrapped_key_b64)

        # Decode key in base64.
        key = base64.b64decode(key_b64)
        
        # Decrypt the file.
        decrypted_file = decrypt_file_CTR(encrypted_file_data_b64, key)
        
        # Get user from the person who signed the file.
        user = file_record[1]
        print(f'User: {user}')

        # Verify the signature.
        public_key_b64 = db_config.get_public_key_from_db(user)
        # Convert the public key to bytes.
        public_key_b64 = public_key_b64.encode()
        print(f'Public key (base64): {public_key_b64}')
        # Decode the signature in base64 format.
        signature = base64.b64decode(signature_b64)
        print(f'Signature: {signature}')

        if verify_signature(decrypted_file, signature, public_key_b64):
            print('Signature verified.')
            
            # Remove the .sig extension from the original filename
            original_filename = os.path.splitext(filename)[0]
            print(original_filename)
            
            # Create a BytesIO object and write the decrypted file to it.
            decrypted_file_io = BytesIO(decrypted_file)
            # Set the pointer to the beginning of the file.
            decrypted_file_io.seek(0)
            # Send the file to the client
            return send_file(decrypted_file_io, as_attachment=True, download_name=original_filename)
        else:
            print('Signature not verified.')
    else:
        print('Signature not found in the concatenated file data.')
    
    return redirect(url_for('index'))

# -------------------------------------------------------------------------------------------------- #
# Initialize the database when the app starts.
db_config.init_db()

if __name__ == '__main__':
    app.run(debug=True)