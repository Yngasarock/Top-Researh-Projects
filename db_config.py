# Configuration of MySQL database.

# config.py

import mysql.connector

# MySQL configuration.
MYSQL_HOST = 'localhost'
MYSQL_USER = 'root'
MYSQL_PASSWORD = 'S3rver01_NGRN'
MYSQL_DATABASE = 'users'

# Function to get a database connection.
def get_db_connection():
    return mysql.connector.connect(
        host=MYSQL_HOST,
        user=MYSQL_USER,
        password=MYSQL_PASSWORD,
        database=MYSQL_DATABASE
    )

# Function to initialize the database.
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(100) NOT NULL,
            password VARCHAR(100) NOT NULL,
            public_key VARCHAR(2000) NOT NULL,
            private_key VARCHAR(2000) NOT NULL
        );
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            filename TEXT NOT NULL,
            signature TEXT NOT NULL,
            aes_key TEXT NOT NULL,
            upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    ''')
    conn.commit()
    conn.close()

# Function to get the private key from the database.
def get_private_key_from_db(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT private_key FROM users WHERE username = %s", (username,))
    private_key = cursor.fetchone()[0]
    conn.close()
    return private_key

# Function to get the public key from the database.
def get_public_key_from_db(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT public_key FROM users WHERE id = %s", (user_id,))
    #cursor.execute("SELECT public_key FROM users WHERE username = %s", (username,))
    public_key = cursor.fetchone()[0]
    conn.close()
    return public_key

# Function to save a file in the database.
def save_files_in_db(user_id, filename, signature, aes_key):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO files (user_id, filename, signature, aes_key) VALUES (%s, %s, %s, %s)", (user_id, filename, signature, aes_key))
    conn.commit()
    conn.close()

# Function to save a user in the database.
def save_user_in_db(username, password, public_key, private_key):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (username, password, public_key, private_key) VALUES (%s, %s, %s, %s)", (username, password, public_key, private_key))
    conn.commit()
    conn.close()
    
# Function to get a file from the database.
def get_file_from_db_by_filename(filename):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM files WHERE filename = %s", (filename,))
    file_record = cursor.fetchone()
    conn.close()
    return file_record

# Function to get a user from the database.
def get_user_from_db(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    conn.close()
    return user

# Function to get the user id from the database.
def get_user_id_from_db(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
    user_id = cursor.fetchone()[0]
    conn.close()
    return user_id