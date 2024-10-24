import sqlite3
import bcrypt

# Setup database
def setup_db():
    conn = sqlite3.connect('user_auth.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT UNIQUE, password BLOB)''')  # Using BLOB for storing encrypted password
    conn.commit()
    conn.close()

# Register user
def register_user(username, password):
    if len(username) > 15:
        return "Failure: Username exceeds 15 characters."

    if len(password) < 8 or not any(char.isdigit() for char in password) or not any(char.isalpha() for char in password) or not any(char in "!@#$%^&*()-_=+" for char in password):
        return "Failure: Password must be at least 8 characters long and contain letters, numbers, and symbols."

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    try:
        conn = sqlite3.connect('user_auth.db')
        c = conn.cursor()
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        conn.close()
        return "Success: User registered."
    except sqlite3.IntegrityError:
        return "Failure: Username already exists."

# Authenticate user
def authenticate_user(username, password):
    conn = sqlite3.connect('user_auth.db')
    c = conn.cursor()
    c.execute("SELECT password FROM users WHERE username=?", (username,))
    result = c.fetchone()
    conn.close()

    # Check if user exists and if the password matches
    if result and bcrypt.checkpw(password.encode('utf-8'), result[0]):
        return "Success: Authentication succeeded."
    else:
        return "Failure: Authentication failed."

# View all users in the database (for verification purposes)
def view_users():
    conn = sqlite3.connect('user_auth.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users")
    rows = c.fetchall()
    conn.close()
    
    print("Users in database:")
    for row in rows:
        print(f"Username: {row[0]}, Password Hash: {row[1]}")

# Main program
def main():
    setup_db()

    while True:
        print("\nChoose an option:")
        print("(1) Register")
        print("(2) Authenticate")
        print("(3) View Users in Database")
        print("(4) Exit")
        
        choice = input("Enter your choice (1/2/3/4): ")

        if choice == '1':
            username = input("Enter username (max 15 chars): ")
            password = input("Enter password (min 8 chars, must include letters, numbers, and symbols): ")
            print(register_user(username, password))

        elif choice == '2':
            username = input("Enter username: ")
            password = input("Enter password: ")
            print(authenticate_user(username, password))

        elif choice == '3':
            view_users()

        elif choice == '4':
            print("Exiting the program.")
            break

        else:
            print("Invalid option. Please enter 1, 2, 3, or 4.")

if __name__ == "__main__":
    main()
