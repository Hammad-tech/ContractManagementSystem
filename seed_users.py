#!/usr/bin/env python3
"""
Script to seed the database with initial users for each role.
"""
import sqlite3
import os
from werkzeug.security import generate_password_hash

# Database path
DB_PATH = './instance/database.db'

# User data to seed
# You can change these default credentials
USERS_DATA = [
    {
        "username": "admin_user",
        "email": "admin@example.com",
        "password": "admin123",
        "role": "admin"
    },
    {
        "username": "owner_user",
        "email": "owner@example.com",
        "password": "owner123",
        "role": "owner"
    },
    {
        "username": "contractor_user",
        "email": "contractor@example.com",
        "password": "contractor123",
        "role": "contractor"
    }
]

def seed_users():
    """Seeds the database with initial admin, owner, and contractor users."""
    if not os.path.exists(DB_PATH):
        print(f"❌ Database file not found at {DB_PATH}. Please run the Flask app first to create the database.")
        return

    conn = None
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        print("🌱 Seeding users into the database...")

        for user_data in USERS_DATA:
            # Check if user already exists by email
            cursor.execute("SELECT email FROM user WHERE email = ?", (user_data["email"],))
            existing_user = cursor.fetchone()

            if existing_user:
                print(f"⚠️ User with email {user_data['email']} already exists. Skipping.")
            else:
                hashed_password = generate_password_hash(user_data["password"])
                cursor.execute(
                    "INSERT INTO user (username, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)",
                    (user_data["username"], user_data["email"], hashed_password, user_data["role"])
                )
                print(f"✅ Created {user_data['role']} user: {user_data['username']} ({user_data['email']})")

        conn.commit()
        print("\n🎉 User seeding complete!")
        print("Default credentials (username / password):")
        for user in USERS_DATA:
            print(f"  - {user['role'].title()}: {user['email']} / {user['password']}")

    except sqlite3.Error as e:
        print(f"❌ SQLite error during seeding: {e}")
        if conn:
            conn.rollback()
    except Exception as e:
        print(f"❌ An unexpected error occurred: {e}")
        if conn:
            conn.rollback()
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    # Ensure the app context is available if run directly and models are involved
    # For this script, direct SQLite is fine as we're not using Flask-SQLAlchemy session
    seed_users() 