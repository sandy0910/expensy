from flask import Flask, request, jsonify
from pymongo import MongoClient
from flask_cors import CORS
from datetime import datetime
import requests
from requests.auth import HTTPBasicAuth
from bson import ObjectId
from dotenv import load_dotenv
import os
import threading
import sys
import base64
import calendar
from cryptography.fernet import Fernet
import requests
from requests.auth import HTTPBasicAuth
from flask import Flask, request, jsonify, session

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for cross-origin requests from Flutter app

# Database configuration
class Database:
    def __init__(self, uri, db_name):
        self.client = MongoClient(uri)
        self.db = self.client[db_name]

    def get_collection(self, collection_name):
        return self.db[collection_name]

load_dotenv()
db = Database(os.getenv("MONGO_URI"), "expense_tracker")

# CryptoKeyManager to handle cryptoKey securely
class CryptoKeyManager:
    _crypto_key = None

    @staticmethod
    def set_key(key):
        if CryptoKeyManager._crypto_key is None:
            CryptoKeyManager._crypto_key = key
        else:
            raise ValueError("Crypto key is already set and cannot be changed.")

    @staticmethod
    def get_key():
        if CryptoKeyManager._crypto_key is None:
            raise ValueError("Crypto key is not set yet.")
        return CryptoKeyManager._crypto_key

# User management
class User:
    def __init__(self, db):
        self.collection = db.get_collection("users")

    def login(self, email, password, mpin):
        user = self.collection.find_one({"email": email, "password": password, "mpin": mpin})
        return user

    def signup(self, name, email, password, mpin):
        if self.collection.find_one({"email": email}):
            return None
        new_user = {
            "name": name,
            "email": email,
            "password": password,  # Storing plain passwords (not secure)
            "mpin": mpin
        }
        self.collection.insert_one(new_user)
        return new_user

users = User(db)

# User management for cryptoKey
class Key:
    def __init__(self, db):
        self.collection = db.get_collection("keys")

    def get_key(self, email, key):
        key = self.collection.find_one({"email": email, "key": key})
        return key

    def store_key(self, email, key):
        if self.collection.find_one({"email": email}):
            print("storing key email")
            return None
        new_key = {
            "email": email,
            "key": key
        }
        self.collection.insert_one(new_key)
        print("stored key")
        return new_key

keys = Key(db)

# Transaction management with encryption and decryption
class Transaction:
    def __init__(self, db):
        self.collection = db.get_collection("transactions")

    def encrypt_transaction_data(self, data):
        fernet = Fernet(CryptoKeyManager.get_key())
        encrypted_data = fernet.encrypt(data.encode())
        # Base64 encode the binary data to make it JSON serializable
        return base64.b64encode(encrypted_data).decode()

    def decrypt_transaction_data(self, encrypted_data):
        # Base64 decode the encrypted data before decryption
        encrypted_data_bytes = base64.b64decode(encrypted_data)
        fernet = Fernet(CryptoKeyManager.get_key())
        decrypted_data = fernet.decrypt(encrypted_data_bytes).decode()
        return decrypted_data

    def get_transactions(self):
        transactions = list(self.collection.find({}))
        for transaction in transactions:
            transaction['_id'] = str(transaction['_id'])
            transaction['amount'] = self.decrypt_transaction_data(transaction['amount'])
            transaction['category'] = self.decrypt_transaction_data(transaction['category'])
            transaction['userEmail'] = self.decrypt_transaction_data(transaction['userEmail'])

        return transactions

    def calculate_expense_stats(self, user_email, month):
        try:
            # Convert month name to number
            month_num = datetime.strptime(month, "%B").month
            current_year = datetime.now().year

            # Generate date range strings
            start_date = f"{current_year}-{month_num:02d}-01T00:00:00.000000"
            _, last_day = calendar.monthrange(current_year, month_num)
            end_date = f"{current_year}-{month_num:02d}-{last_day}T23:59:59.999999"

            # Fetch all transactions within the date range
            user_transactions = list(self.collection.find({
                "timestamp": {"$gte": start_date, "$lte": end_date}
            }))

            # Filter transactions by decrypting and comparing userEmail
            matching_transactions = [
                transaction for transaction in user_transactions
                if self.decrypt_transaction_data(transaction.get('userEmail')) == user_email
            ]

            if not matching_transactions:
                return {"message": "No transactions found for this user in the specified month"}, 404

            # Define categories dynamically
            categories = set(self.decrypt_transaction_data(transaction.get('category')) for transaction in user_transactions)
            
            total_expense = 0
            category_totals = {category: 0 for category in categories}

            for transaction in user_transactions:
                amount = float(self.decrypt_transaction_data(transaction.get('amount')))
                category = self.decrypt_transaction_data(transaction.get('category'))
                total_expense += amount
                category_totals[category] += amount

            avg_expense = total_expense / len(user_transactions) if user_transactions else 0

            # Sort category_totals by value in descending order
            sorted_category_totals = dict(sorted(category_totals.items(), key=lambda item: item[1], reverse=True))

            stats = {
                'total_expense': total_expense,
                'average_expense': avg_expense,
                'category_totals': sorted_category_totals
            }

            return stats, 200
        except Exception as e:
            return {'error': str(e)}, 500


transactions = Transaction(db)

class Payment:
    RAZORPAY_KEY = 'rzp_test_McwSUcwNGFPUuj'
    RAZORPAY_SECRET = 'tMiEVgXMLywBs8e2EzN5cv0F'

    def __init__(self, db):
        self.collection = db.get_collection("transactions")

    def encrypt_transaction_data(self, data):
        # Encrypt the data using Fernet and the global cryptoKey
        print("Encrypting with key:", CryptoKeyManager.get_key())
        fernet = Fernet(CryptoKeyManager.get_key())
        encrypted_data = fernet.encrypt(data.encode())
        # Base64 encode the binary data to make it JSON serializable
        return base64.b64encode(encrypted_data).decode()

    def decrypt_transaction_data(self, encrypted_data):
        # Base64 decode the encrypted data before decryption
        encrypted_data_bytes = base64.b64decode(encrypted_data)
        print("Decrypting with key:", CryptoKeyManager.get_key())
        fernet = Fernet(CryptoKeyManager.get_key())
        decrypted_data = fernet.decrypt(encrypted_data_bytes).decode()
        return decrypted_data

    def save_payment_details(self, payment_id, category, userEmail):
        url = f'https://api.razorpay.com/v1/payments/{payment_id}'
        response = requests.get(url, auth=HTTPBasicAuth(self.RAZORPAY_KEY, self.RAZORPAY_SECRET))

        if response.status_code == 200:
            payment_data = response.json()
            # Convert amount from paise to rupees and encrypt it
            payment_data['amount'] = self.encrypt_transaction_data(str(payment_data.get('amount', 0) / 100))
            payment_data['category'] = self.encrypt_transaction_data(category)
            payment_data['userEmail'] = self.encrypt_transaction_data(userEmail)
            payment_data['timestamp'] = datetime.now().isoformat()

            # Save the payment details in the database
            inserted_id = self.collection.insert_one(payment_data).inserted_id
            payment_data['_id'] = str(inserted_id)  # Convert ObjectId to string for JSON serialization
            return payment_data, None
        else:
            return None, "Failed to fetch payment details from Razorpay"


payments = Payment(db)

# Routes
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = users.login(data.get('email'), data.get('password'), data.get('mpin'))
    if user:
        return jsonify({"message": "Login successful", "user": {"name": user.get('name')}}), 200
    return jsonify({"message": "Invalid email or password"}), 400

@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    new_user = users.signup(data.get('name'), data.get('email'), data.get('password'), data.get('mpin'))
    if new_user:
        return jsonify({"message": "Signup successful"}), 201
    return jsonify({"message": "Email already registered"}), 400

# Secret key for session management
app.secret_key = 'sandy@0910'
@app.route('/logout', methods=['POST'])
def logout():
    # Clear session data
    session.clear()

    # Send the logout success response
    response = jsonify({"message": "Logout successful. Restarting server..."}), 200

    # Schedule server restart after sending the response
    def restart_server():
        python = sys.executable
        os.execl(python, python, *sys.argv)

    threading.Timer(1, restart_server).start()  # Delay restart by 1 second

    return response

@app.route('/transactions', methods=['GET'])
def get_transactions():
    try:
        all_transactions = transactions.get_transactions()
        return jsonify(all_transactions), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/payment', methods=['POST'])
def get_payment_details():
    data = request.json
    payment_id = data.get('paymentId')
    email = data.get('email')
    category = data.get('category')

    if not payment_id or not category:
        return jsonify({'error': 'Payment ID and category are required'}), 400

    payment_data, error_message = payments.save_payment_details(payment_id, category, email)
    if payment_data:
        return jsonify({'message': 'Payment details saved successfully', 'data': payment_data}), 200

    return jsonify({'error': 'Failed to fetch payment details', 'details': error_message}), 500

@app.route('/store_key', methods=['POST'])
def store_key():
    # Get the data from the request body
    data = request.json
    key = data.get('key')  # The key parameter from the request body
    email = data.get('email')

    if not key or not email:
        return jsonify({"error": "Key and email are required"}), 400

    # Check if the key already exists for this email in the database
    ckey = keys.get_key(email, key)

    if ckey == None:
        # Update the user record with the new key
        print("storing key")
        keys.store_key(email, key)  
        # Return success message after storing the new key
        return jsonify({"message": "Key stored successfully"}), 200

    # Check if the key already exists in the database for this user
    if ckey['key'] == key:
        CryptoKeyManager.set_key(ckey['key'])
        return jsonify({"message": "This key is already stored for the user"}), 200

@app.route('/expense_stats', methods=['GET'])
def expense_stats():
    user_email = request.args.get('email')
    month = request.args.get('month')

    if not user_email:
        return jsonify({"error": "Email is required"}), 400
    if not month:
        return jsonify({"error": "Month is required"}), 400

    stats, status_code = transactions.calculate_expense_stats(user_email, month)
    return jsonify(stats), status_code


# Run the Flask app
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True) 

