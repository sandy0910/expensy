from flask import Flask, request, jsonify
from pymongo import MongoClient
from flask_cors import CORS
from datetime import datetime
import requests
from requests.auth import HTTPBasicAuth
from bson import ObjectId
from dotenv import load_dotenv
import os


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

# Transactions management
class Transaction:
    def __init__(self, db):
        self.collection = db.get_collection("transactions")

    def add_transaction(self, amount, category, email, description):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        transaction = {
            "amount": amount,
            "category": category,
            "description": description,
            "time": timestamp,
            "email": email
        }
        self.collection.insert_one(transaction)
        return transaction

    def get_transactions(self):
        transactions = list(self.collection.find({}))
        for transaction in transactions:
            transaction['_id'] = str(transaction['_id'])  # Convert ObjectId to string
        return transactions

transactions = Transaction(db)

# Payment integration
class Payment:
    RAZORPAY_KEY = 'rzp_test_McwSUcwNGFPUuj'
    RAZORPAY_SECRET = 'tMiEVgXMLywBs8e2EzN5cv0F'

    def __init__(self, db):
        self.collection = db.get_collection("transactions")

    def save_payment_details(self, payment_id, category, userEmail):
        url = f'https://api.razorpay.com/v1/payments/{payment_id}'
        response = requests.get(url, auth=HTTPBasicAuth(self.RAZORPAY_KEY, self.RAZORPAY_SECRET))

        if response.status_code == 200:
            payment_data = response.json()
            #Convert amount from paise to rupees
            payment_data['amount'] = payment_data.get('amount', 0) / 100
            payment_data['category'] = category
            payment_data['userEmail'] = userEmail
            payment_data['timestamp'] = datetime.now().isoformat()

            inserted_id = self.collection.insert_one(payment_data).inserted_id
            payment_data['_id'] = str(inserted_id)
            return payment_data, None
        else:
            return None

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

@app.route('/addTransaction', methods=['POST'])
def add_transaction():
    data = request.json
    transaction = transactions.add_transaction(data.get('amount'), data.get('category'), data.get('email'), data.get('description'))
    return jsonify({"message": "Transaction added successfully", "transaction": transaction}), 201

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


from flask import jsonify, request
from datetime import datetime
import calendar

@app.route('/expense_stats', methods=['GET'])
def expense_stats():
    try:
        # Get the user email and month from request parameters
        user_email = request.args.get('email')
        month = request.args.get('month')  # 'month' should be in 'January', 'February', etc.

        if not user_email:
            return jsonify({"error": "Email is required"}), 400
        if not month:
            return jsonify({"error": "Month is required"}), 400

        # Convert month name to a number (e.g., 'January' -> 1, 'February' -> 2, etc.)
        try:
            month_num = datetime.strptime(month, "%B").month
        except ValueError:
            return jsonify({"error": "Invalid month name"}), 400

        # Get the current year
        current_year = datetime.now().year

        # Generate start and end date strings for the query
        start_date = f"{current_year}-{month_num:02d}-01T00:00:00.000000"  # First day of the month
        _, last_day = calendar.monthrange(current_year, month_num)  # Get the last day of the month
        end_date = f"{current_year}-{month_num:02d}-{last_day}T23:59:59.999999"  # Last day of the month

        # Fetch transactions for the given user email and month using timestamp
        user_transactions = list(transactions.collection.find({
            "email": user_email,
            "timestamp": {"$gte": start_date, "$lte": end_date}  # Filter by string-based timestamp range
        }))

        if not user_transactions:
            return jsonify({"message": "No transactions found for this user in the specified month"}), 404

        # Define categories dynamically based on transaction data
        categories = set(transaction.get('category') for transaction in user_transactions)

        # Calculate total, average, and category-wise totals
        total_expense = 0
        category_totals = {category: 0 for category in categories}

        for transaction in user_transactions:
            total_expense += transaction.get('amount', 0)  # Ensure 'amount' is accessible
            category = transaction.get('category', 'Other')  # Default to 'Other' if no category
            category_totals[category] += transaction.get('amount', 0)

        avg_expense = total_expense / len(user_transactions) if user_transactions else 0

        # Sort the category_totals dictionary by value in decreasing order
        sorted_category_totals = dict(sorted(category_totals.items(), key=lambda item: item[1], reverse=True))

        # Prepare the response data
        stats = {
            'total_expense': total_expense,
            'average_expense': avg_expense,
            'category_totals': sorted_category_totals
        }

        return jsonify(stats), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500




# Run the Flask app
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True) 

