from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from bson.objectid import ObjectId
import datetime
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app, supports_credentials=True, origins=["https://finance-trackerfrontend.vercel.app"])

app.config["MONGO_URI"] = os.getenv("MONGO_URI", "mongodb+srv://FT:1@cluster0.sre23jl.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "super-secret-key")

mongo = PyMongo(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = mongo.db.users.find_one({"email": data['email']})
    if user and bcrypt.check_password_hash(user['password'], data['password']):
        access_token = create_access_token(identity=str(user['_id']), expires_delta=datetime.timedelta(days=1))
        return jsonify(token=access_token)
    return jsonify(message="Invalid credentials"), 401

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.json
        if not data or 'email' not in data or 'password' not in data:
            return jsonify(message="Email and password required"), 400
        email = data['email']
        password = data['password']
        existing_user = mongo.db.users.find_one({'email': email})
        if existing_user:
            return jsonify(message="User already exists"), 409
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        user = {"email": email, "password": hashed_pw, "role": "user"}
        mongo.db.users.insert_one(user)
        return jsonify(message="User registered"), 201
    except Exception as e:
        return jsonify(message="Internal server error", error=str(e)), 500

@app.route('/transactions', methods=['POST'])
@jwt_required()
def add_transaction():
    user_id = get_jwt_identity()
    data = request.json
    data['user_id'] = user_id
    if 'date' not in data:
        data['date'] = datetime.datetime.now()
    else:
        data['date'] = datetime.datetime.strptime(data['date'], '%Y-%m-%d')
    mongo.db.transactions.insert_one(data)

    # === 🔔 Notification Trigger ===
    category = data.get('category')
    if category:
        total_spent = sum(
            float(t.get('amount', 0))
            for t in mongo.db.transactions.find({'user_id': user_id, 'category': category})
            if t.get('amount') is not None
        )
        budget = mongo.db.budgets.find_one({'user_id': user_id, 'category': category})
        if budget and total_spent > float(budget['limit']):
            mongo.db.notifications.insert_one({
                "user_id": user_id,
                "message": f"🚨 You’ve exceeded your ${budget['limit']} budget for {category}!",
                "timestamp": datetime.datetime.utcnow(),
                "read": False
            })
    return jsonify(message="Transaction added"), 201

@app.route('/transactions', methods=['GET'])
@jwt_required()
def get_transactions():
    user_id = get_jwt_identity()
    date_filter = request.args.get('date')
    query = {'user_id': user_id}
    if date_filter:
        try:
            start_date = datetime.datetime.strptime(date_filter, '%Y-%m-%d')
            end_date = start_date + datetime.timedelta(days=1)
            query['date'] = {'$gte': start_date, '$lt': end_date}
        except ValueError:
            return jsonify(message="Invalid date format. Use YYYY-MM-DD."), 400
    transactions = list(mongo.db.transactions.find(query))
    for t in transactions:
        t['_id'] = str(t['_id'])
        if isinstance(t['date'], datetime.datetime):
            t['date'] = t['date'].strftime('%Y-%m-%d')
    return jsonify(transactions)

@app.route('/transactions/<id>', methods=['PUT'])
@jwt_required()
def update_transaction(id):
    user_id = get_jwt_identity()
    data = request.json
    if 'date' in data:
        try:
            data['date'] = datetime.datetime.strptime(data['date'], '%Y-%m-%d')
        except ValueError:
            return jsonify(message="Invalid date format. Use YYYY-MM-DD."), 400
    result = mongo.db.transactions.update_one({'_id': ObjectId(id), 'user_id': user_id}, {'$set': data})
    if result.matched_count == 0:
        return jsonify(message="Transaction not found"), 404
    return jsonify(message="Transaction updated"), 200

@app.route('/transactions/<id>', methods=['DELETE'])
@jwt_required()
def delete_transaction(id):
    user_id = get_jwt_identity()
    result = mongo.db.transactions.delete_one({'_id': ObjectId(id), 'user_id': user_id})
    if result.deleted_count == 1:
        return jsonify(message="Deleted"), 200
    return jsonify(message="Transaction not found"), 404

@app.route('/categories', methods=['POST'])
@jwt_required()
def create_category():
    user_id = get_jwt_identity()
    data = request.json
    data['user_id'] = user_id
    mongo.db.categories.insert_one(data)
    return jsonify(message="Category created"), 201

@app.route('/categories', methods=['GET'])
@jwt_required()
def get_categories():
    user_id = get_jwt_identity()
    categories = list(mongo.db.categories.find({'user_id': user_id}))
    for cat in categories:
        cat['_id'] = str(cat['_id'])
    return jsonify(categories)

@app.route('/budgets', methods=['POST'])
@jwt_required()
def create_budget():
    user_id = get_jwt_identity()
    data = request.json
    data['user_id'] = user_id
    mongo.db.budgets.insert_one(data)
    return jsonify(message="Budget created"), 201

@app.route('/budgets', methods=['GET'])
@jwt_required()
def get_budgets():
    user_id = get_jwt_identity()
    budgets = list(mongo.db.budgets.find({'user_id': user_id}))
    for b in budgets:
        b['_id'] = str(b['_id'])
    return jsonify(budgets)

@app.route('/notifications', methods=['POST'])
@jwt_required()
def create_notification():
    user_id = get_jwt_identity()
    data = request.json
    data['user_id'] = user_id
    data['timestamp'] = datetime.datetime.utcnow()
    data['read'] = False
    mongo.db.notifications.insert_one(data)
    return jsonify(message="Notification created"), 201

@app.route('/notifications', methods=['GET'])
@jwt_required()
def get_notifications():
    user_id = get_jwt_identity()
    notifs = list(mongo.db.notifications.find({'user_id': user_id}))
    for n in notifs:
        n['_id'] = str(n['_id'])
        n['timestamp'] = n['timestamp'].isoformat()
    return jsonify(notifs)

@app.route('/me', methods=['GET'])
@jwt_required()
def get_profile():
    user_id = get_jwt_identity()
    user = mongo.db.users.find_one({'_id': ObjectId(user_id)})
    if not user:
        return jsonify(message="User not found"), 404
    return jsonify(email=user['email'], role=user.get('role', 'user'))

@app.route('/profile', methods=['POST'])
@jwt_required()
def create_or_update_profile():
    user_id = get_jwt_identity()
    data = request.json
    data['user_id'] = user_id
    mongo.db.profiles.update_one({'user_id': user_id}, {'$set': data}, upsert=True)
    return jsonify(message="Profile saved"), 200

@app.route('/profile', methods=['GET'])
@jwt_required()
def get_profile_info():
    user_id = get_jwt_identity()
    profile = mongo.db.profiles.find_one({'user_id': user_id})
    if profile:
        profile['_id'] = str(profile['_id'])
        return jsonify(profile)
    return jsonify(message="No profile found"), 404

if __name__ == '__main__':
    app.run(debug=True, port=5001)
