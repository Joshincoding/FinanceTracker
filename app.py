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
CORS(app, origins=["*"], supports_credentials=True)

app.config["MONGO_URI"] = os.getenv("MONGO_URI", "mongodb://localhost:27017/finance_tracker")
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "super-secret-key")

mongo = PyMongo(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    email = data['email']
    password = data['password']

    if mongo.db.users.find_one({'email': email}):
        return jsonify(message="User already exists"), 409

    hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
    user = {"email": email, "password": hashed_pw, "role": "user"}
    mongo.db.users.insert_one(user)
    return jsonify(message="User registered"), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = mongo.db.users.find_one({"email": data['email']})
    if user and bcrypt.check_password_hash(user['password'], data['password']):
        access_token = create_access_token(identity=str(user['_id']), expires_delta=datetime.timedelta(days=1))
        return jsonify(token=access_token)
    return jsonify(message="Invalid credentials"), 401

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
        elif isinstance(t['date'], str):
            try:
                t['date'] = datetime.datetime.strptime(t['date'], '%Y-%m-%d').strftime('%Y-%m-%d')
            except:
                pass
    return jsonify(transactions)

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
