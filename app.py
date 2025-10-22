import os
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List

from flask import Flask, jsonify, request, send_from_directory
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity,
    JWTManager,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
from flask_cors import CORS

# Local import - your existing function to get the database
from config import get_database

# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

app = Flask(__name__, static_folder="dist", static_url_path="/")
CORS(app, supports_credentials=True)  # Add this line

# ✅ Serve React Frontend
@app.route("/")
@app.route("/<path:path>")
def serve_react(path=None):
    if path and os.path.exists(os.path.join("dist", path)):
        return send_from_directory("dist", path)
    return send_from_directory("dist", "index.html")


# Load secrets from environment for production safety
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "shivam@9022")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=int(os.getenv("JWT_ACCESS_HOURS", "12")))
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=int(os.getenv("JWT_REFRESH_DAYS", "30")))
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

jwt = JWTManager(app)

# Rate limiter
limiter = Limiter(key_func=get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

# Logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database
db = get_database()
user_collection = db['users']
data_collection = db['data']
friend_collection = db['friends']

# Helper utilities
def objid(id_str: str) -> ObjectId:
    try:
        return ObjectId(id_str)
    except Exception:
        raise ValueError("Invalid ObjectId")


def user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    try:
        user = user_collection.find_one({"_id": objid(user_id)})
        if user:
            user['_id'] = str(user['_id'])
        return user
    except Exception:
        return None


def sanitize_doc(doc: Dict[str, Any]) -> Dict[str, Any]:
    # Convert _id to string for JSON
    if not doc:
        return {}
    d = dict(doc)
    if '_id' in d:
        d['_id'] = str(d['_id'])
    return d


# ------------------------------------------------------------
# AUTH
# ------------------------------------------------------------
@app.route('/')
def start():
    return jsonify({"message":"Start Successfuly"})

@limiter.limit("5 per minute")
@app.route('/api/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json(force=True)
        first_name = (data.get('first_name') or '').strip()
        last_name = (data.get('last_name') or '').strip()
        mobile_no = (data.get('mobile_no') or '').strip()
        email = (data.get('email') or '').strip().lower()
        password = data.get('password')

        if not all([first_name, last_name, mobile_no, email, password]):
            return jsonify({"error": "All fields are required"}), 400

        # Unique check
        if user_collection.find_one({"$or": [{"email": email}, {"mobile_no": mobile_no}] } ):
            return jsonify({"error": "User with this email or mobile number already exists"}), 409

        password_hash = generate_password_hash(password)

        new_user = {
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
            "mobile_no": mobile_no,
            "password": password_hash,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        }

        res = user_collection.insert_one(new_user)
        user_id = str(res.inserted_id)

        access_token = create_access_token(identity=user_id)
        refresh_token = create_refresh_token(identity=user_id)

        logger.info(f"New user signed up: {email}")
        return jsonify({"access_token": access_token, "refresh_token": refresh_token, "user_id": user_id}), 201

    except Exception as e:
        logger.exception("Error during signup")
        return jsonify({"error": str(e)}), 400


@limiter.limit("10 per minute")
@app.route('/api/signin', methods=['POST'])
def signin():
    try:
        data = request.get_json(force=True)
        email = (data.get('email') or '').strip().lower()
        password = data.get('password')

        if not all([email, password]):
            return jsonify({"error": "Email and password required"}), 400

        user = user_collection.find_one({"email": email})
        if not user or not check_password_hash(user.get('password', ''), password):
            return jsonify({"error": "Invalid email or password"}), 401

        user_id = str(user['_id'])
        access_token = create_access_token(identity=user_id)
        refresh_token = create_refresh_token(identity=user_id)

        user_response = sanitize_doc(user)
        user_response.pop('password', None)

        logger.info(f"User signed in: {email}")
    
        return jsonify({
            "success": True,
            "message": "Login successful",
            "access_token": access_token, 
            "refresh_token": refresh_token, 
            "user": user_response,
            "user_id": user_id
        }), 200

    except Exception as e:
        logger.exception("Error during signin")
        return jsonify({"error": str(e)}), 400

@app.route('/api/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    try:
        user_id = get_jwt_identity()
        new_access = create_access_token(identity=user_id)
        return jsonify({"access_token": new_access}), 200
    except Exception as e:
        logger.exception("Error refreshing token")
        return jsonify({"error": str(e)}), 400


# ------------------------------------------------------------
# MONEY / TRANSACTIONS
# ------------------------------------------------------------

@app.route('/api/addmoney', methods=['POST'])
@jwt_required()
def addmoney():
    try:
        user_id = get_jwt_identity()
        data = request.get_json(force=True)

        receiver_id = data.get('receiver_id')
        money_raw = data.get('money')
        description = (data.get('description') or '').strip()

        # Basic checks
        if not all([receiver_id, money_raw, description]):
            return jsonify({"error": "All fields are required"}), 400

        if user_id == receiver_id:
            return jsonify({"error": "You cannot add udhar to yourself"}), 400

        # Validate money
        try:
            money = float(money_raw)
            if money <= 0:
                raise ValueError("Money must be positive")
        except Exception:
            return jsonify({"error": "Invalid money value"}), 400

        sender = user_by_id(user_id)
        receiver = user_by_id(receiver_id)
        if not sender or not receiver:
            return jsonify({"error": "Sender or receiver not found"}), 404

        now = datetime.utcnow()
        entry = {
            "user_id": user_id,
            "user_name": f"{sender['first_name']} {sender['last_name']}",
            "receiver_user_id": receiver_id,
            "receiver_name": f"{receiver['first_name']} {receiver['last_name']}",
            "money": money,
            "description": description,
            "date": now,
            "status": "pending",
            "confirmations": [],
            "delete_confirmations": []
        }

        res = data_collection.insert_one(entry)
        logger.info(f"Transaction added: {res.inserted_id} by {user_id} -> {receiver_id}")
        return jsonify({"message": "Money record added successfully", "transaction_id": str(res.inserted_id)}), 201

    except Exception as e:
        logger.exception("Error adding money")
        return jsonify({"error": str(e)}), 400


@app.route('/api/mylents', methods=['GET'])
@jwt_required()
def get_my_lents():
    try:
        user_id = get_jwt_identity()
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))

        cursor = data_collection.find({"user_id": user_id}).sort("date", -1).skip((page-1)*per_page).limit(per_page)
        lents = [sanitize_doc(d) for d in cursor]

        return jsonify({"count": len(lents), "lents": lents}), 200
    except Exception as e:
        logger.exception("Error fetching mylents")
        return jsonify({"error": str(e)}), 400


@app.route('/api/myudhars', methods=['GET'])
@jwt_required()
def get_my_udhars():
    try:
        user_id = get_jwt_identity()
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))

        cursor = data_collection.find({"receiver_user_id": user_id}).sort("date", -1).skip((page-1)*per_page).limit(per_page)
        udhars = [sanitize_doc(d) for d in cursor]

        return jsonify({"count": len(udhars), "udhars": udhars}), 200
    except Exception as e:
        logger.exception("Error fetching myudhars")
        return jsonify({"error": str(e)}), 400


@app.route('/api/mysummary', methods=['GET'])
@jwt_required()
def get_summary():
    try:
        user_id = get_jwt_identity()
        lents = list(data_collection.find({"user_id": user_id}))
        udhars = list(data_collection.find({"receiver_user_id": user_id}))

        # Convert ObjectIds and calculate totals
        for d in lents + udhars:
            d['_id'] = str(d['_id'])

        lent_total = sum(float(d.get('money', 0)) for d in lents)
        udhar_total = sum(float(d.get('money', 0)) for d in udhars)

        return jsonify({
            "you_lent": [sanitize_doc(d) for d in lents],
            "lent_on_you": [sanitize_doc(d) for d in udhars],
            "totals": {
                "lent_total": lent_total,
                "udhar_total": udhar_total,
                "net_balance": lent_total - udhar_total
            }
        }), 200
    except Exception as e:
        logger.exception("Error getting summary")
        return jsonify({"error": str(e)}), 400


@app.route('/api/delete', methods=['POST'])
@jwt_required()
def delete_transaction():
    try:
        user_id = get_jwt_identity()
        data = request.get_json(force=True)
        transaction_id = data.get('transaction_id')

        if not transaction_id:
            return jsonify({"error": "Transaction ID required"}), 400

        transaction = data_collection.find_one({"_id": objid(transaction_id)})
        if not transaction:
            return jsonify({"error": "Transaction not found"}), 404

        if user_id not in [transaction['user_id'], transaction['receiver_user_id']]:
            return jsonify({"error": "You are not authorized for this transaction"}), 403

        delete_confirmations = transaction.get("delete_confirmations", [])
        if user_id not in delete_confirmations:
            delete_confirmations.append(user_id)

        # Update in DB
        if all(uid in delete_confirmations for uid in [transaction['user_id'], transaction['receiver_user_id']]):
            data_collection.update_one({"_id": objid(transaction_id)}, {"$set": {"status": "deleted", "delete_confirmations": delete_confirmations, "deleted_at": datetime.utcnow()}})
            return jsonify({"message": "Transaction deleted successfully"}), 200
        else:
            data_collection.update_one({"_id": objid(transaction_id)}, {"$set": {"delete_confirmations": delete_confirmations}})
            return jsonify({"message": "Waiting for the other user to confirm deletion"}), 200

    except Exception as e:
        logger.exception("Error deleting transaction")
        return jsonify({"error": str(e)}), 400


@app.route('/api/settle', methods=['POST'])
@jwt_required()
def settle_transaction():
    try:
        user_id = get_jwt_identity()
        data = request.get_json(force=True)
        transaction_id = data.get('transaction_id')

        if not transaction_id:
            return jsonify({"error": "Transaction ID required"}), 400

        transaction = data_collection.find_one({"_id": objid(transaction_id)})
        if not transaction:
            return jsonify({"error": "Transaction not found"}), 404

        if user_id not in [transaction['user_id'], transaction['receiver_user_id']]:
            return jsonify({"error": "You are not authorized for this transaction"}), 403

        confirmations = transaction.get("confirmations", [])
        if user_id not in confirmations:
            confirmations.append(user_id)

        if all(uid in confirmations for uid in [transaction['user_id'], transaction['receiver_user_id']]):
            data_collection.update_one({"_id": objid(transaction_id)}, {"$set": {"status": "settled", "confirmations": confirmations, "settled_at": datetime.utcnow()}})
            return jsonify({"message": "Transaction settled successfully"}), 200
        else:
            data_collection.update_one({"_id": objid(transaction_id)}, {"$set": {"confirmations": confirmations}})
            return jsonify({"message": "Waiting for the other user to confirm settlement"}), 200

    except Exception as e:
        logger.exception("Error settling transaction")
        return jsonify({"error": str(e)}), 400

@app.route('/api/pending-actions', methods=['GET'])
@jwt_required()
def get_pending_actions():
    """Get all transactions waiting for user's confirmation"""
    try:
        user_id = get_jwt_identity()
        
        # Find transactions where user is involved and needs to confirm
        pending_settle = list(data_collection.find({
            "$or": [
                {"user_id": user_id},
                {"receiver_user_id": user_id}
            ],
            "status": "pending",
            "confirmations": {"$ne": user_id}  # User hasn't confirmed yet
        }))
        
        pending_delete = list(data_collection.find({
            "$or": [
                {"user_id": user_id},
                {"receiver_user_id": user_id}
            ],
            "status": "pending",
            "delete_confirmations": {"$ne": user_id}  # User hasn't confirmed deletion yet
        }))
        
        # Combine and format results
        pending_actions = []
        
        for tx in pending_settle + pending_delete:
            # Determine action type and if user action is needed
            needs_settle_confirmation = (tx in pending_settle) and (user_id not in tx.get("confirmations", []))
            needs_delete_confirmation = (tx in pending_delete) and (user_id not in tx.get("delete_confirmations", []))
            
            if needs_settle_confirmation or needs_delete_confirmation:
                # Get the other user's info
                other_user_id = tx['receiver_user_id'] if tx['user_id'] == user_id else tx['user_id']
                other_user = user_by_id(other_user_id)
                
                action_type = "settle" if needs_settle_confirmation else "delete"
                initiated_by_other = tx.get("confirmations") or tx.get("delete_confirmations")
                
                pending_actions.append({
                    "transaction_id": str(tx['_id']),
                    "action_type": action_type,
                    "amount": tx['money'],
                    "description": tx['description'],
                    "date": tx['date'],
                    "other_user_name": f"{other_user['first_name']} {other_user['last_name']}" if other_user else "Unknown",
                    "other_user_id": other_user_id,
                    "initiated_by_me": user_id in (initiated_by_other or []),
                    "message": f"{other_user['first_name'] if other_user else 'Someone'} requested to {action_type} this transaction" if not initiated_by_other else f"You requested to {action_type} this transaction"
                })
        
        return jsonify({"pending_actions": pending_actions}), 200
        
    except Exception as e:
        logger.exception("Error fetching pending actions")
        return jsonify({"error": str(e)}), 400


@app.route('/api/transaction/<transaction_id>', methods=['GET'])
@jwt_required()
def get_transaction_details(transaction_id):
    """Get detailed information about a specific transaction"""
    try:
        user_id = get_jwt_identity()
        
        transaction = data_collection.find_one({"_id": objid(transaction_id)})
        if not transaction:
            return jsonify({"error": "Transaction not found"}), 404
        
        # Check if user is authorized to view this transaction
        if user_id not in [transaction['user_id'], transaction['receiver_user_id']]:
            return jsonify({"error": "Not authorized"}), 403
        
        # Get user details
        sender = user_by_id(transaction['user_id'])
        receiver = user_by_id(transaction['receiver_user_id'])
        
        transaction_details = sanitize_doc(transaction)
        transaction_details.update({
            "sender_name": f"{sender['first_name']} {sender['last_name']}" if sender else "Unknown",
            "receiver_name": f"{receiver['first_name']} {receiver['last_name']}" if receiver else "Unknown",
            "can_settle": user_id not in transaction.get("confirmations", []),
            "can_delete": user_id not in transaction.get("delete_confirmations", []),
            "settlement_initiated": len(transaction.get("confirmations", [])) > 0,
            "delete_initiated": len(transaction.get("delete_confirmations", [])) > 0
        })
        
        return jsonify({"transaction": transaction_details}), 200
        
    except Exception as e:
        logger.exception("Error fetching transaction details")
        return jsonify({"error": str(e)}), 400

# ------------------------------------------------------------
# HISTORY
# ------------------------------------------------------------

@app.route('/api/lent_history', methods=['GET'])
@jwt_required()
def lent_history():
    try:
        user_id = get_jwt_identity()
        history = list(data_collection.find({
            "$and": [
                {"$or": [
                    {"user_id": user_id},
                    {"receiver_user_id": user_id}
                ]},
                {"status": {"$in": ["settled", "deleted"]}}
            ]
        }).sort("date", -1))

        for item in history:
            item['_id'] = str(item['_id'])
            if item['status'] == "settled":
                item['completed_at'] = item.get('settled_at')
            elif item['status'] == "deleted":
                item['completed_at'] = item.get('deleted_at')

        return jsonify({"count": len(history), "history": history} if history else {"message": "No history found"}), 200
    except Exception as e:
        logger.exception("Error getting history")
        return jsonify({"error": str(e)}), 400


# ------------------------------------------------------------
# FRIENDS (single record approach)
# ------------------------------------------------------------

@app.route('/api/friends/add', methods=['POST'])
@jwt_required()
def add_friend():
    try:
        user_id = get_jwt_identity()
        data = request.get_json(force=True)
        mobile_no = (data.get('mobile_no') or '').strip()

        if not mobile_no:
            return jsonify({"error": "Friend's mobile number is required"}), 400

        friend_user = user_collection.find_one({"mobile_no": mobile_no})
        if not friend_user:
            return jsonify({"error": "User with this mobile number does not exist"}), 404

        friend_user_id = str(friend_user['_id'])
        if user_id == friend_user_id:
            return jsonify({"error": "You cannot add yourself as a friend"}), 400

        # Check for existing request or friendship either way
        existing = friend_collection.find_one({
            "$or": [
                {"sender_id": user_id, "receiver_id": friend_user_id},
                {"sender_id": friend_user_id, "receiver_id": user_id}
            ]
        })
        if existing:
            return jsonify({"error": "Friend request already exists or you are already friends"}), 409

        now = datetime.utcnow()
        friend_collection.insert_one({
            "sender_id": user_id,
            "receiver_id": friend_user_id,
            "status": "pending",
            "created_at": now,
            "accepted_at": None
        })

        logger.info(f"Friend request: {user_id} -> {friend_user_id}")
        return jsonify({"message": "Friend request sent"}), 201

    except Exception as e:
        logger.exception("Error adding friend")
        return jsonify({"error": str(e)}), 400


@app.route('/api/friends/respond', methods=['POST'])
@jwt_required()
def respond_friend_request():
    try:
        user_id = get_jwt_identity()
        data = request.get_json(force=True)
        sender_id = data.get('sender_id')
        action = data.get('action')  # "accept" or "reject"

        if not all([sender_id, action]):
            return jsonify({"error": "Sender ID and action required"}), 400

        if action == "accept":
            now = datetime.utcnow()
            result = friend_collection.update_one({"sender_id": sender_id, "receiver_id": user_id}, {"$set": {"status": "accepted", "accepted_at": now}})
            if result.matched_count == 0:
                return jsonify({"error": "Friend request not found"}), 404
            return jsonify({"message": "Friend request accepted"}), 200
        elif action == "reject":
            friend_collection.delete_one({"sender_id": sender_id, "receiver_id": user_id})
            return jsonify({"message": "Friend request rejected"}), 200
        else:
            return jsonify({"error": "Invalid action"}), 400

    except Exception as e:
        logger.exception("Error responding to friend request")
        return jsonify({"error": str(e)}), 400


@app.route('/api/friends', methods=['GET'])
@jwt_required()
def list_friends():
    try:
        user_id = get_jwt_identity()
        search = request.args.get('search', '')

        # Find accepted friendships where user is sender or receiver
        friends_cursor = friend_collection.find({
            "$and": [
                {"status": "accepted"},
                {"$or": [
                    {"sender_id": user_id},
                    {"receiver_id": user_id}
                ]}
            ]
        })

        friends = []
        for f in friends_cursor:
            f['_id'] = str(f['_id'])
            # Determine other user id
            other_id = f['receiver_id'] if f['sender_id'] == user_id else f['sender_id']
            other_user = user_by_id(other_id)
            if not other_user:
                continue
            # apply search on mobile or name
            if search:
                if search.lower() not in other_user.get('mobile_no', '').lower() and search.lower() not in f"{other_user.get('first_name','')} {other_user.get('last_name','')}".lower():
                    continue
            friends.append({
                "friend_id": str(f['_id']),
                "user_id": other_id,
                "name": f"{other_user.get('first_name','')} {other_user.get('last_name','')}",
                "mobile_no": other_user.get('mobile_no')
            })

        return jsonify({"count": len(friends), "friends": friends}), 200
    except Exception as e:
        logger.exception("Error listing friends")
        return jsonify({"error": str(e)}), 400


@app.route('/api/friends/remove', methods=['POST'])
@jwt_required()
def remove_friend():
    try:
        user_id = get_jwt_identity()
        data = request.get_json(force=True)
        friend_user_id = data.get('friend_user_id')

        if not friend_user_id:
            return jsonify({"error": "Friend user id is required"}), 400

        # Remove friendship both ways
        result = friend_collection.delete_many({
            "$or": [
                {"sender_id": user_id, "receiver_id": friend_user_id},
                {"sender_id": friend_user_id, "receiver_id": user_id}
            ]
        })

        if result.deleted_count == 0:
            return jsonify({"error": "Friend not found or not authorized"}), 404

        return jsonify({"message": "Friend removed successfully"}), 200
    except Exception as e:
        logger.exception("Error removing friend")
        return jsonify({"error": str(e)}), 400


@app.route('/api/friends/requests', methods=['GET'])
@jwt_required()
def pending_requests():
    try:
        user_id = get_jwt_identity()
        requests_cursor = friend_collection.find({"receiver_id": user_id, "status": "pending"})
        requests = []
        for r in requests_cursor:
            sender = user_by_id(r['sender_id'])
            if not sender:
                continue
            requests.append({
                "request_id": str(r['_id']),
                "sender_id": r['sender_id'],
                "sender_name": f"{sender.get('first_name','')} {sender.get('last_name','')}",
                "sender_mobile": sender.get('mobile_no')
            })
        return jsonify({"count": len(requests), "requests": requests}), 200
    except Exception as e:
        logger.exception("Error fetching pending friend requests")
        return jsonify({"error": str(e)}), 400


# ------------------------------------------------------------
# SEARCH / FILTER for transactions
# ------------------------------------------------------------

@app.route('/api/transactions/search', methods=['GET'])
@jwt_required()
def search_transactions():
    try:
        user_id = get_jwt_identity()
        q = request.args.get('q', '')
        status = request.args.get('status')
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))

        base_filter = {"$or": [{"user_id": user_id}, {"receiver_user_id": user_id}]}
        if status:
            base_filter["status"] = status
        if q:
            base_filter["description"] = {"$regex": q, "$options": "i"}

        cursor = data_collection.find(base_filter).sort("date", -1).skip((page-1)*per_page).limit(per_page)
        results = [sanitize_doc(d) for d in cursor]
        return jsonify({"count": len(results), "results": results}), 200
    except Exception as e:
        logger.exception("Error searching transactions")
        return jsonify({"error": str(e)}), 400
    
# ============================================================
# 1️⃣ USER PROFILE ROUTES
# ============================================================

@app.route('/api/profile', methods=['GET'])
@jwt_required()
def get_profile():
    """Fetch logged-in user's profile details"""
    try:
        user_id = get_jwt_identity()
        user = user_collection.find_one({"_id": ObjectId(user_id)}, {"password": 0})

        if not user:
            return jsonify({"error": "User not found"}), 404

        user["_id"] = str(user["_id"])
        return jsonify({"profile": user}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/profile/update', methods=['PUT'])
@jwt_required()
def update_profile():
    """Update user profile fields"""
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        allowed_fields = ["first_name", "last_name", "email", "mobile_no"]
        update_data = {k: v for k, v in data.items() if k in allowed_fields}

        if not update_data:
            return jsonify({"error": "No valid fields provided"}), 400

        update_data["updated_at"] = datetime.utcnow()
        user_collection.update_one({"_id": ObjectId(user_id)}, {"$set": update_data})

        return jsonify({"message": "Profile updated successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================
# 2️⃣ ANALYTICS SUMMARY ROUTE
# ============================================================

@app.route('/api/analytics', methods=['GET'])
@jwt_required()
def analytics_summary():
    """Summarize total lent, borrowed, and pending transactions"""
    try:
        user_id = get_jwt_identity()

        lent_total = 0
        borrowed_total = 0
        pending_count = 0
        settled_count = 0

        transactions = list(data_collection.find({
            "$or": [
                {"user_id": user_id},
                {"receiver_user_id": user_id}
            ]
        }))

        for tx in transactions:
            if tx.get("status") == "pending":
                pending_count += 1
            elif tx.get("status") == "settled":
                settled_count += 1

            if tx.get("user_id") == user_id:
                lent_total += tx.get("amount", 0)
            elif tx.get("receiver_user_id") == user_id:
                borrowed_total += tx.get("amount", 0)

        summary = {
            "total_lent": lent_total,
            "total_borrowed": borrowed_total,
            "pending_transactions": pending_count,
            "settled_transactions": settled_count
        }

        return jsonify({"analytics": summary}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/analytics/summary', methods=['GET'])
@jwt_required()
def analytics_summary_v2():
    try:
        user_id = get_jwt_identity()

        # Fetch last 10 transactions involving the user
        transactions = list(
            data_collection.find(
                {"$or": [{"user_id": user_id}, {"receiver_user_id": user_id}]}
            ).sort("date", -1).limit(10)
        )

        total_balance = 0
        recent_tx = []

        for tx in transactions:
            sender_id = tx.get("user_id")
            receiver_id = tx.get("receiver_user_id")
            amount = float(tx.get("money", 0))
            date = tx.get("date").strftime("%Y-%m-%d") if tx.get("date") else None

            # Balance calculation: + for received, - for sent
            if user_id == sender_id:
                total_balance -= amount
                title = f"Sent to {tx.get('receiver_name', 'Unknown')}"
            elif user_id == receiver_id:
                total_balance += amount
                title = f"Received from {tx.get('user_name', 'Unknown')}"
            else:
                continue

            recent_tx.append({
                "title": title,
                "amount": amount if user_id == receiver_id else -amount,
                "date": date
            })

        return jsonify({
            "total_balance": total_balance,
            "recent_transactions": recent_tx
        }), 200

    except Exception as e:
        logger.exception("Error in analytics summary")
        return jsonify({"error": str(e)}), 500


# ------------------------------------------------------------
# RUN
# ------------------------------------------------------------
if __name__ != "__main__":
    # Export a callable named `app` for Vercel
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app)