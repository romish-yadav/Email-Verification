from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token
from flasgger import Swagger, swag_from
from datetime import datetime, timedelta, timezone
import secrets
import re
from werkzeug.security import generate_password_hash, check_password_hash
from ratelimit import limits, RateLimitException
from functools import wraps
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'Emailv@123'
app.config['OTP_EXPIRY_MINUTES'] = 5
app.config['RATE_LIMIT_MINUTES'] = 1
app.config['RATE_LIMIT_CALLS'] = 5

# Initialize Swagger
swagger = Swagger(app)

db = SQLAlchemy(app)
jwt = JWTManager(app)

# Error handler if Otp exceeding more than 5 times.
@app.errorhandler(RateLimitException)
def handle_rate_limit_exceeded(error):
    return jsonify({"message": "Too many OTP requests. Please wait 1 minute and try again."}), 429

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(50), nullable=False)
    surname = db.Column(db.String(50), nullable=False)
    gender = db.Column(db.String(20), nullable=False)
    phone = db.Column(db.String(15), unique=True, nullable=False)
    age = db.Column(db.Integer, nullable=False)
    otp = db.Column(db.String(100))
    otp_expiry = db.Column(db.DateTime)
    otp_attempts = db.Column(db.Integer, default=0)
    is_verified = db.Column(db.Boolean, default=False)


# Mock Email Service
def send_otp_email(email, otp):
    logger.info(f"OTP for {email}: {otp}")


# OTP Limiting Decorator
def rate_limit():
    def decorator(f):
        @wraps(f)
        @limits(calls=app.config['RATE_LIMIT_CALLS'], period=app.config['RATE_LIMIT_MINUTES'] * 60)
        def wrapped_function(*args, **kwargs):
            return f(*args, **kwargs)
        return wrapped_function
    return decorator

# Validation Functions
def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def is_valid_phone(phone):
    pattern = r'^\d{10}$'  # Basic 10-digit phone number validation
    return re.match(pattern, phone) is not None

def is_valid_gender(gender):
    return gender in ['Male', 'Female', 'Other']

# API Endpoints
@app.route('/api/register', methods=['POST'])
@swag_from({
    'tags': ['Authentication'],
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'email': {'type': 'string', 'example': 'user@example.com'},
                    'name': {'type': 'string', 'example': 'John'},
                    'surname': {'type': 'string', 'example': 'Doe'},
                    'gender': {'type': 'string', 'example': 'Male', 'enum': ['Male', 'Female', 'Other']},
                    'phone': {'type': 'string', 'example': '1234567890'},
                    'age': {'type': 'integer', 'example': 25}
                },
                'required': ['email', 'name', 'surname', 'gender', 'phone', 'age']
            }
        }
    ],
    'responses': {
        201: {
            'description': 'Registration successful',
            'schema': {
                'type': 'object',
                'properties': {'message': {'type': 'string'}}
            }
        },
        400: {
            'description': 'Invalid input or duplicate email/phone'
        }
    }
})
def register():
    data = request.get_json()
    email = data.get('email')
    name = data.get('name')
    surname = data.get('surname')
    gender = data.get('gender')
    phone = data.get('phone')
    age = data.get('age')

    # Validate inputs
    if not all([email, name, surname, gender, phone, age]):
        return jsonify({"message": "All fields are required"}), 400

    if not is_valid_email(email):
        return jsonify({"message": "Invalid email format"}), 400

    if not name.isalpha() or not surname.isalpha():
        return jsonify({"message": "Name and surname must contain only letters"}), 400

    if not is_valid_gender(gender):
        return jsonify({"message": "Gender must be Male, Female, or Other"}), 400

    if not is_valid_phone(phone):
        return jsonify({"message": "Invalid phone number (must be 10 digits)"}), 400

    if not isinstance(age, int) or age < 1 or age > 120:
        return jsonify({"message": "Invalid age (must be between 1 and 120)"}), 400

    # Check for duplicates
    if User.query.filter_by(email=email).first():
        return jsonify({"message": "Email already registered"}), 400

    if User.query.filter_by(phone=phone).first():
        return jsonify({"message": "Phone number already registered"}), 400

    user = User(email=email, name=name, surname=surname, gender=gender, phone=phone, age=age)
    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "Registration successful. Please verify your email."}), 201

@app.route('/api/request-otp', methods=['POST'])
@rate_limit()
@swag_from({
    'tags': ['Authentication'],
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'email': {'type': 'string', 'example': 'user@example.com'}
                },
                'required': ['email']
            }
        }
    ],
    'responses': {
        200: {
            'description': 'OTP sent successfully',
            'schema': {
                'type': 'object',
                'properties': {'message': {'type': 'string'}}
            }
        },
        404: {
            'description': 'Email not registered'
        },
        429: {
            'description': 'Too many OTP requests'
        }
    }
})
def request_otp():
    data = request.get_json()
    email = data.get('email')

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"message": "Email not registered"}), 404

    # Generate 6-character OTP
    otp = secrets.token_hex(3)
    hashed_otp = generate_password_hash(otp)
    expiry = datetime.now(timezone.utc) + timedelta(minutes=app.config['OTP_EXPIRY_MINUTES'])


    user.otp = hashed_otp
    user.otp_expiry = expiry
    user.otp_attempts = 0
    db.session.commit()

    send_otp_email(email, otp)
    return jsonify({"message": "OTP sent to your email."}), 200

@app.route('/api/verify-otp', methods=['POST'])
@swag_from({
    'tags': ['Authentication'],
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'email': {'type': 'string', 'example': 'user@example.com'},
                    'otp': {'type': 'string', 'example': '123456'}
                },
                'required': ['email', 'otp']
            }
        }
    ],
    'responses': {
        200: {
            'description': 'Login successful',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {'type': 'string'},
                    'token': {'type': 'string'}
                }
            }
        },
        400: {
            'description': 'OTP expired or invalid'
        },
        401: {
            'description': 'Invalid OTP'
        },
        404: {
            'description': 'Email not registered'
        },
        429: {
            'description': 'Too many attempts'
        }
    }
})


def verify_otp():
    data = request.get_json()
    email = data.get('email')
    otp = data.get('otp')

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"message": "Email not registered"}), 404

    if user.otp_attempts >= 3:
        return jsonify({"message": "Too many attempts. Please request a new OTP."}), 429

    # OTP already verified
    if user.otp is None and user.otp_expiry is None:
        return jsonify({"message": "OTP already verified."}), 400

    # OTP expired
    if user.otp_expiry.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        user.otp = None
        user.otp_expiry = None
        db.session.commit()
        return jsonify({"message": "OTP has expired. Please request a new one."}), 400

    # OTP invalid
    if not check_password_hash(user.otp, otp):
        user.otp_attempts += 1
        db.session.commit()
        return jsonify({"message": "Invalid OTP. Please try again or request a new one."}), 401

    # OTP valid
    user.otp = None
    user.otp_expiry = None
    user.otp_attempts = 0
    db.session.commit()

    access_token = create_access_token(identity=email)
    return jsonify({"message": "Login successful.", "token": access_token}), 200


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000)