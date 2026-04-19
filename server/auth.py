import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from functools import wraps
from flask import request, jsonify
from database import get_user_by_key

def require_api_key(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        key = request.headers.get("x-api-key")

        if not key:
            return jsonify({"error": "API key missing"}), 401

        user = get_user_by_key(key)

        if not user:
            return jsonify({"error": "Invalid API key"}), 401

        return f(user, *args, **kwargs)

    return wrapper