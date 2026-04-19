import sys
import os

# Ensure sibling modules (database, auth, detector) are importable
# regardless of the working directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, request, jsonify, render_template, session, redirect, url_for, flash
from database import create_user, verify_user, store_alert, get_user_alerts
from auth import require_api_key
from detector import detect

app = Flask(
    __name__,
    template_folder="../web/templates",
    static_folder="../web/static",
)
app.secret_key = "supersecretkey"


# 🔹 Root — redirect to dashboard or login
@app.route("/")
def index():
    if "user" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


# 🔹 Register
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if not username or not password:
            flash("Username and password are required.", "error")
            return render_template("register.html")

        user = create_user(username, password)

        if user is None:
            flash("Username already exists. Please choose another.", "error")
            return render_template("register.html")

        flash("Account created successfully! Please sign in.", "info")
        return redirect(url_for("login"))

    return render_template("register.html")


# 🔹 Login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if not username or not password:
            flash("Username and password are required.", "error")
            return render_template("login.html")

        user = verify_user(username, password)

        if user:
            session["user"] = user["username"]
            session["api_key"] = user["api_key"]
            return redirect(url_for("dashboard"))

        flash("Invalid username or password.", "error")
        return render_template("login.html")

    return render_template("login.html")


# 🔹 Logout
@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# 🔹 Dashboard
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))

    return render_template("dashboard.html")


# 🔹 User Data (API key display)
@app.route("/user_data")
def user_data():
    if "user" not in session:
        return jsonify({"error": "unauthorized"}), 401

    return jsonify({
        "username": session["user"],
        "api_key": session["api_key"],
    })


# 🔹 CLI ingest (API key auth)
@app.route("/ingest", methods=["POST"])
@require_api_key
def ingest(user):
    data = request.json

    if not data or "command" not in data:
        return jsonify({"error": "Missing 'command' field"}), 400

    command = data.get("command")
    parent = data.get("parent", "Unknown")
    result = detect(command, parent)

    if result:
        store_alert(result, user["username"])
        
        # Real-time logging to alerts.log and console
        try:
            timestamp = result.get("timestamp", "")
            severity = result.get("severity", "UNKNOWN").upper()
            cmd_snippet = result.get("command", "")[:100]
            reason = result.get("reason", "N/A")
            
            log_msg = f"[{timestamp}] ALERT {severity} - User: {user['username']} | Cmd: {cmd_snippet} | Reason: {reason}\n"
            
            # Write to alerts.log in the project root
            log_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "alerts.log")
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(log_msg)
                
            # Print formatted message to console without colors
            print(f"\n[REAL-TIME ALERT] {log_msg.strip()}")
        except Exception as e:
            print(f"[!] Error logging alert: {e}")

        return jsonify({"status": "alert_created", "alert": result})

    return jsonify({"status": "ok", "message": "No threat detected"})


# 🔹 Alerts (dashboard)
@app.route("/alerts")
def alerts():
    if "user" not in session:
        return jsonify({"error": "unauthorized"}), 401

    return jsonify(get_user_alerts(session["user"]))


if __name__ == "__main__":
    app.run(debug=True)