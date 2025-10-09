from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.secret_key = "secretkey123"

# ======================= Database setup =======================
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Hardcoded admin credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

# ======================= Models =======================
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    equipment = db.Column(db.String(50), nullable=False)
    date = db.Column(db.String(20), nullable=False)
    time_slot = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), default="Pending")

# Create tables
with app.app_context():
    db.create_all()

# ======================= Routes =======================

# Homepage
@app.route("/")
def homepage():
    return render_template("homepage.html")

# Login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Admin login
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["username"] = username
            session["is_admin"] = True
            flash("Login Successful ✅")
            return redirect(url_for("admin_panel"))

        # Regular user login
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session["username"] = username
            session["is_admin"] = False
            flash("Login Successful ✅")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid Credentials ❌")
            return redirect(url_for("login"))

    return render_template("login.html")

# Register
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if User.query.filter_by(username=username).first():
            flash("Username already exists ❌")
            return redirect(url_for("register"))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash("Registration Successful ✅ Please Login")
        return redirect(url_for("login"))

    return render_template("register.html")

# Logout
@app.route("/logout")
def logout():
    session.pop("username", None)
    session.pop("is_admin", None)
    flash("Logged out successfully ✅")
    return redirect(url_for("login"))

# Dashboard
@app.route("/dashboard")
def dashboard():
    if "username" in session and not session.get("is_admin"):
        return render_template("dashboard.html", username=session["username"])
    else:
        flash("Please login first ❌")
        return redirect(url_for("login"))

# Book Equipment
@app.route("/book", methods=["GET", "POST"])
def book_equipment():
    if "username" not in session or session.get("is_admin"):
        flash("Please login first ❌")
        return redirect(url_for("login"))

    if request.method == "POST":
        equipment = request.form["equipment"]
        date = request.form["date"]
        time_slot = request.form["time_slot"]

        existing_booking = Booking.query.filter_by(
            equipment=equipment,
            date=date,
            time_slot=time_slot
        ).first()

        if existing_booking:
            flash(f"{equipment} is already booked on {date} during {time_slot} ❌")
            return redirect(url_for("book_equipment"))

        new_booking = Booking(
            username=session["username"],
            equipment=equipment,
            date=date,
            time_slot=time_slot
        )
        db.session.add(new_booking)
        db.session.commit()

        flash(f"Equipment {equipment} booked on {date} during {time_slot} ✅")
        return redirect(url_for("dashboard"))

    return render_template("book_equipment.html")

# View user's bookings
@app.route("/my_bookings")
def my_bookings():
    if "username" not in session or session.get("is_admin"):
        flash("Please login first ❌")
        return redirect(url_for("login"))

    user_bookings = Booking.query.filter_by(username=session["username"]).all()
    return render_template("view_bookings.html", bookings=user_bookings)

# Cancel booking
@app.route("/cancel/<int:booking_id>")
def cancel_booking(booking_id):
    if "username" not in session or session.get("is_admin"):
        flash("Please login first ❌")
        return redirect(url_for("login"))

    booking = Booking.query.get_or_404(booking_id)
    if booking.username != session["username"]:
        flash("You are not allowed to cancel this booking ❌")
        return redirect(url_for("my_bookings"))

    db.session.delete(booking)
    db.session.commit()
    flash("Booking cancelled ✅")
    return redirect(url_for("my_bookings"))

# Update booking
@app.route("/update/<int:booking_id>", methods=["GET", "POST"])
def update_booking(booking_id):
    if "username" not in session or session.get("is_admin"):
        flash("Please login first ❌")
        return redirect(url_for("login"))

    booking = Booking.query.get_or_404(booking_id)
    if booking.username != session["username"]:
        flash("You are not allowed to update this booking ❌")
        return redirect(url_for("my_bookings"))

    if request.method == "POST":
        equipment = request.form["equipment"]
        date = request.form["date"]
        time_slot = request.form["time_slot"]

        existing_booking = Booking.query.filter(
            Booking.equipment == equipment,
            Booking.date == date,
            Booking.time_slot == time_slot,
            Booking.id != booking.id
        ).first()

        if existing_booking:
            flash(f"{equipment} is already booked on {date} during {time_slot} ❌")
            return redirect(url_for("update_booking", booking_id=booking.id))

        booking.equipment = equipment
        booking.date = date
        booking.time_slot = time_slot
        db.session.commit()
        flash("Booking updated ✅")
        return redirect(url_for("my_bookings"))

    return render_template("update_booking.html", booking=booking)

# Admin Panel
@app.route("/admin")
def admin_panel():
    if "username" not in session or not session.get("is_admin"):
        flash("Access denied ❌")
        return redirect(url_for("login"))

    all_bookings = Booking.query.all()
    return render_template("admin_panel.html", bookings=all_bookings)

# Admin: Approve/Reject booking
@app.route("/update_status/<int:booking_id>/<status>")
def update_status(booking_id, status):
    if "username" not in session or not session.get("is_admin"):
        flash("Access denied ❌")
        return redirect(url_for("login"))

    booking = Booking.query.get_or_404(booking_id)
    booking.status = status
    db.session.commit()
    flash(f"Booking status updated to {status} ✅")
    return redirect(url_for("admin_panel"))

# Run App
if __name__ == "__main__":
    app.run(debug=True)
