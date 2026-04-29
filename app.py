import re, pytz
import secrets
import sqlite3
from datetime import timedelta, datetime

from flask import Flask, render_template, request, make_response, redirect, url_for, flash, abort, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bcrypt import Bcrypt

from database import get_db, close_db, init_db, audit_log

app = Flask(__name__)
app.config["SECRET_KEY"] = "6ewrEYScgvW7VzgaHc8vMw93eRoTUsuwPaWiqjdoVPLIRR4FrcmiAcL6V9L3KDok" #token imbunatatit
app.config['PERMANENT_SESSION_LIFETIME'] =  timedelta(minutes=15) #sesiune de 15 min
bcrypt = Bcrypt(app)

@app.cli.command("init-db")
def init_db_command():
    init_db()
    db = get_db()
    audit_log(user_id=0, action="database initialized", resource="database", resource_id=0)
    print(db.execute("SELECT * FROM audit_logs").fetchall()[0]["action"])

@app.cli.command("set-cookies-config")
def set_cookies_config(): #vulnerabilitate cookies slabe - fixed + sesiuni
    app.config["SESSION_COOKIE_HTTPONLY"] = True #cookie cu HttpOnly, secure si samesite
    app.config["SESSION_COOKIE_SECURE"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = True

@app.teardown_appcontext
def teardown_db(exception):
    close_db(exception)

def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    db = get_db()
    return db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

#HOME PAGE
@app.get("/")
def home():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    return render_template("home.html", user=user)

#REGISTER
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip()
        password = request.form.get("password") or ""
        role = request.form.get("role")

        if not email or not password:
            flash("Email and password are mandatory.")
            return render_template("register.html")

        db = get_db()

        #vulnerabilitate - nicio validare nici la email nici la parola - fixed
        # si fara hash la parola - fixed

        #check email
        email_match = re.search(r"^[-\w\.]+@([\w-]+\.)+[\w-]{2,4}$", email)
        if not email_match:
            flash("Invalid email format.")
            return render_template("register.html")

        #verificare daca email ul exista deja in baza de date
        email_exists = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if email_exists:
            flash("Email already registered.")
            return render_template("register.html")

        #check password
        pw_check = re.search(r"^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*()_+\-=[\]{}|;':\",./<>?])(?=.*[a-zA-Z]).{8,}$", password)
        if not pw_check:
            flash("Password must be at least 8 characters long and include an uppercase letter, a lowercase letter, a number and a special character.")
            return render_template("register.html")

        pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')



        try:
            db.execute(
                "INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)",
                (email, pw_hash, role), #stocare a parolei hashuite!!
            )
            db.commit()

            #user id ptr audit log
            new_user_id = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()["id"]
        except Exception as e:
            flash(f"Erorr creating account. Please try again") #mesaj eroare fara stack trace-
            return render_template("register.html")

        flash("Account created. Please log in")

        audit_log(user_id=new_user_id, action="registration", resource="auth", resource_id=new_user_id)

        return redirect(url_for("login"))
    return render_template("register.html")

#LOGIN
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip()
        password = request.form.get("password") or ""


        db = get_db()

        email_query = db.execute( "SELECT * FROM users WHERE email = ?",(email,)).fetchone()
        pw_check = bcrypt.check_password_hash(email_query["password_hash"] , password ) if email_query else False

        if not email_query or not pw_check:
            flash("Incorrect credentials.")#vulerabilitate parola / email specific incorect - fixed
            if email_query: #exista contul, a gresit parola
                # vulnerabilitate - numar nelimitat de incercari de login - fixed
                audit_log(user_id=email_query["id"], action="failed login attempt", resource="auth", resource_id=email_query["id"])
                #daca au fost 5 incercari in ultima ora, blocam contul
                failed_attempts = db.execute(
                    "SELECT COUNT(*) FROM audit_logs WHERE user_id = ? AND action = 'failed login attempt' AND timestamp > datetime('now', '-1 hour')",
                    (email_query["id"],)
                ).fetchone()[0]
                if failed_attempts == 2:
                    flash("Remaining login attempts in the last hour: 3")
                elif failed_attempts == 3:
                    flash("Remaining login attempts in the last hour: 2")
                elif failed_attempts == 4:
                    flash("Remaining login attempts in the last hour: 1")
                elif failed_attempts >= 5:
                    flash("Account locked due to too many failed login attempts in the last hour. Please contact management.")
                    db.execute("UPDATE users SET locked = 1 WHERE id = ?", (email_query["id"],))
                    db.commit()
                    audit_log(user_id=email_query["id"], action="account locked", resource="auth", resource_id=email_query["id"])

            return render_template("login.html")


        locked = db.execute(
            "SELECT locked FROM users WHERE id = ?",
            (email_query["id"],)
        ).fetchone()
        if locked == 0:
            flash("Account is currently locked due to too many failed login attempts. Please contact managment.")
            return render_template("login.html")

        session["permanent"] = True #ca sa fie 15 min
        session["user_id"] = email_query["id"]
        audit_log(user_id=email_query["id"], action="login", resource="auth", resource_id=email_query["id"])

        return render_template("home.html", user=email_query)

    return render_template("login.html")

#LOGOUT
@app.post("/logout")
def logout():
    user = current_user()
    audit_log(user_id=user["id"], action="logout", resource="auth", resource_id=user["id"])
    session.clear()
    return redirect(url_for("login"))

#password reset email input page -> token generation
@app.route("/forgot-password-email", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        #vulnerabilitate token slab / reutilizabil - fixed
        #daca nu e expirat token ul, nu generam altul nou, ci folosim pe ala existent
        if session.get("rst_tkn") and session.get("tkn_cldwn") and session["tkn_cldwn"] > pytz.utc.localize(datetime.now()) - timedelta(minutes=1):
            token = session["rst_tkn"]

        else:
            token = secrets.token_urlsafe(10)
            session["rst_tkn"] = token
            session["tkn_cldwn"] = datetime.now()  # scurtate in speranta sa nu fie prea vizibile ptr client
        flash("Token for password reset:" + token) #pentru demo

        return render_template("forgot-password-token.html", email=request.form.get("email"), token=token)

    return render_template("forgot-password-email.html")

#password reset token verification -> password reset page
@app.post("/forgot-password-token-verification")
def forgot_password_token_verification():
    email = request.form.get("email")
    input_token = request.form.get("input_token")

    print("Session token:", session.get("tkn_cldwn"))
    #check sa nu fi expirat token ul
    if session["tkn_cldwn"] < pytz.utc.localize(datetime.now()) - timedelta(minutes=1):
        session.clear()
        flash("Token expired. Please request a new one.")
        return render_template("forgot-password-email.html")

    if session["rst_tkn"] != input_token:
        flash("Invalid token")
        return render_template("forgot-password-token.html", email=email)

    return render_template("forgot-password-reset.html", email=email)

#password reset page -> password update in database
@app.post("/forgot-password-reset")
def forgot_password_reset():
    email = request.form.get("email")
    new_password = request.form.get("new_password")

    pw_check = re.search(r"^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*()_+\-=[\]{}|;':\",./<>?])(?=.*[a-zA-Z]).{8,}$",
                         new_password)
    if not pw_check:
        flash(
            "Password must be at least 8 characters long and include an uppercase letter, a lowercase letter, a number and a special character.")
        return render_template("register.html")

    db = get_db()
    pw_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
    db.execute("UPDATE users SET password_hash = ? WHERE email = ?",(pw_hash, email,)) #vulnerabilitate fara hashing - fixed
    db.commit()

    email_query = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

    flash("Password reset. Please log in.")
    audit_log(user_id=email_query["id"], action="reset password", resource="auth", resource_id=email_query["id"])
    return redirect(url_for("login"))


#TICKETE
@app.route("/tickets", methods=["GET", "POST"])
def tickets():
    user = current_user() #verificare sesiune
    if not user:
        return redirect(url_for("login"))

    db = get_db()

    if request.method == "POST":
        title = request.form.get("title")
        description = request.form.get("description")
        severity = request.form.get("severity")
        status = request.form.get("status")

        query_string = ""
        parameters = []

        if user["role"] == "MANAGER":
            query_string = "SELECT t.*, u.email FROM tickets t JOIN users u ON t.owner_id==u.id WHERE 1=1"
        else:
            query_string = "SELECT * FROM tickets WHERE owner_id = ?"
            parameters.append(user["id"])

        if title:
            query_string += " AND title LIKE ?"
            parameters.append(f"%{title}%")
        if description:
            query_string += " AND description LIKE ?"
            parameters.append(f"%{description}%")
        if severity != "None":
            query_string += " AND severity = ?"
            parameters.append(severity)
        if status != "None":
            query_string += " AND status = ?"
            parameters.append(status)

        db = get_db()
        user_tickets = db.execute(query_string,
                                  parameters).fetchall()

        return render_template("tickets.html", user=user, tickets=user_tickets)

    user_tickets = []
    if user["role"] == "MANAGER":
        user_tickets = db.execute("SELECT t.*, u.email FROM tickets t JOIN users u ON t.owner_id==u.id").fetchall()
    else:
        user_tickets = db.execute("SELECT * FROM tickets WHERE owner_id = ?", (user["id"],)).fetchall()

    return render_template("tickets.html", user=user, tickets=user_tickets)


@app.post("/tickets/<ticket_id>") #update ticket status
def update_ticket(ticket_id):
    user = current_user() #verificare sesiune
    if not user:
        return redirect(url_for("login"))

    new_status = request.form.get("status")
    db = get_db()



    ticket = db.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    if not ticket:
        return redirect(url_for("tickets"))

    # verificam daca user ul e manager
    if user["role"] != "MANAGER":
        return redirect(url_for("home"))

    db.execute("UPDATE tickets SET status = ? WHERE id = ?", (new_status, ticket_id))
    db.commit()
    flash("Ticket updated.")
    audit_log(user_id=user["id"], action="update ticket", resource="ticket", resource_id=ticket_id)
    return redirect(url_for("tickets"))

 #add new ticket
@app.post("/tickets/add")
def add_ticket():
    user = current_user() #verificare sesiune
    if not user:
        return redirect(url_for("login"))
    db = get_db()
    title = request.form.get("title")
    description = request.form.get("description")
    severity = request.form.get("severity")
    status = request.form.get("status")
    if not title or not description:
        flash("Title and description are mandatory.")
        return render_template("tickets.html", user=user, tickets=[])

    db.execute(
        "INSERT INTO tickets (title, description, severity, status, owner_id) VALUES (?, ?, ?, ?, ?)",
        (title, description, severity, status, user["id"])
    )
    db.commit()
    flash("Ticket created.")
    audit_log(user_id=user["id"], action="create ticket", resource="ticket",
              resource_id=db.execute("SELECT last_insert_rowid() FROM TICKETS").fetchone()[0])
    return redirect(url_for("tickets"))

@app.get("/audit-logs")
def audit_logs():
    user = current_user() #verificare sesiune
    if not user:
        return redirect(url_for("login"))

    if user["role"] != "MANAGER": #doar managerii pot vedea audit log ul
        return redirect(url_for("home"))

    db = get_db()
    logs = db.execute("SELECT al.*, u.email FROM audit_logs al JOIN users u ON al.user_id==u.id").fetchall()
    return render_template("audit-logs.html", user=user, logs=logs)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)


