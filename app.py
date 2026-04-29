import sqlite3
from flask import Flask, render_template, request, make_response, redirect, url_for, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash

from database import get_db, close_db, init_db, audit_log

app = Flask(__name__)
app.config["SECRET_KEY"] = "123"

@app.cli.command("init-db")
def init_db_command():
    init_db()
    db = get_db()
    audit_log(user_id=0, action="database initialized", resource="database", resource_id=0)
    print(db.execute("SELECT * FROM audit_logs").fetchall()[0]["action"])

@app.cli.command("set-cookies-config")
def set_cookies_config(): #vulnerabilitate cookies slabe
    app.config["SESSION_COOKIE_HTTPONLY"] = False #cookie fara HttpOnly, secure si samesite
    app.config["SESSION_COOKIE_SECURE"] = False
    app.config["SESSION_COOKIE_SAMESITE"] = False

@app.teardown_appcontext
def teardown_db(exception):
    close_db(exception)

def current_user():
    user_email = request.cookies.get("user_email")
    if not user_email:
        return None
    db = get_db()
    return db.execute("SELECT * FROM users WHERE email = ?", (user_email,)).fetchone()

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

        #vulnerabilitate - nicio validare nici la email nici la parola
        # si fara hash la parola

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)",
                (email, password, role), #stocare a parolei in clar
            )
            db.commit()

            #user id ptr audit log
            new_user_id = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()["id"]
        except sqlite3.IntegrityError as e:
            flash(f"Error: {e}")
            return render_template("register.html")
        except Exception as e:
            flash(f"Error: {e}")
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

        query = f"SELECT id FROM users WHERE email = '{email}' AND password_hash = '{password}'"
        user = db.execute(query).fetchone()

        query_user = f"SELECT * FROM users WHERE email = '{email}'"
        email_query = db.execute(query_user).fetchone()


        if not email_query: #vulerabilitate parola / email specific incorect
            flash("Incorrect email.")
            return render_template("login.html")
        elif email_query and not user:
            flash("Incorrect password.")
            return render_template("login.html")

        #vulnerabilitate - numar nelimitat de incercari de login
        response = make_response(redirect(url_for("home")))
        response.set_cookie("user_email", email, max_age=60*60*24) #vulnerabilitate, cookie tine o zi intreaga
        audit_log(user_id=user["id"], action="login", resource="auth", resource_id=user["id"])

        return response

    return render_template("login.html")

#LOGOUT
@app.post("/logout")
def logout():
    response = make_response(redirect(url_for("home")))
    response.set_cookie("user_email", "", expires=0)
    audit_log(user_id=current_user()["id"], action="logout", resource="auth", resource_id=current_user()["id"])
    return response

#password reset email input page -> token generation
@app.route("/forgot-password-email", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        token = "123"  #vulnerabilitate token slab / reutilizabil
        flash("Token for password reset:" + token)
        return render_template("forgot-password-token.html", email=request.form.get("email"))

    return render_template("forgot-password-email.html")

#password reset token verification -> password reset page
@app.post("/forgot-password-token-verification")
def forgot_password_token_verification():
    email = request.form.get("email")
    token = request.form.get("token")

    if token != "123":
        flash("invalid token")
        return render_template("forgot-password-token.html", email=email)

    return render_template("forgot-password-reset.html", email=email)

#password reset page -> password update in database
@app.post("/forgot-password-reset")
def forgot_password_reset():
    email = request.form.get("email")
    new_password = request.form.get("new_password")
    db = get_db()

    # verificare daca email-ul exista in baza de date
    query_user = f"SELECT * FROM users WHERE email = '{email}'"
    email_query = db.execute(query_user).fetchone()
    if not email_query:
        flash("Invalid EMAIL." + email)
        return render_template("forgot-password-token.html", email=email)

    db.execute(f"UPDATE users SET password_hash = '{new_password}' WHERE email = '{email}'") #vulnerabilitate fara hashing
    db.commit()
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

        db = get_db()
        parameters = "AND "
        if title:
            parameters += f"title LIKE '%{title}%' AND "
        if description:
            parameters += f"description LIKE '%{description}%' AND "
        if severity != "None":
            parameters += f"severity = upper('{severity}') AND "
        if status != "None":
            parameters += f"status = upper('{status}') AND "


        parameters = parameters[:-5]  # elimin ultimul AND
        user_tickets = []
        if user["role"] == "MANAGER":
            user_tickets = db.execute(
                f"SELECT t.*, u.email FROM tickets t JOIN users u ON t.owner_id==u.id WHERE 1=1 {parameters}",
                ).fetchall()
        else:
            user_tickets = db.execute(f"SELECT * FROM tickets WHERE owner_id = ? {parameters}",
                                      (user["id"], )).fetchall()

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


