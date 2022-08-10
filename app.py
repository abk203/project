from crypt import methods
from email import message
import json
from random import randint
from re import L
from flask import Flask, render_template, session, request, redirect
from flask_session import Session
import sqlite3
from functools import wraps
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import Encrypt, create

#Set name of application
app = Flask(__name__)

#auto reload the templates
app.config["TEMPLATES_AUTO_RELOAD"] = True

#session use filesystem instead of signed cookies
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

#create and connect the sqlite database (Without using CS50 Library) 
db = sqlite3.connect("project.db", check_same_thread=False)
cursor = db.cursor()

#create a table for users
cursor.execute("CREATE TABLE IF NOT EXISTS users(id integer PRIMARY KEY, username TEXT NOT NULL, password TEXT NOT NULL)")

 #Create a table for keep track of storing passwords
cursor.execute("CREATE TABLE IF NOT EXISTS passwords (id INTEGER, cipher TEXT NOT NULL, key INTEGER, name TEXT, description TEXT, time TEXT NOT NULL)")
db.commit()

def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/1.1.x/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

special_char = ['!', '@', '#', '$', '&', '*', '(', ')', '-', '_', '?', '/']

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
def home():
    #return homepage
    if request.method == "GET":
        return render_template("home.html")

@app.route("/index", methods=["GET", "POST"])
@login_required
def index():
    #Select data to show on index page from database
    cursor.execute("SELECT * FROM passwords WHERE id = ?", (session["user_id"], ))
    #Fetch from the database
    rows = cursor.fetchall()
    db.commit()
    if rows:
        #Store the data in another list 
        row = [r for r in rows]
        #Another list for decryption of encrypted password
        pas = [Encrypt.decryption(r[1], r[2]) for r in rows]
        if request.method == "GET":
            return render_template("index.html", row=row, rows=rows, pas=pas)

        if request.method == "POST":
            password_name  = request.form["password_name"]

            if password_name not in [r[3] for r in rows]:
                return render_template("failure.html", message="Name does not exist")

            name = request.form["name"]

            if request.form["action"] == "Delete":
                if request.form["confirm"] == "False":
                    return redirect("/index")

                cursor.execute("DELETE FROM passwords WHERE id = ? AND name = ?", (session["user_id"], name))

                cursor.execute("SELECT * FROM passwords WHERE id = ?", (session["user_id"], ))
                row = cursor.fetchall()
                db.commit()

            if request.form["action"] == "Save":
                url = request.form.get("url")
                cursor.execute("UPDATE passwords SET name = ? WHERE id = ? AND name = ?", (name, session["user_id"], password_name))
                cursor.execute("SELECT * FROM passwords WHERE id = ?", (session["user_id"], ))
                row = cursor.fetchall()
                db.commit()
            
        return render_template("index.html", row=row, rows=rows, pas=pas)
    else:
        return render_template("index.html")
       

#allow users to register 
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html", special_char=special_char)

    if request.method == "POST":
        #Ask for username
        username = request.form.get("username")
        #Confirm the username
        confirmation = request.form.get("confirmation")
        #ask for password
        password = request.form.get("password")
        #Hash the password
        hashed = generate_password_hash(password)
        #Get existing user from database
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        #fetch 
        existing = cursor.fetchall()
        db.commit()

        #Conditions for registering 
        if not username:
            return render_template("failure.html", message="Enter a valid username")
        if username != confirmation:
            return render_template("failure.html", message="Usernames do not match")
        if not any(char in special_char for char in password):
            return render_template("failure.html", message="At least one special char")
        if not any(digit.isdigit() for digit in password):
            return render_template("failure.html", message="At least one digit")
        if not any(char.isupper() for char in password):
            return render_template("failure.html", message="At least one upper character")
        if not any(char.islower() for char in password):
            return render_template("failure.html", message="At least one lower character")
        #If username already exists
        #Check if "existing" exists
        if existing is not None:
            if len(existing) != 0:
                return render_template("failure.html", message="Username already exists")

     
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed))
        db.commit()
        return redirect("/login")

@app.route("/login", methods=["POST", "GET"])
def login():
    #clear cookies
    session.clear
    if request.method == "GET":
        return render_template("login.html")

    if request.method == "POST":
        #Ask for username
        username = request.form.get("username")
        #Ask for password
        password = request.form.get("password")


        #Logging in conditions
        if not username or not password:
            return render_template("failure.html", message="Invalid username or password")

        #Check for existing username in database
        cursor.execute("SELECT * FROM USERS WHERE username = ?", (username,))
        #Get all the usernames from the database
        existing = cursor.fetchall()


        if len(existing) != 1 or not check_password_hash(existing[0][2], password):
            return render_template("failure.html", message="Invalid username or password")

        #Keep user logged in
        session["user_id"] = existing[0][0]

        #Redirect the user to index page
        return redirect("/index")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/add", methods=["GET", "POST"])
@login_required
def add():
    if request.method == "GET":
        return render_template("add.html")
    
    if request.method == "POST":
        password = request.form.get("password")
        name = request.form.get("name")
        description = request.form.get("description")
        key = randint(0, 50)

        if len(password) < 1:
            return redirect("/add")

        if not password:
            return render_template("failure.html", message="Must enter password")
        
        #Store blank space instead of "None" in table
        if description == None:
            description = ""
        #Store passwords in the table
        if password:
            if len(name) < 1:
                return redirect("/add")
            else:
                cursor.execute("INSERT INTO passwords (id, cipher, key, name, description, time) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)", (session["user_id"], Encrypt.encryption(password, key), key, name, description,))
                db.commit()
                return redirect("/index")


@app.route("/generate", methods=["GET", "POST"])
@login_required
def generate():
    if request.method == "GET":
        return render_template("generate.html")

    if request.method == "POST":
        length = request.form.get("length")
        name = request.form.get("name")
        description = request.form.get("description")

        key = randint(0, 50)
        if length:
            if int(length) < 8 or int(length) > 16:
                return render_template("failure.html", message="Length must be less than 16 and greater than 8")
            created = create(int(length))
        else:
            created = create(16)

        #Store blank space instead of "None" in table
        if (name) == None:
            name = ""
        if description == None:
            description = ""

        password = Encrypt.encryption(created, key)
        cursor.execute("INSERT INTO passwords (id, cipher, key, name, description, time) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)", (session["user_id"], password, key, name, description))
        db.commit()

        return redirect("/created")

@app.route("/created", methods=["GET", "POST"])
def created():
    cursor.execute("SELECT * FROM passwords WHERE id = ?", (session["user_id"], ))
    rows = cursor.fetchall()
    db.commit()
    
    if request.method == "GET":
        return render_template("created.html", created=Encrypt.decryption(rows[: : -1][0][1], rows[: : -1][0][2]))

    if request.method == "POST":
        
        if request.form["options"] == "No":
            cursor.execute("DELETE FROM passwords WHERE id = ? AND cipher = ?", (session["user_id"], rows[: : -1][0][1]))
            db.commit()
            return redirect("/index")

        if request.form["options"] == "Yes":
            return redirect("/index")

@app.route("/delete", methods=["POST"])
def delete():
    if request.method == "POST":
        name = request.form.get("name")

        
        return redirect("/index")