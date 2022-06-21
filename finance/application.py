import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    """Show portfolio of stocks"""

    if request.method == "POST":
        if not request.form.get("m"):
            return apology("Enter amount of money to be increased")
        c = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
        new_money = float(request.form.get("m")) + float(c)
        db.execute("UPDATE users SET cash = ?", new_money)
        return redirect("/")

    if request.method == "GET":
        # Get symbol , name of stock, number of shares, cost, total value
        user = session["user_id"]
        data = db.execute(
            "SELECT symbol, SUM(nos) as ts FROM a WHERE user_id = ? AND type = 'bought' GROUP BY symbol HAVING ts > 0", user)
        cash = db.execute("SELECT cash FROM users WHERE id = ?", user)[0]["cash"]

        # Store info
        info = []
        gt = 0
        for row in data:
            stock = lookup(row["symbol"])
            info.append({
                "symbol": stock["symbol"],
                "name": stock["name"],
                "shares": row["ts"],
                "price": stock["price"],
                "total": usd(stock["price"] * row["ts"])
            })
            gt += stock["price"] * row["ts"]
        gt += cash

    return render_template("index.html", info=info, cash=usd(cash), gt=usd(gt))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "GET":
        return render_template("buy.html")

    if request.method == "POST":
        # Ensure number of shares is a number
        if request.form.get("shares").isnumeric():
            sym = request.form.get("symbol").upper()
            # Get the info of symbol
            info = lookup(sym)
            # If entered symbol is invalid
            if info == None:
                return apology("Stock Didn't Exist")
            # Check the amount in user's account
            user = session["user_id"]
            balance = db.execute("SELECT cash FROM users WHERE id = ?", user)[0]["cash"]
            # Total Amount of shares
            ns = request.form.get("shares")
            amount = info["price"] * float(ns)
            # Check if user can afford the shares
            if amount > float(balance):
                return apology("Not Enough Cash")
            # If can afford then update the database
            else:
                date = datetime.now()
                db.execute("UPDATE users SET cash = ? WHERE id = ?", balance - amount, user)
                db.execute("INSERT INTO stock_info (user_id, symbol, name, cost, nos) VALUES(?, ?, ?, ?, ?)",
                           user, sym, info["name"], info["price"], ns)
                db.execute("INSERT INTO a (user_id, symbol, nos, type, time) VALUES(?,?,?,?,?)", user, sym, ns, 'bought', date)
            flash("Bought!")
        else:
            return apology("Invalid number of shares", 400)

        return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # Get symbol , name of stock, number of shares, cost, total value
    user = session["user_id"]
    data = db.execute("SELECT symbol, nos, time,type FROM a WHERE user_id = ?", user)
    time = db.execute("SELECT time FROM stock_info WHERE user_id = ?", user)

    # Store info
    info = []
    for row in data:
        stock = lookup(row["symbol"])
        info.append({
            "symbol": stock["symbol"],
            "shares": row["nos"],
            "price": stock["price"],
            "time": row["time"],
            "type": row["type"]
        })

    return render_template("history.html", info=info, usd=usd)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    if request.method == "GET":
        return render_template("quote.html")

    if request.method == "POST":
        sym = request.form.get("symbol")
        # Get the info of symbol
        info = lookup(sym)
        # If entered symbol is invalid
        if info is None:
            return apology("Stock Didn't Exist")
        else:
            return render_template("quote.html", info=info)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "GET":
        return render_template("register.html")

    else:
        # Ensure if username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 0:
            return apology("Username already Taken", 400)

        # Ensure password was submitted Again
        if not request.form.get("confirmation"):
            return apology("Enter the Password again to Confirm")

        # Ensure password and confirmation are same:
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("Passwords didn't Match")

        # Hash the password
        hashed_pw = generate_password_hash(request.form.get("password"), method='pbkdf2:sha256')

        # Insert the username and password in the database
        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", request.form.get("username"), hashed_pw)

    return redirect("/")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # If method is GET
    if request.method == "GET":
        s = db.execute("SELECT symbol FROM a WHERE user_id = ? AND type ='bought' GROUP BY symbol", session["user_id"])
        return render_template("sell.html", s=s)

    # If method is POST
    if request.method == "POST":
        # If share column left blank
        if not request.form.get("shares"):
            return apology("Enter number of shares to sell", 400)

        # If share column's value is -ve
        if int(request.form.get("shares")) < 1:
            return apology("Invalid number of shares to sell", 400)

        # If symbol choice left blank
        if not request.form.get("symbol"):
            return apology("Enter the name of share", 400)

        # Checking if the user does not own entered number of shares of the stock.
        check_nos = db.execute("SELECT nos FROM stock_info WHERE symbol = ? AND user_id = ?",
                               request.form.get("symbol"), session["user_id"])[0]["nos"]
        if int(request.form.get("shares")) > check_nos:
            return apology("Invalid number of shares entered", 400)

        # Checking if (somehow, once submitted) the user does not own any shares of that stock.
        if check_nos is None:
            return apology("You don't own entered stock")

        # Updating the cash and number of stocks owned
        sname = request.form.get("symbol")
        user = session["user_id"]
        inf = lookup(sname)
        pr = inf["price"]
        money = pr * check_nos

        c = db.execute("SELECT cash FROM users WHERE id = ?", user)[0]["cash"]
        newc = money + c
        db.execute("UPDATE users SET cash = ? WHERE id = ?", newc, user)

        sn = request.form.get("shares")
        new_s = check_nos - int(sn)
        date = datetime.now()

        db.execute("UPDATE stock_info SET nos = ? WHERE user_id = ? AND symbol = ?",
                   new_s, session["user_id"], request.form.get("symbol"))
        db.execute("UPDATE a SET nos = ?, type = ?, time = ? WHERE user_id = ? AND symbol = ?",
                   sn, 'sold', date, session["user_id"], request.form.get("symbol"))

    flash("Sold!")
    return redirect('/')


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
