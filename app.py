import os
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    current_user = session["user_id"]
    owned = db.execute("SELECT * FROM owned WHERE user_id =?", current_user)
    print(owned)
        
    for i in owned:
        found = lookup(i['sym'])
        print(found)
        i['price'] = found['price']
        i['total'] = i['price']*i['shares']
         
    balance = db.execute("SELECT cash FROM users WHERE id =?", current_user)
    
    TOTAL = balance[0]['cash']
    print(TOTAL)
    
    for i in owned:
        TOTAL += i['total']
        print(TOTAL)
        
    print(TOTAL)
    return render_template("index.html", owned = owned, cash = balance[0]['cash'], TOTAL = TOTAL)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")
    elif request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        
        current_user = session["user_id"]
        balance = db.execute("SELECT cash FROM users WHERE id =?", current_user)
         
        found = lookup(request.form.get("symbol"))
        print(found)
        
        """password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        """
        
        try:
            shares =int(shares)
        except ValueError:
              return apology("Invalid amount!")  
        if not symbol:
            print("Wrong")
            return apology("Invalid symbol!")
        elif not shares >0:
            return apology("Invalid amount!")

        elif found == None:
            return apology("Invalid symbol!")
        
        elif found['price'] * float(shares) > balance[0]['cash']:
            return apology("Insufficient cash!")

        else:
            own_sym = db.execute("SELECT sym FROM owned WHERE user_id = ? AND sym = ?", current_user, symbol)
            #db.execute("SELECT cash FROM users WHERE id =?", current_user)
            #db.execute("SELECT cash FROM users WHERE id =?", current_user)
            print(own_sym)
            if len(own_sym) == 0:
                db.execute("INSERT INTO owned VALUES (?, ?, ?, ?)", current_user, found['name'], symbol, shares)
                db.execute("INSERT INTO trans VALUES (?, ?, ?, ?, julianday('now'), ?)", current_user, symbol, "buy", found['price'], shares)
                db.execute("UPDATE users SET cash = ? WHERE id = ?", balance[0]['cash']-(found['price']*shares), current_user)
                return render_template("index.html", name=found['name'], price=found['price'], sym=found['symbol'])
            else:
                own_sha = db.execute("SELECT shares FROM owned WHERE user_id = ? and sym = ?", current_user, symbol)
                db.execute("UPDATE owned SET shares = ? WHERE user_id = ? and sym = ?", own_sha[0]['shares'] + shares, current_user, symbol)
                db.execute("INSERT INTO trans VALUES (?, ?, ?, ?, julianday('now'), ?)", current_user, symbol, "buy", found['price'], shares)
                db.execute("UPDATE users SET cash = ? WHERE id = ?", balance[0]['cash']-(found['price']*shares), current_user)
                return redirect("/")

@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    current_user = session["user_id"]
    trans = db.execute("SELECT sym, shares, form, price, date(date), time(date) FROM trans WHERE user_id = ?", current_user)
    print(trans)
    return render_template("history.html", trans=trans)


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
    
@app.route("/password", methods=["GET", "POST"])
@login_required
def password():
    """Change password"""
    if request.method == "GET":
        return render_template("password.html")
    elif request.method ==  "POST":
        current = request.form.get("current")
        password = request.form.get("password")
        again = request.form.get("again")
        current_user = session["user_id"]
        hash1 = db.execute("SELECT hash FROM users WHERE id = ?", current_user)
        #usernames = db.execute("SELECT username FROM users WHERE username=?", username)
        hash2 = generate_password_hash(request.form.get("current"))
        
        # Ensure username was submitted
        if not current:
            print(1)
            return apology("must provide current password", 403)    
            
        # Ensure password was submitted
        elif not password:
            print(2)           
            return apology("new password not given", 403) 
        
        elif not check_password_hash(hash1[0]["hash"], request.form.get("current")):
            print(3)
            return apology("wrong current password", 403)

        elif password != again:
            print(4)
            return apology("passwords don't match", 403)
            
        else:
            hashed = generate_password_hash(password)
            db.execute("UPDATE users SET hash = ? WHERE id =?", hashed, current_user)
            print(hashed)
            return redirect("/login")  


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote.html")
    elif request.method == "POST":
        found = lookup(request.form.get("symbol"))
        print(found)
        return render_template("quoted.html", name=found['name'], price=found['price'], sym=found['symbol'])


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")
    elif request.method ==  "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        usernames = db.execute("SELECT username FROM users WHERE username=?", username)
        print(usernames)

        # Ensure username was submitted
        if not username:
            return apology("must provide username", 403)
            
            
        # Ensure password was submitted
        elif not password:            
            return apology("must provide password", 403) 

        elif password != confirmation:
            return apology("passwords don't match", 403)
        
        # Ensure username exists and password is correct
        elif len(usernames)>0:
            print(4)
            return apology("username taken, select another", 403)
        
        else:
        # Redirect user to home page
            hashed = generate_password_hash(request.form.get("password"))
            db.execute("INSERT INTO users(username, hash) VALUES(?, ?)", username, hashed)
            print(hashed)
            return redirect("/login")  

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    symbol = request.form.get("symbol")
    print(symbol)
    shares = request.form.get("shares")        
    print(shares)
    current_user = session["user_id"]
    own_sym = db.execute("SELECT sym FROM owned WHERE user_id = ?", current_user)
    
    own_syms = []
    for i in own_sym:
        own_syms.append(i['sym'])
    print(own_syms)
    if request.method == "GET":
        return render_template("sell.html", own_syms = own_syms)
    
    elif request.method == "POST":
        own_sha = db.execute("SELECT shares FROM owned WHERE user_id = ? and sym = ?", current_user, symbol)
        balance = db.execute("SELECT cash FROM users WHERE id =?", current_user)
        
        if own_sha == None:
            print(7)
            return redirect("/")
        try:
            shares =int(shares)
        except ValueError:
              return apology("Invalid amount!")  

                
        if symbol not in own_syms or symbol  == None:
            print(1)
            return apology("Unknown stock!")
        
        print(own_sha)
        if shares > own_sha[0]['shares']:
            print(2)
            return apology("Insufficient stocks!")
        elif shares == own_sha[0]['shares']:
            found = lookup(request.form.get("symbol"))
            db.execute("DELETE FROM owned WHERE user_id = ? and sym = ?", current_user, symbol)
            db.execute("INSERT INTO trans VALUES (?, ?, ?, ?, julianday('now'), ?)", current_user, symbol, "sell", found['price'], shares)
            db.execute("UPDATE users SET cash = ? WHERE id = ?", balance[0]['cash']+(found['price']*shares), current_user)
            return redirect("/")
            
        else:
            to_sell = db.execute("SELECT shares FROM owned WHERE sym = ?", symbol)
            found = lookup(request.form.get("symbol"))
            db.execute("UPDATE owned SET shares = ? WHERE user_id = ? and sym = ?", own_sha[0]['shares'] - shares, current_user, symbol)
            db.execute("INSERT INTO trans VALUES (?, ?, ?, ?, julianday('now'), ?)", current_user, symbol, "sell", found['price'], shares)
            db.execute("UPDATE users SET cash = ? WHERE id = ?", balance[0]['cash']+(found['price']*shares), current_user)
            return redirect("/")
            
            
    
#pk_d1f7965ef7f94dedba5fc76de2e02906