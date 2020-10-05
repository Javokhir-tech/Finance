import os
import datetime

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

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


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    
    table = db.execute('''SELECT * FROM purchases 
    WHERE user_id = :user_id''', user_id=session["user_id"])
    
    user = db.execute('''SELECT username, cash FROM users 
    WHERE id = :id''', id=session["user_id"])
    
    cash = user[0]['cash']
    #
    total = float(cash)
    
    for i in table:
        total += (i['price'] * i['shares'])
    
    return render_template("index.html", table=table, cash=cash, total=total, user=user)

@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    """ Account settings """
    if request.method == 'GET':
        return render_template("account.html")
    else:
        oldPassword = request.form.get("oldPassword")
        newPassword = request.form.get("newPassword")
        confirmation = request.form.get("confirmation")
        
        # check password
        if oldPassword == '' or newPassword == '' or confirmation == '':
            return apology("password field is blank", 403)
        
        if newPassword != confirmation:
            return apology("password doesn't match", 403)
        
        elif newPassword == oldPassword:
            return apology("Enter new password")
        
        user_id = session["user_id"]
        
        user = db.execute(''' SELECT hash FROM users WHERE id = :user_id''', user_id=user_id)

        # Ensure username exists and password is correct
        if not check_password_hash(user[0]["hash"], oldPassword):
            return apology("invalid password", 403)
        
        # generate hash password
        hash_password = generate_password_hash(newPassword)
        
        db.execute(''' UPDATE users SET hash = :hash_password 
        WHERE id = :user_id''', hash_password=hash_password, user_id=user_id )
        
        flash("Password has been changed!")
        
        return redirect("/")
        
@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    # GET info
    if request.method == "GET":
        return render_template("buy.html")
    # send info (POST)
    else:
        # current user id
        user_id = session['user_id']
        
        # get from page
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))
        
        quote = lookup(symbol)
        
        # check if symbol is blank or not exist
        if not symbol:
            return apology("stock not found")
        
        # check if not positive
        if shares <= 0:
            return apology("input can't be a negative integer or 0")
            
        #call lookup to look up a stock’s current price.
        stockPrice = float(quote["price"])
        
        # calculation of total expenditure
        expense = shares * stockPrice
        
        # SELECT how much cash the user currently has in users.
        user = db.execute("SELECT * FROM users WHERE id = :user_id", user_id=user_id)
        
        # userCash [{'cash': 10000}]
        
        userCash = float(user[0]['cash']) # to get 10000
        
        #return render_template('test.html', user=user)
        
        if userCash < expense:
            return apology("Sorry! you can't afford the number of shares at current price.")
        
        else:
            stock = db.execute(''' SELECT * FROM purchases WHERE user_id = :user_id
            AND symbol = :symbol''',user_id=user_id, symbol=symbol)
            
            # changing value of cash
            db.execute('''UPDATE users SET cash = :userCash 
            WHERE id = :id''', userCash=(userCash-expense), id=user_id)
    
            # history of transactions
            db.execute(''' INSERT INTO history (user_id, symbol, shares, price, transacted)
            VALUES (:user_id, :symbol, :shares, :price, :transacted)''', user_id=user_id, symbol=symbol, shares=shares, price=stockPrice, transacted=datetime.datetime.now())
            
            # update with new price if already owned
            if len(stock) == 1:
                
                newShare = stock[0]['shares']+shares
                
                db.execute(''' UPDATE purchases SET shares = :shares, price = :price
                WHERE symbol = :symbol AND user_id = :user_id''', shares=newShare, price=stockPrice, symbol=symbol, user_id=user_id)
               
            else:
                db.execute('''INSERT INTO purchases (user_id, symbol, price, name, shares) 
                VALUES (:user_id, :symbol, :price, :name, :shares)''', user_id=user_id, symbol=symbol, price=stockPrice, name=quote['name'], shares=shares)
            
            flash("Bought!")
            
            return redirect("/")
        
@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    table = db.execute('''SELECT symbol, shares, price, transacted FROM history 
    WHERE user_id = :user_id''', user_id=session["user_id"])
    
    return render_template("history.html", table=table)

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
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

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
    
    else:
        symbol = request.form.get("symbol")
        
        if symbol == '':
            return apology("input is blank")
        elif symbol not in lookup(symbol)['symbol']:
            return apology("symbol doesn't exist")
        
        return render_template("quoted.html", lookupSymbol=lookup(symbol))


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")
    else:
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        users = db.execute("SELECT * FROM users")
        
        if username in users:
            return apology("username already exists")
        elif username == '':
            return apology("must provide a username")
            
        if password == '':
            return apology("must provide a password")
            
        elif password != confirmation:
            return apology("password doesn't match")
        
            
        hashpassword = generate_password_hash(password)
    
        new_user = db.execute("INSERT INTO users (username, hash) VALUES (:username, :password)", username=username, password=hashpassword)
    
        # unique username constraint violated?
        if not new_user:
            return apology("username taken", 400)
    
        # Remember which user has logged in
        session["user_id"] = new_user
        
        # Display a flash message
        flash("Registered!")
        
        return redirect("/")
    
@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "GET":
        return render_template("sell.html")
    
    else:
        user_id = session["user_id"]
        
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))

        if shares <= 0:
            return apology("input should be a positive number")
        
        # user cash
        cash = db.execute('''SELECT cash FROM users 
        WHERE id = :id''', id=user_id)
        
        userCash = cash[0]["cash"]
        
        #call lookup to look up a stock’s current price.
        stockPrice = float(lookup(symbol)["price"])
        
        # calculation of profit
        profit = shares * stockPrice
    
        # purchases db of user    
        stock = db.execute(''' SELECT * FROM purchases WHERE user_id = :user_id
        AND symbol = :symbol''',user_id=user_id, symbol=symbol)
        
        # check if user owned stock
        if len(stock) == 1:
            
            # update owned shares
            newShare = stock[0]['shares']-shares
            
            # check user's shares which can be sold
            if newShare < 0:
                return apology("you do not own that many shares of that stock.")
            
            # if shares no left delete it from db
            elif newShare == 0:
                db.execute('''DELETE FROM purchases WHERE user_id = :user_id 
                AND symbol = :symbol''', user_id=user_id, symbol=symbol)
                
            # history of transactions
            db.execute(''' INSERT INTO history (user_id, symbol, shares, price, transacted)
            VALUES (:user_id, :symbol, :shares, :price, :transacted)''', user_id=user_id, symbol=symbol, shares=-(shares), price=stockPrice, transacted=datetime.datetime.now())
            
            # update owned shares of stock
            db.execute(''' UPDATE purchases SET shares = :shares, price = :price
            WHERE symbol=:symbol AND user_id = :user_id''', shares=newShare, price=stockPrice, symbol=symbol, user_id=user_id)
            
            # changing value of cash
            db.execute('''UPDATE users SET cash = :userCash 
            WHERE id = :id''', userCash=(userCash+profit), id=user_id)
        
        else:
            return apology("you do not have this stock!")
            
        flash("Sold!")
            
        return redirect("/")
        

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
