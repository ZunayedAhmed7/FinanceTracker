from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
from database import get_db_connection, create_tables, drop_all_tables
from encryption import encrypt_data, decrypt_data, hash_password, verify_password
import os
from datetime import datetime
import sqlite3
import re
from dotenv import load_dotenv


load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
bcrypt = Bcrypt(app)

# Main categories for transactions and budgets
MAIN_CATEGORIES = [
    "Food", "Transport", "Utilities", "Entertainment", "Health", "Others", "Subscription"
]

# Routes
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with get_db_connection() as conn:
            user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user and bcrypt.check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        email = request.form['email']

        # Server-side password validation
        if len(password) < 8:
            flash('Password must be at least 8 characters long.')
            return redirect(url_for('register'))

        if not re.search(r'[A-Z]', password):
            flash('Password must include at least one uppercase letter.')
            return redirect(url_for('register'))

        if not re.search(r'[0-9]', password):
            flash('Password must include at least one number.')
            return redirect(url_for('register'))

        if not re.search(r'[!@#$%^&*]', password):
            flash('Password must include at least one special character (e.g., !@#$%^&*).')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('Passwords do not match.')
            return redirect(url_for('register'))

        # Hash the password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Save the user to the database
        with get_db_connection() as conn:
            try:
                conn.execute(
                    'INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
                    (username, hashed_password, email)
                )
                conn.commit()
            except sqlite3.IntegrityError:
                flash('Username or email already taken.')
                return redirect(url_for('register'))

        flash('Registration successful. Please login.')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Get the selected month from the query parameter (default to current month)
    selected_month = request.args.get('month', datetime.now().strftime('%Y-%m'))

    if request.method == 'POST':
        category = request.form['category']
        price = float(request.form['price'])
        date = request.form.get('date')

        if not date:
            date = datetime.now().strftime('%Y-%m-%d')  # YYYY-MM-DD

        month = date[:7]  # Extract YYYY-MM format

        with get_db_connection() as conn:
            conn.execute(
                'INSERT INTO transactions (user_id, category, price, timestamp, month) VALUES (?, ?, ?, ?, ?)',
                (session['user_id'], category, price, date, month)
            )
            conn.commit()

        flash('Transaction added successfully.')
        return redirect(url_for('dashboard', month=selected_month))

    # Fetch transactions for the selected month
    with get_db_connection() as conn:
        transactions = conn.execute(
            'SELECT category, price, timestamp FROM transactions WHERE user_id = ? AND month = ? ORDER BY timestamp ASC',
            (session['user_id'], selected_month)
        ).fetchall()

        # Fetch budgets for the selected month
        budgets = conn.execute(
            'SELECT category, amount FROM budgets WHERE user_id = ? AND month = ?',
            (session['user_id'], selected_month)
        ).fetchall()

        # Fetch total spending for each category in the selected month
        spending = conn.execute(
            'SELECT category, SUM(price) AS total_spent FROM transactions WHERE user_id = ? AND month = ? GROUP BY category',
            (session['user_id'], selected_month)
        ).fetchall()

        # Fetch available months for the dropdown
        available_months = conn.execute(
            'SELECT DISTINCT month FROM transactions WHERE user_id = ? UNION SELECT DISTINCT month FROM budgets WHERE user_id = ? ORDER BY month DESC',
            (session['user_id'], session['user_id'])
        ).fetchall()

    # Convert budgets and spending to dictionaries for easy access
    budget_dict = {budget['category']: budget['amount'] for budget in budgets}
    spending_dict = {item['category']: item['total_spent'] for item in spending}

    # Calculate remaining budget and percentage spent for each category
    budget_progress = {}
    for category in MAIN_CATEGORIES:
        budget = budget_dict.get(category, 0)
        spent = spending_dict.get(category, 0)
        remaining = max(budget - spent, 0)
        percentage_spent = (spent / budget) * 100 if budget > 0 else 0
        budget_progress[category] = {
            'budget': budget,
            'spent': spent,
            'remaining': remaining,
            'percentage_spent': percentage_spent
        }

    return render_template(
        'dashboard.html',
        transactions=transactions,
        categories=MAIN_CATEGORIES,
        budget_progress=budget_progress,
        available_months=[row['month'] for row in available_months],
        selected_month=selected_month
    )

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    with get_db_connection() as conn:
        user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()

    if user:
        return render_template('profile.html', username=user['username'], email=user['email'])
    return redirect(url_for('login'))

@app.route('/planning', methods=['GET', 'POST'])
def planning():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Get the selected month from the query parameter (default to current month)
    selected_month = request.args.get('month', datetime.now().strftime('%Y-%m'))

    if request.method == 'POST':
        category = request.form['category']
        amount = float(request.form['amount'])
        month = request.form['month']

        with get_db_connection() as conn:
            existing_budget = conn.execute(
                'SELECT id FROM budgets WHERE user_id = ? AND category = ? AND month = ?',
                (session['user_id'], category, month)
            ).fetchone()

            if existing_budget:
                conn.execute(
                    'UPDATE budgets SET amount = ? WHERE id = ?',
                    (amount, existing_budget['id'])
                )
            else:
                conn.execute(
                    'INSERT INTO budgets (user_id, category, amount, month) VALUES (?, ?, ?, ?)',
                    (session['user_id'], category, amount, month)
                )
            conn.commit()

        flash(f'Budget for {category} updated for {month}.')
        return redirect(url_for('planning', month=selected_month))

    # Fetch budgets for the selected month
    with get_db_connection() as conn:
        budgets = conn.execute(
            'SELECT category, amount FROM budgets WHERE user_id = ? AND month = ?',
            (session['user_id'], selected_month)
        ).fetchall()

        # Fetch transactions for the selected month
        transactions = conn.execute(
            'SELECT category, price, timestamp FROM transactions WHERE user_id = ? AND month = ? ORDER BY timestamp DESC',
            (session['user_id'], selected_month)
        ).fetchall()

        # Fetch available months for the dropdown
        available_months = conn.execute(
            'SELECT DISTINCT month FROM budgets WHERE user_id = ? UNION SELECT DISTINCT month FROM transactions WHERE user_id = ? ORDER BY month DESC',
            (session['user_id'], session['user_id'])
        ).fetchall()

    # Convert budgets to a dictionary
    budget_dict = {budget['category']: budget['amount'] for budget in budgets}

    return render_template(
        'planning.html',
        categories=MAIN_CATEGORIES,
        budgets=budget_dict,
        transactions=transactions,
        available_months=[row['month'] for row in available_months],
        selected_month=selected_month
    )

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out successfully.')
    return redirect(url_for('login'))

@app.route('/all_transactions')
def all_transactions():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    with get_db_connection() as conn:
        transactions = conn.execute(
            'SELECT id, category, price, timestamp FROM transactions WHERE user_id = ? ORDER BY timestamp DESC',
            (session['user_id'],)
        ).fetchall()

    return render_template('all_transactions.html', transactions=transactions)


@app.route('/delete_transaction/<int:transaction_id>', methods=['POST'])
def delete_transaction(transaction_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    with get_db_connection() as conn:
        # Ensure the transaction belongs to the logged-in user
        transaction = conn.execute(
            'SELECT * FROM transactions WHERE id = ? AND user_id = ?',
            (transaction_id, session['user_id'])
        ).fetchone()

        if transaction:
            conn.execute('DELETE FROM transactions WHERE id = ?', (transaction_id,))
            conn.commit()
            flash('Transaction deleted successfully.')
        else:
            flash('Transaction not found or you do not have permission to delete it.')

    return redirect(url_for('all_transactions'))