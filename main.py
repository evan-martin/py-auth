"""main.py - contains the routes for five webpages"""

import re

import uuid

import logging

from datetime import datetime

from flask import Flask, render_template, request, session, redirect

from passlib.hash import sha256_crypt

app = Flask(__name__)
dt = datetime.now()
app.secret_key = uuid.uuid4().hex
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)
logging.basicConfig(filename='access.log', format='%(asctime)s - %(message)s', datefmt='%d-%b-%y %H:%M:%S')

# --------------------Register and Login Helper Functions -------------------------


def user_exists(user):
    """checks if a user exists in the passfile"""
    with open('passfile.txt', "r") as file:
        if user in file.read():
            return bool(1)
    return bool(0)


def pw_complexity_check(password):
    """checks the password satisfies the requirements"""
    if re.match(r'^\S*(?=\S*[a-z])(?=\S*[A-Z])(?=\S*[\d])(?=\S*[\W_])(?=\S{12,})\S*$', password):
        return bool(1)
    return bool(0)


def check_hashed_password(username, user_pass):
    """checks the users password matches the hashed password"""
    with open('passfile.txt', "r") as file:
        lines = file.readlines()
        hash_index = 1
        for line in lines:
            if line.strip() == username:
                hash_pass = lines[hash_index].strip()
                if sha256_crypt.verify(user_pass, hash_pass):
                    return bool(1)
            hash_index += 1
    return bool(0)


def update_password(username, password):
    """updates a users password"""
    with open('passfile.txt', "r+") as file:
        lines = file.readlines()
        hash_index = 1
        for line in lines:
            if line.strip() == username:
                break
            hash_index += 1
    current_line = 0
    with open('passfile.txt', 'w') as file:
        for line in lines:
            if current_line == hash_index:
                hash_pass = sha256_crypt.hash(password)
                file.write(hash_pass + "\n")
            else:
                file.write(line)
            current_line += 1


def check_common_passwords(password):
    """checks for commonly used passwords"""
    with open('CommonPassword.txt', "r") as file:
        if password in file.read():
            return bool(1)
    return bool(0)


# -------------------- Routes -------------------------


@app.route('/')
def index(date=dt):
    """renders the index template"""
    if 'username' in session:
        return render_template('index.html', date=date)
    return render_template('login.html', date=date)


@app.route("/page1")
def page1(date=dt):
    """renders the page1 template"""
    if 'username' in session:
        return render_template('page1.html', date=date)
    return 'You are not logged in'


@app.route("/page2")
def page2(date=dt):
    """renders the page2 template"""
    if 'username' in session:
        return render_template('page2.html', date=date)
    return 'You are not logged in'


@app.route('/update', methods=['GET', 'POST'])
def update():
    """renders the update template and allows user to reset password"""
    error = ''
    if 'username' in session:
        if request.method == 'POST':

            username = session['username']
            password = request.form['password']

            if check_common_passwords(password):
                error = 'Password is too common'
            elif not pw_complexity_check(password):
                error = 'Password must be 12 characters in length, ' \
                        'and include at least 1 uppercase ' \
                        'character, 1 lowercase character, 1 number ' \
                        'and 1 special character'
            else:
                update_password(username, password)
                return redirect('/')
    return render_template('update.html', error=error, user=session["username"])


@app.route('/', methods=['GET', 'POST'])
def login(date=dt):
    """logs a user in and renders the login template"""

    error = ''
    client_ip = request.remote_addr

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if user_exists(username) and check_hashed_password(username, password):
            session['username'] = username
            return render_template('index.html', msg=error, date=date)

    error = 'Incorrect username or password!'
    logging.warning('Failed Login by: %s', client_ip)
    return render_template('login.html', msg=error)


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    """logs a user out"""
    if request.method == 'POST':
        session.pop('username', None)
    return redirect('/')


@app.route("/register", methods=['GET', 'POST'])
def register():
    """registers a user and renders the register template"""

    error = ''

    if request.method == 'POST':

        username = request.form['username']
        password = request.form['password']

        if not re.match(r'[A-Za-z0-9]+', username):
            error = 'Invalid username'
        elif user_exists(username):
            error = 'User Taken'
        elif not username or not password:
            error = 'Fill all fields'
        elif check_common_passwords(password):
            error = 'Password is too common'
        elif not pw_complexity_check(password):
            error = 'Password must be 12 characters in length, and include at least 1' \
                    'uppercase character, 1 lowercase character, 1 number and 1 special character'
        else:
            with open('passfile.txt', "a+") as file:
                hash_pass = sha256_crypt.hash(password)
                file.writelines(username + "\n")
                file.writelines(hash_pass + "\n")
            return redirect('/')

    return render_template('register.html', error=error)


# --------------------------------------------------------------


if __name__ == '__main__':
    app.run()
