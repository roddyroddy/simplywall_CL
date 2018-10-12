from flask import Flask, render_template, request, redirect, session, flash
from mysqlconnection import connectToMySQL
from flask_bcrypt import Bcrypt
import re

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = 'poop'
mysql = connectToMySQL('simple_walldb')
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

@app.route('/')
def index():
    print("this is what's in session", session)
    if 'loggedIn' not in session:
        return render_template('index.html')
    elif session['loggedIn'] == True:
        return redirect('/home')
    else:
        return render_template('index.html')

@app.route('/register', methods=['POST'])
def create():
    print("register session",session)
    session['loggedIn'] = False
    goodForm = True
    if not EMAIL_REGEX.match(request.form['email']):
        flash('Not a valid email!', 'reg')
        goodForm = False
    if len(request.form['first_name']) < 2:
        flash('First name needs to be at least two characters!', 'reg')
        goodForm = False
    if len(request.form['last_name']) < 2:
        flash('Last name needs to be at least two characters!', 'reg')
        goodForm = False
    if len(request.form['password']) < 8:
        flash('Password needs to be at least eight characters!', 'reg')
        goodForm = False
    if request.form['confirm'] != request.form['password']:
        flash('Password and Confirm Password do not match!', 'reg')
        goodForm = False

    if goodForm == False:
        return redirect('/')
    else:
        flash("You\'ve been successfully registerd.")
        query = 'INSERT INTO users (first_name, last_name, email, password, created_at) VALUES (%(first_name)s, %(last_name)s, %(email)s, %(password)s,NOW());'
        hash_password = bcrypt.generate_password_hash(request.form['password'])
        data = {
            'first_name': request.form['first_name'],
            'last_name': request.form['last_name'],
            'email': request.form['email'],
            'password': hash_password
        }
        mysql.query_db(query, data)
        session['user'] = request.form['email']
        session['first_name'] = request.form['first_name']

        userquery = mysql.query_db('SELECT * FROM users;')
        session['emailquery'] = userquery
        newid = mysql.query_db('Select id from USERS WHERE email = "' + session['user'] + '";')
        newid = newid[0]
        newid = newid['id']

        session['id'] = newid
        print('session["id"]session["id"]session["id"]session["id"]session["id"]session["id"]', session['id'])
        session['loggedIn'] = True
        return redirect('/home')

@app.route('/home')
def success():
    print("logged session!!!!!!!!!!!!!!!!!!",session['id'])
    if 'user' not in session:
        flash('You are not logged in!')
        return redirect('/')

    query = "SELECT * FROM users WHERE id <> %(id)s"
    data = {
        'id' : session['id']
    }
    friends = mysql.query_db(query, data)

    query2 = "SELECT * FROM messages JOIN users on sender_id = users.id WHERE receiver_id = %(id)s;"
    messages = mysql.query_db(query2, data)

    query3 = 'SELECT COUNT(*) as count FROM users JOIN messages on sender_id = users.id WHERE sender_id = %(id)s;'
    counter = mysql.query_db(query3, data)

    query4 = 'SELECT * FROM messages JOIN comments on msg_id = message_id;'
    commentz = mysql.query_db(query4)
    print("***************", commentz)

    return render_template('home.html', friends = friends, messages = messages, counter = counter, commentz = commentz)

@app.route('/login', methods=['POST'])
def login():
    print("login session",session)
    query = mysql.query_db('SELECT * FROM users')

    for i in query:
        if i['email'] == request.form['login_email']:
            print('matched email')
            if bcrypt.check_password_hash(i['password'], request.form['login_password']):
                print('matched password')
                session['user'] = request.form['login_email']
                session['first_name'] = i['first_name']



                userquery = mysql.query_db('SELECT first_name, email FROM users;')
                session['emailquery'] = userquery
                newid = mysql.query_db('Select id from USERS WHERE email = "' + session['user'] + '";')
                session['id'] = newid[0]['id']

                print('session["id"]adsfasdjkfhglakusdjfghldkasfghdsafdskjhf', session['id'])
                

                return redirect('/home')

    flash('You failed to log in', 'login')    
    return redirect('/')

@app.route('/logout')
def delete():
    print("delete session",session)
    session.clear()
    print("after delete session",session)
    return redirect('/')

@app.route('/messages', methods = ['POST'])
def newComment():
    newcomment = request.form['comments']
    myid = session['id']
    receiver = request.form['receiver_id']

    query= 'INSERT INTO messages (message_body, created_at, sender_id, receiver_id) VALUES (%(message_body)s, NOW(), %(sender_id)s, %(receiver_id)s);'
    data={
        'message_body': newcomment,
        'sender_id': myid,
        'receiver_id': receiver
    }
    mysql.query_db(query, data)

    return redirect('/home')

@app.route('/delete/<value>')
def destroy(value):
    queryD = "DELETE FROM messages WHERE message_id = %(id)s AND receiver_id = %(session)s;"
    dataD = {
        'id': value,
        'session': session['id']
    }
    deleted = mysql.query_db(queryD, dataD)
    return redirect('/home')

@app.route('/comment', methods = ['POST'])
def comment():
    comment = request.form['comment_body']
    print(comment)
    myid = session['id']
    print(myid)

    msg_id = request.form['message_id']
    print(msg_id)


    query= 'INSERT INTO comments (text, msg_id, user_id) VALUES (%(comment_body)s, %(message_id)s, %(commenter_id)s);'
    data={
        'comment_body': comment,
        'message_id': myid,
        'commenter_id': msg_id
    }
    result = mysql.query_db(query, data)
    print(result)

    return redirect('/home')

if __name__ == "__main__":
    app.run(debug=True)
