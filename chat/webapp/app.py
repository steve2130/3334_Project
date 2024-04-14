# -*- coding: utf-8 -*-
# ==============================================================================
# Copyright (c) 2024 Xavier de Carné de Carnavalet
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 
# 3. The name of the author may not be used to endorse or promote products
#    derived from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# ==============================================================================

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, abort, flash
from flask_mysqldb import MySQL
from flask_session import Session
import yaml

app = Flask(__name__)

# Configure secret key and Flask-Session
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SESSION_TYPE'] = 'filesystem'  # Options: 'filesystem', 'redis', 'memcached', etc.
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True  # To sign session cookies for extra security
app.config['SESSION_FILE_DIR'] = './sessions'  # Needed if using filesystem type

# Load database configuration from db.yaml or configure directly here
db_config = yaml.load(open('db.yaml'), Loader=yaml.FullLoader)
app.config['MYSQL_HOST'] = db_config['mysql_host']
app.config['MYSQL_USER'] = db_config['mysql_user']
app.config['MYSQL_PASSWORD'] = db_config['mysql_password']
app.config['MYSQL_DB'] = db_config['mysql_db']

mysql = MySQL(app)

# Initialize the Flask-Session
# Session(app)

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    sender_id = session['user_id']
    return render_template('chat.html', sender_id=sender_id)

@app.route('/users')
def users():
    if 'user_id' not in session:
        abort(403)

    cur = mysql.connection.cursor()
    cur.execute("SELECT user_id, username FROM users")
    user_data = cur.fetchall()
    cur.close()

    filtered_users = [[user[0], user[1]] for user in user_data if user[0] != session['user_id']]
    return {'current_user': session['user_id'], 'users': filtered_users}

@app.route('/fetch_messages')
def fetch_messages():
    if 'user_id' not in session:
        abort(403)

    last_message_id = request.args.get('last_message_id', 0, type=int)
    peer_id = request.args.get('peer_id', type=int)
    
    cur = mysql.connection.cursor()
    query = """SELECT message_id,sender_id,receiver_id,message_text FROM messages 
               WHERE message_id > %s AND 
               ((sender_id = %s AND receiver_id = %s) OR (sender_id = %s AND receiver_id = %s))
               ORDER BY message_id ASC"""
    cur.execute(query, (last_message_id, peer_id, session['user_id'], session['user_id'], peer_id))

    # Fetch the column names
    column_names = [desc[0] for desc in cur.description]
    # Fetch all rows, and create a list of dictionaries, each representing a message
    messages = [dict(zip(column_names, row)) for row in cur.fetchall()]

    cur.close()
    return jsonify({'messages': messages})

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        userDetails = request.form
        username = userDetails['username']
        password = userDetails['password']
        cur = mysql.connection.cursor()
        cur.execute("SELECT user_id FROM users WHERE username=%s AND password=%s", (username, password,))
        account = cur.fetchone()
        if account:
            session['username'] = username
            session['user_id'] = account[0]
            return redirect(url_for('index'))
        else:
            error = 'Invalid credentials'
    return render_template('login.html', error=error)



@app.route('/send_message', methods=['POST'])
def send_message():
    if not request.json or not 'message_text' in request.json:
        abort(400)  # Bad request if the request doesn't contain JSON or lacks 'message_text'
    if 'user_id' not in session:
        abort(403)

    # Extract data from the request
    sender_id = session['user_id']
    receiver_id = request.json['receiver_id']
    message_text = request.json['message_text']
    iv = request.json['iv']
    salt = request.json['salt']
    additionalData = request.json['additionalData']
    key_id = int(request.json['key_id'])
    
    key_id -= 1     # AES-GCM instead of HMAC
    

    # Assuming you have a function to save messages
    save_message(sender_id, receiver_id, message_text, iv, salt, additionalData, key_id)
    
    return jsonify({'status': 'success', 'message': 'Message sent'}), 200



def save_message(sender, receiver, message, iv, salt, additionalData, key_id):
    cur = mysql.connection.cursor()
    cur.execute("INSERT INTO messages (sender_id, receiver_id, message_text, iv, salt, additionalData, key_id) VALUES (%s, %s, %s, %s, %s, %s, %s)", (sender, receiver, message, iv, salt, additionalData, key_id))
    mysql.connection.commit()
    cur.close()



@app.route('/erase_chat', methods=['POST'])
def erase_chat():
    if 'user_id' not in session:
        abort(403)

    peer_id = request.json['peer_id']
    cur = mysql.connection.cursor()
    query = "DELETE FROM messages WHERE ((sender_id = %s AND receiver_id = %s) OR (sender_id = %s AND receiver_id = %s))"
    cur.execute(query, (peer_id, session['user_id'], session['user_id'], peer_id))
    mysql.connection.commit()

    # Check if the operation was successful by evaluating affected rows
    if cur.rowcount > 0:
        return jsonify({'status': 'success'}), 200
    else:
        return jsonify({'status': 'failure'}), 200

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been successfully logged out.', 'info')  # Flash a logout success message
    return redirect(url_for('index'))


###########################################################################
@app.route('/retrieve_user_password', methods=['GET'])
def retrieve_user_password():
# To encrypt ECDH private key and AES private key with user password 
    if 'user_id' not in session:
        abort(403)

    user_id = request.args.get('user_id')             # get user_id
    cur = mysql.connection.cursor()
    cur.execute("SELECT password FROM users WHERE user_id = %s", (user_id))
    user_password = cur.fetchone()
    cur.close()

    return jsonify({"password": user_password}), 200






@app.route('/ProcessECDHKey', methods=['POST'])
def ProcessECDHKey():
    if not request.json or not 'key' in request.json:
        abort(400)  # Bad request if the request doesn't contain JSON or lacks 'message_text'
    if 'user_id' not in session:
        abort(403)

    # Extract data from the request
    user_id = session['user_id']
    key = request.json['key']
    print(key)

    # Save ECDH Public Key to MySQL
    cur = mysql.connection.cursor()
    cur.execute("UPDATE users SET session_key = %s WHERE user_id = %s", (key, user_id))
    mysql.connection.commit()
    cur.close()
    
    return jsonify({'status': 'success', 'message': 'Message sent'}), 200



@app.route('/retrieve_ECDH_PublicKey', methods=['GET', 'POST'])
def retrieve_ECDH_PublicKey():
    if 'user_id' not in session:
        abort(403)

    user_id = request.args.get('user_id')             # get user_id
    # print(user_id)
    cur = mysql.connection.cursor()
    cur.execute("SELECT session_key FROM users WHERE user_id = %s", (user_id))
    ECDH_PublicKey = cur.fetchone()
    # print(ECDH_PublicKey)
    cur.close()

    return jsonify({"session_key": ECDH_PublicKey}), 200


@app.route('/Send_Keys_To_Backend', methods=['POST'])
def Send_Keys_To_Backend():
    if not request.json:
        abort(400)  # Bad request if the request doesn't contain JSON or lacks 'message_text'

    key_type = request.json['key_type']
    key_content = request.json['key_content']
    sender_id = request.json['sender_id']
    receiver_id = request.json['receiver_id']
    
    key_content = str(key_content).replace("\'", "\"")
    # print("\n\n\n" + key_content)
    
    cur = mysql.connection.cursor()
    cur.execute("INSERT INTO ENCRYPTIONKEY (key_type, key_content, sender_id, receiver_id) VALUES (%s, %s, %s, %s)", (key_type, key_content, sender_id, receiver_id))
    mysql.connection.commit()
    
    cur.execute("SELECT key_id FROM ENCRYPTIONKEY WHERE (key_type = %s AND key_content = %s AND sender_id = %s AND receiver_id = %s)", (key_type, key_content, sender_id, receiver_id))
    key_id = cur.fetchone()
    cur.close()

    return jsonify({'status': 'success', 'message': 'Key received', 'key_id': key_id[0]})
    
    
    
@app.route('/retrieve_AES_and_HMAC_Key', methods=['GET'])
def retrieve_AES_and_HMAC_Key():
    if 'user_id' not in session:
        abort(403)

    message_id = request.args.get('message_id', type=int)

    cur = mysql.connection.cursor()
    cur.execute("SELECT key_id, iv, additionalData FROM messages WHERE message_id = %s", (message_id))
    Key_Info = cur.fetchone()
    Key_Info = jsonify(Key_Info)
    
    cur.execute("SELECT key_content, sender_id, receiver_id FROM messages WHERE key_id = %s", (Key_Info.key_id))
    Key_Content = cur.fetchone()
    
    Key_Info = Key_Info + Key_Content
    
    cur.close()
    
    return jsonify({"key_info": Key_Info}), 200
    
    
    
    
    
    
if __name__ == '__main__':
    app.run(debug=True)

