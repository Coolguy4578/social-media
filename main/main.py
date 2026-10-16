import os
import json
from argon2 import PasswordHasher
import google.cloud.firestore as firestore
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

import flask
from flask import *

app = Flask(__name__)
_ph = PasswordHasher()

# Firestore setup
db = firestore.Client(database="talko-database")
users = db.collection('users')

userdata = [{"username":"admin","password":"hello"},{"username":"test","password":"testing1234"}]

@app.route("/data")
def data():
    docs = users.stream()

    # 2. Build a dictionary mapping each ID to its JSON document data
    collection_data = {doc.id: doc.to_dict() for doc in docs}
    global json_output
    # 3. Convert the dictionary into a single JSON string
    json_output = json.dumps(collection_data, indent=4, default=str)

    print(json_output)
    # jsonify should be passed a Python object (not a JSON string)
    return app.response_class(json_output, mimetype='application/json')

@app.route('/')
def hello_world():
    return flask.render_template('index.html')

@app.route('/login',methods=['GET','POST'])
def login():
    if request.method == 'GET':
        return flask.render_template('login.html')
    elif request.method == 'POST':
        print(request.form)
        username_form = request.form.get('username', '')
        password_form = request.form.get('password', '')

        # Fetch users from Firestore
        docs = users.stream()
        collection_data = {doc.id: doc.to_dict() for doc in docs}

        found_user = None
        # The Firestore documents in your example look like:
        # { "c8R6...": { "0": { "username": "max", "password": "<hash>", "image": "..." } } }
        # So we iterate through documents and their nested records.
        for doc in collection_data.values():
            if isinstance(doc, dict):
                for record in doc.values():
                    if isinstance(record, dict) and record.get('username') == username_form:
                        found_user = record
                        break
            if found_user:
                break

        if not found_user:
            # Username not found
            return flask.render_template('login.html', fail=True)

        # Verify the password using argon2
        hashed_password = found_user.get('password', '')
        try:
            if _ph.verify(hashed_password, password_form):
                # Optional: rehash if algorithm parameters changed
                try:
                    if _ph.check_needs_rehash(hashed_password):
                        new_hash = _ph.hash(password_form)
                        # Update the Firestore entry with the new hash if desired
                        # NOTE: This requires knowing the document ID and field path. Skipping automatic update here.
                        pass
                except Exception:
                    # If check_needs_rehash isn't available or fails, ignore
                    pass

                return flask.render_template('login.html', username=found_user.get('username'), image=found_user.get('image'))
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            # Verification failed
            pass

        return flask.render_template('login.html', fail=True)

@app.errorhandler(404)
def page_not_found(e):
    return flask.render_template('404.html',error=e), 404

if __name__ == '__main__':
    app.run(debug=True,host='0.0.0.0',port=int(os.environ.get('PORT', 8080)))
