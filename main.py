import os
from argon2 import PasswordHasher
import google.cloud.firestore as firestore
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
db=firestore.Client(database="talko-database")
users=db.collection('users')
import flask
from flask import *
app = Flask(__name__)
_ph = PasswordHasher()
userdata = [{"username":"admin","password":"hello"},{"username":"test","password":"testing1234"}]
@app.route("/data")
def data():
    docs = users.stream()

    # 2. Build a dictionary mapping each ID to its JSON document data
    collection_data = {doc.id: doc.to_dict() for doc in docs}

    # 3. Convert the dictionary into a single JSON string
    json_output = json.dumps(collection_data, indent=4, default=str)

    print(json_output)
    return jsonify(json.dumps(json_output))
@app.route('/')
def hello_world():
    return flask.render_template('index.html')
@app.route('/login',methods=['GET','POST'])
def login():
    if request.method == 'GET':
        return flask.render_template('login.html')
    elif request.method == 'POST':
        print(request.form)
        user_match = False
        for i in userdata:
            if i['username'] == request.form['username']:
                if i['password'] == request.form['password']:
                    user_match = True
                    break
        if user_match:
            return flask.render_template('login.html',username=i["username"])
        else:
            return flask.render_template('login.html',fail=True)
@app.errorhandler(404)
def page_not_found(e):
    return flask.render_template('404.html',error=e), 404
if __name__ == '__main__':
    app.run(debug=True,host='0.0.0.0',port=int(os.environ.get('PORT', 8080)))
