import os
from argon2 import PasswordHasher
import google.cloud.firestore as firestore
from google.cloud import storage
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
import uuid
db=firestore.Client(database="talko-database")
users=db.collection('users')
import flask
import dotenv
from flask import *
app = Flask(__name__)
dotenv.load_dotenv()
app.secret_key=os.getenv('SECRET_KEY')
_ph = PasswordHasher()
doc = users.document("c8R6YmSTWw7kOoqWzPC8")
userdata = [{"username":"admin","password":"hello"},{"username":"test","password":"testing1234"}]
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return flask.render_template('login.html')

    # POST
    username_form = request.form.get('username', '').strip()
    password_form = request.form.get('password', '')

    # Fetch users from Firestore
    docs = users.stream()
    found_user = None

    # Your Firestore documents are shaped like:
    # { "docId": { "0": { "username": "max", "password": "<argon2-hash>", "image": "..." } } }
    for doc in docs:
        doc_dict = doc.to_dict()
        if not isinstance(doc_dict, dict):
            continue
        # Iterate nested records inside the document (e.g. keys like "0", "1", etc.)

        for record in doc_dict.values():
            if not isinstance(record, dict):
                continue
            if record.get('username') == username_form:
                found_user = record

                print(record)
                break
        if found_user:
            break
        key = [k for k, v in doc_dict.items() if v == found_user][0]
    # If user not found -> authentication fail
    if not found_user:
        # You can render a generic failure message to avoid user enumeration
        return flask.render_template('login.html', fail=True)

    # Verify password hash (stored expected to be an Argon2 hash)
    hashed_password = found_user.get('password', '')
    try:
        if _ph.verify(hashed_password, password_form):
            # optional: rehash if needed
            try:
                if hasattr(_ph, 'check_needs_rehash') and _ph.check_needs_rehash(hashed_password):
                    # If you want to update the stored hash, update Firestore here.
                    # Example (requires knowing doc id and path): users.document(doc.id).update(...)
                    pass
            except Exception:
                pass
            session['logged_in'] = True
            session['username'] = found_user.get('username')
            session['image'] = found_user.get('image')
            session['id'] = key
            response = flask.make_response(flask.render_template('login.html', success=True))
            return response
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        # verification failed; fall through to show generic failure
        pass

    return flask.render_template('login.html', fail=True)
image_extensions = [
    "jpg", "jpeg", "png", "gif", "webp",
    "tiff", "tif", "bmp", "svg", "heic",
    "heif", "ico", "avif"
]

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in image_extensions
@app.route("/signup", methods=['GET', 'POST'])
def signup():
    if request.method == 'GET':
        return flask.render_template('signup.html')

    if 'image' not in request.files:
        flash('No file part')
        return redirect(request.url)
    file = request.files['image']
    # If the user does not select a file, the browser submits an
    # empty file without a filename.
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)
    if file and allowed_file(file.filename):
        filename = flask.secure_filename(file.filename)
        storage_client = storage.Client()
        bucket = storage_client.get_bucket('social-media-flask')
        blob = bucket.blob(file.filename)

        # 5. Upload directly from the Flask FileStorage stream object
        # This keeps the image in memory instead of writing it to local disk
        blob.upload_from_file(
            file,
            content_type=file.content_type
        )
        blob.make_public()
        image_url = blob.public_url
        doc_ref = db.collection('users').document("c8R6YmSTWw7kOoqWzPC8")
        data = doc_ref.get().to_dict()
        newUserId = str(uuid.uuid4())
        data[newUserId] = {"username": request.form['username'],"password":_ph.hash(request.form['password']),"image":image_url}
        doc_ref.set(data)
        session['logged_in'] = True
        session['username'] = request.form['username']
        session['image'] = image_url
        session['id'] = newUserId
        return redirect("/")

# @app.route("/data")
# def data():
#     docs = users.stream()
#
#     # 2. Build a dictionary mapping each ID to its JSON document data
#     collection_data = [{doc.id: doc.to_dict() for doc in docs},{"version":"new"}]
#     global json_output
#     # 3. Convert the dictionary into a single JSON string
#     json_output = json.dumps(collection_data, indent=4, default=str)
#
#     print(json_output)
#     return jsonify(json_output)
@app.route('/')
def hello_world():
    return flask.render_template('index.html')
@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    session.pop('image', None)
    session.pop('id', None)
    return flask.redirect('/')
@app.errorhandler(404)
def page_not_found(e):
    return flask.render_template('404.html',error=e), 404
if __name__ == '__main__':
    app.run(debug=True,host='0.0.0.0',port=int(os.environ.get('PORT', 8080)))
