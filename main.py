import hashlib
import json
import os
import secrets
import uuid
import datetime
import dotenv
import google.cloud.firestore as firestore
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
from flask import Flask, abort, flash, make_response, redirect, render_template, request, session
from google.api_core.exceptions import AlreadyExists
from google.cloud import storage
import flask
dotenv.load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
if not app.secret_key:
    raise RuntimeError("SECRET_KEY environment variable is not set")

db = firestore.Client(database="talko-database")
# users/{user_id} = {username, password, image}
users = db.collection('users')
# usernames/{username_key(username)} = {user_id}; creating this document claims the username
usernames = db.collection('usernames')
_ph = PasswordHasher()


def username_key(username):
    # Usernames can contain characters that aren't valid in document IDs (like "/"), so hash them
    return hashlib.sha256(username.encode()).hexdigest()

# Content type is derived from the extension, never from the client. SVG is excluded
# because it can carry scripts.
image_content_types = {
    "jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png",
    "gif": "image/gif", "webp": "image/webp", "tiff": "image/tiff",
    "tif": "image/tiff", "bmp": "image/bmp", "heic": "image/heic",
    "heif": "image/heif", "ico": "image/x-icon", "avif": "image/avif",
}


def file_extension(filename):
    return filename.rsplit('.', 1)[1].lower() if '.' in filename else ''


def allowed_file(filename):
    return file_extension(filename) in image_content_types


@app.context_processor
def utility_processor():
    def add_flash_message(message, category="info"):
        flash(message)
        return ""  # Return an empty string so nothing prints out in the HTML

    return dict(trigger_flash=add_flash_message)
def csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']


app.jinja_env.globals['csrf_token'] = csrf_token


@app.before_request
def csrf_protect():
    if request.method == 'POST':
        expected = session.get('csrf_token')
        submitted = request.form.get('csrf_token', '')
        if not expected or not secrets.compare_digest(expected, submitted):
            abort(400)


def find_user(username):
    """Return (user_id, record) for the given username, or (None, None)."""
    reservation = usernames.document(username_key(username)).get()
    if not reservation.exists:
        return None, None
    user_id = reservation.get('user_id')
    user_doc = users.document(user_id).get()
    if not user_doc.exists:
        return None, None
    return user_id, user_doc.to_dict()


def log_in(user_id, record):
    session.clear()
    session['logged_in'] = True
    session['username'] = record.get('username')
    session['image'] = record.get('image')
    session['id'] = user_id


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    username_form = request.form.get('username', '').strip()
    password_form = request.form.get('password', '')

    user_id, found_user = find_user(username_form)
    if not found_user:
        # Same failure message as a wrong password, to avoid user enumeration
        return render_template('login.html', fail=True)

    try:
        _ph.verify(found_user.get('password', ''), password_form)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return render_template('login.html', fail=True)

    log_in(user_id, found_user)
    return render_template('login.html', success=True)


def _add_user(user_id, record):
    """Add a user record unless the username is taken. Returns True on success."""
    batch = db.batch()
    # create() fails if the document exists, and the batch is atomic, so a taken
    # username means neither document is written
    batch.create(usernames.document(username_key(record['username'])), {"user_id": user_id})
    batch.create(users.document(user_id), record)
    try:
        batch.commit()
    except AlreadyExists:
        return False
    return True


@app.route("/signup", methods=['GET', 'POST'])
def signup():
    if request.method == 'GET':
        return render_template('signup.html')

    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    if not username or not password:
        flash('Username and password are required')
        return redirect(request.url)
    if find_user(username)[1]:
        flash('That username is already taken')
        return redirect(request.url)

    file = request.files.get('image')
    # If the user does not select a file, the browser submits an
    # empty file without a filename.
    if not file or file.filename == '':
        flash('No selected file')
        return redirect(request.url)
    if not allowed_file(file.filename):
        flash('Please upload an image file (' + ', '.join(image_content_types) + ')')
        return redirect(request.url)

    ext = file_extension(file.filename)
    storage_client = storage.Client()
    bucket = storage_client.bucket('social-media-flask')  # no metadata request, so no buckets.get needed
    blob = bucket.blob(f"avatars/{uuid.uuid4()}.{ext}")
    blob.upload_from_file(file, content_type=image_content_types[ext])

    new_user_id = str(uuid.uuid4())
    record = {"username": username, "password": _ph.hash(password), "image": blob.public_url}
    if not _add_user(new_user_id, record):
        # Someone else claimed the username while the image was uploading
        blob.delete()
        flash('That username is already taken')
        return redirect(request.url)

    log_in(new_user_id, record)
    return redirect("/dashboard")


@app.route('/')
def hello_world():
    return render_template('index.html')


@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        flash('You must be logged in to access the dashboard.')
        return redirect('/login')
    return render_template('dashboard.html')


@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect('/')


def redact_passwords(value):
    """Return a copy of Firestore data with every 'password' field hidden."""
    if isinstance(value, dict):
        return {k: '[redacted]' if k == 'password' else redact_passwords(v) for k, v in value.items()}
    return value
@firestore.transactional
def increment_like_counter(transaction,doc_ref,like_or_unlike):
    snapshot = doc_ref.get(transaction=transaction)
    current_likes = snapshot.to_dict().get('likes')
    if like_or_unlike:
        new_likes = current_likes + 1
    else:
        new_likes = current_likes - 1

    # 2. Write the incremented value back
    transaction.update(doc_ref, {"likes": new_likes})
    return new_likes

@app.post('/like')
def like():
    post = request.form['post-id']
    if not post:
        return {"error":"post id is required"}
    transaction = db.transaction()
    return flask.jsonify({"likes": increment_like_counter(transaction, post,True)})
@app.post('/unlike')
def unlike():
    post = request.form['post-id']
    if not post:
        return {"error":"post id is required"}
    transaction = db.transaction()
    return flask.jsonify({"likes": increment_like_counter(transaction, post,False)})
@app.post('/api/create-post')
def create_post():
    try:
        posts = db.collection('posts')
        file = request.files.get('image')
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if not file or file.filename == '':
            print("empty image")
            image = None
        else:
            if not allowed_file(file.filename):
                return {"error":"invalid image format"}
            ext = file_extension(file.filename)
            storage_client = storage.Client()
            bucket = storage_client.bucket('social-media-flask')  # no metadata request, so no buckets.get needed
            blob = bucket.blob(f"posts/{uuid.uuid4()}.{ext}")
            blob.upload_from_file(file, content_type=image_content_types[ext])
            image = blob.public_url
            print(image)
        posts.add({"title": request.form.get('title', ''), 'textContent': request.form.get('textContent', ''),'timestamp': firestore.SERVER_TIMESTAMP,"user": session['id'],"image":image,"likes":0})
        return redirect("/dashboard")
    except KeyError as e:
        return flask.jsonify({"error":str(e)}), 400
    except Exception as e:
        return flask.jsonify({"error":str(e)}), 500


@app.route('/api/posts')
def api_posts():
    query_desc = db.collection('posts').order_by("timestamp", direction=firestore.Query.DESCENDING).stream()
    post_data = []
    for post in query_desc:
        post_data.append({**post.to_dict(), "id": post.id})
    return flask.jsonify(post_data)



@app.route('/api/users/<user_id>')
def api_user(user_id):
    user_doc = users.document(user_id).get()
    if not user_doc.exists:
        return flask.jsonify({"error": "user not found"}), 404
    # Only public fields; never send the password hash
    return flask.jsonify({"username": user_doc.get('username'), "image": user_doc.get('image')})


@app.route('/admin/data', methods=['GET', 'POST'])
def admin_data():
    # Kept out of the repo: set it from Secret Manager like SECRET_KEY
    admin_hash = os.getenv('ADMIN_PASSWORD_HASH')
    if not admin_hash:
        abort(404)
    if request.method == 'GET':
        return render_template('admin_data.html')

    try:
        _ph.verify(admin_hash, request.form.get('password', ''))
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return render_template('admin_data.html', fail=True), 403

    data = {
        collection.id: {doc.id: redact_passwords(doc.to_dict()) for doc in collection.stream()}
        for collection in db.collections()
    }
    response = make_response(render_template(
        'admin_data.html', data=json.dumps(data, indent=2, default=str, ensure_ascii=False)))
    response.headers['Cache-Control'] = 'no-store'
    return response


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html', error=e), 404


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))
