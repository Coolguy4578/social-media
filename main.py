import os
import secrets
import uuid

import dotenv
import google.cloud.firestore as firestore
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
from flask import Flask, abort, flash, redirect, render_template, request, session
from google.cloud import storage

dotenv.load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
if not app.secret_key:
    raise RuntimeError("SECRET_KEY environment variable is not set")

db = firestore.Client(database="talko-database")
users = db.collection('users')
# All user records currently live as fields of this one document, keyed by user id
USERS_DOC_ID = "c8R6YmSTWw7kOoqWzPC8"
_ph = PasswordHasher()

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
    for doc in users.stream():
        doc_dict = doc.to_dict()
        if not isinstance(doc_dict, dict):
            continue
        # Records are nested inside the document, keyed by user id
        for user_id, record in doc_dict.items():
            if isinstance(record, dict) and record.get('username') == username:
                return user_id, record
    return None, None


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


@firestore.transactional
def _add_user(transaction, doc_ref, user_id, record):
    """Add a user record unless the username is taken. Returns True on success."""
    data = doc_ref.get(transaction=transaction).to_dict() or {}
    for existing in data.values():
        if isinstance(existing, dict) and existing.get('username') == record['username']:
            return False
    # merge=True writes only this user's field, so concurrent signups don't overwrite each other
    transaction.set(doc_ref, {user_id: record}, merge=True)
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
    if not _add_user(db.transaction(), users.document(USERS_DOC_ID), new_user_id, record):
        # Someone else claimed the username while the image was uploading
        blob.delete()
        flash('That username is already taken')
        return redirect(request.url)

    log_in(new_user_id, record)
    return redirect("/")


@app.route('/')
def hello_world():
    return render_template('index.html')


@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect('/')


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html', error=e), 404


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))
