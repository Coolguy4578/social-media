import os

import flask
from flask import Flask
app = Flask(__name__)

@app.route('/')
def hello_world():
    return flask.render_template('index.html')
@app.errorhandler(404)
def page_not_found(e):
    return flask.render_template('404.html',error=e), 404
if __name__ == '__main__':
    app.run(debug=True,host='0.0.0.0',port=int(os.environ.get('PORT', 8080)))