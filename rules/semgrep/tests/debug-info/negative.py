import os

from flask import Flask

app = Flask(__name__)

if __name__ == "__main__":
    # ok: python-flask-debug-true
    app.run(host="127.0.0.1", debug=False)
