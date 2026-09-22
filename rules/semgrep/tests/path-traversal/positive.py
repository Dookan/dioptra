import os

from flask import request, send_file

UPLOADS = "/srv/uploads"


def download():
    # ruleid: python-path-traversal
    with open(os.path.join(UPLOADS, request.args["file"])) as handle:
        data = handle.read()
    # ruleid: python-path-traversal
    return send_file(f"{UPLOADS}/{request.args['name']}")
