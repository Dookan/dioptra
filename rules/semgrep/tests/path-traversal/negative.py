from pathlib import Path

from flask import request, send_file

UPLOADS = Path("/srv/uploads")


def download():
    safe = UPLOADS / Path(request.args["file"]).name
    # ok: python-path-traversal
    with open(safe) as handle:
        data = handle.read()
    # ok: python-path-traversal
    return send_file("/srv/static/index.html")
