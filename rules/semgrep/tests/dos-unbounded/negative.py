import re


def search(request):
    # ok: python-regex-from-input
    pattern = re.compile(re.escape(request.args["q"]))
    # ok: python-regex-from-input
    return re.search(r"^[a-z]+$", request.args["q"])
