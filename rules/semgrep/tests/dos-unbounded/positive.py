import re


def search(request):
    # ruleid: python-regex-from-input
    pattern = re.compile(request.args["q"])
    # ruleid: python-regex-from-input
    return re.search(request.GET["q"], "haystack")
