from markupsafe import Markup, escape


def render(request):
    # ok: python-markup-non-literal
    return escape(request.args.get("body"))


def constant():
    # ok: python-markup-non-literal
    return Markup("<b>fixed</b>")
