from django.utils.safestring import mark_safe
from markupsafe import Markup


def render(request):
    # ruleid: python-markup-non-literal
    return Markup(request.args.get("body"))


def render2(comment):
    # ruleid: python-markup-non-literal
    return mark_safe(comment.text)
