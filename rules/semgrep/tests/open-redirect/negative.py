from flask import redirect, url_for


def go():
    # ok: python-open-redirect
    return redirect(url_for("home"))


def go2():
    # ok: python-open-redirect
    return redirect("/dashboard")
