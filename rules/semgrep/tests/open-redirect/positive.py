from flask import redirect, request


def go():
    # ruleid: python-open-redirect
    return redirect(request.args.get("next"))


def go2(request):
    # ruleid: python-open-redirect
    return HttpResponseRedirect(request.GET["next"])
