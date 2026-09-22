def run(request):
    # ruleid: python-eval-exec-injection
    return eval(request.args.get("expr"))


def load(payload):
    # ruleid: python-eval-exec-injection
    exec(payload)
