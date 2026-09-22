import ast


def run(payload):
    # ok: python-eval-exec-injection
    return ast.literal_eval(payload)


def constant():
    # ok: python-eval-exec-injection
    return eval("1 + 1")
