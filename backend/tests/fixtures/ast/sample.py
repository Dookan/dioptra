"""Fixture: hand-counted control flow (see tests/test_ast_python.py)."""


class Account:
    def check(self, age, name=None):
        if age >= 18 and name:
            return "ok"
        elif age < 0:
            raise ValueError("neg")
        else:
            total = 0
            for i in range(age):
                total += i
        try:
            value = int(name)
        except ValueError:
            value = 0
        finally:
            print(value)
        while total > 0:
            total -= 1
        return value if value else total


def plain(x):
    y = x + 1
    z = y * 2
    return z


def nested(items):
    def inner(v):
        if v:
            return 1
        return 0

    return [inner(i) for i in items if i]


def matcher(cmd):
    match cmd:
        case "go":
            return 1
        case "stop":
            return 2
        case _:
            return 0
