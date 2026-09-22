import subprocess


def run(request):
    name = request.args["name"]
    # ok: python-subprocess-shell-injection
    subprocess.run(["ping", "-c", "1", name], check=False)
    # ok: python-subprocess-shell-injection
    subprocess.run("ls -la", shell=True)
