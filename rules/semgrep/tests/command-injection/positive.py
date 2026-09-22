import os
import subprocess


def run(request):
    name = request.args["name"]
    # ruleid: python-subprocess-shell-injection
    subprocess.run("ping " + name, shell=True)
    # ruleid: python-subprocess-shell-injection
    os.system(f"rm -rf {name}")
