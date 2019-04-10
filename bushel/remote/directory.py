
import random
import requests

authority_dir_ports = [
    "194.109.206.212:80",
    "199.58.81.140:80",
    "131.188.40.189:80",
    "154.35.175.225:80",
    "193.23.244.244:80",
    "171.25.193.9:443",
    "204.13.164.118:80",
    "86.59.21.38:80",
    "128.31.0.34:9131",
]

def consensus(server=None, flavor="ns", future=False):
    if server is None:
        server = random.choice(authority_dir_ports)
    timing = "next" if future else "current"
    if flavor == "ns":
        flavor = ""
    else:
        flavor = "-" + flavor
    r = requests.get(f"http://{server}/tor/status-vote/{timing}/consensus{flavor}")
    return r.content
