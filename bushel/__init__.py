
from stem import DirPort
from stem import ORPort

DIRECTORY_AUTHORITIES = [
    DirPort("128.31.0.39", 9131),  # moria1
    ORPort("86.59.21.38", 443),  # tor26
    DirPort("194.109.206.212", 80),  # dizum
    DirPort("131.188.40.189", 80),  # gabelmoo
    DirPort("193.23.244.244", 80),  # dannenberg
    DirPort("171.25.193.9", 443),  # maatuska
    DirPort("154.35.175.225", 80),  # Faravahar
    DirPort("199.58.81.140", 80),  # longclaw
    DirPort("204.13.164.11", 80),  # bastet
]

SERVER_DESCRIPTOR = 10
EXTRA_INFO_DESCRIPTOR = 20

