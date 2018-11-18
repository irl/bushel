
from collections import namedtuple

import stem.util
from stem import DirPort
from stem import ORPort

DirectoryAuthority = namedtuple('DirectoryAuthority', ['nickname',
                                                       'v3ident',
                                                       'or_port',
                                                       'dir_port'])

DIRECTORY_AUTHORITIES = [
    DirectoryAuthority("moria1", "D586D18309DED4CD6D57C18FDB97EFA96D330566",
                       ORPort("128.31.0.39", 9101),
                       DirPort("128.31.0.39", 9131)),
    DirectoryAuthority("tor26", "14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4",
                       ORPort("86.59.21.38", 443),
                       DirPort("86.59.21.38", 80)),
    DirectoryAuthority("dizum", "E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58",
                       ORPort("194.109.206.212", 443),
                       DirPort("194.109.206.212", 80)),
    DirectoryAuthority("gabelmoo", "ED03BB616EB2F60BEC80151114BB25CEF515B226",
                       ORPort("131.188.40.189", 443),
                       DirPort("131.188.40.189", 80)),
    DirectoryAuthority("dannenberg", "0232AF901C31A04EE9848595AF9BB7620D4C5B2E",
                       ORPort("193.23.244.244", 443),
                       DirPort("193.23.244.244", 80)),
    DirectoryAuthority("maatuska", "49015F787433103580E3B66A1707A00E60F2D15B",
                       ORPort("171.25.193.9", 80),
                       DirPort("171.25.193.9", 443)),
    DirectoryAuthority("Faravahar", "EFCBE720AB3A82B99F9E953CD5BF50F7EEFC7B97",
                       ORPort("154.35.175.225", 443),
                       DirPort("154.35.175.225", 80)),
    DirectoryAuthority("longclaw", "23D15D965BC35114467363C165C4F724B64B4F66",
                       ORPort("199.58.81.140", 443),
                       DirPort("199.58.81.140", 80)),
    DirectoryAuthority("bastet", "27102BC123E7AF1D4741AE047E160C91ADC76B21",
                       ORPort("204.13.164.11", 80),
                       DirPort("204.13.164.11", 80)),
]

LOCAL_DIRECTORY_CACHE = DirPort("127.0.0.1", 9030)

SERVER_DESCRIPTOR = 10
EXTRA_INFO_DESCRIPTOR = 20

DirectoryCacheMode = stem.util.enum.UppercaseEnum(
    'CLIENT',
    'DIRECTORY_CACHE',
    'TESTING',
)
