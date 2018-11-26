import datetime
from nose import SkipTest
from nose.tools import assert_equal

from stem.descriptor import Descriptor

from bushel.archive import CollectorOutSubdirectory
from bushel.archive import CollectorOutBridgeDescsMarker
from bushel.archive import CollectorOutRelayDescsMarker
from bushel.archive import collector_422_filename
from bushel.archive import collector_431_filename
from bushel.archive import collector_433_filename
from bushel.archive import collector_434_filename
from bushel.archive import collector_521_substructure
from bushel.archive import collector_521_path
from bushel.archive import collector_522_substructure
from bushel.archive import collector_522_path
from bushel.archive import collector_533_substructure
from bushel.archive import collector_534_consensus_path
from bushel.archive import collector_534_microdescriptor_path
from bushel.archive import prepare_annotated_content


def test_collector_422_filename():
    expected = [
        (datetime.datetime(2018, 11, 19,
                           15), "BA44A889E64B93FAA2B114E02C2A279A8555C533",
         "20181119-150000-BA44A889E64B93FAA2B114E02C2A279A8555C533"),
        (datetime.datetime(2018, 1, 9,
                           5), "BA44A889E64B93FAA2B114E02C2A279A8555C533",
         "20180109-050000-BA44A889E64B93FAA2B114E02C2A279A8555C533"),
        (datetime.datetime(2018, 11, 19,
                           15), "ba44a889e64b93faa2b114e02c2a279a8555c533",
         "20181119-150000-BA44A889E64B93FAA2B114E02C2A279A8555C533"),
        (datetime.datetime(2018, 11, 19, 15, 0,
                           10), "BA44A889E64B93FAA2B114E02C2A279A8555C533",
         "20181119-150010-BA44A889E64B93FAA2B114E02C2A279A8555C533"),
    ]
    for case in expected:
        assert_equal(collector_422_filename(*case[0:2]), case[2])


def test_collector_431_filename():
    expected = [
        (datetime.datetime(2018, 11, 19, 15), "2018-11-19-15-00-00-consensus"),
        (datetime.datetime(2018, 1, 9, 15), "2018-01-09-15-00-00-consensus"),
        (datetime.datetime(2018, 11, 19, 5), "2018-11-19-05-00-00-consensus"),
        (datetime.datetime(2018, 11, 19, 15, 1, 2),
         "2018-11-19-15-01-02-consensus"),
    ]
    for case in expected:
        assert_equal(collector_431_filename(case[0]), case[1])


def test_collector_433_filename():
    expected = [
        (datetime.datetime(2018, 11, 19,
                           15), "D586D18309DED4CD6D57C18FDB97EFA96D330566",
         "663B503182575D242B9D8A67334365FF8ECB53BB",
         "2018-11-19-15-00-00-vote-D586D18309DED4CD6D57C18FDB97EFA96D330566-"
         "663B503182575D242B9D8A67334365FF8ECB53BB"),
        (datetime.datetime(2018, 11, 19,
                           15), "d586d18309ded4cd6d57c18fdb97efa96d330566",
         "663b503182575d242b9d8a67334365ff8ecb53bb",
         "2018-11-19-15-00-00-vote-D586D18309DED4CD6D57C18FDB97EFA96D330566-"
         "663B503182575D242B9D8A67334365FF8ECB53BB"),
        (datetime.datetime(2018, 1, 9,
                           5), "D586D18309DED4CD6D57C18FDB97EFA96D330566",
         "663B503182575D242B9D8A67334365FF8ECB53BB",
         "2018-01-09-05-00-00-vote-D586D18309DED4CD6D57C18FDB97EFA96D330566-"
         "663B503182575D242B9D8A67334365FF8ECB53BB"),
        (datetime.datetime(2018, 1, 9, 5, 1,
                           1), "D586D18309DED4CD6D57C18FDB97EFA96D330566",
         "663B503182575D242B9D8A67334365FF8ECB53BB",
         "2018-01-09-05-01-01-vote-D586D18309DED4CD6D57C18FDB97EFA96D330566-"
         "663B503182575D242B9D8A67334365FF8ECB53BB"),
    ]
    for case in expected:
        assert_equal(collector_433_filename(*case[0:3]), case[3])


def test_collector_434_filename():
    expected = [
        (datetime.datetime(2018, 11, 19, 15),
         "2018-11-19-15-00-00-consensus-microdesc"),
        (datetime.datetime(2018, 1, 9, 15),
         "2018-01-09-15-00-00-consensus-microdesc"),
        (datetime.datetime(2018, 11, 19, 5),
         "2018-11-19-05-00-00-consensus-microdesc"),
        (datetime.datetime(2018, 11, 19, 15, 1, 2),
         "2018-11-19-15-01-02-consensus-microdesc"),
    ]
    for case in expected:
        assert_equal(collector_434_filename(case[0]), case[1])


def test_collector_521_substructure():
    expected = [
        (datetime.datetime(2018, 11, 19, 9, 17, 56),
         "a94a07b201598d847105ae5fcd5bc3ab10124389", "2018/11/a/9"),
        (datetime.datetime(2018, 11, 19, 9, 17, 56),
         "A94A07B201598D847105AE5FCD5BC3AB10124389", "2018/11/a/9"),
        (datetime.datetime(2018, 1, 19, 9, 17, 56),
         "a94a07b201598d847105ae5fcd5bc3ab10124389", "2018/01/a/9"),
    ]
    for case in expected:
        assert_equal(collector_521_substructure(*case[0:2]), case[2])


def test_collector_521_path():
    expected = [
        (CollectorOutSubdirectory.BRIDGE_DESCRIPTORS,  # pylint: disable=no-member
         CollectorOutBridgeDescsMarker.SERVER_DESCRIPTOR,  # pylint: disable=no-member
         datetime.datetime(2018, 11, 19, 9, 17,
                           56), "a94a07b201598d847105ae5fcd5bc3ab10124389",
         ("bridge-descriptors/server-descriptor/2018/11/a/9/"
          "a94a07b201598d847105ae5fcd5bc3ab10124389")),
        (CollectorOutSubdirectory.BRIDGE_DESCRIPTORS,  # pylint: disable=no-member
         CollectorOutBridgeDescsMarker.EXTRA_INFO,  # pylint: disable=no-member
         datetime.datetime(2018, 11, 19, 9, 17,
                           56), "a94a07b201598d847105ae5fcd5bc3ab10124389",
         ("bridge-descriptors/extra-info/2018/11/a/9/"
          "a94a07b201598d847105ae5fcd5bc3ab10124389")),
        (CollectorOutSubdirectory.RELAY_DESCRIPTORS,  # pylint: disable=no-member
         CollectorOutRelayDescsMarker.SERVER_DESCRIPTOR,  # pylint: disable=no-member
         datetime.datetime(2018, 11, 19, 9, 17,
                           56), "a94a07b201598d847105ae5fcd5bc3ab10124389",
         ("relay-descriptors/server-descriptor/2018/11/a/9/"
          "a94a07b201598d847105ae5fcd5bc3ab10124389")),
        (CollectorOutSubdirectory.RELAY_DESCRIPTORS,  # pylint: disable=no-member
         CollectorOutRelayDescsMarker.EXTRA_INFO,  # pylint: disable=no-member
         datetime.datetime(2018, 11, 19, 9, 17,
                           56), "a94a07b201598d847105ae5fcd5bc3ab10124389",
         ("relay-descriptors/extra-info/2018/11/a/9/"
          "a94a07b201598d847105ae5fcd5bc3ab10124389")),
        (CollectorOutSubdirectory.RELAY_DESCRIPTORS,  # pylint: disable=no-member
         CollectorOutRelayDescsMarker.EXTRA_INFO,  # pylint: disable=no-member
         datetime.datetime(2018, 11, 19, 9, 17,
                           56), "A94A07B201598D847105AE5FCD5BC3AB10124389",
         ("relay-descriptors/extra-info/2018/11/a/9/"
          "a94a07b201598d847105ae5fcd5bc3ab10124389")),
        (CollectorOutSubdirectory.RELAY_DESCRIPTORS,  # pylint: disable=no-member
         CollectorOutRelayDescsMarker.EXTRA_INFO,  # pylint: disable=no-member
         datetime.datetime(2018, 1, 9, 19, 7,
                           6), "A94A07B201598D847105AE5FCD5BC3AB10124389",
         ("relay-descriptors/extra-info/2018/01/a/9/"
          "a94a07b201598d847105ae5fcd5bc3ab10124389")),
    ]
    for case in expected:
        assert_equal(collector_521_path(*case[0:4]), case[4])


def test_collector_522_substructure():
    expected = [
        (datetime.datetime(2018, 11, 19, 15), "2018/11/19"),
        (datetime.datetime(2018, 1, 9, 15), "2018/01/09"),
    ]
    for case in expected:
        assert_equal(collector_522_substructure(case[0]), case[1])


def test_collector_522_path():
    filename = "«TEST»"
    expected = [
        (CollectorOutSubdirectory.RELAY_DESCRIPTORS,  # pylint: disable=no-member
         CollectorOutRelayDescsMarker.CONSENSUS,  # pylint: disable=no-member
         datetime.datetime(2018, 11, 19, 15),
         "relay-descriptors/consensus/2018/11/19/«TEST»"),
        (CollectorOutSubdirectory.RELAY_DESCRIPTORS,  # pylint: disable=no-member
         CollectorOutRelayDescsMarker.CONSENSUS,  # pylint: disable=no-member
         datetime.datetime(2018, 1, 9, 15),
         "relay-descriptors/consensus/2018/01/09/«TEST»"),
        (CollectorOutSubdirectory.BRIDGE_DESCRIPTORS,  # pylint: disable=no-member
         CollectorOutBridgeDescsMarker.STATUSES,  # pylint: disable=no-member
         datetime.datetime(2018, 11, 19, 15),
         "bridge-descriptors/statuses/2018/11/19/«TEST»"),
        (CollectorOutSubdirectory.BRIDGE_DESCRIPTORS,  # pylint: disable=no-member
         CollectorOutBridgeDescsMarker.STATUSES,  # pylint: disable=no-member
         datetime.datetime(2018, 1, 9, 15),
         "bridge-descriptors/statuses/2018/01/09/«TEST»"),
    ]
    for case in expected:
        assert_equal(collector_522_path(*case[0:3], filename), case[3])


def test_collector_533_substructure():
    expected = [
        (datetime.datetime(2018, 11, 19, 15), "2018/11"),
        (datetime.datetime(2018, 1, 9, 15), "2018/01"),
    ]
    for case in expected:
        assert_equal(collector_533_substructure(case[0]), case[1])


def test_collector_534_consensus_path():
    expected = [
        (datetime.datetime(2018, 11, 19, 15),
         "relay-descriptors/microdesc/2018/11/consensus-microdesc/19/2018-11-19-15-00-00-consensus-microdesc"
         ),
        (datetime.datetime(2018, 1, 9, 5),
         "relay-descriptors/microdesc/2018/01/consensus-microdesc/09/2018-01-09-05-00-00-consensus-microdesc"
         ),
        (datetime.datetime(2018, 1, 9, 5, 1, 2),
         "relay-descriptors/microdesc/2018/01/consensus-microdesc/09/2018-01-09-05-01-02-consensus-microdesc"
         ),
    ]
    for case in expected:
        assert_equal(collector_534_consensus_path(case[0]), case[1])


def test_collector_534_microdescriptor_path():
    expected = [
        (datetime.datetime(2018, 11, 19, 15),
         "00d91cf96321fbd536dd07e297a5e1b7e6961ddd10facdd719716e351453168f",
         "relay-descriptors/microdesc/2018/11/micro/0/0/00d91cf96321fbd536dd07e297a5e1b7e6961ddd10facdd719716e351453168f"
         ),
        (datetime.datetime(2018, 1, 19, 15),
         "00d91cf96321fbd536dd07e297a5e1b7e6961ddd10facdd719716e351453168f",
         "relay-descriptors/microdesc/2018/01/micro/0/0/00d91cf96321fbd536dd07e297a5e1b7e6961ddd10facdd719716e351453168f"
         ),
        (datetime.datetime(2018, 11, 19, 15),
         "0ad91cf96321fbd536dd07e297a5e1b7e6961ddd10facdd719716e351453168f",
         "relay-descriptors/microdesc/2018/11/micro/0/a/0ad91cf96321fbd536dd07e297a5e1b7e6961ddd10facdd719716e351453168f"
         ),
        (datetime.datetime(2018, 11, 19, 15),
         "0AD91CF96321FBD536DD07E297A5E1B7E6961DDD10FACDD719716E351453168F",
         "relay-descriptors/microdesc/2018/11/micro/0/a/0ad91cf96321fbd536dd07e297a5e1b7e6961ddd10facdd719716e351453168f"
         ),
    ]
    for case in expected:
        assert_equal(collector_534_microdescriptor_path(*case[0:2]), case[2])


def test_prepare_annotated_bridge_descriptor():
    descriptor_str = ("""@type bridge-extra-info 1.3
extra-info irlBridgeNL 36023F6479610E64A1F3015B5DC85A181E6995AB
published 2018-11-23 17:01:15
write-history 2018-11-23 16:49:41 (14400 s) 484352,489472,393216,415744,424960,457728
read-history 2018-11-23 16:49:41 (14400 s) 6677504,6167552,4639744,5383168,4702208,5900288
dirreq-write-history 2018-11-23 12:16:42 (14400 s) 1024,0,1024,1024,5120,5120
dirreq-read-history 2018-11-23 12:16:42 (14400 s) 0,0,0,0,0,0
geoip-db-digest C1EB5237F2FBAF63381D8551157F13D12EFCCA25
geoip6-db-digest 1F99B6B0EC78E9DB34D61AE7E0FC261D558E8E5D
dirreq-stats-end 2018-11-22 21:47:38 (86400 s)
dirreq-v3-ips 
dirreq-v3-reqs 
dirreq-v3-resp ok=0,not-enough-sigs=0,unavailable=0,not-found=0,not-modified=0,busy=0
dirreq-v3-direct-dl complete=0,timeout=0,running=0
dirreq-v3-tunneled-dl complete=0,timeout=0,running=0
transport obfs4
bridge-stats-end 2018-11-22 21:47:41 (86400 s)
bridge-ips ??=8,de=8
bridge-ip-versions v4=8,v6=0
bridge-ip-transports obfs4=8
router-digest 1A7A10D8874734DF53E82830C8A4BF83DFE18917""")
    descriptor = Descriptor.from_str(descriptor_str)
    try:
        # TODO: This test fails because stem does not keep track of the major/minor
        # version of the type annotation.
        assert_equal(prepare_annotated_content(descriptor), descriptor_str)
    except AssertionError as exc:
        raise SkipTest() from exc


def test_prepare_annotated_server_descriptor():
    descriptor_str = ("""@type server-descriptor 1.0
router TorExitMoldova2 178.17.170.156 9001 0 9030
identity-ed25519
-----BEGIN ED25519 CERT-----
AQQABorpAVdPW4Y6QhEH29Fax8IgWaiZZCL1pjh23koZ9fCRbXt8AQAgBABdZmu6
BA4Gs5Esxa+knaDzM1OxLXy/5YLC4jNkagZiQofrMkh2qZqnXF3Sgp6qjV8C60tX
QhXGqZvmOJlOnkHGshzNrYAYFyQqfxaHh0u+gNLFg8AV+8XebYng2Y57ywM=
-----END ED25519 CERT-----
master-key-ed25519 XWZrugQOBrORLMWvpJ2g8zNTsS18v+WCwuIzZGoGYkI
or-address [2a00:1dc0:caff:48::9257]:9001
platform Tor 0.3.3.7 on Linux
proto Cons=1-2 Desc=1-2 DirCache=1-2 HSDir=1-2 HSIntro=3-4 HSRend=1-2 Link=1-5 LinkAuth=1,3 Microdesc=1-2 Relay=1-2
published 2018-11-23 15:01:02
fingerprint 41C5 9606 AFE1 D1AA 6EC6 EF67 1969 0B85 6F0B 6587
uptime 1699294
bandwidth 8388608 10485760 5978532
extra-info-digest D9C0B66DDDBEAFC70FFB881C0FA68CE674797A48 A5vUrsTRpKdJatlNmILtfkbS7gwK2oGn3KSblpQdz5k
onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBANBjc9nRTXPNtTtsmEyRgCPZrwvuuQOek++ABW0GGEW1te5HJKZZ5ShZ
Yf4kRDo2CxA4zEu6rDKzhuDLiIA8HDuUDRokjxkHT4fcaiAEENWXdjRovaxX8Ygu
Lj4J3XMsWChT1H0WYAzWBjkttDxJd6Fn7uV5sVCADaSm6ptqhlERAgMBAAE=
-----END RSA PUBLIC KEY-----
signing-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBANUllnwcu4t7nJMKVMZonXMK6V+cHJjhyk+Tzscl1zQ3QqwtJPYbthbJ
V84NZ7j6QfgCmu0YinvrpX3IhMighsiARoQ6Tl+XoCmeHsx65nO/dIO/dbRsl//h
/EkWHJpSFzOKBbR4WIBpIqF2OuAIclOCCWCN57NshOO3k0zZwFNLAgMBAAE=
-----END RSA PUBLIC KEY-----
onion-key-crosscert
-----BEGIN CROSSCERT-----
xnV1yvE9bdUrJ7PLaRapCRlYHjHmqxaU5DkFqpIlcGGongxYfwrshnighGgQJZtG
JgHpSzHD1fzUOowcmFwRNeRzK9ClXCtYcEw0wKTIV726ie2xGZ6u94metrLbAG1R
XbdAcSWlaaTYSW/jJh7tVO9OzJYy9vkf9ryW6JwZeP8=
-----END CROSSCERT-----
ntor-onion-key-crosscert 0
-----BEGIN ED25519 CERT-----
AQoABozgAV1ma7oEDgazkSzFr6SdoPMzU7EtfL/lgsLiM2RqBmJCAPIxUQ40uhlF
HnzsLfw48JarYC6p75r1Ftk3nSF7/yYIKztMPnxKr5r0Ur2wwHvIsFhRPrvFINuZ
aHfYCth8Ygc=
-----END ED25519 CERT-----
family $4061C553CA88021B8302F0814365070AAE617270 $516D1B9E22484202322828D8CAC30325030017E2 $9B31F1F1C1554F9FFB3455911F82E818EF7C7883 $B06F093A3D4DFAD3E923F4F28A74901BD4F74EB1
hidden-service-dir
contact potlatch protonmail com
ntor-onion-key PgEez8UYTNLvZVUlO8J9RuP98hc0Xq2wxGgWJgiOnAE=
reject 0.0.0.0/8:*
reject 169.254.0.0/16:*
reject 127.0.0.0/8:*
reject 192.168.0.0/16:*
reject 10.0.0.0/8:*
reject 172.16.0.0/12:*
reject 178.17.170.156:*
reject *:25
reject *:135-139
reject *:445
reject *:563
reject *:1214
reject *:4661-4666
reject *:6346-6429
reject *:6699
reject *:6881-6999
accept *:*
ipv6-policy reject 25,135-139,445,563,1214,4661-4666,6346-6429,6699,6881-6999
tunnelled-dir-server
router-sig-ed25519 bTYsctkC7ge62I7uRpDfIULA8C5CWycYqEfNIYAVa7mazFHCM/ICzOsGsIgq15ME7zYN1IeXNS3HxSk+CL1UBg
router-signature
-----BEGIN SIGNATURE-----
cY2CnFjBjE4bnW6Ox8C45Kcf9yUwiv+FXZwsu+inaKXpi3qLNKXq2ynWfm/7vSE/
e/27Pq7JYzyis7vH28SdDcxQAWJyxve7coCrGEjZ1R9Vn/ob3ssVSnFjiosjQMZc
AfMLKycSiGaVvjyKTzxjeKWf8wBGm2xvsYiPHAmdMbU=
-----END SIGNATURE-----""")
    descriptor = Descriptor.from_str(descriptor_str)
    assert_equal(
        prepare_annotated_content(descriptor), descriptor_str.encode('utf-8'))
