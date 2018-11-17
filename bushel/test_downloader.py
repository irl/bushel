
import asyncio
import urllib.error
import nose
from nose.tools import assert_equal

from stem import DirPort
from stem.descriptor.remote import get_consensus
from stem.descriptor.networkstatus import NetworkStatusDocumentV3
from stem.descriptor.server_descriptor import RelayDescriptor
from stem.descriptor.extrainfo_descriptor import RelayExtraInfoDescriptor

from bushel.downloader import SERVER_DESCRIPTOR
from bushel.downloader import EXTRA_INFO_DESCRIPTOR
from bushel.downloader import DirectoryDownloader
from bushel.downloader import url_for

LOCAL_DIRECTORY_CACHE = DirPort("127.0.0.1", 9030)

class TestDirectoryDownloader:

    def __init__(self):
        self.has_local_directory_cache = True
        try:
            query = get_consensus(endpoints=[LOCAL_DIRECTORY_CACHE], retries=0)
            query.run()
        except urllib.error.URLError:
            self.has_local_directory_cache = False
        self.downloader = DirectoryDownloader(endpoints=[LOCAL_DIRECTORY_CACHE])

    def test_fetch_consensus(self):
        if not self.has_local_directory_cache:
            raise nose.SkipTest(
                f"No local directory cache available at {LOCAL_DIRECTORY_CACHE}")
        async def go(self):
            consensus = await self.downloader.consensus()
            assert isinstance(consensus, NetworkStatusDocumentV3)
        asyncio.run(go(self))

def test_url_for():
    cases = {
        (SERVER_DESCRIPTOR, None, None): "/tor/server/all",
        (EXTRA_INFO_DESCRIPTOR, None, None): "/tor/extra/all",
        (SERVER_DESCRIPTOR, "<<<FP>>>", None): "/tor/server/fp/<<<FP>>>",
        (EXTRA_INFO_DESCRIPTOR, None, "<<<DIGEST>>>"): "/tor/extra/d/<<<DIGEST>>>",
        (SERVER_DESCRIPTOR, ('a', 'b', 'c'), None): "/tor/server/fp/a+b+c",
        (SERVER_DESCRIPTOR, ('b', 'a', 'c'), None): "/tor/server/fp/a+b+c",
        (SERVER_DESCRIPTOR, ('c', 'b', 'a'), None): "/tor/server/fp/a+b+c",
        (EXTRA_INFO_DESCRIPTOR, ('a', 'b', 'c'), None): "/tor/extra/fp/a+b+c",
        (EXTRA_INFO_DESCRIPTOR, ('b', 'a', 'c'), None): "/tor/extra/fp/a+b+c",
        (EXTRA_INFO_DESCRIPTOR, ('c', 'b', 'a'), None): "/tor/extra/fp/a+b+c",
    }
    for case in cases:
        print(case)
        assert_equal(url_for(*case), cases[case])
