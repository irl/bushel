
import asyncio
import urllib.error
import nose
from nose.tools import assert_equal

from stem import DirPort
from stem.descriptor.remote import get_consensus
from stem.descriptor.networkstatus import NetworkStatusDocumentV3
from stem.descriptor.server_descriptor import RelayDescriptor
from stem.descriptor.extrainfo_descriptor import RelayExtraInfoDescriptor

from bushel import LOCAL_DIRECTORY_CACHE
from bushel import SERVER_DESCRIPTOR
from bushel import EXTRA_INFO_DESCRIPTOR
from bushel.downloader import DirectoryDownloader

class TestDirectoryDownloader:

    def __init__(self):
        self.has_local_directory_cache = True
        try:
            query = get_consensus(endpoints=[LOCAL_DIRECTORY_CACHE], retries=0)
            query.run()
        except urllib.error.URLError:
            self.has_local_directory_cache = False
        self.downloader = DirectoryDownloader()

    def test_fetch_consensus(self):
        if not self.has_local_directory_cache:
            raise nose.SkipTest(
                f"No local directory cache available at {LOCAL_DIRECTORY_CACHE}")
        async def go(self):
            consensus = await self.downloader.relay_consensus(flavor="ns")
            assert isinstance(consensus, NetworkStatusDocumentV3)
        asyncio.run(go(self))
