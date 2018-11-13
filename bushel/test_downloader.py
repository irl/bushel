
import asyncio
import urllib.error
import nose

from stem import DirPort
from stem.descriptor.remote import get_consensus
from stem.descriptor.networkstatus import NetworkStatusDocumentV3
from stem.descriptor.server_descriptor import RelayDescriptor
from stem.descriptor.extrainfo_descriptor import RelayExtraInfoDescriptor

from bushel.downloader import SERVER_DESCRIPTOR
from bushel.downloader import EXTRA_INFO_DESCRIPTOR
from bushel.downloader import DirectoryDownloader

LOCAL_DIRECTORY_CACHE = DirPort("127.0.0.1", 9030)

class TestDirectoryDownloader:

    def __init__(self):
        self.has_local_directory_cache = True
        try:
            query = get_consensus(endpoints=[LOCAL_DIRECTORY_CACHE], retries=0)
            query.run()
        except urllib.error.URLError as e:
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

    def test_fetch_all_relay_descriptors(self):
        if not self.has_local_directory_cache:
            raise nose.SkipTest(
                f"No local directory cache available at {LOCAL_DIRECTORY_CACHE}")
        async def go(self):
            descriptors = await self.downloader.descriptor(
                SERVER_DESCRIPTOR,
                endpoint=LOCAL_DIRECTORY_CACHE)
            for descriptor in descriptors:
                assert isinstance(descriptor, RelayDescriptor)
        asyncio.run(go(self))

    def test_fetch_all_extra_info_descriptors(self):
        if not self.has_local_directory_cache:
            raise nose.SkipTest(
                f"No local directory cache available at {LOCAL_DIRECTORY_CACHE}")
        async def go(self):
            descriptors = await self.downloader.descriptor(
                EXTRA_INFO_DESCRIPTOR,
                endpoint=LOCAL_DIRECTORY_CACHE)
            for descriptor in descriptors:
                assert isinstance(descriptor, RelayExtraInfoDescriptor)
        asyncio.run(go(self))
