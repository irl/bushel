import asyncio
import collections
import logging

import stem

from bushel import SERVER_DESCRIPTOR
from bushel import EXTRA_INFO_DESCRIPTOR
from bushel.archive import DirectoryArchive
from bushel.downloader import DirectoryDownloader

LOG = logging.getLogger('')


class DirectoryScraper:
    def __init__(self, archive_path):
        self.consensus = None
        self.archive = DirectoryArchive(archive_path)
        self.downloader = DirectoryDownloader()

    async def refresh_consensus(self):
        consensus = await self.downloader.consensus()
        if consensus is None:
            return
        self.consensus = consensus
        await self.archive.store(consensus)
        await self._recurse_consensus_references()

    async def _recurse_consensus_references(self):
        wanted_digests = collections.deque()
        download_tasks = []

        for authority in self.consensus.directory_authorities:
            # TODO: Download all votes
            pass

        # Download server descriptors
        server_descriptors = []
        for desc in self.consensus.routers.values():
            server_descriptor = await self.archive.descriptor(
                SERVER_DESCRIPTOR,
                digest=desc.digest)
            if server_descriptor is None:
                wanted_digests.append(desc.digest)
            else:
                server_descriptors.append(server_descriptor)
        while wanted_digests:
            next_batch = [
                wanted_digests.popleft() for _i in range(
                    min(
                        len(wanted_digests),
                        stem.descriptor.remote.MAX_FINGERPRINTS))
            ]
            download_tasks.append(
                self.downloader.descriptor(
                    SERVER_DESCRIPTOR, digest=next_batch))
        for result in await asyncio.gather(*download_tasks):
            for desc in result:
                await self.archive.store(desc)
                server_descriptors.append(desc)
        for desc in server_descriptors:
            if desc.extra_info_digest:
                extra_info_descriptor = await self.archive.descriptor(
                    EXTRA_INFO_DESCRIPTOR,
                    desc.extra_info_digest)
                if extra_info_descriptor is None:
                    wanted_digests.append(desc.extra_info_digest)
        download_tasks.clear()

        # Download extra info descriptors
        while wanted_digests:
            next_batch = [
                wanted_digests.popleft() for _i in range(
                    min(
                        len(wanted_digests),
                        stem.descriptor.remote.MAX_FINGERPRINTS))
            ]
            download_tasks.append(
                self.downloader.descriptor(
                    EXTRA_INFO_DESCRIPTOR, digest=next_batch))
        for result in await asyncio.gather(*download_tasks):
            for desc in result:
                await self.archive.store(desc)

        print("All done")


async def scrape():
    directory = DirectoryScraper(".")
    await directory.refresh_consensus()
