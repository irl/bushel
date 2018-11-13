import pickle
import asyncio
import collections
import logging
import socket
import sys
import urllib.error

import stem
from stem.descriptor.remote import DescriptorDownloader

from bushel.downloader import DirectoryDownloader
from bushel.store import FilesystemStore

LOG = logging.getLogger('')

SERVER_DESCRIPTOR = 10
EXTRA_INFO_DESCRIPTOR = 20


class DirectoryScraper:
    def __init__(self, archive_path):
        self.archive = FilesystemStore(archive_path)
        self.downloader = DirectoryDownloader()

    async def refresh_consensus(self):
        consensus = await self.downloader.consensus()
        if consensus is None:
            return
        self.consensus = consensus
        self.archive.store(consensus)
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
            server_descriptor = self.archive.server_descriptor(desc.digest)
            if server_descriptor is None:
                wanted_digests.append(desc.digest)
            else:
                server_descriptors.append(server_descriptor)
        while len(wanted_digests) > 0:
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
                self.archive.store(desc)
                server_descriptors.append(desc)
        for desc in server_descriptors:
            if desc.extra_info_digest and desc.extra_info_digest:
                extra_info_descriptor = self.archive.extra_info_descriptor(
                    desc.extra_info_digest)
                if extra_info_descriptor is None:
                    wanted_digests.append(desc.extra_info_digest)
        download_tasks.clear()

        # Download extra info descriptors
        while len(wanted_digests) > 0:
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
                self.archive.store(desc)

        print("All done")


async def scrape():
    directory = DirectoryScraper(".")
    await directory.refresh_consensus()
