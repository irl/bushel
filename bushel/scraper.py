import asyncio
import collections
import datetime
import logging

import stem

from bushel import SERVER_DESCRIPTOR
from bushel import EXTRA_INFO_DESCRIPTOR
from bushel import DIRECTORY_AUTHORITIES
from bushel.archive import DirectoryArchive
from bushel.downloader import DirectoryDownloader

LOG = logging.getLogger('')


class DirectoryScraper:
    def __init__(self, archive_path):
        self.consensus = None
        self.archive = DirectoryArchive(archive_path)
        self.downloader = DirectoryDownloader()

    async def fetch_consensus(self):
        if self.consensus is None:
            self.consensus = await self.archive.consensus()
        # TODO: Use the check built in to stem once it exists
        # https://trac.torproject.org/projects/tor/ticket/28448
        if not self.consensus or \
                datetime.datetime.utcnow() > self.consensus.valid_until:
            consensus = await self.downloader.consensus()
            if consensus is None:
                return
            self.consensus = consensus
            await self.archive.store(consensus)
            await self._recurse_network_status_references(consensus)

    async def fetch_votes(self, next_vote=False):
        for authority in DIRECTORY_AUTHORITIES:
            vote = await self.downloader.vote(endpoint=authority, next_vote=next_vote)
            if vote is None:
                continue
            await self.archive.store(vote)
            await self._recurse_network_status_references(vote)

    async def _recurse_network_status_references(self, network_status):
        wanted_digests = collections.deque()
        download_tasks = []
        endpoint = None

        if network_status.is_consensus:
            for authority in self.consensus.directory_authorities:
                # TODO: Download all votes
                pass
        else:
            endpoint = stem.DirPort(network_status.directory_authorities[0].address,
                                    network_status.directory_authorities[0].dir_port)

        # Download server descriptors
        server_descriptors = []
        for desc in network_status.routers.values():
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
                    SERVER_DESCRIPTOR, digest=next_batch, endpoint=endpoint))
        await self.downloader.perform_downloads()
        for result in await asyncio.gather(*download_tasks):
            for desc in result:
                await self.archive.store(desc)
                server_descriptors.append(desc)
        for desc in server_descriptors:
            if desc.extra_info_digest:
                extra_info_descriptor = await self.archive.descriptor(
                    EXTRA_INFO_DESCRIPTOR, desc.extra_info_digest)
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
                    EXTRA_INFO_DESCRIPTOR, digest=next_batch, endpoint=endpoint))
        await self.downloader.perform_downloads()
        for result in await asyncio.gather(*download_tasks):
            for desc in result:
                await self.archive.store(desc)

        print("All done")


async def scrape():
    directory = DirectoryScraper(".")
    await directory.fetch_votes()
    await directory.fetch_consensus()
