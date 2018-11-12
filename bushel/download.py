import pickle
import asyncio
import collections
import logging
import socket
import sys
import traceback
import urllib.error

from random import randint

import stem
from stem import DirPort
from stem import ORPort
from stem.descriptor.remote import DescriptorDownloader

from bushel.store import FilesystemStore

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

LOG = logging.getLogger('')

SERVER_DESCRIPTOR = 10
EXTRA_INFO_DESCRIPTOR = 20


class TorDirectory:
    def __init__(self, archive_path):
        self.bs = asyncio.BoundedSemaphore(5)
        self.downloader_lock = asyncio.BoundedSemaphore(1)
        self.archive = FilesystemStore(".")
        self.current_consensus = None
        self.downloader = DescriptorDownloader(
            timeout=5,
            retries=10,
            endpoints=DIRECTORY_AUTHORITIES,
        )
        self.recent_extra_info_descriptors = {}

    async def _download_consensus(self, retries=3):
        # Swap retries counter for a random choice of directory authority and give each a few goes
        query = self.downloader.get_consensus(
            document_handler=stem.descriptor.DocumentHandler.DOCUMENT)
        LOG.debug("Started consensus download")
        while not query.is_done:
            await asyncio.sleep(1)
        LOG.debug("Consensus download completed")
        try:
            result = query.run()  # This will throw any exceptions, the query
            # is already done so this doesn't block.
            return result[0]
        except (urllib.error.URLError, socket.timeout, ValueError) as e:
            traceback.print_exc()
            if retries > 0:
                LOG.warning("Consensus download failed - sleeping 20 seconds")
                await asyncio.sleep(20)
                return self._download_consensus(retries - 1)
            else:
                LOG.error("Did not download a consensus after many attempts!")

    def _resource_url(self, doctype, digest):
        if digest is None:
            digest_str = "all"
        else:
            digest_str = "+".join(digest)
        if doctype is SERVER_DESCRIPTOR:
            return "/tor/server/d/" + digest_str
        if doctype is EXTRA_INFO_DESCRIPTOR:
            return "/tor/extra/d/" + digest_str
        raise RuntimeError("Unknown document type requested")

    async def _download_descriptor(self, doctype, digest=None):
        async with self.bs:
            query = self.downloader.query(self._resource_url(doctype, digest))
            while not query.is_done:
                await asyncio.sleep(1)
            return [d for d in query]

    async def refresh_consensus(self):
        consensus = await self._download_consensus()
        if consensus is None:
            return
        self.consensus = consensus
        self.archive.store(consensus)
        await self._recurse_consensus_references()

    async def _recurse_consensus_references(self):
        async with self.downloader_lock:
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
                    self._download_descriptor(SERVER_DESCRIPTOR, next_batch))
            for result in await asyncio.gather(*download_tasks):
                for desc in result:
                    self.archive.store(desc)
                    server_descriptors.append(desc)
            for desc in server_descriptors:
                if desc.extra_info_digest and desc.extra_info_digest not in self.recent_extra_info_descriptors.keys(
                ):
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
                    self._download_descriptor(EXTRA_INFO_DESCRIPTOR,
                                              next_batch))
            for result in await asyncio.gather(*download_tasks):
                for desc in result:
                    self.recent_extra_info_descriptors[
                        desc.digest()] = desc.published
                    self.archive.store(desc)

            print("All done")


async def download():
    directory = TorDirectory(".")
    await directory.refresh_consensus()
