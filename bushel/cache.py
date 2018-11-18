import asyncio
import collections
import datetime
import logging
import random

import stem

from bushel import SERVER_DESCRIPTOR
from bushel import EXTRA_INFO_DESCRIPTOR
from bushel.archive import DirectoryArchive
from bushel.downloader import DirectoryDownloader

LOG = logging.getLogger('')

DirectoryCacheMode = stem.util.enum.UppercaseEnum(
    'CLIENT',
    'DIRECTORY_CACHE',
)

class DirectoryCache:
    def __init__(self, archive_path):
        self.descriptors = {}
        self.archive = DirectoryArchive(archive_path)
        self.downloader = DirectoryDownloader()

    def set_mode(self, directory_cache_mode):
        if directory_cache_mode is DirectoryCacheMode.CLIENT:
            self.downloader.set_endpoints(self.downloader.directory_caches())
        if directory_cache_mode is DirectoryCacheMode.DIRECTORY_CACHE:
            self.downloader.set_endpoints(self.downloader.directory_authorities())
        # TODO: Catch unknown modes

    async def consensus(self, valid_after=None):
        """
        Returns the consensus with the specified valid_after time if available
        from the archive or a directory server.

        :param datetime valid_after: The valid_after time for the requested
                                     consensus. If *None* then the latest
                                     consensus will be retrieved.
        """
        consensus = await self.archive.consensus(valid_after)
        now = datetime.datetime.utcnow().replace(minute=0, second=0)
        estimated_fresh_until = valid_after + datetime.timedelta(hour=1)
        if not valid_after or \
              now >= valid_after and now < estimated_fresh_until:
            consensus = await self.downloader.consensus()
            if consensus is None:
                return
            await self.archive.store(consensus)
        return consensus

#    async def vote(self, endpoint=None, digest=None, valid_after=None):
#            vote = await self.archive.vote()
#            if vote is None:
#                vote = await self.downloader.vote()
#                if vote is None:
#                    continue
#                await self.archive.store(vote)

    def _cached_descriptor(self, doctype, digest):
        if doctype in self.descriptors:
            if digest in self.descriptors[doctype]:
                return self.descriptors[doctype][digest]

    async def descriptor(self, doctype, digest=None, endpoint=None):
        if isinstance(digest, str):
            descriptor = self._cached_descriptor(doctype, digest)
            if descriptor:
                return descriptor
            descriptor = await self.archive.descriptor(
                doctype,
                digest=digest
              )
            if not descriptor:
                descriptor = await self.downloader.descriptor(
                    doctype, digest=digest, endpoint=endpoint)
                if descriptor:
                    await self.archive.store(descriptor)
            if descriptor:
                if not self.descriptors.get(doctype):
                    self.descriptors[doctype] = {}
                self.descriptors[doctype][digest] = descriptor
            return descriptor
        else:
            results = await asyncio.gather(*[self.descriptor(
                                                 doctype, d, endpoint)
                                             for d in digest])
            return [r for r in results if r]
