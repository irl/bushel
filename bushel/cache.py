import asyncio
import collections
import datetime
import logging
import random

import stem

from bushel import SERVER_DESCRIPTOR
from bushel import EXTRA_INFO_DESCRIPTOR
from bushel import DirectoryCacheMode
from bushel.archive import DirectoryArchive
from bushel.downloader import DirectoryDownloader

LOG = logging.getLogger('')

class DirectoryCache:
    def __init__(self, archive_path):
        self.descriptors = {}
        self.archive = DirectoryArchive(archive_path)
        self.downloader = DirectoryDownloader()
        self.downloader.descriptor_cache = self._cached_descriptor # TODO: Do something more sensible

    def set_mode(self, directory_cache_mode):
        self.downloader.set_mode(directory_cache_mode)

    async def consensus(self, valid_after=None):
        """
        Returns the consensus with the specified valid_after time if available
        from the archive or a directory server.

        :param datetime valid_after: The valid_after time for the requested
                                     consensus. If *None* then the latest
                                     consensus will be retrieved.
        """
        if valid_after is None:
            valid_after = datetime.datetime.utcnow()
            valid_after = valid_after.replace(minute=0, second=0)
        consensus = await self.archive.consensus(valid_after)
        if consensus:
            now = datetime.datetime.utcnow().replace(minute=0, second=0)
            estimated_fresh_until = valid_after + datetime.timedelta(hours=1)
            if valid_after and \
                  now >= valid_after and now < estimated_fresh_until:
                return consensus
        consensus = await self.downloader.consensus()
        if consensus:
            await self.archive.store(consensus)
        return consensus

    async def vote(self, v3ident=None, digest=None, next_vote=False):
        vote = await self.archive.vote(v3ident=v3ident)
        if vote is None:
            vote = await self.downloader.vote()
            if vote is None:
                return
            await self.archive.store(vote)
        return vote

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
