"""Remote CollecTor instance interaction.

This module provides tools for interacting with remote CollecTor instances,
such as those run by `Tor Metrics <https://metrics.torproject.org/>`_ or
3rd-party public or private CollecTor instances.

.. data:: DEFAULT_COLLECTOR_HOST

   The default CollecTor host to use when none is specified, currently
   `collector.torproject.org` although this is subject to change. It will be
   set to the currently recommended public Tor Metrics instance.

.. data:: DEFAULT_INDEX_COMPRESSION

   The default compression algorithm used with CollecTor indexes. This is
   currently set to *xz* although is subject to change in line with any
   recommendations from Tor Metrics.
"""

import typing

import requests

from bushel.collector.filesystem import collector_index_path
from bushel.collector.filesystem import CollecTorIndexCompression
from bushel.collector.index import CollecTorIndex

DEFAULT_COLLECTOR_HOST = "collector.torproject.org"
DEFAULT_INDEX_COMPRESSION = CollecTorIndexCompression.XZ


class CollecTorRemote:
    """
    A remote CollecTor instance. Methods are provided for querying the data
    available on the remote instance, as well as retrieving data from the
    remote instance.

    :param str host: The FQDN of the CollecTor instance. If None, then the
                     :data:`DEFAULT_COLLECTOR_HOST` is used.
    :param bool https: Whether HTTPS should be used. This defaults to *True*.
    """
    host: str
    https: bool

    def __init__(self,
                 host: typing.Optional[str] = None,
                 *,
                 https: bool = True) -> None:
        self.host = host or DEFAULT_COLLECTOR_HOST
        self.https = https

    def get_raw_by_path(self, path: str) -> bytes:
        """
        Fetch the raw bytes of a file from a CollecTor instance.

        :param str path: CollecTor path with no leading slash (/).
        :rtype: bytes
        :returns: Raw bytes of the reply, which may be compressed depending on
                  the requested path.
        """
        if not isinstance(path, str):
            raise TypeError("CollecTor paths must be strings.")
        if len(path) >= 1 and path[0] == "/":
            raise ValueError("CollecTor paths must not have leading slashes. "
                             "The path is always considered to be absolute.")
        url = "http" + ("s" if self.https else "") + f"://{self.host}/{path}"
        req = requests.get(url)
        return req.content

    def get_index(self, compression: typing.Optional[CollecTorIndexCompression]
                  ) -> CollecTorIndex:
        """
        Fetch the index from the CollecTor instance, optionally specifying the
        compression algorithm to use. This function will return an object that
        contains the (decompressed if necessary) and parsed index.

        :param CollecTorIndexCompression compression: Compression algorithm to
            use. If *None*, the default specified in
            :data:`DEFAULT_INDEX_COMPRESSION` will be used.
        :rtype: CollecTorIndex
        """
        compression = compression or DEFAULT_INDEX_COMPRESSION
        raw_bytes = self.get_raw_by_path(collector_index_path(compression))
        decompressed_bytes = compression.decompress(raw_bytes)
        return CollecTorIndex(decompressed_bytes)


def get_index(host: typing.Optional[str] = None,
              compression: typing.Optional[CollecTorIndexCompression] = None,
              *,
              https: bool = True) -> CollecTorIndex:
    """
    Convenience function for
    ``CollecTorRemote(host, https=https).get_index(compression)``.

    .. seealso:: :meth:`CollecTorRemote.get_index`
    """
    return CollecTorRemote(host, https=https).get_index(compression)
