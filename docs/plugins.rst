Plugin API
==========

The following documents a draft API to be implemented by plugins. These
functions will be called by the reference checker. While plugins may keep state
internally, it is expected that any state they do keep is not required to be
persistent.

.. py:class:: DocumentIdentifier(doctype, subject, datetime, digests):

   Represents a document that is expected to exist.

   **Attributes:**

   .. py:attribute:: doctype
   
      The :py:class:`type` of the document.
   
   .. py:attribute:: subject
   
      The subject of the document. This is usually a string containing an opaque
      identifier. Examples include the fingerprint of a relay for a server
      descriptor, or the hostname of an OnionPerf vantage point.
   
   .. py:attribute:: datetime
   
      A :py:class:`~datetime.datetime` related to the document. The exact
      meaning of this will be document dependent. Example include the published
      time for a server descriptor, or the valid-after time for a network
      status consensus.
   
   .. py:attribute:: digests
   
      A :py:class:`dict` containing mappings of
      :py:class:`~stem.descriptor.DigestHash` to :py:class:`tuple`s. Each tuple
      contains a :py:class:`str` representation of the digest and a
      :py:class:`stem.descriptor.DigestEncoding`.

.. py:class:: ExamplePlugin

   .. py:method:: expectations()

      :returns: A :py:class:`list` of :py:class:`DocumentIdentifier` for
                documents that are expected to be available for fetching.

   .. py:method:: fetch(docid)

      Fetches a document from a remote location.

      :param DocumentIdentifier docid: Identifier for the document to be
                                       fetched.

   .. py:method:: parse(document)

      Parses a retrieved document for any documents that are referenced and
      should be fetched.

      :param DocumentIdentifier document: A retrieved document.

      :returns: A :py:class:`list` of :py:class:`DocumentIdentifier` for
                documents that are expected to be available for fetching.
