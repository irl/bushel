import base64
import collections
import datetime
import enum
import logging
import re

import nacl.signing
import nacl.encoding

from bushel.documents.base import BaseDocument

LOG = logging.getLogger('bushel')

def parse_timestamp(item, argindex=0):
    """
    Parses a timestamp from a directory document's item using the common format
    from [dir-spec]_. This format is not defined explicitly but is used with
    many keywords including ``valid-after``, ``fresh-until``, and
    ``valid-until``.

    .. note::

        Due to the way the tokenizer works, timestamps are parsed as two
        arguments split by whitespace. This function takes this into account
        when parsing the timestamp.

    Most items will have the timestamp as the first argument on the keyword
    line. At the time of writing, there are no keywords defined that expect
    timestamps at other indexes. Should this be required though, *argindex* may
    be used to parse a timestamp from a later argument.

    :param DirectoryDocumentItem item: the directory document item
    :param int argindex:
        zero-indexed index of date portion of timestamp, the time portion is
        expected in ``argindex+1``

    :returns: the parsed timestamp
    :rtype: ~datetime.datetime
    """

    timestamp = f"{item.arguments[argindex]} {item.arguments[argindex+1]}"
    return datetime.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")

def decode_object_data(lines):
    """
    Decodes the base64 encoded data found within directory document objects.

    :param list(str) lines:
        the lines as found in a directory document object, not including
        newlines or the begin/end lines

    :returns: the decoded data
    :rtype: bytes
    """
    return base64.b64decode("".join(lines))

def expect_arguments(minargs, maxargs, strictmax=False):
    def expect_arguments_decorator(parser_func):
        def function_wrapper(self, item):
            if len(item.arguments) < minargs:
                raise RuntimeError(
                    "Incorrect number of arguments found for "
                    f"{item.keyword} item in document. Expected at "
                    f"least {minargs} but found {len(item.arguments)}")
            elif len(item.arguments) > maxargs:
                msg = (
                    f"Found additional arguments for {item.keyword} item in "
                    f"document. Expected no more than {maxargs} but found "
                    f"{len(item.arguments)}.")
                if strictmax:
                    raise RuntimeError(msg)
                else:
                    LOG.warning(msg)
            return parser_func(self, item)

        return function_wrapper

    return expect_arguments_decorator


class DirectoryCertificateExtension(
        collections.namedtuple('DirectoryCertificateExtension',
                               ['type', 'flags', 'data'])):
    """
    A Tor Ed25519 certificate extension as specified by [cert-spec]_.

    .. graphviz::

        digraph g {
            rankdir=LR;

            certificate [label="Certificate",shape="box"];
            extension [label="Extension",shape="box",style="filled",fillcolor="yellow"];

            certificate->extension [label="has zero or more"];
        }

    :var int type: extension type
    :var int flags: extension flags
    :var bytes data: extension data

    .. seealso:: These will be found in :class:`DirectoryCertificate` s.
    """


class DirectoryCertificate:
    """
    A Tor Ed25519 certificate as specified by [cert-spec]_. It is not the only
    certificate format that Tor uses. Typically these are found as the data
    contained within :class:`DirectoryDocumentObject` s.

    .. graphviz::

        digraph g {
            rankdir=LR;

            certificate [label="Certificate",shape="box",style="filled",fillcolor="yellow"];
            extension [label="Extension",shape="box"];

            certificate->extension [label="has zero or more"];
        }

    :param bytes raw_content: raw certificate contents

    :var bytes data: raw certificate contents
    :var int version: version of the certificate format (currently always 1)
    :var int cert_type: type of certificate
    :var ~datetime.datetime expiration_date: expiration date of certificate
    :var int cert_key_type: type of certified key
    :var bytes certified_key: an Ed25519 public key if cert_key_type is 1, or a
                              SHA256 hash of some other key type depending on
                              the value of cert_key_type
    :var int n_extensions: declared number of extensions
    :var list(DirectoryCertificateExtension) extensions: parsed extensions
    :var bytes signature: certificate signature
    """

    def __init__(self, raw_content):
        self.raw_content = raw_content
        self.version = None
        self.cert_type = None
        self.expiration_date = None
        self.cert_key_type = None
        self.certified_key = None
        self.n_extensions = None
        self.extensions = None
        self.signature = None

    def parse(self):
        """
        Parses the certificate to make the fields available via instance
        attributes. This does not validate or verify the certificate, but must
        be called before making calls to :meth:`~DirectoryCertificate.is_valid`
        or :meth:`~DirectoryCertificate.verify`.
        """
        # TODO: check that the data is at least long enough for zero extensions
        self.version = int.from_bytes(self.raw_content[0:1], "big")
        self.cert_type = int.from_bytes(self.raw_content[1:2], "big")
        self.expiration_date = datetime.datetime.utcfromtimestamp(
            int.from_bytes(self.raw_content[2:6], "big") * 3600)
        self.cert_key_type = int.from_bytes(self.raw_content[6:7], "big")
        self.certified_key = self.raw_content[7:39]
        self.n_extensions = int.from_bytes(self.raw_content[39:40], "big")
        index = self._parse_extensions()  # end of extensions
        if len(self.raw_content) - index == 64:
            self.signature = self.raw_content[-64:]
        else:
            pass
        # TODO: throw parse error if it went wrong

    def _parse_extensions(self):
        self.extensions = []
        index = 40
        for _ in range(self.n_extensions):
            # len(length + kind + flags) = 4
            length = int.from_bytes(self.raw_content[index:index + 2], "big")
            kind = int.from_bytes(self.raw_content[index + 2:index + 3], "big")
            flags = int.from_bytes(self.raw_content[index + 3:index + 4], "big")
            data = self.raw_content[index + 4:index + 4 + length]
            self.extensions.append(
                DirectoryCertificateExtension(kind, flags, data))
            index += 4 + length
        return index

    def is_valid(self):
        """
        Checks that the certificate is valid. This is the counterpart to
        :meth:`~DirectoryCertificate.verify` that checks that the certificate
        data conforms to the specification. The two checks performed are:

        * expiration date is not passed
        * there are no extensions that affect validation that we do not
          understand

        .. note::

            In the Tor Metrics use case, we need to check that certificates
            were valid at the time they were expected to be valid, but
            the current API does not support this.
        """
        if self.expiration_date > datetime.datetime.utcnow():
            # TODO: Need to check based on provided time, not just now
            raise RuntimeError("Attempted to validate a certificate but it "
                               "has expired.")
        known_extension_kinds = [4] # TODO: make this more global
        for extension in self.extensions:
            if extension.kind not in known_extension_kinds:
                raise RuntimeError("Certificate has unknown extensions that "
                                   "affect validation, so cannot validate.")

    def verify(self, verify_key_data=None):
        """
        Verify the certificate using the verification key. Optionally provide
        key material, otherwise the key found in the "signed-with-ed25519-key"
        (type 4) extension will be used.

        This only verifies the signature. To validate the certificate data
        the seperate :meth:`DirectoryCertificate.is_valid` method must be
        used.

        .. warning::

            This verifies the raw data that the object was initialized with,
            the fields may have been played with since parsing and the parser
            may also have unknown bugs.

        :param bytes verify_key_data: an Ed25519 verification key
        """
        if not verify_key_data:
            for extension in self.extensions:
                if extension.type == 4:  # Signed-with-ed25519-key extension
                    verify_key_data = extension.data
                    break
        verify_key = nacl.signing.VerifyKey(verify_key_data,
                                            nacl.encoding.RawEncoder)
        verify_key.verify(self.raw_content[:-64], self.signature)
        return True


class DirectoryDocumentItem:
    """
    A directory document item as described in the Tor directory protocol meta
    format (§1.2 [dir-spec]_).

    .. graphviz::

        digraph g {
            rankdir=LR;

            document [label="Document",shape="box"];
            item [label="Item",style="filled",fillcolor="yellow",shape="box"];
            object [label="Object",shape="box"];

            document->item [label="has one or more"];
            item->object [label="has zero or more"];
        }

    :param bytes keyword: the item keyword
    :param list(bytes) arguments: list of item arguments
    :param list(tuple(bytes,bytes)) objects: list of item objects as tuples of (object keyword, decoded object data)
    :param list(DirectoryDocumentItemError) errors: list of errors found during item parsing

    :var bytes keyword: the item keyword
    :var list(bytes) arguments: list of item arguments
    :var list(tuple(bytes,bytes)) objects: list of item objects as tuples of (object keyword, decoded object data)
    :var list(DirectoryDocumentItemError) errors: list of errors found during item parsing
    """
    def __init__(self, keyword, arguments, objects, errors):
        self.keyword = keyword
        self.arguments = arguments
        self.objects = objects
        self.errors = errors

    def __str__(self):
        if self.arguments:
            arguments = " " + " ".join(self.arguments)
        else:
            arguments = ""
        object_lines = []
        if self.objects:
            for obj in self.objects:
                object_lines.append(f"-----BEGIN {obj[0]}-----")
                object_lines.extend(obj[1])
                object_lines.append(f"-----END {obj[0]}-----")
        lines = [f"{self.keyword}{arguments}"]
        lines.extend(object_lines)
        return "\n".join(lines)

class DirectoryDocumentItemError(enum.Enum):
    """
    Enumeration of forgivable errors that may be encountered during itemization
    of a directory document.

    ======================= ===========
    Name                    Description
    ======================= ===========
    TRAILING_WHITESPACE     Trailing whitespace on KeywordLines
                            https://bugs.torproject.org/30105
    ======================= ===========
    """

    TRAILING_WHITESPACE = 'trailing-whitespace'


class DirectoryDocumentItemizer:
    """
    Parses :class:`DirectoryDocumentToken` s into
    :class:`DirectoryDocumentItem` s. By default this is a strict
    implementation of the Tor directory protocol meta format (§1.2
    [dir-spec]_), but this can be relaxed to account for implementation bugs in
    known Tor implementations.

    Items are produced by processing tokens according to a state machine:

    .. graphviz::

        digraph g {
            start [label="START"];
            keyword_line [label="KEYWORD-LINE"];
            keyword_line_ws [label="KEYWORD-LINE-WS"];
            keyword_line_end [label="KEYWORD-LINE-END"];
            object_data [label="OBJECT-DATA"];
            object_data_eol [label="OBJECT-DATA-EOL"];

            start -> keyword_line [label="PRINATABLE"];
            keyword_line -> keyword_line_end [label="NL"];
            keyword_line -> keyword_line_ws [label="WS"];
            keyword_line_ws -> keyword_line [label="PRINTABLE"];
            keyword_line_ws -> keyword_line_end [label="NL", color="red"];
            keyword_line_end -> object_data [label="BEGIN"];
            keyword_line_end -> start [label="EOF"];
            keyword_line_end -> keyword_line [label="PRINTABLE"];
            object_data -> object_data_eol [label="PRINTABLE"];
            object_data_eol -> object_data [label="NL"];
            object_data -> keyword_line_end [label="END"];
        }

    State transitions shown in red would ideally not be needed as they are
    protocol violations, but implementations of the protocol exist that produce
    documents requiring these transitions and we need to be bug compatible.

    .. warning::

        All printable strings are treated equally right now, so we're not
        testing for keywords being the restricted set, nor are we decoding
        object data yet.

    :param allowed_errors:
        A list of errors that will be considered non-fatal during itemization.
    :type allowed_errors: list(DirectoryDocumentItemError)
    """

    def __init__(self, allowed_errors=None):
        self.state = 'START'
        self.allowed_errors = allowed_errors or []
        self.token = None
        self.token_handlers = {
            'START': self.token_start,
            'KEYWORD-LINE': self.token_keyword_line,
            'KEYWORD-LINE-WS': self.token_keyword_line_ws,
            'KEYWORD-LINE-END': self.token_keyword_line_end,
            'OBJECT-DATA': self.token_object_data,
            'OBJECT-DATA-EOL': self.token_object_data_eol,
        }
        # item state follows
        self.keyword = None
        self.arguments = []
        self.objects = []
        self.errors = []
        # object state follows
        self.object_keyword = None
        self.object_data = []

    def reset_item_state(self, next_keyword=None):
        self.keyword = next_keyword
        self.arguments = []
        self.objects = []
        self.errors = []
        self.reset_object_state()

    def reset_object_state(self):
        self.object_keyword = None
        self.object_data = []

    def item_done(self, next_keyword=None):
        done_item = self.item()
        self.reset_item_state(next_keyword=next_keyword)
        self.state = 'KEYWORD-LINE' if next_keyword else 'START'
        return done_item

    def error(self, error):
        if error in self.allowed_errors:
            self.errors.append(error)
        else:
            raise RuntimeError(f"Encountered a {error.value} error on line "
                               f"{self.token.line} at col {self.token.column}")

    def expected_not_found(self, expected):
        raise RuntimeError(f"Expected {expected} on line "
                           f"{self.token.line} at "
                           f"col {self.token.column}, but found "
                           f"{self.token.kind} {self.token.value}")

    def item(self):
        return DirectoryDocumentItem(self.keyword, self.arguments, self.objects,
                                     self.errors)

    def eat(self, token):
        #LOG.info("Itemizer state is %s", self.state)
        #LOG.info("Next token is %s", token)
        self.token = token
        return self.token_handlers[self.state]()

    def token_start(self):
        if self.token.kind == 'PRINTABLE':
            self.keyword = self.token.value
            self.state = 'KEYWORD-LINE'
        else:
            self.expected_not_found("keyword")

    def token_keyword_line(self):
        if self.token.kind == 'NL':
            self.state = 'KEYWORD-LINE-END'
        elif self.token.kind == 'WS':
            self.state = 'KEYWORD-LINE-WS'
        else:
            self.expected_not_found("whitespace or newline")

    def token_keyword_line_ws(self):
        if self.token.kind == 'NL':
            self.error(DirectoryDocumentItemError.TRAILING_WHITESPACE)
            self.state = 'KEYWORD-LINE-END'
        elif self.token.kind == 'PRINTABLE':
            self.arguments.append(self.token.value)
            self.state = 'KEYWORD-LINE'
        else:
            self.expected_not_found("argument")

    def token_keyword_line_end(self):
        if self.token.kind == 'BEGIN':
            self.object_keyword = self.token.value
            self.state = 'OBJECT-DATA'
        elif self.token.kind == 'PRINTABLE':
            return self.item_done(next_keyword=self.token.value) # TODO: Why am I passing this?
        elif self.token.kind == 'EOF':
            return self.item_done()
        else:
            self.expected_not_found("begin line, keyword or EOF")
        return None

    def token_object_data(self):
        if self.token.kind == 'END':
            self.objects.append(DirectoryDocumentObject(
                self.object_keyword,
                decode_object_data(self.object_data)
            ))
            self.reset_object_state()
            self.state = 'KEYWORD-LINE-END'
        elif self.token.kind == 'PRINTABLE':
            self.object_data.append(self.token.value)
            self.state = 'OBJECT-DATA-EOL'
        else:
            self.expected_not_found("object data or end line")

    def token_object_data_eol(self):
        if self.token.kind == 'NL':
            self.state = 'OBJECT-DATA'
        else:
            self.expected_not_found("newline")


class DirectoryDocument(BaseDocument):
    """
    A directory document as described in the Tor directory protocol meta
    format (§1.2 [dir-spec]_).

    .. graphviz::

        digraph g {
            rankdir=LR;

            document [label="Document",shape="box",style="filled",fillcolor="yellow"];
            item [label="Item",shape="box"];
            object [label="Object",shape="box"];

            document->item [label="has one or more"];
            item->object [label="has zero or more"];
        }

    :param bytes raw_content: raw document contents
    """

    def __init__(self, raw_content):
        super().__init__(raw_content)
        self.PARSE_FUNCTIONS = dict()

    def parse(self):
        for item in self.items():
            if item.keyword in self.PARSE_FUNCTIONS:
                self.PARSE_FUNCTIONS[item.keyword](item)

    def items(self, allowed_errors=None):
        itemizer = DirectoryDocumentItemizer(allowed_errors)
        for token in self.tokenize():
            item = itemizer.eat(token)
            if item:
                yield item

    def tokenize(self):
        """
        Tokenizes the document using the following tokens:

        ================== ======================================= ========
        Kind               Matches on                              Value
        ================== ======================================= ========
        END                ``"-----END " Keyword "-----"``         Keyword
        BEGIN              ``"-----BEGIN " Keyword "-----"``       Keyword
        NL                 The ascii LF character (hex value 0x0a) Raw data
        PRINTABLE          Printing, non-whitespace, UTF-8         Raw data
        WS                 Space or tab                            Raw data
        MISMATCH           Anything else (likely binary nonsense)  Raw data
        ================== ======================================= ========

        Note that these tokens do not match the non-terminals exactly as they
        are specified in the Tor directory protocol meta format. In particular,
        the PRINTABLE token is used for both keywords and arguments (and object
        data). It is up to whatever is processing these tokens to decide if
        something is valid keyword or argument.

        >>> document_bytes = b'''super-keyword 3
        ... onion-magic
        ... -----BEGIN ONION MAGIC-----
        ... AQQABp6MAT7yJjlcuWLDbr8A5J8YgyDh5SPYkLpj7fmcBaFbKekjAQAgBADKnR/C
        ... -----END ONION MAGIC-----'''
        >>> for token in DirectoryDocument(document_bytes).tokenize():
        ...     print(token)
        DirectoryDocumentToken(kind='PRINTABLE', value='super-keyword', line=1, column=0)
        DirectoryDocumentToken(kind='WS', value=' ', line=1, column=13)
        DirectoryDocumentToken(kind='PRINTABLE', value='3', line=1, column=14)
        DirectoryDocumentToken(kind='NL', value='\\n', line=2, column=15)
        DirectoryDocumentToken(kind='PRINTABLE', value='onion-magic', line=2, column=0)
        DirectoryDocumentToken(kind='NL', value='\\n', line=3, column=11)
        DirectoryDocumentToken(kind='BEGIN', value='ONION MAGIC', line=3, column=0)
        DirectoryDocumentToken(kind='NL', value='\\n', line=4, column=27)
        DirectoryDocumentToken(kind='PRINTABLE', value='AQ.../C', line=4, column=0)
        DirectoryDocumentToken(kind='NL', value='\\n', line=5, column=64)
        DirectoryDocumentToken(kind='END', value='ONION MAGIC', line=5, column=0)
        DirectoryDocumentToken(kind='EOF', value=None, line=5, column=0)

        :returns: iterator for :class:`DirectoryDocumentToken`
        """
        token_specification = [('END', r'-----END [A-Za-z0-9- ]+-----\n'),
                               ('BEGIN', r'-----BEGIN [A-Za-z0-9- ]+-----\n'),
                               ('NL', r'\n'), ('PRINTABLE', r'\S+'),
                               ('WS', r'[ \t]+'), ('MISMATCH', r'.')]
        tok_regex = '|'.join(
            '(?P<%s>%s)' % pair for pair in token_specification)
        line_num = 1
        line_start = 0
        for mo in re.finditer(tok_regex, self.raw_content.decode('utf-8')):
            kind = mo.lastgroup
            value = mo.group()
            column = mo.start() - line_start
            if kind == 'NL':
                line_start = mo.end()
                line_num += 1
            if kind == 'BEGIN':
                value = value[11:-6]
            if kind == 'END':
                value = value[9:-6]
            if kind == 'MISMATCH':
                raise RuntimeError(
                    f'{value!r} unexpected on line {line_num} at col {column}')
            yield DirectoryDocumentToken(kind, value, line_num, column)
        yield DirectoryDocumentToken('EOF', None, line_num, column)


class DirectoryDocumentToken(collections.namedtuple('DirectoryDocumentToken', ['kind', 'value', 'line', 'column'])):
    """
    :var DirectoryDocumentTokenType kind: the kind of token
    :var bytes value: kind-dependent value
    :var int line: line number
    :var int column: column number
    """

class DirectoryDocumentObject(collections.namedtuple('DirectoryDocumentObject', ['keyword', 'data'])):
    """
    A directory document item as described in the Tor directory protocol meta
    format (§1.2 [dir-spec]_).

    .. graphviz::

        digraph g {
            rankdir=LR;

            document [label="Document",shape="box"];
            item [label="Item",shape="box"];
            object [label="Object",shape="box",style="filled",fillcolor="yellow"];

            document->item [label="has one or more"];
            item->object [label="has zero or more"];
        }

    :var bytes keyword: object keyword
    :var bytes data: decoded object data
    """
