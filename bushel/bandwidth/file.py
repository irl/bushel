"""
Bandwidth files.
"""
# TODO: Write better docstring

import base64
import collections
import datetime
import enum
import logging
import re
import textwrap

import nacl.signing
import nacl.encoding

from bushel.document import BaseDocument

LOG = logging.getLogger('bushel')

class BandwidthFileLineError(enum.Enum):
    """
    Enumeration of forgivable errors that may be encountered during parsing of
    lines in a bandwidth file.

    ======================= ===========
    Name                    Description
    ======================= ===========
    SHORT_TERMINATOR        A terminator with 4 `=` instead of 5.
                            https://bugs.torproject.org/28379
    NO_TERMINATOR           No terminator present, for pre-1.0.0 compatibility.
    ======================= ===========
    """

    SHORT_TERMINATOR = "short-terminator"

class BandwidthFileLiner:
    """
    Parses :class:`BandwidthFileToken` s into :class:`BandwidthFileTimestamp`,
    :class:`BandwidthFileHeaderLine` s and :class:`BandwidthFileRelayLine`. By
    default this is a strict implementation of the Tor Bandwidth File
    Specification version 1.4.0 [bandwidth-file-spec]_, but this can be relaxed
    to account for parsing older versions, or for known bugs in Tor
    implementations.

    Lines are produced by processing tokens according to a state machine:

    .. graphviz::

        digraph g {
            start [label="START"];
            timestamp [label="TIMESTAMP"];
            header_line [label="HEADER-LINE"];
            header_line_kv [label="HEADER-LINE-KV"];
            relay_line [label="RELAY-LINE"];
            relay_line_sp [label="RELAY-LINE-SP"];
            relay_line_kv [label="RELAY-LINE-KV"];
            done [label="DONE"];

            start -> timestamp [label="TIMESTAMP"];
            timestamp -> header_line [label="NL"];
            header_line -> header_line_kv [label="KEYVALUE"];
            header_line_kv -> header_line [label="NL"];
            header_line -> relay_line [label="TERMINATOR"];
            header_line -> relay_line [label="SHORT_TERMINATOR", color="red"];
            header_line_kv -> relay_line_sp [label="SP", color="red"];
            relay_line -> relay_line_kv [label="KEYVALUE"];
            relay_line_kv -> relay_line [label="NL"];
            relay_line_kv -> relay_line_sp [label="SP"];
            relay_line_sp -> relay_line_kv [label="KEYVALUE"];
            relay_line -> done [label="EOF"];
        }

    State transitions shown in red would ideally not be needed as they are
    protocol violations, but implementations of the protocol exist that produce
    documents requiring these transitions and we need to be bug compatible.

    :param allowed_errors:
        A list of errors that will be considered non-fatal during itemization.
    :type allowed_errors: list(BandwidthFileLineError)
    """

    def __init__(self, allowed_errors=None):
        self.state = 'START'

    def eat(self, token):
        if self.state == 'START':
            if token.kind == 'TIMESTAMP':
                self.state = 'TIMESTAMP'
                return
            else:
                self.expected_not_found("timestamp")
        elif self.state == 'TIMESTAMP':
            if token.kind == 'NL':
                self.state = 'HEADER-LINE'
                return
            else:
                self.expected_not_found("newline")
        elif self.state == 'HEADER-LINE':
            if token.kind == 'KEYVALUE':
                self.state = 'HEADER-LINE-KV'
                return
            elif token.kind == 'TERMINATOR':
                self.state = 'RELAY-LINE'
                return
            elif token.kind == 'SHORT_TERMINATOR':
                self.state = 'RELAY-LINE'
                # TODO: this is an error
                return
            else:
                self.expected_not_found("terminator")
        elif self.state == 'HEADER-LINE-KV':
            if token.kind == 'NL':
                self.state = 'HEADER-LINE'
                return
            elif token.kind == 'SP':
                self.state = 'RELAY-LINE-SP'
                # TODO: this is an error
                return
            else:
                self.expected_not_found("newline (or space if pre-1.0.0)")
        elif self.state == 'RELAY-LINE':
            if token.kind == 'KEYVALUE':
                self.state = 'RELAY-LINE-KV'
                return
            elif token.kind == 'EOF':
                self.state = 'DONE'
                return
            else:
                self.expected_not_found("keyvalue or eof")
        elif self.state == 'RELAY-LINE-KV':
            if token.kind == 'SP':
                self.state = 'RELAY-LINE-SP'
                return
            elif token.kind == 'NL':
                self.state = 'RELAY-LINE'
                return
            else:
                self.expected_not_found("space or newline")
        elif self.state == 'RELAY-LINE-SP':
            if token.kind == 'KEYVALUE':
                self.state = 'RELAY-LINE-KV'
                return
            else:
                self.expected_not_found("keyvalue")
        raise RuntimeError("Bad state transition")

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

class BandwidthFile(BaseDocument):

    def __init__(self, raw_content):
        super().__init__(raw_content)
        self.PARSE_FUNCTIONS = dict()

    def parse(self):
        for line in self.lines():
            if item.keyword in self.PARSE_FUNCTIONS:
                self.PARSE_FUNCTIONS[line.keyword](item)

    def lines(self, allowed_errors=None):
        liner = BandwidthFileLiner(allowed_errors)
        for token in self.tokenize():
            line = liner.eat(token)
            if line:
                yield line

    def tokenize(self):
        """
        Tokenizes the document using the following tokens:

        ================== ======================================= ========
        Kind               Matches on                              Value
        ================== ======================================= ========
        TIMESTAMP          A string of ASCII numbers               Raw data
        TERMINATOR         ``"=====?\n"``                          Raw data
        KEYVALUE           ``Key "=" Value``                       Raw data
        NL                 The ASCII LF character (hex value 0x0a) Raw data
        SP                 The ASCII SP character (hex value 0x20) Raw data
        MISMATCH           Anything else (likely binary nonsense)  Raw data
        ================== ======================================= ========

        Note that these tokens do not match the non-terminals exactly as they
        are specified in the Tor Bandwidth File Format. In particular,
        the PRINTABLE token is used for anything not a KEYVALUE but still
        meaningful. It is up to whatever is processing these tokens to decide if
        something is valid key, value, timestamp, etc.

        :returns: iterator for :class:`BandwidthFileToken`
        """
        token_specification = [('SHORT_TERMINATOR', r'====\n'),
                               ('TERMINATOR', r'=====\n'),
                               ('TIMESTAMP', r'[0-9]+'),
                               ('KEYVALUE', r'[-A-Za-z0-9_]+=\S+'),
                               ('NL', r'\n'),
                               ('SP', r' '),
                               ('MISMATCH', r'.')]
        tok_regex = '|'.join(
            '(?P<%s>%s)' % pair for pair in token_specification)
        line_num = 1
        line_start = 0
        for mo in re.finditer(tok_regex, self.raw_content.decode('utf-8')):
            kind = mo.lastgroup
            value = mo.group()
            column = mo.start() - line_start
            if kind == 'MISMATCH':
                raise RuntimeError(
                    f'{value!r} unexpected on line {line_num} at col {column}')
            yield BandwidthFileToken(kind, value, line_num, column)
            if kind in ['NL', 'TERMINATOR']:
                line_start = mo.end()
                line_num += 1
        column = mo.end() - line_start
        yield BandwidthFileToken('EOF', None, line_num, column)


class BandwidthFileToken(collections.namedtuple('BandwidthFileToken', ['kind', 'value', 'line', 'column'])):
    """
    :var str kind: the kind of token
    :var bytes value: kind-dependent value
    :var int line: line number
    :var int column: column number
    """
