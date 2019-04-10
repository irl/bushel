import collections
import datetime
import re

import nacl.signing
import nacl.encoding

from bushel.documents.base import Document

Token = collections.namedtuple('Token', ['type', 'value', 'line', 'column'])


def parse_timestamp(item, argindex=0):
    timestamp = f"{item.arguments[argindex]} {item.arguments[argindex+1]}"
    return datetime.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")


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
                    logger.warning(msg)
            return parser_func(self, item)

        return function_wrapper

    return expect_arguments_decorator


class DirectoryCertificateExtension(
        collections.namedtuple('DirectoryCertificateExtension',
                               ['type', 'flags', 'data'])):
    pass


class DirectoryCertificate:
    def __init__(self, data):
        self.data = data

    def parse(self):
        # TODO: check that the data is at least long enough for zero extensions
        self.version = int.from_bytes(self.data[0:1], "big")
        self.cert_type = int.from_bytes(self.data[1:2], "big")
        self.expiration_date = datetime.datetime.utcfromtimestamp(
            int.from_bytes(self.data[2:6], "big") * 3600)
        self.cert_key_type = int.from_bytes(self.data[6:7], "big")
        self.certified_key = self.data[7:39]
        self.n_extensions = int.from_bytes(self.data[39:40], "big")
        index = self._parse_extensions()  # end of extensions
        if len(self.data) - index == 64:
            self.signature = self.data[-64:]
        else:
            pass
        # TODO: throw parse error if it went wrong

    def _parse_extensions(self):
        self.extensions = []
        index = 40
        for n in range(self.n_extensions):
            # len(length + kind + flags) = 4
            length = int.from_bytes(self.data[index:index + 2], "big")
            kind = int.from_bytes(self.data[index + 2:index + 3], "big")
            flags = int.from_bytes(self.data[index + 3:index + 4], "big")
            data = self.data[index + 4:index + 4 + length]
            self.extensions.append(
                DirectoryCertificateExtension(kind, flags, data))
            index += 4 + length
        return index

    def is_valid(self):
        # TODO: check for affecting validation extensions we don't know about
        # TODO: check expiration date
        pass

    def verify(self, verify_key_data=None):
        # TODO: this verifies the raw data underneath, the fields may have
        # been played with since parsing and the parser may also be wrong
        if not verify_key_data:
            for extension in self.extensions:
                if extension.type == 4:  # Signed-with-ed25519-key extension
                    verify_key_data = extension.data
                    break
        verify_key = nacl.signing.VerifyKey(verify_key_data,
                                            nacl.encoding.RawEncoder)
        verify_key.verify(self.data[:-64], self.signature)
        return True


class DirectoryDocumentItem:
    def __init__(self, keyword, arguments, objects, trailing_whitespace):
        self.keyword = keyword
        self.arguments = arguments
        self.objects = objects
        self.trailing_whitespace = trailing_whitespace

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


class DirectoryDocument(Document):
    def __init__(self, raw_content):
        super().__init__(raw_content)

    def parse(self):
        for item in self.items():
            if item.keyword in self.PARSE_FUNCTIONS:
                self.PARSE_FUNCTIONS[item.keyword](item)

    def items(self):
        # TODO: Write something more testable
        state = 'START'
        for token in self.tokenize():
            if state == 'START':
                keyword = None  # This will never remain None, because if we don't find one, it's an error
                arguments = []
                object_keyword = None
                object_data = None
                trailing_whitespace = False
                objects = None
                if token.type != 'PRINTABLE':
                    raise RuntimeError("Expected a keyword on line "
                                       f"{token.line} at "
                                       f"col {token.column}, but found "
                                       f"{token.type} {token.value}")
                keyword = token.value
                state = 'KEYWORD-LINE'
                continue
            if state == 'KEYWORD-LINE':
                if token.type == 'NL':
                    state = 'KEYWORD-LINE-END'
                    continue
                if token.type != 'WS':
                    raise RuntimeError(
                        "Expected whitespace or newline on line "
                        f"{token.line} at "
                        f"col {token.column}, but found "
                        f"{token.type}")
                state = 'KEYWORD-LINE-WS'
                continue
            if state == 'KEYWORD-LINE-WS':
                if token.type == 'NL':
                    trailing_whitespace = True
                    state = 'KEYWORD-LINE-END'
                    continue
                if token.type != 'PRINTABLE':
                    raise RuntimeError("Expected argument on line "
                                       f"{token.line} at "
                                       f"col {token.column}, but found "
                                       f"{token.type}")
                arguments.append(token.value)
                state = 'KEYWORD-LINE'
                continue
            if state == 'KEYWORD-LINE-END':
                if token.type == 'BEGIN':
                    object_keyword = token.value
                    object_data = []
                    if not objects:
                        objects = []
                    state = 'OBJECT-DATA'
                    continue
                elif token.type == 'PRINTABLE':
                    yield DirectoryDocumentItem(keyword, arguments, objects,
                                                trailing_whitespace)
                    keyword = token.value
                    arguments = []
                    trailing_whitespace = False
                    object_keyword = None
                    object_data = None
                    objects = None
                    state = 'KEYWORD-LINE'
                    continue
                elif token.type == 'EOF':
                    yield DirectoryDocumentItem(keyword, arguments, objects,
                                                trailing_whitespace)
                    continue
            if state == 'OBJECT-DATA':
                if token.type == 'END':
                    objects.append((object_keyword, object_data))
                    object_keyword = None
                    object_data = None
                    state = 'KEYWORD-LINE-END'
                    continue
                if token.type == 'PRINTABLE':
                    object_data.append(token.value)

    def tokenize(self):
        token_specification = [('END', r'-----END [A-Za-z0-9-]+-----'),
                               ('BEGIN', r'-----BEGIN [A-Za-z0-9-]+-----'),
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
                value = value[11:-5]
            if kind == 'END':
                value = value[9:-5]
            if kind == 'MISMATCH':
                raise RuntimeError(
                    f'{value!r} unexpected on line {line_num} at col {column}')
            yield Token(kind, value, line_num, column)
        yield Token('EOF', None, line_num, column)
