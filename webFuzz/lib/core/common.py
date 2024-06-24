from __future__ import division

import binascii
import codecs
import contextlib
import copy
import functools
import getpass
import hashlib
import inspect
import io
import json
import keyword
import locale
import logging
import ntpath
import os
import platform
import posixpath
import random
import re
import socket
import string
import subprocess
import sys
import tempfile
import threading
import time
import types
import unicodedata

from difflib import SequenceMatcher
from math import sqrt
from optparse import OptionValueError
from xml.sax import parse
from xml.sax import SAXParseException

from lib.core.bigarray import BigArray
from lib.core.compat import cmp
from lib.core.compat import LooseVersion
from lib.core.compat import round
from lib.core.compat import xrange
from lib.core.convert import base64pickle
from lib.core.convert import base64unpickle
from lib.core.convert import decodeBase64
from lib.core.convert import decodeHex
from lib.core.convert import getBytes
from lib.core.convert import getText
from lib.core.convert import getUnicode
from lib.core.convert import htmlUnescape
from lib.core.convert import stdoutEncode
from lib.core.data import cmdLineOptions
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import paths
from lib.core.datatype import OrderedSet
from lib.core.dicts import DBMS_DICT
from lib.core.dicts import DEFAULT_DOC_ROOTS
from lib.core.dicts import DEPRECATED_OPTIONS
from lib.core.dicts import OBSOLETE_OPTIONS
from lib.core.dicts import SQL_STATEMENTS
from lib.core.enums import ADJUST_TIME_DELAY
from lib.core.enums import CHARSET_TYPE
from lib.core.enums import CONTENT_STATUS
from lib.core.enums import DBMS
from lib.core.enums import EXPECTED
from lib.core.enums import HASHDB_KEYS
from lib.core.enums import HEURISTIC_TEST
from lib.core.enums import HTTP_HEADER
from lib.core.enums import HTTPMETHOD
from lib.core.enums import LOGGING_LEVELS
from lib.core.enums import MKSTEMP_PREFIX
from lib.core.enums import OPTION_TYPE
from lib.core.enums import OS
from lib.core.enums import PAYLOAD
from lib.core.enums import PLACE
from lib.core.enums import POST_HINT
from lib.core.enums import REFLECTIVE_COUNTER
from lib.core.enums import SORT_ORDER
from lib.core.exception import SqlmapBaseException
from lib.core.exception import SqlmapDataException
from lib.core.exception import SqlmapGenericException
from lib.core.exception import SqlmapInstallationException
from lib.core.exception import SqlmapMissingDependence
from lib.core.exception import SqlmapNoneDataException
from lib.core.exception import SqlmapSilentQuitException
from lib.core.exception import SqlmapSyntaxException
from lib.core.exception import SqlmapSystemException
from lib.core.exception import SqlmapUserQuitException
from lib.core.exception import SqlmapValueException
from lib.core.settings import BOLD_PATTERNS
from lib.core.settings import BOUNDARY_BACKSLASH_MARKER
from lib.core.settings import BOUNDED_INJECTION_MARKER
from lib.core.settings import BRUTE_DOC_ROOT_PREFIXES
from lib.core.settings import BRUTE_DOC_ROOT_SUFFIXES
from lib.core.settings import BRUTE_DOC_ROOT_TARGET_MARK
from lib.core.settings import BURP_REQUEST_REGEX
from lib.core.settings import BURP_XML_HISTORY_REGEX
from lib.core.settings import CRAWL_EXCLUDE_EXTENSIONS
from lib.core.settings import CUSTOM_INJECTION_MARK_CHAR
from lib.core.settings import DBMS_DIRECTORY_DICT
from lib.core.settings import DEFAULT_COOKIE_DELIMITER
from lib.core.settings import DEFAULT_GET_POST_DELIMITER
from lib.core.settings import DEFAULT_MSSQL_SCHEMA
from lib.core.settings import DOLLAR_MARKER
from lib.core.settings import DUMMY_USER_INJECTION
from lib.core.settings import DYNAMICITY_BOUNDARY_LENGTH
from lib.core.settings import ERROR_PARSING_REGEXES
from lib.core.settings import EVALCODE_ENCODED_PREFIX
from lib.core.settings import FILE_PATH_REGEXES
from lib.core.settings import FORCE_COOKIE_EXPIRATION_TIME
from lib.core.settings import FORM_SEARCH_REGEX
from lib.core.settings import GENERIC_DOC_ROOT_DIRECTORY_NAMES
from lib.core.settings import GITHUB_REPORT_OAUTH_TOKEN
from lib.core.settings import GOOGLE_ANALYTICS_COOKIE_PREFIX
from lib.core.settings import HASHDB_MILESTONE_VALUE
from lib.core.settings import HOST_ALIASES
from lib.core.settings import HTTP_CHUNKED_SPLIT_KEYWORDS
from lib.core.settings import IGNORE_PARAMETERS
from lib.core.settings import IGNORE_SAVE_OPTIONS
from lib.core.settings import INFERENCE_UNKNOWN_CHAR
from lib.core.settings import IP_ADDRESS_REGEX
from lib.core.settings import IS_TTY
from lib.core.settings import IS_WIN
from lib.core.settings import LARGE_OUTPUT_THRESHOLD
from lib.core.settings import LOCALHOST
from lib.core.settings import MAX_INT
from lib.core.settings import MIN_ENCODED_LEN_CHECK
from lib.core.settings import MIN_ERROR_PARSING_NON_WRITING_RATIO
from lib.core.settings import MIN_TIME_RESPONSES
from lib.core.settings import MIN_VALID_DELAYED_RESPONSE
from lib.core.settings import NETSCAPE_FORMAT_HEADER_COOKIES
from lib.core.settings import NULL
from lib.core.settings import PARAMETER_AMP_MARKER
from lib.core.settings import PARAMETER_SEMICOLON_MARKER
from lib.core.settings import PARAMETER_PERCENTAGE_MARKER
from lib.core.settings import PARTIAL_HEX_VALUE_MARKER
from lib.core.settings import PARTIAL_VALUE_MARKER
from lib.core.settings import PAYLOAD_DELIMITER
from lib.core.settings import PLATFORM
from lib.core.settings import PRINTABLE_CHAR_REGEX
from lib.core.settings import PROBLEMATIC_CUSTOM_INJECTION_PATTERNS
from lib.core.settings import PUSH_VALUE_EXCEPTION_RETRY_COUNT
from lib.core.settings import PYVERSION
from lib.core.settings import RANDOMIZATION_TLDS
from lib.core.settings import REFERER_ALIASES
from lib.core.settings import REFLECTED_BORDER_REGEX
from lib.core.settings import REFLECTED_MAX_REGEX_PARTS
from lib.core.settings import REFLECTED_REPLACEMENT_REGEX
from lib.core.settings import REFLECTED_REPLACEMENT_TIMEOUT
from lib.core.settings import REFLECTED_VALUE_MARKER
from lib.core.settings import REFLECTIVE_MISS_THRESHOLD
from lib.core.settings import SENSITIVE_DATA_REGEX
from lib.core.settings import SENSITIVE_OPTIONS
from lib.core.settings import STDIN_PIPE_DASH
from lib.core.settings import SUPPORTED_DBMS
from lib.core.settings import TEXT_TAG_REGEX
from lib.core.settings import TIME_STDEV_COEFF
from lib.core.settings import UNICODE_ENCODING
from lib.core.settings import UNKNOWN_DBMS_VERSION
from lib.core.settings import URI_QUESTION_MARKER
from lib.core.settings import URLENCODE_CHAR_LIMIT
from lib.core.settings import URLENCODE_FAILSAFE_CHARS
from lib.core.settings import USER_AGENT_ALIASES
from lib.core.settings import VERSION_COMPARISON_CORRECTION
from lib.core.settings import ZIP_HEADER
from lib.core.settings import WEBSCARAB_SPLITTER
from lib.core.threads import getCurrentThreadData
from lib.utils.safe2bin import safecharencode
from thirdparty import six
from thirdparty.odict import OrderedDict
from thirdparty.six import unichr as _unichr
from thirdparty.six.moves import collections_abc as _collections
from thirdparty.six.moves import configparser as _configparser
from thirdparty.six.moves import http_client as _http_client
from thirdparty.six.moves import input as _input
from thirdparty.six.moves import reload_module as _reload_module
from thirdparty.six.moves import urllib as _urllib
from thirdparty.six.moves import zip as _zip

class UnicodeRawConfigParser(_configparser.RawConfigParser):
    """
    RawConfigParser with unicode writing support
    """

    def write(self, fp):
        """
        Write an .ini-format representation of the configuration state.
        """

        if self._defaults:
            fp.write("[%s]\n" % _configparser.DEFAULTSECT)

            for (key, value) in self._defaults.items():
                fp.write("%s = %s" % (key, getUnicode(value, UNICODE_ENCODING)))

            fp.write("\n")

        for section in self._sections:
            fp.write("[%s]\n" % section)

            for (key, value) in self._sections[section].items():
                if key != "__name__":
                    if value is None:
                        fp.write("%s\n" % (key))
                    elif not isListLike(value):
                        fp.write("%s = %s\n" % (key, getUnicode(value, UNICODE_ENCODING)))

            fp.write("\n")

class Format(object):
    @staticmethod
    def humanize(values, chain=" or "):
        return chain.join(values)

    # Get methods
    @staticmethod
    def getDbms(versions=None):
        """
        Format the back-end DBMS fingerprint value and return its
        values formatted as a human readable string.

        @return: detected back-end DBMS based upon fingerprint techniques.
        @rtype: C{str}
        """

        if versions is None and Backend.getVersionList():
            versions = Backend.getVersionList()

        return Backend.getDbms() if versions is None else "%s %s" % (Backend.getDbms(), " and ".join(filterNone(versions)))

    @staticmethod
    def getErrorParsedDBMSes():
        """
        Parses the knowledge base htmlFp list and return its values
        formatted as a human readable string.

        @return: list of possible back-end DBMS based upon error messages
        parsing.
        @rtype: C{str}
        """

        htmlParsed = None

        if len(kb.htmlFp) == 0 or kb.heuristicTest != HEURISTIC_TEST.POSITIVE:
            pass
        elif len(kb.htmlFp) == 1:
            htmlParsed = kb.htmlFp[0]
        elif len(kb.htmlFp) > 1:
            htmlParsed = " or ".join(kb.htmlFp)

        return htmlParsed

    @staticmethod
    def getOs(target, info):
        """
        Formats the back-end operating system fingerprint value
        and return its values formatted as a human readable string.

        Example of info (kb.headersFp) dictionary:

        {
          'distrib': set(['Ubuntu']),
          'type': set(['Linux']),
          'technology': set(['PHP 5.2.6', 'Apache 2.2.9']),
          'release': set(['8.10'])
        }

        Example of info (kb.bannerFp) dictionary:

        {
          'sp': set(['Service Pack 4']),
          'dbmsVersion': '8.00.194',
          'dbmsServicePack': '0',
          'distrib': set(['2000']),
          'dbmsRelease': '2000',
          'type': set(['Windows'])
        }

        @return: detected back-end operating system based upon fingerprint
        techniques.
        @rtype: C{str}
        """

        infoStr = ""
        infoApi = {}

        if info and "type" in info:
            if conf.api:
                infoApi["%s operating system" % target] = info
            else:
                infoStr += "%s operating system: %s" % (target, Format.humanize(info["type"]))

                if "distrib" in info:
                    infoStr += " %s" % Format.humanize(info["distrib"])

                if "release" in info:
                    infoStr += " %s" % Format.humanize(info["release"])

                if "sp" in info:
                    infoStr += " %s" % Format.humanize(info["sp"])

                if "codename" in info:
                    infoStr += " (%s)" % Format.humanize(info["codename"])

        if "technology" in info:
            if conf.api:
                infoApi["web application technology"] = Format.humanize(info["technology"], ", ")
            else:
                infoStr += "\nweb application technology: %s" % Format.humanize(info["technology"], ", ")

        if conf.api:
            return infoApi
        else:
            return infoStr.lstrip()

class Backend(object):

    @staticmethod
    def setVersion(version):
        if isinstance(version, six.string_types):
            kb.dbmsVersion = [version]

        return kb.dbmsVersion

    @staticmethod
    def setVersionList(versionsList):
        if isinstance(versionsList, list):
            kb.dbmsVersion = versionsList
        elif isinstance(versionsList, six.string_types):
            Backend.setVersion(versionsList)        

    @staticmethod
    def forceDbms(dbms, sticky=False):
        if not kb.stickyDBMS:
            kb.forcedDbms = aliasToDbmsEnum(dbms)
            kb.stickyDBMS = sticky

    @staticmethod
    def flushForcedDbms(force=False):
        if not kb.stickyDBMS or force:
            kb.forcedDbms = None
            kb.stickyDBMS = False


    @staticmethod
    def setOsVersion(version):
        if version is None:
            return None

        elif kb.osVersion is None and isinstance(version, six.string_types):
            kb.osVersion = version

    @staticmethod
    def setOsServicePack(sp):
        if sp is None:
            return None

        elif kb.osSP is None and isinstance(sp, int):
            kb.osSP = sp

    # Get methods
    @staticmethod
    def getForcedDbms():
        return aliasToDbmsEnum(conf.get("forceDbms")) or aliasToDbmsEnum(kb.get("forcedDbms"))

    @staticmethod
    def getDbms():
        return aliasToDbmsEnum(kb.get("dbms"))

    @staticmethod
    def getErrorParsedDBMSes():
        """
        Returns array with parsed DBMS names till now

        This functions is called to:

        1. Ask user whether or not skip specific DBMS tests in detection phase,
           lib/controller/checks.py - detection phase.
        2. Sort the fingerprint of the DBMS, lib/controller/handler.py -
           fingerprint phase.
        """

        return kb.htmlFp if kb.get("heuristicTest") == HEURISTIC_TEST.POSITIVE else []

    @staticmethod
    def getIdentifiedDbms():
        """
        This functions is called to:

        1. Sort the tests, getSortedInjectionTests() - detection phase.
        2. Etc.
        """

        dbms = None

        if not kb:
            pass
        elif not kb.get("testMode") and conf.get("dbmsHandler") and getattr(conf.dbmsHandler, "_dbms", None):
            dbms = conf.dbmsHandler._dbms
        elif Backend.getForcedDbms() is not None:
            dbms = Backend.getForcedDbms()
        elif Backend.getDbms() is not None:
            dbms = Backend.getDbms()
        elif kb.get("injection") and kb.injection.dbms:
            dbms = unArrayizeValue(kb.injection.dbms)
        elif Backend.getErrorParsedDBMSes():
            dbms = unArrayizeValue(Backend.getErrorParsedDBMSes())
        elif conf.get("dbms"):
            dbms = conf.get("dbms")

        return aliasToDbmsEnum(dbms)

    @staticmethod
    def getVersion():
        versions = filterNone(flattenValue(kb.dbmsVersion)) if not isinstance(kb.dbmsVersion, six.string_types) else [kb.dbmsVersion]
        if not isNoneValue(versions):
            return versions[0]
        else:
            return None

    @staticmethod
    def getVersionList():
        versions = filterNone(flattenValue(kb.dbmsVersion)) if not isinstance(kb.dbmsVersion, six.string_types) else [kb.dbmsVersion]
        if not isNoneValue(versions):
            return versions
        else:
            return None

    @staticmethod
    def getOs():
        return kb.os

    @staticmethod
    def getOsVersion():
        return kb.osVersion

    @staticmethod
    def getOsServicePack():
        return kb.osSP

    # Comparison methods
    @staticmethod
    def isDbms(dbms):
        if not kb.get("testMode") and all((Backend.getDbms(), Backend.getIdentifiedDbms())) and Backend.getDbms() != Backend.getIdentifiedDbms():
            singleTimeWarnMessage("identified ('%s') and fingerprinted ('%s') DBMSes differ. If you experience problems in enumeration phase please rerun with '--flush-session'" % (Backend.getIdentifiedDbms(), Backend.getDbms()))
        return Backend.getIdentifiedDbms() == aliasToDbmsEnum(dbms)

    @staticmethod
    def isFork(fork):
        return hashDBRetrieve(HASHDB_KEYS.DBMS_FORK) == fork

    @staticmethod
    def isDbmsWithin(aliases):
        return Backend.getDbms() is not None and Backend.getDbms().lower() in aliases

    @staticmethod
    def isVersion(version):
        return Backend.getVersion() is not None and Backend.getVersion() == version

    @staticmethod
    def isVersionWithin(versionList):
        if Backend.getVersionList() is None:
            return False

        for _ in Backend.getVersionList():
            if _ != UNKNOWN_DBMS_VERSION and _ in versionList:
                return True

        return False

    @staticmethod
    def isVersionGreaterOrEqualThan(version):
        retVal = False

        if all(_ not in (None, UNKNOWN_DBMS_VERSION) for _ in (Backend.getVersion(), version)):
            _version = unArrayizeValue(Backend.getVersion())
            _version = re.sub(r"[<>= ]", "", _version)

            try:
                retVal = LooseVersion(_version) >= LooseVersion(version)
            except:
                retVal = str(_version) >= str(version)

        return retVal

    @staticmethod
    def isOs(os):
        return Backend.getOs() is not None and Backend.getOs().lower() == os.lower()

def filePathToSafeString(filePath):
    """
    Returns string representation of a given filepath safe for a single filename usage

    >>> filePathToSafeString('C:/Windows/system32')
    'C__Windows_system32'
    """

    retVal = filePath.replace("/", "_").replace("\\", "_")
    retVal = retVal.replace(" ", "_").replace(":", "_")

    return retVal

def singleTimeDebugMessage(message):
    singleTimeLogMessage(message, logging.DEBUG)

def singleTimeWarnMessage(message):
    singleTimeLogMessage(message, logging.WARN)

def singleTimeLogMessage(message, level=logging.INFO, flag=None):
    if flag is None:
        flag = hash(message)

    if not conf.smokeTest and flag not in kb.singleLogFlags:
        kb.singleLogFlags.add(flag)
        

def clearColors(message):
    """
    Clears ANSI color codes

    >>> clearColors("\x1b[38;5;82mHello \x1b[38;5;198mWorld")
    'Hello World'
    """

    retVal = message

    if isinstance(message, str):
        retVal = re.sub(r"\x1b\[[\d;]+m", "", message)

    return retVal

def dataToTrafficFile(data):
    if not conf.trafficFile:
        return

    try:
        conf.trafficFP.write(data)
        conf.trafficFP.flush()
    except IOError as ex:
        errMsg = "something went wrong while trying "
        errMsg += "to write to the traffic file '%s' ('%s')" % (conf.trafficFile, getSafeExString(ex))
        raise SqlmapSystemException(errMsg)

def dataToDumpFile(dumpFile, data):
    try:
        dumpFile.write(data)
        dumpFile.flush()
    except IOError as ex:
        if "No space left" in getUnicode(ex):
            errMsg = "no space left on output device"
            
        elif "Permission denied" in getUnicode(ex):
            errMsg = "permission denied when flushing dump data"
            
        else:
            errMsg = "error occurred when writing dump data to file ('%s')" % getUnicode(ex)
            

def dataToOutFile(filename, data):
    """
    Saves data to filename

    >>> pushValue(conf.get("filePath"))
    >>> conf.filePath = tempfile.gettempdir()
    >>> "_etc_passwd" in dataToOutFile("/etc/passwd", b":::*")
    True
    >>> conf.filePath = popValue()
    """

    retVal = None

    if data:
        while True:
            retVal = os.path.join(conf.filePath, filePathToSafeString(filename))

            try:
                with open(retVal, "w+b") as f:  # has to stay as non-codecs because data is raw ASCII encoded data
                    f.write(getBytes(data))
            except UnicodeEncodeError as ex:
                _ = normalizeUnicode(filename)
                if filename != _:
                    filename = _
                else:
                    errMsg = "couldn't write to the "
                    errMsg += "output file ('%s')" % getSafeExString(ex)
                    raise SqlmapGenericException(errMsg)
            except IOError as ex:
                errMsg = "something went wrong while trying to write "
                errMsg += "to the output file ('%s')" % getSafeExString(ex)
                raise SqlmapGenericException(errMsg)
            else:
                break

    return retVal

def setTechnique(technique):
    """
    Thread-safe setting of currently used technique (Note: dealing with cases of per-thread technique switching)
    """

    getCurrentThreadData().technique = technique

def getTechnique():
    """
    Thread-safe getting of currently used technique
    """

    return getCurrentThreadData().technique or kb.get("technique")

def randomRange(start=0, stop=1000, seed=None):
    """
    Returns random integer value in given range

    >>> random.seed(0)
    >>> randomRange(1, 500)
    152
    """

    if seed is not None:
        _ = getCurrentThreadData().random
        _.seed(seed)
        randint = _.randint
    else:
        randint = random.randint

    return int(randint(start, stop))

def randomInt(length=4, seed=None):
    """
    Returns random integer value with provided number of digits

    >>> random.seed(0)
    >>> randomInt(6)
    963638
    """

    if seed is not None:
        _ = getCurrentThreadData().random
        _.seed(seed)
        choice = _.choice
    else:
        choice = random.choice

    return int("".join(choice(string.digits if _ != 0 else string.digits.replace('0', '')) for _ in xrange(0, length)))

def randomStr(length=4, lowercase=False, alphabet=None, seed=None):
    """
    Returns random string value with provided number of characters

    >>> random.seed(0)
    >>> randomStr(6)
    'FUPGpY'
    """

    if seed is not None:
        _random = getCurrentThreadData().random
        _random.seed(seed)
        choice = _random.choice
    else:
        choice = random.choice

    if alphabet:
        retVal = "".join(choice(alphabet) for _ in xrange(0, length))
    elif lowercase:
        retVal = "".join(choice(string.ascii_lowercase) for _ in xrange(0, length))
    else:
        retVal = "".join(choice(string.ascii_letters) for _ in xrange(0, length))

    return retVal

def sanitizeStr(value):
    """
    Sanitizes string value in respect to newline and line-feed characters

    >>> sanitizeStr('foo\\n\\rbar') == 'foo bar'
    True
    >>> sanitizeStr(None) == 'None'
    True
    """

    return getUnicode(value).replace("\n", " ").replace("\r", "")

def getHeader(headers, key):
    """
    Returns header value ignoring the letter case

    >>> getHeader({"Foo": "bar"}, "foo")
    'bar'
    """

    retVal = None

    for header in (headers or {}):
        if header.upper() == key.upper():
            retVal = headers[header]
            break

    return retVal

def checkPipedInput():
    """
    Checks whether input to program has been provided via standard input (e.g. cat /tmp/req.txt | python sqlmap.py -r -)
    # Reference: https://stackoverflow.com/a/33873570
    """

    return hasattr(sys.stdin, "fileno") and not os.isatty(sys.stdin.fileno())

def isZipFile(filename):
    """
    Checks if file contains zip compressed content

    >>> isZipFile(paths.WORDLIST)
    True
    """

    checkFile(filename)

    return openFile(filename, "rb", encoding=None).read(len(ZIP_HEADER)) == ZIP_HEADER

def isDigit(value):
    """
    Checks if provided (string) value consists of digits (Note: Python's isdigit() is problematic)

    >>> u'\xb2'.isdigit()
    True
    >>> isDigit(u'\xb2')
    False
    >>> isDigit('123456')
    True
    >>> isDigit('3b3')
    False
    """

    return re.search(r"\A[0-9]+\Z", value or "") is not None

def checkFile(filename, raiseOnError=True):
    """
    Checks for file existence and readability

    >>> checkFile(__file__)
    True
    """

    valid = True

    if filename:
        filename = filename.strip('"\'')

    if filename == STDIN_PIPE_DASH:
        return checkPipedInput()
    else:
        try:
            if filename is None or not os.path.isfile(filename):
                valid = False
        except:
            valid = False

        if valid:
            try:
                with open(filename, "rb"):
                    pass
            except:
                valid = False

    if not valid and raiseOnError:
        raise SqlmapSystemException("unable to read file '%s'" % filename)

    return valid

def parseJson(content):
    """
    This function parses POST_HINT.JSON and POST_HINT.JSON_LIKE content

    >>> parseJson("{'id':1}")["id"] == 1
    True
    >>> parseJson('{"id":1}')["id"] == 1
    True
    """

    quote = None
    retVal = None

    for regex in (r"'[^']+'\s*:", r'"[^"]+"\s*:'):
        match = re.search(regex, content)
        if match:
            quote = match.group(0)[0]

    try:
        if quote == '"':
            retVal = json.loads(content)
        elif quote == "'":
            content = content.replace('"', '\\"')
            content = content.replace("\\'", BOUNDARY_BACKSLASH_MARKER)
            content = content.replace("'", '"')
            content = content.replace(BOUNDARY_BACKSLASH_MARKER, "'")
            retVal = json.loads(content)
    except:
        pass

    return retVal

def parsePasswordHash(password):
    """
    In case of Microsoft SQL Server password hash value is expanded to its components

    >>> pushValue(kb.forcedDbms)
    >>> kb.forcedDbms = DBMS.MSSQL
    >>> "salt: 4086ceb6" in parsePasswordHash("0x01004086ceb60c90646a8ab9889fe3ed8e5c150b5460ece8425a")
    True
    >>> kb.forcedDbms = popValue()
    """

    blank = ' ' * 8

    if isNoneValue(password) or password == ' ':
        retVal = NULL
    else:
        retVal = password

    if Backend.isDbms(DBMS.MSSQL) and retVal != NULL and isHexEncodedString(password):
        retVal = "%s\n" % password
        retVal += "%sheader: %s\n" % (blank, password[:6])
        retVal += "%ssalt: %s\n" % (blank, password[6:14])
        retVal += "%smixedcase: %s\n" % (blank, password[14:54])

        if password[54:]:
            retVal += "%suppercase: %s" % (blank, password[54:])

    return retVal

def cleanQuery(query):
    """
    Switch all SQL statement (alike) keywords to upper case

    >>> cleanQuery("select id from users")
    'SELECT id FROM users'
    """

    retVal = query

    for sqlStatements in SQL_STATEMENTS.values():
        for sqlStatement in sqlStatements:
            candidate = sqlStatement.replace("(", "").replace(")", "").strip()
            queryMatch = re.search(r"(?i)\b(%s)\b" % candidate, query)

            if queryMatch and "sys_exec" not in query:
                retVal = retVal.replace(queryMatch.group(1), candidate.upper())

    return retVal

def cleanReplaceUnicode(value):
    """
    Cleans unicode for proper encode/decode

    >>> cleanReplaceUnicode(['a', 'b'])
    ['a', 'b']
    """

    def clean(value):
        return value.encode(UNICODE_ENCODING, errors="replace").decode(UNICODE_ENCODING) if isinstance(value, six.text_type) else value

    return applyFunctionRecursively(value, clean)

def setPaths(rootPath = None):
    """
    Sets absolute paths for project directories and files
    """
    paths.ROOT_PATH = rootPath if rootPath else './'

    paths.DATA_PATH = os.path.join(paths.ROOT_PATH, "webFuzz/Payloads/SQLi")

    paths.XML_PATH = os.path.join(paths.DATA_PATH, "xml")
    paths.XML_BANNER_PATH = os.path.join(paths.XML_PATH, "banner")
    paths.XML_PAYLOADS_PATH = os.path.join(paths.XML_PATH, "payloads")

    paths.ERRORS_XML = os.path.join(paths.XML_PATH, "errors.xml")
    paths.BOUNDARIES_XML = os.path.join(paths.XML_PATH, "boundaries.xml")
    paths.QUERIES_XML = os.path.join(paths.XML_PATH, "queries.xml")

    for path in paths.values():
        if any(path.endswith(_) for _ in (".txt", ".xml", ".tx_")):
            checkFile(path)



def weAreFrozen():
    """
    Returns whether we are frozen via py2exe.
    This will affect how we find out where we are located.

    # Reference: http://www.py2exe.org/index.cgi/WhereAmI
    """

    return hasattr(sys, "frozen")

def parseTargetUrl():
    """
    Parse target URL and set some attributes into the configuration singleton

    >>> pushValue(conf.url)
    >>> conf.url = "https://www.test.com/?id=1"
    >>> parseTargetUrl()
    >>> conf.hostname
    'www.test.com'
    >>> conf.scheme
    'https'
    >>> conf.url = popValue()
    """

    if not conf.url:
        return

    originalUrl = conf.url

    if re.search(r"://\[.+\]", conf.url) and not socket.has_ipv6:
        errMsg = "IPv6 communication is not supported "
        errMsg += "on this platform"
        raise SqlmapGenericException(errMsg)

    if not re.search(r"^(http|ws)s?://", conf.url, re.I):
        if re.search(r":443\b", conf.url):
            conf.url = "https://%s" % conf.url
        else:
            conf.url = "http://%s" % conf.url

    if kb.customInjectionMark in conf.url:
        conf.url = conf.url.replace('?', URI_QUESTION_MARKER)

    try:
        urlSplit = _urllib.parse.urlsplit(conf.url)
    except ValueError as ex:
        errMsg = "invalid URL '%s' has been given ('%s'). " % (conf.url, getSafeExString(ex))
        errMsg += "Please be sure that you don't have any leftover characters (e.g. '[' or ']') "
        errMsg += "in the hostname part"
        raise SqlmapGenericException(errMsg)

    hostnamePort = urlSplit.netloc.split(":") if not re.search(r"\[.+\]", urlSplit.netloc) else filterNone((re.search(r"\[.+\]", urlSplit.netloc).group(0), re.search(r"\](:(?P<port>\d+))?", urlSplit.netloc).group("port")))

    conf.scheme = (urlSplit.scheme.strip().lower() or "http")
    conf.path = urlSplit.path.strip()
    conf.hostname = hostnamePort[0].strip()

    if conf.forceSSL:
        conf.scheme = re.sub(r"(?i)\A(http|ws)\Z", r"\g<1>s", conf.scheme)

    conf.ipv6 = conf.hostname != conf.hostname.strip("[]")
    conf.hostname = conf.hostname.strip("[]").replace(kb.customInjectionMark, "")

    try:
        conf.hostname.encode("idna")
        conf.hostname.encode(UNICODE_ENCODING)
    except (LookupError, UnicodeError):
        invalid = True
    else:
        invalid = False

    if any((invalid, re.search(r"\s", conf.hostname), '..' in conf.hostname, conf.hostname.startswith('.'), '\n' in originalUrl)):
        errMsg = "invalid target URL ('%s')" % originalUrl
        raise SqlmapSyntaxException(errMsg)

    if len(hostnamePort) == 2:
        try:
            conf.port = int(hostnamePort[1])
        except:
            errMsg = "invalid target URL"
            raise SqlmapSyntaxException(errMsg)
    elif conf.scheme in ("https", "wss"):
        conf.port = 443
    else:
        conf.port = 80

    if conf.port < 1 or conf.port > 65535:
        errMsg = "invalid target URL port (%d)" % conf.port
        raise SqlmapSyntaxException(errMsg)

    conf.url = getUnicode("%s://%s%s%s" % (conf.scheme, ("[%s]" % conf.hostname) if conf.ipv6 else conf.hostname, (":%d" % conf.port) if not (conf.port == 80 and conf.scheme == "http" or conf.port == 443 and conf.scheme == "https") else "", conf.path))
    conf.url = conf.url.replace(URI_QUESTION_MARKER, '?')

    if urlSplit.query:
        if '=' not in urlSplit.query:
            conf.url = "%s?%s" % (conf.url, getUnicode(urlSplit.query))
        else:
            conf.parameters[PLACE.GET] = urldecode(urlSplit.query, spaceplus=not conf.base64Parameter) if urlSplit.query and urlencode(DEFAULT_GET_POST_DELIMITER, None) not in urlSplit.query else urlSplit.query

    if (intersect(REFERER_ALIASES, conf.testParameter, True) or conf.level >= 3) and not any(_[0].upper() == HTTP_HEADER.REFERER.upper() for _ in conf.httpHeaders):
        debugMsg = "setting the HTTP Referer header to the target URL"
        
        conf.httpHeaders = [_ for _ in conf.httpHeaders if _[0] != HTTP_HEADER.REFERER]
        conf.httpHeaders.append((HTTP_HEADER.REFERER, conf.url.replace(kb.customInjectionMark, "")))

    if (intersect(HOST_ALIASES, conf.testParameter, True) or conf.level >= 5) and not any(_[0].upper() == HTTP_HEADER.HOST.upper() for _ in conf.httpHeaders):
        debugMsg = "setting the HTTP Host header to the target URL"
        
        conf.httpHeaders = [_ for _ in conf.httpHeaders if _[0] != HTTP_HEADER.HOST]
        conf.httpHeaders.append((HTTP_HEADER.HOST, getHostHeader(conf.url)))

    if conf.url != originalUrl:
        kb.originalUrls[conf.url] = originalUrl

def escapeJsonValue(value):
    """
    Escapes JSON value (used in payloads)

    # Reference: https://stackoverflow.com/a/16652683

    >>> "\\n" in escapeJsonValue("foo\\nbar")
    False
    >>> "\\\\t" in escapeJsonValue("foo\\tbar")
    True
    """

    retVal = ""

    for char in value:
        if char < ' ' or char == '"':
            retVal += json.dumps(char)[1:-1]
        else:
            retVal += char

    return retVal

def expandAsteriskForColumns(expression):
    """
    If the user provided an asterisk rather than the column(s)
    name, sqlmap will retrieve the columns itself and reprocess
    the SQL query string (expression)
    """

    match = re.search(r"(?i)\ASELECT(\s+TOP\s+[\d]+)?\s+\*\s+FROM\s+(([`'\"][^`'\"]+[`'\"]|[\w.]+)+)(\s|\Z)", expression)

    if match:
        infoMsg = "you did not provide the fields in your query. "
        infoMsg += "sqlmap will retrieve the column names itself"
        

        _ = match.group(2).replace("..", '.').replace(".dbo.", '.')
        db, conf.tbl = _.split('.', 1) if '.' in _ else (None, _)

        if db is None:
            if expression != conf.sqlQuery:
                conf.db = db
            elif conf.db:
                expression = re.sub(r"([^\w])%s" % re.escape(conf.tbl), r"\g<1>%s.%s" % (conf.db, conf.tbl), expression)
        else:
            conf.db = db

        conf.db = safeSQLIdentificatorNaming(conf.db)
        conf.tbl = safeSQLIdentificatorNaming(conf.tbl, True)

        columnsDict = conf.dbmsHandler.getColumns(onlyColNames=True)

        if columnsDict and conf.db in columnsDict and conf.tbl in columnsDict[conf.db]:
            columns = list(columnsDict[conf.db][conf.tbl].keys())
            columns.sort()
            columnsStr = ", ".join(column for column in columns)
            expression = expression.replace('*', columnsStr, 1)

            infoMsg = "the query with expanded column name(s) is: "
            infoMsg += "%s" % expression
            

    return expression

def getLimitRange(count, plusOne=False):
    """
    Returns range of values used in limit/offset constructs

    >>> [_ for _ in getLimitRange(10)]
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
    """

    retVal = None
    count = int(count)
    limitStart, limitStop = 1, count
    reverse = False

    if kb.dumpTable:
        if conf.limitStart and conf.limitStop and conf.limitStart > conf.limitStop:
            limitStop = conf.limitStart
            limitStart = conf.limitStop
            reverse = True
        else:
            if isinstance(conf.limitStop, int) and conf.limitStop > 0 and conf.limitStop < limitStop:
                limitStop = conf.limitStop

            if isinstance(conf.limitStart, int) and conf.limitStart > 0 and conf.limitStart <= limitStop:
                limitStart = conf.limitStart

    retVal = xrange(limitStart, limitStop + 1) if plusOne else xrange(limitStart - 1, limitStop)

    if reverse:
        retVal = xrange(retVal[-1], retVal[0] - 1, -1)

    return retVal

def parseUnionPage(page):
    """
    Returns resulting items from UNION query inside provided page content

    >>> parseUnionPage("%sfoo%s%sbar%s" % (kb.chars.start, kb.chars.stop, kb.chars.start, kb.chars.stop))
    ['foo', 'bar']
    """

    if page is None:
        return None

    if re.search(r"(?si)\A%s.*%s\Z" % (kb.chars.start, kb.chars.stop), page):
        if len(page) > LARGE_OUTPUT_THRESHOLD:
            warnMsg = "large output detected. This might take a while"
            

        data = BigArray()
        keys = set()

        for match in re.finditer(r"%s(.*?)%s" % (kb.chars.start, kb.chars.stop), page, re.DOTALL | re.IGNORECASE):
            entry = match.group(1)

            if kb.chars.start in entry:
                entry = entry.split(kb.chars.start)[-1]

            if kb.unionDuplicates:
                key = entry.lower()
                if key not in keys:
                    keys.add(key)
                else:
                    continue

            entry = entry.split(kb.chars.delimiter)

            if conf.hexConvert:
                entry = applyFunctionRecursively(entry, decodeDbmsHexValue)

            if kb.safeCharEncode:
                entry = applyFunctionRecursively(entry, safecharencode)

            data.append(entry[0] if len(entry) == 1 else entry)
    else:
        data = page

    if len(data) == 1 and isinstance(data[0], six.string_types):
        data = data[0]

    return data

def parseFilePaths(page):
    """
    Detects (possible) absolute system paths inside the provided page content

    >>> _ = "/var/www/html/index.php"; parseFilePaths("<html>Error occurred at line 207 of: %s<br>Please contact your administrator</html>" % _); _ in kb.absFilePaths
    True
    """

    if page:
        for regex in FILE_PATH_REGEXES:
            for match in re.finditer(regex, page):
                absFilePath = match.group("result").strip()
                page = page.replace(absFilePath, "")

                if isWindowsDriveLetterPath(absFilePath):
                    absFilePath = posixToNtSlashes(absFilePath)

                if absFilePath not in kb.absFilePaths:
                    kb.absFilePaths.add(absFilePath)

def getLocalIP():
    """
    Get local IP address (exposed to the remote/target)
    """

    retVal = None

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((conf.hostname, conf.port))
        retVal, _ = s.getsockname()
        s.close()
    except:
        debugMsg = "there was an error in opening socket "
        debugMsg += "connection toward '%s'" % conf.hostname
        

    return retVal

def getRemoteIP():
    """
    Get remote/target IP address

    >>> pushValue(conf.hostname)
    >>> conf.hostname = "localhost"
    >>> getRemoteIP() == "127.0.0.1"
    True
    >>> conf.hostname = popValue()
    """

    retVal = None

    try:
        retVal = socket.gethostbyname(conf.hostname)
    except socket.gaierror:
        errMsg = "address resolution problem "
        errMsg += "occurred for hostname '%s'" % conf.hostname
        singleTimeLogMessage(errMsg, logging.ERROR)

    return retVal

def getCharset(charsetType=None):
    """
    Returns list with integers representing characters of a given
    charset type appropriate for inference techniques

    >>> getCharset(CHARSET_TYPE.BINARY)
    [0, 1, 47, 48, 49]
    """

    asciiTbl = []

    if charsetType is None:
        asciiTbl.extend(xrange(0, 128))

    # Binary
    elif charsetType == CHARSET_TYPE.BINARY:
        asciiTbl.extend((0, 1))
        asciiTbl.extend(xrange(47, 50))

    # Digits
    elif charsetType == CHARSET_TYPE.DIGITS:
        asciiTbl.extend((0, 9))
        asciiTbl.extend(xrange(47, 58))

    # Hexadecimal
    elif charsetType == CHARSET_TYPE.HEXADECIMAL:
        asciiTbl.extend((0, 1))
        asciiTbl.extend(xrange(47, 58))
        asciiTbl.extend(xrange(64, 71))
        asciiTbl.extend((87, 88))  # X
        asciiTbl.extend(xrange(96, 103))
        asciiTbl.extend((119, 120))  # x

    # Characters
    elif charsetType == CHARSET_TYPE.ALPHA:
        asciiTbl.extend((0, 1))
        asciiTbl.extend(xrange(64, 91))
        asciiTbl.extend(xrange(96, 123))

    # Characters and digits
    elif charsetType == CHARSET_TYPE.ALPHANUM:
        asciiTbl.extend((0, 1))
        asciiTbl.extend(xrange(47, 58))
        asciiTbl.extend(xrange(64, 91))
        asciiTbl.extend(xrange(96, 123))

    return asciiTbl

def directoryPath(filepath):
    """
    Returns directory path for a given filepath

    >>> directoryPath('/var/log/apache.log')
    '/var/log'
    >>> directoryPath('/var/log')
    '/var/log'
    """

    retVal = filepath

    if filepath and os.path.splitext(filepath)[-1]:
        retVal = ntpath.dirname(filepath) if isWindowsDriveLetterPath(filepath) else posixpath.dirname(filepath)

    return retVal

def normalizePath(filepath):
    """
    Returns normalized string representation of a given filepath

    >>> normalizePath('//var///log/apache.log')
    '/var/log/apache.log'
    """

    retVal = filepath

    if retVal:
        retVal = retVal.strip("\r\n")
        retVal = ntpath.normpath(retVal) if isWindowsDriveLetterPath(retVal) else re.sub(r"\A/{2,}", "/", posixpath.normpath(retVal))

    return retVal

def safeFilepathEncode(filepath):
    """
    Returns filepath in (ASCII) format acceptable for OS handling (e.g. reading)

    >>> 'sqlmap' in safeFilepathEncode(paths.HOME_PATH)
    True
    """

    retVal = filepath

    if filepath and six.PY2 and isinstance(filepath, six.text_type):
        retVal = getBytes(filepath, sys.getfilesystemencoding() or UNICODE_ENCODING)

    return retVal


def safeExpandUser(filepath):
    """
    Patch for a Python Issue18171 (http://bugs.python.org/issue18171)

    >>> os.path.basename(__file__) in safeExpandUser(__file__)
    True
    """

    retVal = filepath

    try:
        retVal = os.path.expanduser(filepath)
    except UnicodeError:
        _ = locale.getdefaultlocale()
        encoding = _[1] if _ and len(_) > 1 else UNICODE_ENCODING
        retVal = getUnicode(os.path.expanduser(filepath.encode(encoding)), encoding=encoding)

    return retVal

def safeStringFormat(format_, params):
    """
    Avoids problems with inappropriate string format strings

    >>> safeStringFormat('SELECT foo FROM %s LIMIT %d', ('bar', '1'))
    'SELECT foo FROM bar LIMIT 1'
    >>> safeStringFormat("SELECT foo FROM %s WHERE name LIKE '%susan%' LIMIT %d", ('bar', '1'))
    "SELECT foo FROM bar WHERE name LIKE '%susan%' LIMIT 1"
    """

    if format_.count(PAYLOAD_DELIMITER) == 2:
        _ = format_.split(PAYLOAD_DELIMITER)
        _[1] = re.sub(r"(\A|[^A-Za-z0-9])(%d)([^A-Za-z0-9]|\Z)", r"\g<1>%s\g<3>", _[1])
        retVal = PAYLOAD_DELIMITER.join(_)
    else:
        retVal = re.sub(r"(\A|[^A-Za-z0-9])(%d)([^A-Za-z0-9]|\Z)", r"\g<1>%s\g<3>", format_)

    if isinstance(params, six.string_types):
        retVal = retVal.replace("%s", params, 1)
    elif not isListLike(params):
        retVal = retVal.replace("%s", getUnicode(params), 1)
    else:
        start, end = 0, len(retVal)
        match = re.search(r"%s(.+)%s" % (PAYLOAD_DELIMITER, PAYLOAD_DELIMITER), retVal)
        if match and PAYLOAD_DELIMITER not in match.group(1):
            start, end = match.start(), match.end()
        if retVal.count("%s", start, end) == len(params):
            for param in params:
                index = retVal.find("%s", start)
                if isinstance(param, six.string_types):
                    param = param.replace('%', PARAMETER_PERCENTAGE_MARKER)
                retVal = retVal[:index] + getUnicode(param) + retVal[index + 2:]
        else:
            if any('%s' in _ for _ in conf.parameters.values()):
                parts = format_.split(' ')
                for i in xrange(len(parts)):
                    if PAYLOAD_DELIMITER in parts[i]:
                        parts[i] = parts[i].replace(PAYLOAD_DELIMITER, "")
                        parts[i] = "%s%s" % (parts[i], PAYLOAD_DELIMITER)
                        break
                format_ = ' '.join(parts)

            count = 0
            while True:
                match = re.search(r"(\A|[^A-Za-z0-9])(%s)([^A-Za-z0-9]|\Z)", retVal)
                if match:
                    if count >= len(params):
                        warnMsg = "wrong number of parameters during string formatting. "
                        raise SqlmapValueException(warnMsg)
                    else:
                        try:
                            retVal = re.sub(r"(\A|[^A-Za-z0-9])(%s)([^A-Za-z0-9]|\Z)", r"\g<1>%s\g<3>" % params[count], retVal, 1)
                        except re.error:
                            retVal = retVal.replace(match.group(0), match.group(0) % params[count], 1)
                        count += 1
                else:
                    break

    retVal = getText(retVal).replace(PARAMETER_PERCENTAGE_MARKER, '%')

    return retVal

def getFilteredPageContent(page, onlyText=True, split=" "):
    """
    Returns filtered page content without script, style and/or comments
    or all HTML tags

    >>> getFilteredPageContent(u'<html><title>foobar</title><body>test</body></html>') == "foobar test"
    True
    """

    retVal = page

    # only if the page's charset has been successfully identified
    if isinstance(page, six.text_type):
        retVal = re.sub(r"(?si)<script.+?</script>|<!--.+?-->|<style.+?</style>%s" % (r"|<[^>]+>|\t|\n|\r" if onlyText else ""), split, page)
        retVal = re.sub(r"%s{2,}" % split, split, retVal)
        retVal = htmlUnescape(retVal.strip().strip(split))

    return retVal

def getPageWordSet(page):
    """
    Returns word set used in page content

    >>> sorted(getPageWordSet(u'<html><title>foobar</title><body>test</body></html>')) == [u'foobar', u'test']
    True
    """

    retVal = set()

    # only if the page's charset has been successfully identified
    if isinstance(page, six.string_types):
        retVal = set(_.group(0) for _ in re.finditer(r"\w+", getFilteredPageContent(page)))

    return retVal

def showStaticWords(firstPage, secondPage, minLength=3):
    """
    Prints words appearing in two different response pages

    >>> showStaticWords("this is a test", "this is another test")
    ['this']
    """

    infoMsg = "finding static words in longest matching part of dynamic page content"
    

    firstPage = getFilteredPageContent(firstPage)
    secondPage = getFilteredPageContent(secondPage)

    infoMsg = "static words: "

    if firstPage and secondPage:
        match = SequenceMatcher(None, firstPage, secondPage).find_longest_match(0, len(firstPage), 0, len(secondPage))
        commonText = firstPage[match[0]:match[0] + match[2]]
        commonWords = getPageWordSet(commonText)
    else:
        commonWords = None

    if commonWords:
        commonWords = [_ for _ in commonWords if len(_) >= minLength]
        commonWords.sort(key=functools.cmp_to_key(lambda a, b: cmp(a.lower(), b.lower())))

        for word in commonWords:
            infoMsg += "'%s', " % word

        infoMsg = infoMsg.rstrip(", ")
    else:
        infoMsg += "None"

    

    return commonWords

def isWindowsDriveLetterPath(filepath):
    """
    Returns True if given filepath starts with a Windows drive letter

    >>> isWindowsDriveLetterPath('C:\\boot.ini')
    True
    >>> isWindowsDriveLetterPath('/var/log/apache.log')
    False
    """

    return re.search(r"\A[\w]\:", filepath) is not None

def posixToNtSlashes(filepath):
    """
    Replaces all occurrences of Posix slashes in provided
    filepath with NT backslashes

    >>> posixToNtSlashes('C:/Windows')
    'C:\\\\Windows'
    """

    return filepath.replace('/', '\\') if filepath else filepath

def ntToPosixSlashes(filepath):
    """
    Replaces all occurrences of NT backslashes in provided
    filepath with Posix slashes

    >>> ntToPosixSlashes(r'C:\\Windows')
    'C:/Windows'
    """

    return filepath.replace('\\', '/') if filepath else filepath

def isHexEncodedString(subject):
    """
    Checks if the provided string is hex encoded

    >>> isHexEncodedString('DEADBEEF')
    True
    >>> isHexEncodedString('test')
    False
    """

    return re.match(r"\A[0-9a-fA-Fx]+\Z", subject) is not None

def getConsoleWidth(default=80):
    """
    Returns console width

    >>> any((getConsoleWidth(), True))
    True
    """

    width = None

    if os.getenv("COLUMNS", "").isdigit():
        width = int(os.getenv("COLUMNS"))
    else:
        try:
            output = shellExec("stty size")
            match = re.search(r"\A\d+ (\d+)", output)

            if match:
                width = int(match.group(1))
        except (OSError, MemoryError):
            pass

    if width is None:
        try:
            import curses

            stdscr = curses.initscr()
            _, width = stdscr.getmaxyx()
            curses.endwin()
        except:
            pass

    return width or default

def shellExec(cmd):
    """
    Executes arbitrary shell command

    >>> shellExec('echo 1').strip() == '1'
    True
    """

    retVal = ""

    try:
        retVal = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0] or ""
    except Exception as ex:
        retVal = getSafeExString(ex)
    finally:
        retVal = getText(retVal)

    return retVal

def parseXmlFile(xmlFile, handler):
    """
    Parses XML file by a given handler
    """

    try:
        with contextlib.closing(io.StringIO(readCachedFileContent(xmlFile))) as stream:
            parse(stream, handler)
    except (SAXParseException, UnicodeError) as ex:
        errMsg = "something appears to be wrong with "
        errMsg += "the file '%s' ('%s'). Please make " % (xmlFile, getSafeExString(ex))
        errMsg += "sure that you haven't made any changes to it"
        raise SqlmapInstallationException(errMsg)

def readCachedFileContent(filename, mode="rb"):
    """
    Cached reading of file content (avoiding multiple same file reading)

    >>> "readCachedFileContent" in readCachedFileContent(__file__)
    True
    """

    if filename not in kb.cache.content:
        with kb.locks.cache:
            if filename not in kb.cache.content:
                checkFile(filename)
                try:
                    with openFile(filename, mode) as f:
                        kb.cache.content[filename] = f.read()
                except (IOError, OSError, MemoryError) as ex:
                    errMsg = "something went wrong while trying "
                    errMsg += "to read the content of file '%s' ('%s')" % (filename, getSafeExString(ex))
                    raise SqlmapSystemException(errMsg)

    return kb.cache.content[filename]

def average(values):
    """
    Computes the arithmetic mean of a list of numbers.

    >>> "%.1f" % average([0.9, 0.9, 0.9, 1.0, 0.8, 0.9])
    '0.9'
    """

    return (1.0 * sum(values) / len(values)) if values else None

def stdev(values):
    """
    Computes standard deviation of a list of numbers.

    # Reference: http://www.goldb.org/corestats.html

    >>> "%.3f" % stdev([0.9, 0.9, 0.9, 1.0, 0.8, 0.9])
    '0.063'
    """

    if not values or len(values) < 2:
        return None
    else:
        avg = average(values)
        _ = 1.0 * sum(pow((_ or 0) - avg, 2) for _ in values)
        return sqrt(_ / (len(values) - 1))

def calculateDeltaSeconds(start):
    """
    Returns elapsed time from start till now

    >>> calculateDeltaSeconds(0) > 1151721660
    True
    """

    return time.time() - start

def initCommonOutputs():
    """
    Initializes dictionary containing common output values used by "good samaritan" feature

    >>> initCommonOutputs(); "information_schema" in kb.commonOutputs["Databases"]
    True
    """

    kb.commonOutputs = {}
    key = None

    for line in openFile(paths.COMMON_OUTPUTS, 'r'):
        if line.find('#') != -1:
            line = line[:line.find('#')]

        line = line.strip()

        if len(line) > 1:
            if line.startswith('[') and line.endswith(']'):
                key = line[1:-1]
            elif key:
                if key not in kb.commonOutputs:
                    kb.commonOutputs[key] = set()

                if line not in kb.commonOutputs[key]:
                    kb.commonOutputs[key].add(line)

def getFileItems(filename, commentPrefix='#', unicoded=True, lowercase=False, unique=False):
    """
    Returns newline delimited items contained inside file

    >>> "SELECT" in getFileItems(paths.SQL_KEYWORDS)
    True
    """

    retVal = list() if not unique else OrderedDict()

    if filename:
        filename = filename.strip('"\'')

    checkFile(filename)

    try:
        with openFile(filename, 'r', errors="ignore") if unicoded else open(filename, 'r') as f:
            for line in f:
                if commentPrefix:
                    if line.find(commentPrefix) != -1:
                        line = line[:line.find(commentPrefix)]

                line = line.strip()

                if line:
                    if lowercase:
                        line = line.lower()

                    if unique and line in retVal:
                        continue

                    if unique:
                        retVal[line] = True
                    else:
                        retVal.append(line)
    except (IOError, OSError, MemoryError) as ex:
        errMsg = "something went wrong while trying "
        errMsg += "to read the content of file '%s' ('%s')" % (filename, getSafeExString(ex))
        raise SqlmapSystemException(errMsg)

    return retVal if not unique else list(retVal.keys())

def goGoodSamaritan(prevValue, originalCharset):
    """
    Function for retrieving parameters needed for common prediction (good
    samaritan) feature.

    prevValue: retrieved query output so far (e.g. 'i').

    Returns commonValue if there is a complete single match (in kb.partRun
    of txt/common-outputs.txt under kb.partRun) regarding parameter
    prevValue. If there is no single value match, but multiple, commonCharset is
    returned containing more probable characters (retrieved from matched
    values in txt/common-outputs.txt) together with the rest of charset as
    otherCharset.
    """

    if kb.commonOutputs is None:
        initCommonOutputs()

    predictionSet = set()
    commonValue = None
    commonPattern = None
    countCommonValue = 0

    # If the header (e.g. Databases) we are looking for has common
    # outputs defined
    if kb.partRun in kb.commonOutputs:
        commonPartOutputs = kb.commonOutputs[kb.partRun]
        commonPattern = commonFinderOnly(prevValue, commonPartOutputs)

        # If the longest common prefix is the same as previous value then
        # do not consider it
        if commonPattern and commonPattern == prevValue:
            commonPattern = None

        # For each common output
        for item in commonPartOutputs:
            # Check if the common output (item) starts with prevValue
            # where prevValue is the enumerated character(s) so far
            if item.startswith(prevValue):
                commonValue = item
                countCommonValue += 1

                if len(item) > len(prevValue):
                    char = item[len(prevValue)]
                    predictionSet.add(char)

        # Reset single value if there is more than one possible common
        # output
        if countCommonValue > 1:
            commonValue = None

        commonCharset = []
        otherCharset = []

        # Split the original charset into common chars (commonCharset)
        # and other chars (otherCharset)
        for ordChar in originalCharset:
            if _unichr(ordChar) not in predictionSet:
                otherCharset.append(ordChar)
            else:
                commonCharset.append(ordChar)

        commonCharset.sort()

        return commonValue, commonPattern, commonCharset, originalCharset
    else:
        return None, None, None, originalCharset

def longestCommonPrefix(*sequences):
    """
    Returns longest common prefix occuring in given sequences

    # Reference: http://boredzo.org/blog/archives/2007-01-06/longest-common-prefix-in-python-2

    >>> longestCommonPrefix('foobar', 'fobar')
    'fo'
    """

    if len(sequences) == 1:
        return sequences[0]

    sequences = [pair[1] for pair in sorted((len(fi), fi) for fi in sequences)]

    if not sequences:
        return None

    for i, comparison_ch in enumerate(sequences[0]):
        for fi in sequences[1:]:
            ch = fi[i]

            if ch != comparison_ch:
                return fi[:i]

    return sequences[0]

def commonFinderOnly(initial, sequence):
    """
    Returns parts of sequence which start with the given initial string

    >>> commonFinderOnly("abcd", ["abcdefg", "foobar", "abcde"])
    'abcde'
    """

    return longestCommonPrefix(*[_ for _ in sequence if _.startswith(initial)])

def pushValue(value):
    """
    Push value to the stack (thread dependent)
    """

    exception = None
    success = False

    for i in xrange(PUSH_VALUE_EXCEPTION_RETRY_COUNT):
        try:
            getCurrentThreadData().valueStack.append(copy.deepcopy(value))
            success = True
            break
        except Exception as ex:
            exception = ex

    if not success:
        getCurrentThreadData().valueStack.append(None)

        if exception:
            raise exception

def popValue():
    """
    Pop value from the stack (thread dependent)

    >>> pushValue('foobar')
    >>> popValue()
    'foobar'
    """

    retVal = None

    try:
        retVal = getCurrentThreadData().valueStack.pop()
    except IndexError:
        pass

    return retVal

def wasLastResponseDBMSError():
    """
    Returns True if the last web request resulted in a (recognized) DBMS error page
    """

    threadData = getCurrentThreadData()
    return threadData.lastErrorPage and threadData.lastErrorPage[0] == threadData.lastRequestUID

def wasLastResponseHTTPError():
    """
    Returns True if the last web request resulted in an erroneous HTTP code (like 500)
    """

    threadData = getCurrentThreadData()
    return threadData.lastHTTPError and threadData.lastHTTPError[0] == threadData.lastRequestUID

def adjustTimeDelay(lastQueryDuration, lowerStdLimit):
    """
    Provides tip for adjusting time delay in time-based data retrieval
    """

    candidate = (1 if not isHeavyQueryBased() else 2) + int(round(lowerStdLimit))

    kb.delayCandidates = [candidate] + kb.delayCandidates[:-1]

    if all((_ == candidate for _ in kb.delayCandidates)) and candidate < conf.timeSec:
        if lastQueryDuration / (1.0 * conf.timeSec / candidate) > MIN_VALID_DELAYED_RESPONSE:  # Note: to prevent problems with fast responses for heavy-queries like RANDOMBLOB
            conf.timeSec = candidate

            infoMsg = "adjusting time delay to "
            infoMsg += "%d second%s due to good response times" % (conf.timeSec, 's' if conf.timeSec > 1 else '')
            

def getLastRequestHTTPError():
    """
    Returns last HTTP error code
    """

    threadData = getCurrentThreadData()
    return threadData.lastHTTPError[1] if threadData.lastHTTPError else None

def extractErrorMessage(page):
    """
    Returns reported error message from page if it founds one

    >>> getText(extractErrorMessage(u'<html><title>Test</title>\\n<b>Warning</b>: oci_parse() [function.oci-parse]: ORA-01756: quoted string not properly terminated<br><p>Only a test page</p></html>') )
    'oci_parse() [function.oci-parse]: ORA-01756: quoted string not properly terminated'
    >>> extractErrorMessage('Warning: This is only a dummy foobar test') is None
    True
    """

    retVal = None

    if isinstance(page, six.string_types):
        if wasLastResponseDBMSError():
            page = re.sub(r"<[^>]+>", "", page)

        for regex in ERROR_PARSING_REGEXES:
            match = re.search(regex, page, re.IGNORECASE)

            if match:
                candidate = htmlUnescape(match.group("result")).replace("<br>", "\n").strip()
                if candidate and (1.0 * len(re.findall(r"[^A-Za-z,. ]", candidate)) / len(candidate) > MIN_ERROR_PARSING_NON_WRITING_RATIO):
                    retVal = candidate
                    break

        if not retVal and wasLastResponseDBMSError():
            match = re.search(r"[^\n]*SQL[^\n:]*:[^\n]*", page, re.IGNORECASE)

            if match:
                retVal = match.group(0)

    return retVal

def findLocalPort(ports):
    """
    Find the first opened localhost port from a given list of ports (e.g. for Tor port checks)
    """

    retVal = None

    for port in ports:
        try:
            try:
                s = socket._orig_socket(socket.AF_INET, socket.SOCK_STREAM)
            except AttributeError:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((LOCALHOST, port))
            retVal = port
            break
        except socket.error:
            pass
        finally:
            try:
                s.close()
            except socket.error:
                pass

    return retVal

def findMultipartPostBoundary(post):
    """
    Finds value for a boundary parameter in given multipart POST body

    >>> findMultipartPostBoundary("-----------------------------9051914041544843365972754266\\nContent-Disposition: form-data; name=text\\n\\ndefault")
    '9051914041544843365972754266'
    """

    retVal = None

    done = set()
    candidates = []

    for match in re.finditer(r"(?m)^--(.+?)(--)?$", post or ""):
        _ = match.group(1).strip().strip('-')

        if _ in done:
            continue
        else:
            candidates.append((post.count(_), _))
            done.add(_)

    if candidates:
        candidates.sort(key=lambda _: _[0], reverse=True)
        retVal = candidates[0][1]

    return retVal

def urldecode(value, encoding=None, unsafe="%%?&=;+%s" % CUSTOM_INJECTION_MARK_CHAR, convall=False, spaceplus=True):
    """
    URL decodes given value

    >>> urldecode('AND%201%3E%282%2B3%29%23', convall=True) == 'AND 1>(2+3)#'
    True
    >>> urldecode('AND%201%3E%282%2B3%29%23', convall=False) == 'AND 1>(2%2B3)#'
    True
    >>> urldecode(b'AND%201%3E%282%2B3%29%23', convall=False) == 'AND 1>(2%2B3)#'
    True
    """

    result = value

    if value:
        value = getUnicode(value)

        if convall:
            result = _urllib.parse.unquote_plus(value) if spaceplus else _urllib.parse.unquote(value)
        else:
            result = value
            charset = set(string.printable) - set(unsafe)

            def _(match):
                char = decodeHex(match.group(1), binary=False)
                return char if char in charset else match.group(0)

            if spaceplus:
                result = result.replace('+', ' ')  # plus sign has a special meaning in URL encoded data (hence the usage of _urllib.parse.unquote_plus in convall case)

            result = re.sub(r"%([0-9a-fA-F]{2})", _, result or "")

        result = getUnicode(result, encoding or UNICODE_ENCODING)

    return result

def urlencode(value, safe="%&=-_", convall=False, limit=False, spaceplus=False):
    """
    URL encodes given value

    >>> urlencode('AND 1>(2+3)#')
    'AND%201%3E%282%2B3%29%23'
    >>> urlencode("AND COUNT(SELECT name FROM users WHERE name LIKE '%DBA%')>0")
    'AND%20COUNT%28SELECT%20name%20FROM%20users%20WHERE%20name%20LIKE%20%27%25DBA%25%27%29%3E0'
    >>> urlencode("AND COUNT(SELECT name FROM users WHERE name LIKE '%_SYSTEM%')>0")
    'AND%20COUNT%28SELECT%20name%20FROM%20users%20WHERE%20name%20LIKE%20%27%25_SYSTEM%25%27%29%3E0'
    >>> urlencode("SELECT NAME FROM TABLE WHERE VALUE LIKE '%SOME%BEGIN%'")
    'SELECT%20NAME%20FROM%20TABLE%20WHERE%20VALUE%20LIKE%20%27%25SOME%25BEGIN%25%27'
    """

    if conf.get("direct"):
        return value

    count = 0
    result = None if value is None else ""

    if value:
        value = re.sub(r"\b[$\w]+=", lambda match: match.group(0).replace('$', DOLLAR_MARKER), value)

        if Backend.isDbms(DBMS.MSSQL) and not kb.tamperFunctions and any(ord(_) > 255 for _ in value):
            warnMsg = "if you experience problems with "
            warnMsg += "non-ASCII identifier names "
            warnMsg += "you are advised to rerun with '--tamper=charunicodeencode'"
            singleTimeWarnMessage(warnMsg)

        if convall or safe is None:
            safe = ""

        # corner case when character % really needs to be
        # encoded (when not representing URL encoded char)
        # except in cases when tampering scripts are used
        if all('%' in _ for _ in (safe, value)) and not kb.tamperFunctions:
            value = re.sub(r"(?i)\bLIKE\s+'[^']+'", lambda match: match.group(0).replace('%', "%25"), value)
            value = re.sub(r"%(?![0-9a-fA-F]{2})", "%25", value)

        while True:
            result = _urllib.parse.quote(getBytes(value), safe)

            if limit and len(result) > URLENCODE_CHAR_LIMIT:
                if count >= len(URLENCODE_FAILSAFE_CHARS):
                    break

                while count < len(URLENCODE_FAILSAFE_CHARS):
                    safe += URLENCODE_FAILSAFE_CHARS[count]
                    count += 1
                    if safe[-1] in value:
                        break
            else:
                break

        if spaceplus:
            result = result.replace(_urllib.parse.quote(' '), '+')

        result = result.replace(DOLLAR_MARKER, '$')

    return result

def runningAsAdmin():
    """
    Returns True if the current process is run under admin privileges
    """

    isAdmin = None

    if PLATFORM in ("posix", "mac"):
        _ = os.geteuid()

        isAdmin = isinstance(_, (float, six.integer_types)) and _ == 0
    elif IS_WIN:
        import ctypes

        _ = ctypes.windll.shell32.IsUserAnAdmin()

        isAdmin = isinstance(_, (float, six.integer_types)) and _ == 1
    else:
        errMsg = "sqlmap is not able to check if you are running it "
        errMsg += "as an administrator account on this platform. "
        errMsg += "sqlmap will assume that you are an administrator "
        errMsg += "which is mandatory for the requested takeover attack "
        errMsg += "to work properly"
        

        isAdmin = True

    return isAdmin

def logHTTPTraffic(requestLogMsg, responseLogMsg, startTime=None, endTime=None):
    """
    Logs HTTP traffic to the output file
    """

    if conf.harFile:
        conf.httpCollector.collectRequest(requestLogMsg, responseLogMsg, startTime, endTime)

    if conf.trafficFile:
        with kb.locks.log:
            dataToTrafficFile("%s%s" % (requestLogMsg, os.linesep))
            dataToTrafficFile("%s%s" % (responseLogMsg, os.linesep))
            dataToTrafficFile("%s%s%s%s" % (os.linesep, 76 * '#', os.linesep, os.linesep))

def getPageTemplate(payload, place):  # Cross-referenced function
    raise NotImplementedError

def getPublicTypeMembers(type_, onlyValues=False):
    """
    Useful for getting members from types (e.g. in enums)

    >>> [_ for _ in getPublicTypeMembers(OS, True)]
    ['Linux', 'Windows']
    >>> [_ for _ in getPublicTypeMembers(PAYLOAD.TECHNIQUE, True)]
    [1, 2, 3, 4, 5, 6]
    """

    retVal = []

    for name, value in inspect.getmembers(type_):
        if not name.startswith("__"):
            if not onlyValues:
                retVal.append((name, value))
            else:
                retVal.append(value)

    return retVal

def enumValueToNameLookup(type_, value_):
    """
    Returns name of a enum member with a given value

    >>> enumValueToNameLookup(SORT_ORDER, 100)
    'LAST'
    """

    retVal = None

    for name, value in getPublicTypeMembers(type_):
        if value == value_:
            retVal = name
            break

    return retVal

def extractRegexResult(regex, content, flags=0):
    """
    Returns 'result' group value from a possible match with regex on a given
    content

    >>> extractRegexResult(r'a(?P<result>[^g]+)g', 'abcdefg')
    'bcdef'
    >>> extractRegexResult(r'a(?P<result>[^g]+)g', 'ABCDEFG', re.I)
    'BCDEF'
    """

    retVal = None

    if regex and content and "?P<result>" in regex:
        if isinstance(content, six.binary_type) and isinstance(regex, six.text_type):
            regex = getBytes(regex)

        match = re.search(regex, content, flags)

        if match:
            retVal = match.group("result")

    return retVal

def extractTextTagContent(page):
    """
    Returns list containing content from "textual" tags

    >>> extractTextTagContent('<html><head><title>Title</title></head><body><pre>foobar</pre><a href="#link">Link</a></body></html>')
    ['Title', 'foobar']
    """

    page = page or ""

    if REFLECTED_VALUE_MARKER in page:
        try:
            page = re.sub(r"(?i)[^\s>]*%s[^\s<]*" % REFLECTED_VALUE_MARKER, "", page)
        except MemoryError:
            page = page.replace(REFLECTED_VALUE_MARKER, "")

    return filterNone(_.group("result").strip() for _ in re.finditer(TEXT_TAG_REGEX, page))

def trimAlphaNum(value):
    """
    Trims alpha numeric characters from start and ending of a given value

    >>> trimAlphaNum('AND 1>(2+3)-- foobar')
    ' 1>(2+3)-- '
    """

    while value and value[-1].isalnum():
        value = value[:-1]

    while value and value[0].isalnum():
        value = value[1:]

    return value

def isNumPosStrValue(value):
    """
    Returns True if value is a string (or integer) with a positive integer representation

    >>> isNumPosStrValue(1)
    True
    >>> isNumPosStrValue('1')
    True
    >>> isNumPosStrValue(0)
    False
    >>> isNumPosStrValue('-2')
    False
    >>> isNumPosStrValue('100000000000000000000')
    False
    """

    retVal = False

    try:
        retVal = ((hasattr(value, "isdigit") and value.isdigit() and int(value) > 0) or (isinstance(value, int) and value > 0)) and int(value) < MAX_INT
    except ValueError:
        pass

    return retVal

def aliasToDbmsEnum(dbms):
    """
    Returns major DBMS name from a given alias

    >>> aliasToDbmsEnum('mssql')
    'Microsoft SQL Server'
    """

    retVal = None

    if dbms:
        for key, item in DBMS_DICT.items():
            if dbms.lower() in item[0] or dbms.lower() == key.lower():
                retVal = key
                break

    return retVal

def findDynamicContent(firstPage, secondPage):
    """
    This function checks if the provided pages have dynamic content. If they
    are dynamic, proper markings will be made

    >>> findDynamicContent("Lorem ipsum dolor sit amet, congue tation referrentur ei sed. Ne nec legimus habemus recusabo, natum reque et per. Facer tritani reprehendunt eos id, modus constituam est te. Usu sumo indoctum ad, pri paulo molestiae complectitur no.", "Lorem ipsum dolor sit amet, congue tation referrentur ei sed. Ne nec legimus habemus recusabo, natum reque et per. <script src='ads.js'></script>Facer tritani reprehendunt eos id, modus constituam est te. Usu sumo indoctum ad, pri paulo molestiae complectitur no.")
    >>> kb.dynamicMarkings
    [('natum reque et per. ', 'Facer tritani repreh')]
    """

    if not firstPage or not secondPage:
        return

    infoMsg = "searching for dynamic content"
    singleTimeLogMessage(infoMsg)

    blocks = list(SequenceMatcher(None, firstPage, secondPage).get_matching_blocks())
    kb.dynamicMarkings = []

    # Removing too small matching blocks
    for block in blocks[:]:
        (_, _, length) = block

        if length <= 2 * DYNAMICITY_BOUNDARY_LENGTH:
            blocks.remove(block)

    # Making of dynamic markings based on prefix/suffix principle
    if len(blocks) > 0:
        blocks.insert(0, None)
        blocks.append(None)

        for i in xrange(len(blocks) - 1):
            prefix = firstPage[blocks[i][0]:blocks[i][0] + blocks[i][2]] if blocks[i] else None
            suffix = firstPage[blocks[i + 1][0]:blocks[i + 1][0] + blocks[i + 1][2]] if blocks[i + 1] else None

            if prefix is None and blocks[i + 1][0] == 0:
                continue

            if suffix is None and (blocks[i][0] + blocks[i][2] >= len(firstPage)):
                continue

            if prefix and suffix:
                prefix = prefix[-DYNAMICITY_BOUNDARY_LENGTH:]
                suffix = suffix[:DYNAMICITY_BOUNDARY_LENGTH]

                for _ in (firstPage, secondPage):
                    match = re.search(r"(?s)%s(.+)%s" % (re.escape(prefix), re.escape(suffix)), _)
                    if match:
                        infix = match.group(1)
                        if infix[0].isalnum():
                            prefix = trimAlphaNum(prefix)
                        if infix[-1].isalnum():
                            suffix = trimAlphaNum(suffix)
                        break

            kb.dynamicMarkings.append((prefix if prefix else None, suffix if suffix else None))

    if len(kb.dynamicMarkings) > 0:
        infoMsg = "dynamic content marked for removal (%d region%s)" % (len(kb.dynamicMarkings), 's' if len(kb.dynamicMarkings) > 1 else '')
        singleTimeLogMessage(infoMsg)

def removeDynamicContent(page):
    """
    Removing dynamic content from supplied page basing removal on
    precalculated dynamic markings
    """

    if page:
        for item in kb.dynamicMarkings:
            prefix, suffix = item

            if prefix is None and suffix is None:
                continue
            elif prefix is None:
                page = re.sub(r"(?s)^.+%s" % re.escape(suffix), suffix.replace('\\', r'\\'), page)
            elif suffix is None:
                page = re.sub(r"(?s)%s.+$" % re.escape(prefix), prefix.replace('\\', r'\\'), page)
            else:
                page = re.sub(r"(?s)%s.+%s" % (re.escape(prefix), re.escape(suffix)), "%s%s" % (prefix.replace('\\', r'\\'), suffix.replace('\\', r'\\')), page)

    return page

def filterStringValue(value, charRegex, replacement=""):
    """
    Returns string value consisting only of chars satisfying supplied
    regular expression (note: it has to be in form [...])

    >>> filterStringValue('wzydeadbeef0123#', r'[0-9a-f]')
    'deadbeef0123'
    """

    retVal = value

    if value:
        retVal = re.sub(charRegex.replace("[", "[^") if "[^" not in charRegex else charRegex.replace("[^", "["), replacement, value)

    return retVal

def filterControlChars(value, replacement=' '):
    """
    Returns string value with control chars being supstituted with replacement character

    >>> filterControlChars('AND 1>(2+3)\\n--')
    'AND 1>(2+3) --'
    """

    return filterStringValue(value, PRINTABLE_CHAR_REGEX, replacement)

def filterNone(values):
    """
    Emulates filterNone([...]) functionality

    >>> filterNone([1, 2, "", None, 3])
    [1, 2, 3]
    """

    retVal = values

    if isinstance(values, _collections.Iterable):
        retVal = [_ for _ in values if _]

    return retVal

def isDBMSVersionAtLeast(minimum):
    """
    Checks if the recognized DBMS version is at least the version specified

    >>> pushValue(kb.dbmsVersion)
    >>> kb.dbmsVersion = "2"
    >>> isDBMSVersionAtLeast("1.3.4.1.4")
    True
    >>> isDBMSVersionAtLeast(2.1)
    False
    >>> isDBMSVersionAtLeast(">2")
    False
    >>> isDBMSVersionAtLeast(">=2.0")
    True
    >>> kb.dbmsVersion = "<2"
    >>> isDBMSVersionAtLeast("2")
    False
    >>> isDBMSVersionAtLeast("1.5")
    True
    >>> kb.dbmsVersion = "MySQL 5.4.3-log4"
    >>> isDBMSVersionAtLeast("5")
    True
    >>> kb.dbmsVersion = popValue()
    """

    retVal = None

    if not any(isNoneValue(_) for _ in (Backend.getVersion(), minimum)) and Backend.getVersion() != UNKNOWN_DBMS_VERSION:
        version = Backend.getVersion().replace(" ", "").rstrip('.')

        correction = 0.0
        if ">=" in version:
            pass
        elif '>' in version:
            correction = VERSION_COMPARISON_CORRECTION
        elif '<' in version:
            correction = -VERSION_COMPARISON_CORRECTION

        version = extractRegexResult(r"(?P<result>[0-9][0-9.]*)", version)

        if version:
            if '.' in version:
                parts = version.split('.', 1)
                parts[1] = filterStringValue(parts[1], '[0-9]')
                version = '.'.join(parts)

            try:
                version = float(filterStringValue(version, '[0-9.]')) + correction
            except ValueError:
                return None

            if isinstance(minimum, six.string_types):
                if '.' in minimum:
                    parts = minimum.split('.', 1)
                    parts[1] = filterStringValue(parts[1], '[0-9]')
                    minimum = '.'.join(parts)

                correction = 0.0
                if minimum.startswith(">="):
                    pass
                elif minimum.startswith(">"):
                    correction = VERSION_COMPARISON_CORRECTION

                minimum = float(filterStringValue(minimum, '[0-9.]')) + correction

            retVal = version >= minimum

    return retVal

def parseSqliteTableSchema(value):
    """
    Parses table column names and types from specified SQLite table schema

    >>> kb.data.cachedColumns = {}
    >>> parseSqliteTableSchema("CREATE TABLE users(\\n\\t\\tid INTEGER,\\n\\t\\tname TEXT\\n);")
    True
    >>> tuple(kb.data.cachedColumns[conf.db][conf.tbl].items()) == (('id', 'INTEGER'), ('name', 'TEXT'))
    True
    >>> parseSqliteTableSchema("CREATE TABLE dummy(`foo bar` BIGINT, \\"foo\\" VARCHAR, 'bar' TEXT)");
    True
    >>> tuple(kb.data.cachedColumns[conf.db][conf.tbl].items()) == (('foo bar', 'BIGINT'), ('foo', 'VARCHAR'), ('bar', 'TEXT'))
    True
    >>> parseSqliteTableSchema("CREATE TABLE suppliers(\\n\\tsupplier_id INTEGER PRIMARY KEY DESC,\\n\\tname TEXT NOT NULL\\n);");
    True
    >>> tuple(kb.data.cachedColumns[conf.db][conf.tbl].items()) == (('supplier_id', 'INTEGER'), ('name', 'TEXT'))
    True
    >>> parseSqliteTableSchema("CREATE TABLE country_languages (\\n\\tcountry_id INTEGER NOT NULL,\\n\\tlanguage_id INTEGER NOT NULL,\\n\\tPRIMARY KEY (country_id, language_id),\\n\\tFOREIGN KEY (country_id) REFERENCES countries (country_id) ON DELETE CASCADE ON UPDATE NO ACTION,\\tFOREIGN KEY (language_id) REFERENCES languages (language_id) ON DELETE CASCADE ON UPDATE NO ACTION);");
    True
    >>> tuple(kb.data.cachedColumns[conf.db][conf.tbl].items()) == (('country_id', 'INTEGER'), ('language_id', 'INTEGER'))
    True
    """

    retVal = False

    value = extractRegexResult(r"(?s)\((?P<result>.+)\)", value)

    if value:
        table = {}
        columns = OrderedDict()

        value = re.sub(r"\(.+?\)", "", value).strip()

        for match in re.finditer(r"(?:\A|,)\s*(([\"'`]).+?\2|\w+)(?:\s+(INT|INTEGER|TINYINT|SMALLINT|MEDIUMINT|BIGINT|UNSIGNED BIG INT|INT2|INT8|INTEGER|CHARACTER|VARCHAR|VARYING CHARACTER|NCHAR|NATIVE CHARACTER|NVARCHAR|TEXT|CLOB|LONGTEXT|BLOB|NONE|REAL|DOUBLE|DOUBLE PRECISION|FLOAT|REAL|NUMERIC|DECIMAL|BOOLEAN|DATE|DATETIME|NUMERIC)\b)?", decodeStringEscape(value), re.I):
            column = match.group(1).strip(match.group(2) or "")
            if re.search(r"(?i)\A(CONSTRAINT|PRIMARY|UNIQUE|CHECK|FOREIGN)\b", column.strip()):
                continue
            retVal = True

            columns[column] = match.group(3) or "TEXT"

        table[safeSQLIdentificatorNaming(conf.tbl, True)] = columns
        kb.data.cachedColumns[conf.db] = table

    return retVal

def getTechniqueData(technique=None):
    """
    Returns injection data for technique specified
    """

    return kb.injection.data.get(technique if technique is not None else getTechnique())

def isTechniqueAvailable(technique):
    """
    Returns True if there is injection data which sqlmap could use for technique specified

    >>> pushValue(kb.injection.data)
    >>> kb.injection.data[PAYLOAD.TECHNIQUE.ERROR] = [test for test in getSortedInjectionTests() if "error" in test["title"].lower()][0]
    >>> isTechniqueAvailable(PAYLOAD.TECHNIQUE.ERROR)
    True
    >>> kb.injection.data = popValue()
    """

    if conf.technique and isinstance(conf.technique, list) and technique not in conf.technique:
        return False
    else:
        return getTechniqueData(technique) is not None

def isHeavyQueryBased(technique=None):
    """
    Returns True whether current (kb.)technique is heavy-query based

    >>> pushValue(kb.injection.data)
    >>> setTechnique(PAYLOAD.TECHNIQUE.STACKED)
    >>> kb.injection.data[getTechnique()] = [test for test in getSortedInjectionTests() if "heavy" in test["title"].lower()][0]
    >>> isHeavyQueryBased()
    True
    >>> kb.injection.data = popValue()
    """

    retVal = False

    technique = technique or getTechnique()

    if isTechniqueAvailable(technique):
        data = getTechniqueData(technique)
        if data and "heavy query" in data["title"].lower():
            retVal = True

    return retVal

def isStackingAvailable():
    """
    Returns True whether techniques using stacking are available

    >>> pushValue(kb.injection.data)
    >>> kb.injection.data[PAYLOAD.TECHNIQUE.STACKED] = [test for test in getSortedInjectionTests() if "stacked" in test["title"].lower()][0]
    >>> isStackingAvailable()
    True
    >>> kb.injection.data = popValue()
    """

    retVal = False

    if PAYLOAD.TECHNIQUE.STACKED in kb.injection.data:
        retVal = True
    else:
        for technique in getPublicTypeMembers(PAYLOAD.TECHNIQUE, True):
            data = getTechniqueData(technique)
            if data and "stacked" in data["title"].lower():
                retVal = True
                break

    return retVal

def isInferenceAvailable():
    """
    Returns True whether techniques using inference technique are available

    >>> pushValue(kb.injection.data)
    >>> kb.injection.data[PAYLOAD.TECHNIQUE.BOOLEAN] = getSortedInjectionTests()[0]
    >>> isInferenceAvailable()
    True
    >>> kb.injection.data = popValue()
    """

    return any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.BOOLEAN, PAYLOAD.TECHNIQUE.STACKED, PAYLOAD.TECHNIQUE.TIME))

def setOptimize():
    """
    Sets options turned on by switch '-o'
    """

    # conf.predictOutput = True
    conf.keepAlive = True
    conf.threads = 3 if conf.threads < 3 and cmdLineOptions.threads is None else conf.threads
    conf.nullConnection = not any((conf.data, conf.textOnly, conf.titles, conf.string, conf.notString, conf.regexp, conf.tor))

    if not conf.nullConnection:
        debugMsg = "turning off switch '--null-connection' used indirectly by switch '-o'"
        

# def initTechnique(technique=None):
#     """
#     Prepares data for technique specified
#     """

#     try:
#         data = getTechniqueData(technique)
#         resetCounter(technique)

#         if data:
#             kb.pageTemplate, kb.errorIsNone = getPageTemplate(data.templatePayload, kb.injection.place)
#             kb.matchRatio = data.matchRatio
#             kb.negativeLogic = (technique == PAYLOAD.TECHNIQUE.BOOLEAN) and (data.where == PAYLOAD.WHERE.NEGATIVE)

#             # Restoring stored conf options
#             for key, value in kb.injection.conf.items():
#                 if value and (not hasattr(conf, key) or (hasattr(conf, key) and not getattr(conf, key))):
#                     setattr(conf, key, value)
#                     debugMsg = "resuming configuration option '%s' (%s)" % (key, ("'%s'" % value) if isinstance(value, six.string_types) else value)
                    

#                     if value and key == "optimize":
#                         setOptimize()
#         else:
#             warnMsg = "there is no injection data available for technique "
#             warnMsg += "'%s'" % enumValueToNameLookup(PAYLOAD.TECHNIQUE, technique)
            

#     except SqlmapDataException:
#         errMsg = "missing data in old session file(s). "
#         errMsg += "Please use '--flush-session' to deal "
#         errMsg += "with this error"
#         raise SqlmapNoneDataException(errMsg)

def arrayizeValue(value):
    """
    Makes a list out of value if it is not already a list or tuple itself

    >>> arrayizeValue('1')
    ['1']
    """

    if isinstance(value, _collections.KeysView):
        value = [_ for _ in value]
    elif not isListLike(value):
        value = [value]

    return value

def unArrayizeValue(value):
    """
    Makes a value out of iterable if it is a list or tuple itself

    >>> unArrayizeValue(['1'])
    '1'
    >>> unArrayizeValue('1')
    '1'
    >>> unArrayizeValue(['1', '2'])
    '1'
    >>> unArrayizeValue([['a', 'b'], 'c'])
    'a'
    >>> unArrayizeValue(_ for _ in xrange(10))
    0
    """

    if isListLike(value):
        if not value:
            value = None
        elif len(value) == 1 and not isListLike(value[0]):
            value = value[0]
        else:
            value = [_ for _ in flattenValue(value) if _ is not None]
            value = value[0] if len(value) > 0 else None
    elif inspect.isgenerator(value):
        value = unArrayizeValue([_ for _ in value])

    return value

def flattenValue(value):
    """
    Returns an iterator representing flat representation of a given value

    >>> [_ for _ in flattenValue([['1'], [['2'], '3']])]
    ['1', '2', '3']
    """

    for i in iter(value):
        if isListLike(i):
            for j in flattenValue(i):
                yield j
        else:
            yield i

def joinValue(value, delimiter=','):
    """
    Returns a value consisting of joined parts of a given value

    >>> joinValue(['1', '2'])
    '1,2'
    >>> joinValue('1')
    '1'
    """

    if isListLike(value):
        retVal = delimiter.join(value)
    else:
        retVal = value

    return retVal

def isListLike(value):
    """
    Returns True if the given value is a list-like instance

    >>> isListLike([1, 2, 3])
    True
    >>> isListLike('2')
    False
    """

    return isinstance(value, (list, tuple, set, OrderedSet, BigArray))

def getSortedInjectionTests():
    """
    Returns prioritized test list by eventually detected DBMS from error messages

    >>> pushValue(kb.forcedDbms)
    >>> kb.forcedDbms = DBMS.SQLITE
    >>> [test for test in getSortedInjectionTests() if hasattr(test, "details") and hasattr(test.details, "dbms")][0].details.dbms == kb.forcedDbms
    True
    >>> kb.forcedDbms = popValue()
    """

    retVal = copy.deepcopy(conf.tests)

    def priorityFunction(test):
        retVal = SORT_ORDER.FIRST

        if test.stype == PAYLOAD.TECHNIQUE.UNION:
            retVal = SORT_ORDER.LAST

        elif "details" in test and "dbms" in (test.details or {}):
            if intersect(test.details.dbms, Backend.getIdentifiedDbms()):
                retVal = SORT_ORDER.SECOND
            else:
                retVal = SORT_ORDER.THIRD

        return retVal

    if Backend.getIdentifiedDbms():
        retVal = sorted(retVal, key=priorityFunction)

    return retVal

def filterListValue(value, regex):
    """
    Returns list with items that have parts satisfying given regular expression

    >>> filterListValue(['users', 'admins', 'logs'], r'(users|admins)')
    ['users', 'admins']
    """

    if isinstance(value, list) and regex:
        retVal = [_ for _ in value if re.search(regex, _, re.I)]
    else:
        retVal = value

    return retVal

def showHttpErrorCodes():
    """
    Shows all HTTP error codes raised till now
    """

    if kb.httpErrorCodes:
        warnMsg = "HTTP error codes detected during run:\n"
        warnMsg += ", ".join("%d (%s) - %d times" % (code, _http_client.responses[code] if code in _http_client.responses else '?', count) for code, count in kb.httpErrorCodes.items())
        
        if any((str(_).startswith('4') or str(_).startswith('5')) and _ != _http_client.INTERNAL_SERVER_ERROR and _ != kb.originalCode for _ in kb.httpErrorCodes):
            msg = "too many 4xx and/or 5xx HTTP error codes "
            msg += "could mean that some kind of protection is involved (e.g. WAF)"
            

def openFile(filename, mode='r', encoding=UNICODE_ENCODING, errors="reversible", buffering=1):  # "buffering=1" means line buffered (Reference: http://stackoverflow.com/a/3168436)
    """
    Returns file handle of a given filename

    >>> "openFile" in openFile(__file__).read()
    True
    >>> b"openFile" in openFile(__file__, "rb", None).read()
    True
    """

    # Reference: https://stackoverflow.com/a/37462452
    if 'b' in mode:
        buffering = 0

    if filename == STDIN_PIPE_DASH:
        if filename not in kb.cache.content:
            kb.cache.content[filename] = sys.stdin.read()

        return contextlib.closing(io.StringIO(readCachedFileContent(filename)))
    else:
        try:
            return codecs.open(filename, mode, encoding, errors, buffering)
        except IOError:
            errMsg = "there has been a file opening error for filename '%s'. " % filename
            errMsg += "Please check %s permissions on a file " % ("write" if mode and ('w' in mode or 'a' in mode or '+' in mode) else "read")
            errMsg += "and that it's not locked by another process"
            raise SqlmapSystemException(errMsg)

def decodeIntToUnicode(value):
    """
    Decodes inferenced integer value to an unicode character

    >>> decodeIntToUnicode(35) == '#'
    True
    >>> decodeIntToUnicode(64) == '@'
    True
    """
    retVal = value

    if isinstance(value, int):
        try:
            if value > 255:
                _ = "%x" % value

                if len(_) % 2 == 1:
                    _ = "0%s" % _

                raw = decodeHex(_)

                if Backend.isDbms(DBMS.MYSQL):
                    # Reference: https://dev.mysql.com/doc/refman/8.0/en/string-functions.html#function_ord
                    # Note: https://github.com/sqlmapproject/sqlmap/issues/1531
                    retVal = getUnicode(raw, conf.encoding or UNICODE_ENCODING)
                elif Backend.isDbms(DBMS.MSSQL):
                    # Reference: https://docs.microsoft.com/en-us/sql/relational-databases/collations/collation-and-unicode-support?view=sql-server-2017 and https://stackoverflow.com/a/14488478
                    retVal = getUnicode(raw, "UTF-16-BE")
                elif Backend.getIdentifiedDbms() in (DBMS.PGSQL, DBMS.ORACLE, DBMS.SQLITE):     # Note: cases with Unicode code points (e.g. http://www.postgresqltutorial.com/postgresql-ascii/)
                    retVal = _unichr(value)
                else:
                    retVal = getUnicode(raw, conf.encoding)
            else:
                retVal = _unichr(value)
        except:
            retVal = INFERENCE_UNKNOWN_CHAR

    return retVal

def unhandledExceptionMessage():
    """
    Returns detailed message about occurred unhandled exception

    >>> all(_ in unhandledExceptionMessage() for _ in ("unhandled exception occurred", "Operating system", "Command line"))
    True
    """

    errMsg = "unhandled exception occurred in %s. It is recommended to retry your " % VERSION_STRING
    errMsg += "run with the latest development version from official GitHub "
    errMsg += "repository at '%s'. If the exception persists, please open a new issue " % GIT_PAGE
    errMsg += "at '%s' " % ISSUES_PAGE
    errMsg += "with the following text and any other information required to "
    errMsg += "reproduce the bug. Developers will try to reproduce the bug, fix it accordingly "
    errMsg += "and get back to you\n"
    errMsg += "Running version: %s\n" % VERSION_STRING[VERSION_STRING.find('/') + 1:]
    errMsg += "Python version: %s\n" % PYVERSION
    errMsg += "Operating system: %s\n" % platform.platform()
    errMsg += "Command line: %s\n" % re.sub(r".+?\bsqlmap\.py\b", "sqlmap.py", getUnicode(" ".join(sys.argv), encoding=getattr(sys.stdin, "encoding", None)))
    errMsg += "Technique: %s\n" % (enumValueToNameLookup(PAYLOAD.TECHNIQUE, getTechnique()) if getTechnique() is not None else ("DIRECT" if conf.get("direct") else None))
    errMsg += "Back-end DBMS:"

    if Backend.getDbms() is not None:
        errMsg += " %s (fingerprinted)" % Backend.getDbms()

    if Backend.getIdentifiedDbms() is not None and (Backend.getDbms() is None or Backend.getIdentifiedDbms() != Backend.getDbms()):
        errMsg += " %s (identified)" % Backend.getIdentifiedDbms()

    if not errMsg.endswith(')'):
        errMsg += " None"

    return errMsg

def getLatestRevision():
    """
    Retrieves latest revision from the offical repository
    """

    retVal = None
    req = _urllib.request.Request(url="https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/lib/core/settings.py", headers={HTTP_HEADER.USER_AGENT: fetchRandomAgent()})

    try:
        content = getUnicode(_urllib.request.urlopen(req).read())
        retVal = extractRegexResult(r"VERSION\s*=\s*[\"'](?P<result>[\d.]+)", content)
    except:
        pass

    return retVal

def fetchRandomAgent():
    """
    Returns random HTTP User-Agent header value

    >>> '(' in fetchRandomAgent()
    True
    """

    if not kb.userAgents:
        debugMsg = "loading random HTTP User-Agent header(s) from "
        debugMsg += "file '%s'" % paths.USER_AGENTS
        

        try:
            kb.userAgents = getFileItems(paths.USER_AGENTS)
        except IOError:
            errMsg = "unable to read HTTP User-Agent header "
            errMsg += "file '%s'" % paths.USER_AGENTS
            raise SqlmapSystemException(errMsg)

    return random.sample(kb.userAgents, 1)[0]

def maskSensitiveData(msg):
    """
    Masks sensitive data in the supplied message

    >>> maskSensitiveData('python sqlmap.py -u "http://www.test.com/vuln.php?id=1" --banner') == 'python sqlmap.py -u *********************************** --banner'
    True
    >>> maskSensitiveData('sqlmap.py -u test.com/index.go?id=index --auth-type=basic --auth-creds=foo:bar\\ndummy line') == 'sqlmap.py -u ************************** --auth-type=***** --auth-creds=*******\\ndummy line'
    True
    """

    retVal = getUnicode(msg)

    for item in filterNone(conf.get(_) for _ in SENSITIVE_OPTIONS):
        if isListLike(item):
            item = listToStrValue(item)

        regex = SENSITIVE_DATA_REGEX % re.sub(r"(\W)", r"\\\1", getUnicode(item))
        while extractRegexResult(regex, retVal):
            value = extractRegexResult(regex, retVal)
            retVal = retVal.replace(value, '*' * len(value))

    # Just in case (for problematic parameters regarding user encoding)
    for match in re.finditer(r"(?im)[ -]-(u|url|data|cookie|auth-\w+|proxy|host|referer|headers?|H)( |=)(.*?)(?= -?-[a-z]|$)", retVal):
        retVal = retVal.replace(match.group(3), '*' * len(match.group(3)))

    # Fail-safe substitutions
    retVal = re.sub(r"(?i)(Command line:.+)\b(https?://[^ ]+)", lambda match: "%s%s" % (match.group(1), '*' * len(match.group(2))), retVal)
    retVal = re.sub(r"(?i)(\b\w:[\\/]+Users[\\/]+|[\\/]+home[\\/]+)([^\\/]+)", lambda match: "%s%s" % (match.group(1), '*' * len(match.group(2))), retVal)

    if getpass.getuser():
        retVal = re.sub(r"(?i)\b%s\b" % re.escape(getpass.getuser()), '*' * len(getpass.getuser()), retVal)

    return retVal

def listToStrValue(value):
    """
    Flattens list to a string value

    >>> listToStrValue([1,2,3])
    '1, 2, 3'
    """

    if isinstance(value, (set, tuple, types.GeneratorType)):
        value = list(value)

    if isinstance(value, list):
        retVal = value.__str__().lstrip('[').rstrip(']')
    else:
        retVal = value

    return retVal

def intersect(containerA, containerB, lowerCase=False):
    """
    Returns intersection of the container-ized values

    >>> intersect([1, 2, 3], set([1,3]))
    [1, 3]
    """

    retVal = []

    if containerA and containerB:
        containerA = arrayizeValue(containerA)
        containerB = arrayizeValue(containerB)

        if lowerCase:
            containerA = [val.lower() if hasattr(val, "lower") else val for val in containerA]
            containerB = [val.lower() if hasattr(val, "lower") else val for val in containerB]

        retVal = [val for val in containerA if val in containerB]

    return retVal

def decodeStringEscape(value):
    """
    Decodes escaped string values (e.g. "\\t" -> "\t")
    """

    retVal = value

    if value and '\\' in value:
        charset = "\\%s" % string.whitespace.replace(" ", "")
        for _ in charset:
            retVal = retVal.replace(repr(_).strip("'"), _)

    return retVal

def encodeStringEscape(value):
    """
    Encodes escaped string values (e.g. "\t" -> "\\t")
    """

    retVal = value

    if value:
        charset = "\\%s" % string.whitespace.replace(" ", "")
        for _ in charset:
            retVal = retVal.replace(_, repr(_).strip("'"))

    return retVal

def removeReflectiveValues(content, payload, suppressWarning=False):
    """
    Neutralizes reflective values in a given content based on a payload
    (e.g. ..search.php?q=1 AND 1=2 --> "...searching for <b>1%20AND%201%3D2</b>..." --> "...searching for <b>__REFLECTED_VALUE__</b>...")
    """

    retVal = content

    try:
        if all((content, payload)) and isinstance(content, six.text_type) and kb.reflectiveMechanism and not kb.heuristicMode:
            def _(value):
                while 2 * REFLECTED_REPLACEMENT_REGEX in value:
                    value = value.replace(2 * REFLECTED_REPLACEMENT_REGEX, REFLECTED_REPLACEMENT_REGEX)
                return value

            payload = getUnicode(urldecode(payload.replace(PAYLOAD_DELIMITER, ""), convall=True))
            regex = _(filterStringValue(payload, r"[A-Za-z0-9]", encodeStringEscape(REFLECTED_REPLACEMENT_REGEX)))

            if regex != payload:
                if all(part.lower() in content.lower() for part in filterNone(regex.split(REFLECTED_REPLACEMENT_REGEX))[1:]):  # fast optimization check
                    parts = regex.split(REFLECTED_REPLACEMENT_REGEX)

                    # Note: naive approach
                    retVal = content.replace(payload, REFLECTED_VALUE_MARKER)
                    retVal = retVal.replace(re.sub(r"\A\w+", "", payload), REFLECTED_VALUE_MARKER)

                    if len(parts) > REFLECTED_MAX_REGEX_PARTS:  # preventing CPU hogs
                        regex = _("%s%s%s" % (REFLECTED_REPLACEMENT_REGEX.join(parts[:REFLECTED_MAX_REGEX_PARTS // 2]), REFLECTED_REPLACEMENT_REGEX, REFLECTED_REPLACEMENT_REGEX.join(parts[-REFLECTED_MAX_REGEX_PARTS // 2:])))

                    parts = filterNone(regex.split(REFLECTED_REPLACEMENT_REGEX))

                    if regex.startswith(REFLECTED_REPLACEMENT_REGEX):
                        regex = r"%s%s" % (REFLECTED_BORDER_REGEX, regex[len(REFLECTED_REPLACEMENT_REGEX):])
                    else:
                        regex = r"\b%s" % regex

                    if regex.endswith(REFLECTED_REPLACEMENT_REGEX):
                        regex = r"%s%s" % (regex[:-len(REFLECTED_REPLACEMENT_REGEX)], REFLECTED_BORDER_REGEX)
                    else:
                        regex = r"%s\b" % regex

                    _retVal = [retVal]

                    def _thread(regex):
                        try:
                            _retVal[0] = re.sub(r"(?i)%s" % regex, REFLECTED_VALUE_MARKER, _retVal[0])

                            if len(parts) > 2:
                                regex = REFLECTED_REPLACEMENT_REGEX.join(parts[1:])
                                _retVal[0] = re.sub(r"(?i)\b%s\b" % regex, REFLECTED_VALUE_MARKER, _retVal[0])
                        except KeyboardInterrupt:
                            raise
                        except:
                            pass

                    thread = threading.Thread(target=_thread, args=(regex,))
                    thread.daemon = True
                    thread.start()
                    thread.join(REFLECTED_REPLACEMENT_TIMEOUT)

                    if thread.is_alive():
                        kb.reflectiveMechanism = False
                        retVal = content
                            
                    else:
                        retVal = _retVal[0]

                if retVal != content:
                    kb.reflectiveCounters[REFLECTIVE_COUNTER.HIT] += 1
                    
                elif not kb.testMode and not kb.reflectiveCounters[REFLECTIVE_COUNTER.HIT]:
                    kb.reflectiveCounters[REFLECTIVE_COUNTER.MISS] += 1
                    if kb.reflectiveCounters[REFLECTIVE_COUNTER.MISS] > REFLECTIVE_MISS_THRESHOLD:
                        kb.reflectiveMechanism = False
                        
                            
    except (MemoryError, SystemError):
        kb.reflectiveMechanism = False
            

    return retVal

def normalizeUnicode(value, charset=string.printable[:string.printable.find(' ') + 1]):
    """
    Does an ASCII normalization of unicode strings

    # Reference: http://www.peterbe.com/plog/unicode-to-ascii

    >>> normalizeUnicode(u'\\u0161u\\u0107uraj') == u'sucuraj'
    True
    >>> normalizeUnicode(getUnicode(decodeHex("666f6f00626172"))) == u'foobar'
    True
    """

    retVal = value

    if isinstance(value, six.text_type):
        retVal = unicodedata.normalize("NFKD", value)
        retVal = "".join(_ for _ in retVal if _ in charset)

    return retVal

def safeSQLIdentificatorNaming(name, isTable=False):
    """
    Returns a safe representation of SQL identificator name (internal data format)

    # Reference: http://stackoverflow.com/questions/954884/what-special-characters-are-allowed-in-t-sql-column-retVal

    >>> pushValue(kb.forcedDbms)
    >>> kb.forcedDbms = DBMS.MSSQL
    >>> getText(safeSQLIdentificatorNaming("begin"))
    '[begin]'
    >>> getText(safeSQLIdentificatorNaming("foobar"))
    'foobar'
    >>> kb.forceDbms = popValue()
    """

    retVal = name

    if conf.unsafeNaming:
        return retVal

    if isinstance(name, six.string_types):
        retVal = getUnicode(name)
        _ = isTable and Backend.getIdentifiedDbms() in (DBMS.MSSQL, DBMS.SYBASE)

        if _:
            retVal = re.sub(r"(?i)\A\[?%s\]?\." % DEFAULT_MSSQL_SCHEMA, "%s." % DEFAULT_MSSQL_SCHEMA, retVal)

        # Note: SQL 92 has restrictions for identifiers starting with underscore (e.g. http://www.frontbase.com/documentation/FBUsers_4.pdf)
        if retVal.upper() in kb.keywords or (not isTable and (retVal or " ")[0] == '_') or (retVal or " ")[0].isdigit() or not re.match(r"\A[A-Za-z0-9_@%s\$]+\Z" % ('.' if _ else ""), retVal):  # MsSQL is the only DBMS where we automatically prepend schema to table name (dot is normal)
            if not conf.noEscape:
                retVal = unsafeSQLIdentificatorNaming(retVal)

                if Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.ACCESS, DBMS.CUBRID, DBMS.SQLITE):  # Note: in SQLite double-quotes are treated as string if column/identifier is non-existent (e.g. SELECT "foobar" FROM users)
                    retVal = "`%s`" % retVal
                elif Backend.getIdentifiedDbms() in (DBMS.PGSQL, DBMS.DB2, DBMS.HSQLDB, DBMS.H2, DBMS.INFORMIX, DBMS.MONETDB, DBMS.VERTICA, DBMS.MCKOI, DBMS.PRESTO, DBMS.CRATEDB, DBMS.CACHE, DBMS.EXTREMEDB, DBMS.FRONTBASE, DBMS.RAIMA, DBMS.VIRTUOSO):
                    retVal = "\"%s\"" % retVal
                elif Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.ALTIBASE, DBMS.MIMERSQL):
                    retVal = "\"%s\"" % retVal.upper()
                elif Backend.getIdentifiedDbms() in (DBMS.MSSQL, DBMS.SYBASE):
                    if isTable:
                        parts = retVal.split('.', 1)
                        for i in xrange(len(parts)):
                            if parts[i] and (re.search(r"\A\d|[^\w]", parts[i], re.U) or parts[i].upper() in kb.keywords):
                                parts[i] = "[%s]" % parts[i]
                        retVal = '.'.join(parts)
                    else:
                        if re.search(r"\A\d|[^\w]", retVal, re.U) or retVal.upper() in kb.keywords:
                            retVal = "[%s]" % retVal

        if _ and DEFAULT_MSSQL_SCHEMA not in retVal and '.' not in re.sub(r"\[[^]]+\]", "", retVal):
            if (conf.db or "").lower() != "information_schema":     # NOTE: https://github.com/sqlmapproject/sqlmap/issues/5192
                retVal = "%s.%s" % (DEFAULT_MSSQL_SCHEMA, retVal)

    return retVal

def unsafeSQLIdentificatorNaming(name):
    """
    Extracts identificator's name from its safe SQL representation

    >>> pushValue(kb.forcedDbms)
    >>> kb.forcedDbms = DBMS.MSSQL
    >>> getText(unsafeSQLIdentificatorNaming("[begin]"))
    'begin'
    >>> getText(unsafeSQLIdentificatorNaming("foobar"))
    'foobar'
    >>> kb.forceDbms = popValue()
    """

    retVal = name

    if isinstance(name, six.string_types):
        if Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.ACCESS, DBMS.CUBRID, DBMS.SQLITE):
            retVal = name.replace("`", "")
        elif Backend.getIdentifiedDbms() in (DBMS.PGSQL, DBMS.DB2, DBMS.HSQLDB, DBMS.H2, DBMS.INFORMIX, DBMS.MONETDB, DBMS.VERTICA, DBMS.MCKOI, DBMS.PRESTO, DBMS.CRATEDB, DBMS.CACHE, DBMS.EXTREMEDB, DBMS.FRONTBASE, DBMS.RAIMA, DBMS.VIRTUOSO):
            retVal = name.replace("\"", "")
        elif Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.ALTIBASE, DBMS.MIMERSQL):
            retVal = name.replace("\"", "").upper()
        elif Backend.getIdentifiedDbms() in (DBMS.MSSQL, DBMS.SYBASE):
            retVal = name.replace("[", "").replace("]", "")

        if Backend.getIdentifiedDbms() in (DBMS.MSSQL, DBMS.SYBASE):
            retVal = re.sub(r"(?i)\A\[?%s\]?\." % DEFAULT_MSSQL_SCHEMA, "", retVal)

    return retVal

def isNoneValue(value):
    """
    Returns whether the value is unusable (None or '')

    >>> isNoneValue(None)
    True
    >>> isNoneValue('None')
    True
    >>> isNoneValue('')
    True
    >>> isNoneValue([])
    True
    >>> isNoneValue([2])
    False
    """

    if isinstance(value, six.string_types):
        return value in ("None", "")
    elif isListLike(value):
        return all(isNoneValue(_) for _ in value)
    elif isinstance(value, dict):
        return not any(value)
    else:
        return value is None

def isNullValue(value):
    """
    Returns whether the value contains explicit 'NULL' value

    >>> isNullValue(u'NULL')
    True
    >>> isNullValue(u'foobar')
    False
    """

    return hasattr(value, "upper") and value.upper() == NULL

def expandMnemonics(mnemonics, parser, args):
    """
    Expands mnemonic options
    """

    class MnemonicNode(object):
        def __init__(self):
            self.next = {}
            self.current = []

    head = MnemonicNode()
    pointer = None

    for group in parser.option_groups:
        for option in group.option_list:
            for opt in option._long_opts + option._short_opts:
                pointer = head

                for char in opt:
                    if char == "-":
                        continue
                    elif char not in pointer.next:
                        pointer.next[char] = MnemonicNode()

                    pointer = pointer.next[char]
                    pointer.current.append(option)

    for mnemonic in (mnemonics or "").split(','):
        found = None
        name = mnemonic.split('=')[0].replace('-', "").strip()
        value = mnemonic.split('=')[1] if len(mnemonic.split('=')) > 1 else None
        pointer = head

        for char in name:
            if char in pointer.next:
                pointer = pointer.next[char]
            else:
                pointer = None
                break

        if pointer in (None, head):
            errMsg = "mnemonic '%s' can't be resolved to any parameter name" % name
            raise SqlmapSyntaxException(errMsg)

        elif len(pointer.current) > 1:
            options = {}

            for option in pointer.current:
                for opt in option._long_opts + option._short_opts:
                    opt = opt.strip('-')
                    if opt.startswith(name):
                        options[opt] = option

            if not options:
                warnMsg = "mnemonic '%s' can't be resolved" % name
                
            elif name in options:
                found = name
                debugMsg = "mnemonic '%s' resolved to %s). " % (name, found)
                
            else:
                found = sorted(options.keys(), key=len)[0]
                warnMsg = "detected ambiguity (mnemonic '%s' can be resolved to any of: %s). " % (name, ", ".join("'%s'" % key for key in options))
                warnMsg += "Resolved to shortest of those ('%s')" % found
                

            if found:
                found = options[found]
        else:
            found = pointer.current[0]
            debugMsg = "mnemonic '%s' resolved to %s). " % (name, found)
            

        if found:
            try:
                value = found.convert_value(found, value)
            except OptionValueError:
                value = None

            if value is not None:
                setattr(args, found.dest, value)
            elif not found.type:  # boolean
                setattr(args, found.dest, True)
            else:
                errMsg = "mnemonic '%s' requires value of type '%s'" % (name, found.type)
                raise SqlmapSyntaxException(errMsg)

def filterPairValues(values):
    """
    Returns only list-like values with length 2

    >>> filterPairValues([[1, 2], [3], 1, [4, 5]])
    [[1, 2], [4, 5]]
    """

    retVal = []

    if not isNoneValue(values) and hasattr(values, '__iter__'):
        retVal = [value for value in values if isinstance(value, (tuple, list, set)) and len(value) == 2]

    return retVal

def randomizeParameterValue(value):
    """
    Randomize a parameter value based on occurrences of alphanumeric characters

    >>> random.seed(0)
    >>> randomizeParameterValue('foobar')
    'fupgpy'
    >>> randomizeParameterValue('17')
    '36'
    """

    retVal = value

    value = re.sub(r"%[0-9a-fA-F]{2}", "", value)

    for match in re.finditer(r"[A-Z]+", value):
        while True:
            original = match.group()
            candidate = randomStr(len(match.group())).upper()
            if original != candidate:
                break

        retVal = retVal.replace(original, candidate)

    for match in re.finditer(r"[a-z]+", value):
        while True:
            original = match.group()
            candidate = randomStr(len(match.group())).lower()
            if original != candidate:
                break

        retVal = retVal.replace(original, candidate)

    for match in re.finditer(r"[0-9]+", value):
        while True:
            original = match.group()
            candidate = str(randomInt(len(match.group())))
            if original != candidate:
                break

        retVal = retVal.replace(original, candidate)

    if re.match(r"\A[^@]+@.+\.[a-z]+\Z", value):
        parts = retVal.split('.')
        parts[-1] = random.sample(RANDOMIZATION_TLDS, 1)[0]
        retVal = '.'.join(parts)

    if not retVal:
        retVal = randomStr(lowercase=True)

    return retVal

def asciifyUrl(url, forceQuote=False):
    """
    Attempts to make a unicode URL usable with ``urllib/urllib2``.

    More specifically, it attempts to convert the unicode object ``url``,
    which is meant to represent a IRI, to an unicode object that,
    containing only ASCII characters, is a valid URI. This involves:

        * IDNA/Puny-encoding the domain name.
        * UTF8-quoting the path and querystring parts.

    See also RFC 3987.

    # Reference: http://blog.elsdoerfer.name/2008/12/12/opening-iris-in-python/

    >>> asciifyUrl(u'http://www.\\u0161u\\u0107uraj.com')
    'http://www.xn--uuraj-gxa24d.com'
    """

    parts = _urllib.parse.urlsplit(url)
    if not all((parts.scheme, parts.netloc, parts.hostname)):
        # apparently not an url
        return getText(url)

    if all(char in string.printable for char in url):
        return getText(url)

    hostname = parts.hostname

    if isinstance(hostname, six.binary_type):
        hostname = getUnicode(hostname)

    # idna-encode domain
    try:
        hostname = hostname.encode("idna")
    except:
        hostname = hostname.encode("punycode")

    # UTF8-quote the other parts. We check each part individually if
    # if needs to be quoted - that should catch some additional user
    # errors, say for example an umlaut in the username even though
    # the path *is* already quoted.
    def quote(s, safe):
        s = s or ''
        # Triggers on non-ascii characters - another option would be:
        #     _urllib.parse.quote(s.replace('%', '')) != s.replace('%', '')
        # which would trigger on all %-characters, e.g. "&".
        if getUnicode(s).encode("ascii", "replace") != s or forceQuote:
            s = _urllib.parse.quote(getBytes(s), safe=safe)
        return s

    username = quote(parts.username, '')
    password = quote(parts.password, safe='')
    path = quote(parts.path, safe='/')
    query = quote(parts.query, safe="&=")

    # put everything back together
    netloc = getText(hostname)
    if username or password:
        netloc = '@' + netloc
        if password:
            netloc = ':' + password + netloc
        netloc = username + netloc

    try:
        port = parts.port
    except:
        port = None

    if port:
        netloc += ':' + str(port)

    return getText(_urllib.parse.urlunsplit([parts.scheme, netloc, path, query, parts.fragment]) or url)

def isAdminFromPrivileges(privileges):
    """
    Inspects privileges to see if those are coming from an admin user
    """

    privileges = privileges or []

    # In PostgreSQL the usesuper privilege means that the
    # user is DBA
    retVal = (Backend.isDbms(DBMS.PGSQL) and "super" in privileges)

    # In Oracle the DBA privilege means that the
    # user is DBA
    retVal |= (Backend.isDbms(DBMS.ORACLE) and "DBA" in privileges)

    # In MySQL >= 5.0 the SUPER privilege means
    # that the user is DBA
    retVal |= (Backend.isDbms(DBMS.MYSQL) and kb.data.has_information_schema and "SUPER" in privileges)

    # In MySQL < 5.0 the super_priv privilege means
    # that the user is DBA
    retVal |= (Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema and "super_priv" in privileges)

    # In Firebird there is no specific privilege that means
    # that the user is DBA
    retVal |= (Backend.isDbms(DBMS.FIREBIRD) and all(_ in privileges for _ in ("SELECT", "INSERT", "UPDATE", "DELETE", "REFERENCES", "EXECUTE")))

    return retVal

def checkSameHost(*urls):
    """
    Returns True if all provided urls share that same host

    >>> checkSameHost('http://www.target.com/page1.php?id=1', 'http://www.target.com/images/page2.php')
    True
    >>> checkSameHost('http://www.target.com/page1.php?id=1', 'http://www.target2.com/images/page2.php')
    False
    """

    if not urls:
        return None
    elif len(urls) == 1:
        return True
    else:
        def _(value):
            if value and not re.search(r"\A\w+://", value):
                value = "http://%s" % value
            return value

        return all(re.sub(r"(?i)\Awww\.", "", _urllib.parse.urlparse(_(url) or "").netloc.split(':')[0]) == re.sub(r"(?i)\Awww\.", "", _urllib.parse.urlparse(_(urls[0]) or "").netloc.split(':')[0]) for url in urls[1:])

def getHostHeader(url):
    """
    Returns proper Host header value for a given target URL

    >>> getHostHeader('http://www.target.com/vuln.php?id=1')
    'www.target.com'
    """

    retVal = url

    if url:
        retVal = _urllib.parse.urlparse(url).netloc

        if re.search(r"http(s)?://\[.+\]", url, re.I):
            retVal = extractRegexResult(r"http(s)?://\[(?P<result>.+)\]", url)
        elif any(retVal.endswith(':%d' % _) for _ in (80, 443)):
            retVal = retVal.split(':')[0]

    if retVal and retVal.count(':') > 1 and not any(_ in retVal for _ in ('[', ']')):
        retVal = "[%s]" % retVal

    return retVal

def checkOldOptions(args):
    """
    Checks for obsolete/deprecated options
    """

    for _ in args:
        _ = _.split('=')[0].strip()
        if _ in OBSOLETE_OPTIONS:
            errMsg = "switch/option '%s' is obsolete" % _
            if OBSOLETE_OPTIONS[_]:
                errMsg += " (hint: %s)" % OBSOLETE_OPTIONS[_]
            raise SqlmapSyntaxException(errMsg)
        elif _ in DEPRECATED_OPTIONS:
            warnMsg = "switch/option '%s' is deprecated" % _
            if DEPRECATED_OPTIONS[_]:
                warnMsg += " (hint: %s)" % DEPRECATED_OPTIONS[_]
            

def checkSystemEncoding():
    """
    Checks for problematic encodings
    """

    if sys.getdefaultencoding() == "cp720":
        try:
            codecs.lookup("cp720")
        except LookupError:
            errMsg = "there is a known Python issue (#1616979) related "
            errMsg += "to support for charset 'cp720'. Please visit "
            errMsg += "'http://blog.oneortheother.info/tip/python-fix-cp720-encoding/index.html' "
            errMsg += "and follow the instructions to be able to fix it"
            

            warnMsg = "temporary switching to charset 'cp1256'"
            

            _reload_module(sys)
            sys.setdefaultencoding("cp1256")

def evaluateCode(code, variables=None):
    """
    Executes given python code given in a string form

    >>> _ = {}; evaluateCode("a = 1; b = 2; c = a", _); _["c"]
    1
    """

    try:
        exec(code, variables)
    except KeyboardInterrupt:
        raise
    except Exception as ex:
        errMsg = "an error occurred while evaluating provided code ('%s') " % getSafeExString(ex)
        raise SqlmapGenericException(errMsg)

def serializeObject(object_):
    """
    Serializes given object

    >>> type(serializeObject([1, 2, 3, ('a', 'b')])) == str
    True
    """

    return base64pickle(object_)

def unserializeObject(value):
    """
    Unserializes object from given serialized form

    >>> unserializeObject(serializeObject([1, 2, 3])) == [1, 2, 3]
    True
    >>> unserializeObject('gAJVBmZvb2JhcnEBLg==')
    'foobar'
    """

    return base64unpickle(value) if value else None

def resetCounter(technique):
    """
    Resets query counter for a given technique
    """

    kb.counters[technique] = 0

def incrementCounter(technique):
    """
    Increments query counter for a given technique
    """

    kb.counters[technique] = getCounter(technique) + 1

def getCounter(technique):
    """
    Returns query counter for a given technique

    >>> resetCounter(PAYLOAD.TECHNIQUE.STACKED); incrementCounter(PAYLOAD.TECHNIQUE.STACKED); getCounter(PAYLOAD.TECHNIQUE.STACKED)
    1
    """

    return kb.counters.get(technique, 0)

def applyFunctionRecursively(value, function):
    """
    Applies function recursively through list-like structures

    >>> applyFunctionRecursively([1, 2, [3, 4, [19]], -9], lambda _: _ > 0)
    [True, True, [True, True, [True]], False]
    """

    if isListLike(value):
        retVal = [applyFunctionRecursively(_, function) for _ in value]
    else:
        retVal = function(value)

    return retVal

def decodeDbmsHexValue(value, raw=False):
    """
    Returns value decoded from DBMS specific hexadecimal representation

    >>> decodeDbmsHexValue('3132332031') == u'123 1'
    True
    >>> decodeDbmsHexValue('31003200330020003100') == u'123 1'
    True
    >>> decodeDbmsHexValue('00310032003300200031') == u'123 1'
    True
    >>> decodeDbmsHexValue('0x31003200330020003100') == u'123 1'
    True
    >>> decodeDbmsHexValue('313233203') == u'123 ?'
    True
    >>> decodeDbmsHexValue(['0x31', '0x32']) == [u'1', u'2']
    True
    >>> decodeDbmsHexValue('5.1.41') == u'5.1.41'
    True
    """

    retVal = value

    def _(value):
        retVal = value
        if value and isinstance(value, six.string_types):
            value = value.strip()

            if len(value) % 2 != 0:
                retVal = (decodeHex(value[:-1]) + b'?') if len(value) > 1 else value
                singleTimeWarnMessage("there was a problem decoding value '%s' from expected hexadecimal form" % value)
            else:
                retVal = decodeHex(value)

            if not raw:
                if not kb.binaryField:
                    if Backend.isDbms(DBMS.MSSQL) and value.startswith("0x"):
                        try:
                            retVal = retVal.decode("utf-16-le")
                        except UnicodeDecodeError:
                            pass

                    elif Backend.getIdentifiedDbms() in (DBMS.HSQLDB, DBMS.H2):
                        try:
                            retVal = retVal.decode("utf-16-be")
                        except UnicodeDecodeError:
                            pass

                if not isinstance(retVal, six.text_type):
                    retVal = getUnicode(retVal, conf.encoding or UNICODE_ENCODING)

                if u"\x00" in retVal:
                    retVal = retVal.replace(u"\x00", u"")

        return retVal

    try:
        retVal = applyFunctionRecursively(value, _)
    except:
        singleTimeWarnMessage("there was a problem decoding value '%s' from expected hexadecimal form" % value)

    return retVal

def extractExpectedValue(value, expected):
    """
    Extracts and returns expected value by a given type

    >>> extractExpectedValue(['1'], EXPECTED.BOOL)
    True
    >>> extractExpectedValue('1', EXPECTED.INT)
    1
    >>> extractExpectedValue('7\\xb9645', EXPECTED.INT) is None
    True
    """

    if expected:
        value = unArrayizeValue(value)

        if isNoneValue(value):
            value = None
        elif expected == EXPECTED.BOOL:
            if isinstance(value, int):
                value = bool(value)
            elif isinstance(value, six.string_types):
                value = value.strip().lower()
                if value in ("true", "false"):
                    value = value == "true"
                elif value in ('t', 'f'):
                    value = value == 't'
                elif value in ("1", "-1"):
                    value = True
                elif value == '0':
                    value = False
                else:
                    value = None
        elif expected == EXPECTED.INT:
            try:
                value = int(value)
            except:
                value = None

    return value

def hashDBWrite(key, value, serialize=False):
    """
    Helper function for writing session data to HashDB
    """

    if conf.hashDB:
        _ = '|'.join((str(_) if not isinstance(_, six.string_types) else _) for _ in (conf.hostname, conf.path.strip('/') if conf.path is not None else conf.port, key, HASHDB_MILESTONE_VALUE))
        conf.hashDB.write(_, value, serialize)

def hashDBRetrieve(key, unserialize=False, checkConf=False):
    """
    Helper function for restoring session data from HashDB
    """

    retVal = None

    if conf.hashDB:
        _ = '|'.join((str(_) if not isinstance(_, six.string_types) else _) for _ in (conf.hostname, conf.path.strip('/') if conf.path is not None else conf.port, key, HASHDB_MILESTONE_VALUE))
        retVal = conf.hashDB.retrieve(_, unserialize) if kb.resumeValues and not (checkConf and any((conf.flushSession, conf.freshQueries))) else None

        if not kb.inferenceMode and not kb.fileReadMode and isinstance(retVal, six.string_types) and any(_ in retVal for _ in (PARTIAL_VALUE_MARKER, PARTIAL_HEX_VALUE_MARKER)):
            retVal = None

    return retVal

def resetCookieJar(cookieJar):
    """
    Cleans cookies from a given cookie jar
    """

    if not conf.loadCookies:
        cookieJar.clear()
    else:
        try:
            if not cookieJar.filename:
                infoMsg = "loading cookies from '%s'" % conf.loadCookies
                

                content = readCachedFileContent(conf.loadCookies)
                content = re.sub("(?im)^#httpOnly_", "", content)
                lines = filterNone(line.strip() for line in content.split("\n") if not line.startswith('#'))
                handle, filename = tempfile.mkstemp(prefix=MKSTEMP_PREFIX.COOKIE_JAR)
                os.close(handle)

                # Reference: http://www.hashbangcode.com/blog/netscape-http-cooke-file-parser-php-584.html
                with openFile(filename, "w+b") as f:
                    f.write("%s\n" % NETSCAPE_FORMAT_HEADER_COOKIES)
                    for line in lines:
                        _ = line.split("\t")
                        if len(_) == 7:
                            _[4] = FORCE_COOKIE_EXPIRATION_TIME
                            f.write("\n%s" % "\t".join(_))

                cookieJar.filename = filename

            cookieJar.load(cookieJar.filename, ignore_expires=True)

            for cookie in cookieJar:
                if getattr(cookie, "expires", MAX_INT) < time.time():
                    warnMsg = "cookie '%s' has expired" % cookie
                    singleTimeWarnMessage(warnMsg)

            cookieJar.clear_expired_cookies()

            if not cookieJar._cookies:
                errMsg = "no valid cookies found"
                raise SqlmapGenericException(errMsg)

        except Exception as ex:
            errMsg = "there was a problem loading "
            errMsg += "cookies file ('%s')" % re.sub(r"(cookies) file '[^']+'", r"\g<1>", getSafeExString(ex))
            raise SqlmapGenericException(errMsg)


def prioritySortColumns(columns):
    """
    Sorts given column names by length in ascending order while those containing
    string 'id' go first

    >>> prioritySortColumns(['password', 'userid', 'name'])
    ['userid', 'name', 'password']
    """

    def _(column):
        return column and re.search(r"^id|id$", column, re.I) is not None

    return sorted(sorted(columns, key=len), key=functools.cmp_to_key(lambda x, y: -1 if _(x) and not _(y) else 1 if not _(x) and _(y) else 0))

def getRequestHeader(request, name):
    """
    Solving an issue with an urllib2 Request header case sensitivity

    # Reference: http://bugs.python.org/issue2275

    >>> _ = lambda _: _
    >>> _.headers = {"FOO": "BAR"}
    >>> _.header_items = lambda: _.headers.items()
    >>> getText(getRequestHeader(_, "foo"))
    'BAR'
    """

    retVal = None

    if request and request.headers and name:
        _ = name.upper()
        retVal = max(getBytes(value if _ == key.upper() else "") for key, value in request.header_items()) or None

    return retVal

def isNumber(value):
    """
    Returns True if the given value is a number-like object

    >>> isNumber(1)
    True
    >>> isNumber('0')
    True
    >>> isNumber('foobar')
    False
    """

    try:
        float(value)
    except:
        return False
    else:
        return True

def zeroDepthSearch(expression, value):
    """
    Searches occurrences of value inside expression at 0-depth level
    regarding the parentheses

    >>> _ = "SELECT (SELECT id FROM users WHERE 2>1) AS result FROM DUAL"; _[zeroDepthSearch(_, "FROM")[0]:]
    'FROM DUAL'
    >>> _ = "a(b; c),d;e"; _[zeroDepthSearch(_, "[;, ]")[0]:]
    ',d;e'
    """

    retVal = []

    depth = 0
    for index in xrange(len(expression)):
        if expression[index] == '(':
            depth += 1
        elif expression[index] == ')':
            depth -= 1
        elif depth == 0:
            if value.startswith('[') and value.endswith(']'):
                if re.search(value, expression[index:index + 1]):
                    retVal.append(index)
            elif expression[index:index + len(value)] == value:
                retVal.append(index)

    return retVal

def splitFields(fields, delimiter=','):
    """
    Returns list of (0-depth) fields splitted by delimiter

    >>> splitFields('foo, bar, max(foo, bar)')
    ['foo', 'bar', 'max(foo,bar)']
    """

    fields = fields.replace("%s " % delimiter, delimiter)
    commas = [-1, len(fields)]
    commas.extend(zeroDepthSearch(fields, ','))
    commas = sorted(commas)

    return [fields[x + 1:y] for (x, y) in _zip(commas, commas[1:])]

def getSafeExString(ex, encoding=None):
    """
    Safe way how to get the proper exception represtation as a string

    >>> getSafeExString(SqlmapBaseException('foobar')) == 'foobar'
    True
    >>> getSafeExString(OSError(0, 'foobar')) == 'OSError: foobar'
    True
    """

    retVal = None

    if getattr(ex, "message", None):
        retVal = ex.message
    elif getattr(ex, "msg", None):
        retVal = ex.msg
    elif getattr(ex, "args", None):
        for candidate in ex.args[::-1]:
            if isinstance(candidate, six.string_types):
                retVal = candidate
                break

    if retVal is None:
        retVal = str(ex)
    elif not isinstance(ex, SqlmapBaseException):
        retVal = "%s: %s" % (type(ex).__name__, retVal)

    return getUnicode(retVal or "", encoding=encoding).strip()

def safeVariableNaming(value):
    """
    Returns escaped safe-representation of a given variable name that can be used in Python evaluated code

    >>> safeVariableNaming("class.id") == "EVAL_636c6173732e6964"
    True
    """

    if value in keyword.kwlist or re.search(r"\A[^a-zA-Z]|[^\w]", value):
        value = "%s%s" % (EVALCODE_ENCODED_PREFIX, getUnicode(binascii.hexlify(getBytes(value))))

    return value

def unsafeVariableNaming(value):
    """
    Returns unescaped safe-representation of a given variable name

    >>> unsafeVariableNaming("EVAL_636c6173732e6964") == "class.id"
    True
    """

    if value.startswith(EVALCODE_ENCODED_PREFIX):
        value = decodeHex(value[len(EVALCODE_ENCODED_PREFIX):], binary=False)

    return value

def firstNotNone(*args):
    """
    Returns first not-None value from a given list of arguments

    >>> firstNotNone(None, None, 1, 2, 3)
    1
    """

    retVal = None

    for _ in args:
        if _ is not None:
            retVal = _
            break

    return retVal

def removePostHintPrefix(value):
    """
    Remove POST hint prefix from a given value (name)

    >>> removePostHintPrefix("JSON id")
    'id'
    >>> removePostHintPrefix("id")
    'id'
    """

    return re.sub(r"\A(%s) " % '|'.join(re.escape(__) for __ in getPublicTypeMembers(POST_HINT, onlyValues=True)), "", value)

def chunkSplitPostData(data):
    """
    Convert POST data to chunked transfer-encoded data (Note: splitting done by SQL keywords)

    >>> random.seed(0)
    >>> chunkSplitPostData("SELECT username,password FROM users")
    '5;4Xe90\\r\\nSELEC\\r\\n3;irWlc\\r\\nT u\\r\\n1;eT4zO\\r\\ns\\r\\n5;YB4hM\\r\\nernam\\r\\n9;2pUD8\\r\\ne,passwor\\r\\n3;mp07y\\r\\nd F\\r\\n5;8RKXi\\r\\nROM u\\r\\n4;MvMhO\\r\\nsers\\r\\n0\\r\\n\\r\\n'
    """

    length = len(data)
    retVal = ""
    index = 0

    while index < length:
        chunkSize = randomInt(1)

        if index + chunkSize >= length:
            chunkSize = length - index

        salt = randomStr(5, alphabet=string.ascii_letters + string.digits)

        while chunkSize:
            candidate = data[index:index + chunkSize]

            if re.search(r"\b%s\b" % '|'.join(HTTP_CHUNKED_SPLIT_KEYWORDS), candidate, re.I):
                chunkSize -= 1
            else:
                break

        index += chunkSize
        retVal += "%x;%s\r\n" % (chunkSize, salt)
        retVal += "%s\r\n" % candidate

    retVal += "0\r\n\r\n"

    return retVal
