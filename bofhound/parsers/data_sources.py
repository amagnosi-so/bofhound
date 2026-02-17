"""Data source abstractions for BOFHound parsing pipeline."""

import os
import subprocess
import sys
import glob
import json
import logging
import base64
import asyncio
import tempfile
import traceback
import warnings
import lzma
import struct
from pathlib import Path
from uuid import UUID
import base64
from abc import ABC, abstractmethod
from typing import Iterator, AsyncIterator, TypeVar

from py7zr import py7zr
from typing_extensions import override
from mythic import mythic
from syncer import sync
from bofhound.logger import logger
from bofhound.parsers.utils import find_7z_executable

T = TypeVar('T')

class DataSource(ABC):
    """Abstract base class for data sources that provide lines to parse."""

    @abstractmethod
    def get_data_streams(self) -> Iterator['DataStream']:
        """Return an iterator of data streams to process."""


class DataStream(ABC):
    """Abstract base class representing a single stream of data to parse."""

    @property
    @abstractmethod
    def identifier(self) -> str:
        """Unique identifier for this data stream (e.g., filename, callback ID)."""

    @abstractmethod
    def lines(self) -> Iterator[str]:
        """Return an iterator of lines from this data stream."""

    def __str__(self) -> str:
        return self.identifier


class FileDataSource(DataSource):
    """Data source that reads from local files."""

    def __init__(self, input_path: str, filename_pattern: str = "*.log",
                 stream_type=None):
        self.input_path = input_path
        self.filename_pattern = filename_pattern
        self.stream_type = stream_type or FileDataStream

    def get_data_streams(self) -> Iterator['FileDataStream']:
        """Get file-based data streams."""
        if os.path.isfile(self.input_path):
            yield self.stream_type(self.input_path)
        elif os.path.isdir(self.input_path):
            pattern = f"{self.input_path}/**/{self.filename_pattern}"
            files = glob.glob(pattern, recursive=True)
            files.sort(key=os.path.getmtime)

            for file_path in files:
                yield self.stream_type(file_path)
        else:
            raise ValueError(f"Input path does not exist: {self.input_path}")


class FileDataStream(DataStream):
    """Data stream that reads from a local file."""

    def __init__(self, file_path: str):
        self.file_path = file_path

    @property
    def identifier(self) -> str:
        return self.file_path

    def lines(self) -> Iterator[str]:
        """Read lines from the file."""
        with open(self.file_path, 'r', encoding='utf-8') as f:
            for line in f:
                yield line.rstrip('\n\r')


class LzmaFileDataStream(FileDataStream):
    """Data stream that transparently handles LZMA-compressed LDAP dump files."""

    _START_BOUNDARY = "-" * 20
    _FIELD_PREFIX = b"AA"
    _SEARCH_RESULT_START = 0xAAAA
    _SEARCH_RESULT_END = 0xAAAB

    def lines(self) -> Iterator[str]:
        """
        Read lines from an LZMA-compressed LDAP dump.

        The raw blob is binary and organized in TLV records. Convert each LDAP
        entry into pseudo-ldapsearch text so existing parsers can process it.
        """
        data = self._read_binary_payload()
        if not data:
            return

        for rectype, attributes in self._iter_records(data):
            if rectype == self._SEARCH_RESULT_START:
                yield from self._render_object(attributes)
            elif rectype == self._SEARCH_RESULT_END:
                yield ""

    def _last_resort_read_binary_payload(self) -> bytes | None:
        sevenz_exe = find_7z_executable()
        if sevenz_exe:
            try:
                with tempfile.TemporaryDirectory() as temp_dir:
                    # Extract to temporary directory
                    result = subprocess.run(
                        [sevenz_exe, 'e', '-o' + temp_dir, '-y', self.file_path],
                        capture_output=True,
                        text=True,
                        check=True
                    )

                    # Find extracted files
                    extracted_files = list(Path(temp_dir).glob('*'))

                    if not extracted_files:
                        logger.error("No files extracted from archive: %s", self.file_path)
                        return None

                    # Read the first extracted file
                    with open(extracted_files[0], 'rb') as f:
                        data = f.read()
                        import shutil
                        shutil.rmtree(temp_dir, ignore_errors=True)
                        return data

            except subprocess.CalledProcessError as e:
                logger.error("7z extraction failed: %s\nStderr: %s", e, e.stderr)
            except Exception as e:
                logger.error("Error extracting with 7z: %s", e)
        else:
            logger.warning("7-Zip not found on system")

        return None

    def _read_binary_payload(self) -> bytes | None:
        """Return decompressed bytes, supporting both compressed and raw dumps."""
        try:
            # Try 7z format first
            with py7zr.SevenZipFile(self.file_path, 'r') as archive:
                # Get all file names in the archive
                allfiles = archive.readall()
                if not allfiles:
                    logger.error("7z archive is empty: %s", self.file_path)
                    return None

                # Get the first file's content
                first_file = next(iter(allfiles.values()))
                return first_file.read()
        except py7zr.Bad7zFile as exc:
            logger.debug("Not 7z compressed LDAP dump file %s: %s", self.file_path, exc)

        try:
            with open(self.file_path, 'rb') as f:
                compressed_data = f.read()

            decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
            return decompressor.decompress(compressed_data)

        except lzma.LZMAError as e:
            logger.debug("Not raw LZMA format (%s), trying XZ format", e)

        try:
            with lzma.open(self.file_path, 'rb') as f:
                return f.read()
        except lzma.LZMAError as exc:
            logger.debug("Not LZMA compressed LDAP dump file %s: %s", self.file_path, exc)

        try:
            data = self._last_resort_read_binary_payload()
            if data is None:
                raise Exception("Failed to unzip with 7z")

            return data
        except Exception as e:
            logger.error(e)

        try:
            with open(self.file_path, 'rb') as f:
                return f.read()
        except OSError as exc:
            logger.error("Unable to read LDAP dump file %s: %s", self.file_path, exc)
            return None

    def _iter_records(self, data: bytes) -> Iterator[tuple[int, dict[str, list[bytes]]]]:
        """Iterate over TLV records inside the decompressed blob."""
        pos = 0
        length = len(data)

        while pos + 2 <= length:
            record_type = int.from_bytes(data[pos:pos + 2], byteorder="little")
            pos += 2
            attributes: dict[str, list[bytes]] = {}

            while pos + 2 <= length and data[pos:pos + 2] == self._FIELD_PREFIX:
                pos += 2
                if pos >= length:
                    break

                key_len = data[pos]
                pos += 1
                key_bytes = data[pos:pos + key_len]
                key = key_bytes.decode("ascii", errors="ignore")
                pos += key_len

                if pos + 4 > length:
                    break
                value_len = int.from_bytes(data[pos:pos + 4], byteorder="little")
                pos += 4
                value = data[pos:pos + value_len]
                pos += value_len

                attributes.setdefault(key, []).append(value)

            yield record_type, attributes

    def _render_object(self, attributes: dict[str, list[bytes]]) -> Iterator[str]:
        """Render a SearchResult record as ldapsearch-style text lines."""
        yield self._START_BOUNDARY

        for key, values in attributes.items():
            lower_key = key.lower()
            for value in values:
                formatted = self._format_value(lower_key, value)
                yield f"{lower_key}: {formatted}".rstrip()

    def _format_value(self, key: str, value: bytes) -> str:
        """Return a textual representation for the attribute value."""
        sid_value = self._try_decode_sid(key, value)
        if sid_value:
            return sid_value

        guid_value = self._try_decode_guid(key, value)
        if guid_value:
            return guid_value

        text_value = self._safe_utf8_decode(value)
        if text_value is not None:
            return text_value

        return base64.b64encode(value).decode("ascii")

    @staticmethod
    def _safe_utf8_decode(value: bytes) -> str | None:
        """Decode bytes to UTF-8 if printable, otherwise return None."""
        try:
            text = value.decode("utf-8")
        except UnicodeDecodeError:
            return None

        if any((ord(ch) < 32 and ch not in ("\t", "\n", "\r")) for ch in text):
            return None

        return text

    def _try_decode_sid(self, key: str, value: bytes) -> str | None:
        """Convert SID-bearing attributes into S-1-... strings."""
        if not key.endswith("sid") or len(value) < 8:
            return None

        try:
            revision = value[0]
            sub_authority_count = value[1]
            identifier_authority = int.from_bytes(value[2:8], byteorder="big")
            sub_authorities = struct.unpack(
                f"<{sub_authority_count}I", value[8:8 + 4 * sub_authority_count]
            )
            sid = f"S-{revision}-{identifier_authority}"
            if sub_authorities:
                sid += "-" + "-".join(str(sa) for sa in sub_authorities)
            return sid
        except (struct.error, ValueError):
            return base64.b64encode(value).decode("ascii")

    def _try_decode_guid(self, key: str, value: bytes) -> str | None:
        """Convert GUID-bearing attributes into canonical GUID strings."""
        if not key.endswith("guid") or len(value) != 16:
            return None

        try:
            return str(UUID(bytes_le=value))
        except (ValueError, AttributeError):
            return base64.b64encode(value).decode("ascii")


class OutflankDataStream(FileDataStream):
    """Data stream for Outflank logs, inherits from FileDataStream."""
    def lines(self) -> Iterator[str]:
        """Read lines from the Outflank log file."""
        with open(self.file_path, 'r', encoding='utf-8') as f:
            bofname = 'ldapsearch'
            for line in f:
                event_json = json.loads(line.split('UTC ', 1)[1])

                # we only care about task_resonse events
                if (event_json['event_type'] == 'task_response'
                    and event_json['task']['name'].lower() == bofname):
                    # now we have a block of ldapsearch data we can parse through for objects
                    response_lines = event_json['task']['response']
                    for response_line in response_lines.splitlines():
                        yield response_line


class MythicDataSource(DataSource):
    """Data source that fetches data from Mythic server."""

    def __init__(self, mythic_server: str, mythic_token: str):
        # suppress warning
        warnings.filterwarnings("ignore",
                       message=".*AIOHTTPTransport does not verify ssl certificates.*",
                       category=UserWarning)
        self.mythic_server = mythic_server
        self.mythic_token = mythic_token
        self._mythic_instance = None

    def _connect(self):
        logger.debug("Logging into Mythic...")
        try:
            self._mythic_instance = sync(mythic.login(
                apitoken=self.mythic_token,
                server_ip=self.mythic_server,
                server_port=7443,
                timeout=-1,
                logging_level=logging.CRITICAL
            ))
        except Exception as e:
            logger.error("Error logging into Mythic")
            logger.error(e)
            sys.exit(-1)

        logger.debug("Logged into Mythic successfully")

    def _async_iterable_to_sync_iterable(self, iterator: AsyncIterator[T]) -> Iterator[T]:
        """Convert an async iterator to a sync iterator."""
        loop = asyncio.get_event_loop()

        while True:
            try:
                result = loop.run_until_complete(anext(iterator))
                yield result
            except StopAsyncIteration:
                break

    @override
    def get_data_streams(self) -> Iterator['MythicDataStream']:
        """
        Get Mythic output data streams.
        For mythic, instead of processing individual log "files"
        we will processes the outputs from the API server
        """
        if self._mythic_instance is None:
            self._connect()

        async_batch_iterator = mythic.get_all_task_output(self._mythic_instance, batch_size=100)

        for batch in self._async_iterable_to_sync_iterable(async_batch_iterator):
            yield from (MythicDataStream(output) for output in batch)


class MythicDataStream(DataStream):
    """Data stream that reads from a Mythic callback's task outputs."""

    def __init__(self, output: dict):
        """Initialize with Mythic task output data."""
        self._output = output

    @property
    def identifier(self) -> str:
        return f"mythic_output_{self._output.get('id', '-1')}"

    def lines(self) -> Iterator[str]:
        """Get lines from Mythic callback task outputs."""
        # Decode and yield each line
        try:
            decoded_data = base64.b64decode(self._output.get("response_text")).decode("utf-8")
            for line in decoded_data.splitlines():
                if line.strip():  # Skip empty lines
                    yield line
        except Exception:
            pass  # Skip malformed responses
