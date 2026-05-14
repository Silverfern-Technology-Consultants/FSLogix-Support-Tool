"""FSLogix log file parser."""

import re
import os
from datetime import datetime, date
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple
from pathlib import Path

from issues import KNOWN_ISSUES, IssueDefinition


# Format A (most common): time-only timestamp, date comes from the filename
# [HH:MM:SS.mmm] [PPPPPPPP.TTTTTTTT] LEVEL  message
_LOG_RE_TIME = re.compile(
    r'^\[(\d{2}:\d{2}:\d{2}[\.,]\d+)\]\s+'
    r'\[([0-9A-Fa-f]+)\.([0-9A-Fa-f]+)\]\s+'
    r'(VERB|INFO|WARN|ERROR)\s+'
    r'(.*)',
    re.IGNORECASE,
)

# Format B: full datetime in each line
# [YYYY-MM-DD HH:MM:SS.mmm] [PPPPPPPP.TTTTTTTT] LEVEL  message
_LOG_RE_DATETIME = re.compile(
    r'^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}[\.,]\d+)\]\s+'
    r'\[([0-9A-Fa-f]+)\.([0-9A-Fa-f]+)\]\s+'
    r'(VERB|INFO|WARN|ERROR)\s+'
    r'(.*)',
    re.IGNORECASE,
)

# Filename date extractor: matches YYYYMMDD anywhere in the stem
_FILENAME_DATE_RE = re.compile(r'(\d{4})(\d{2})(\d{2})')

_LEVEL_NORM = {"VERB": "VERBOSE", "INFO": "INFO", "WARN": "WARNING", "ERROR": "ERROR"}


def _date_from_filename(file_path: str) -> Optional[date]:
    stem = Path(file_path).stem
    m = _FILENAME_DATE_RE.search(stem)
    if m:
        try:
            return date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        except ValueError:
            pass
    return None


def _parse_timestamp(ts_str: str, file_date: Optional[date]) -> Optional[datetime]:
    ts_str = ts_str.replace(',', '.')  # normalise comma decimal separator
    # Time-only
    for fmt in ("%H:%M:%S.%f", "%H:%M:%S"):
        try:
            t = datetime.strptime(ts_str, fmt)
            if file_date:
                return datetime.combine(file_date, t.time())
            return t
        except ValueError:
            pass
    # Full datetime
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            pass
    return None


@dataclass
class LogEntry:
    timestamp: Optional[datetime]
    pid: str
    tid: str
    level: str
    message: str
    raw: str
    source_file: str
    line_num: int


@dataclass
class ParsedLog:
    file_path: str
    entries: List[LogEntry] = field(default_factory=list)
    errors: int = 0
    warnings: int = 0
    parse_error: Optional[str] = None


@dataclass
class DetectedIssue:
    definition: IssueDefinition
    matched_entries: List[LogEntry]

    @property
    def id(self): return self.definition.id
    @property
    def name(self): return self.definition.name
    @property
    def severity(self): return self.definition.severity
    @property
    def description(self): return self.definition.description
    @property
    def causes(self): return self.definition.causes
    @property
    def remediation_steps(self): return self.definition.remediation_steps
    @property
    def links(self): return self.definition.links


def _try_parse_line(line: str, file_date: Optional[date]) -> Optional[Tuple]:
    """Return (timestamp, pid, tid, level, message) or None."""
    for pattern in (_LOG_RE_TIME, _LOG_RE_DATETIME):
        m = pattern.match(line)
        if m:
            ts_str, pid, tid, level_raw, message = m.groups()
            ts = _parse_timestamp(ts_str, file_date)
            level = _LEVEL_NORM.get(level_raw.upper(), level_raw.upper())
            return ts, pid, tid, level, message.strip()
    return None


def parse_log_file(file_path: str) -> ParsedLog:
    result = ParsedLog(file_path=file_path)
    file_date = _date_from_filename(file_path)

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            for line_num, raw_line in enumerate(fh, 1):
                line = raw_line.rstrip("\r\n")
                if not line.strip():
                    continue

                parsed = _try_parse_line(line, file_date)
                if parsed:
                    ts, pid, tid, level, message = parsed
                    entry = LogEntry(
                        timestamp=ts,
                        pid=pid,
                        tid=tid,
                        level=level,
                        message=message,
                        raw=line,
                        source_file=file_path,
                        line_num=line_num,
                    )
                    result.entries.append(entry)
                    if level == "ERROR":
                        result.errors += 1
                    elif level == "WARNING":
                        result.warnings += 1
                else:
                    # Continuation line — append to previous entry when possible
                    if result.entries:
                        result.entries[-1].message += " " + line.strip()
                        result.entries[-1].raw += "\n" + line
                    else:
                        # Truly unrecognized line at start of file — show it as raw
                        entry = LogEntry(
                            timestamp=None,
                            pid="", tid="",
                            level="VERBOSE",
                            message=line.strip(),
                            raw=line,
                            source_file=file_path,
                            line_num=line_num,
                        )
                        result.entries.append(entry)

    except PermissionError as exc:
        result.parse_error = str(exc)
    except OSError as exc:
        result.parse_error = str(exc)

    return result


def collect_log_files(root: str) -> List[str]:
    paths: List[str] = []
    for dirpath, _dirs, files in os.walk(root):
        for fname in files:
            if fname.lower().endswith((".log", ".txt")):
                paths.append(os.path.join(dirpath, fname))
    return sorted(paths)


def detect_issues(all_entries: List[LogEntry]) -> List[DetectedIssue]:
    detected: List[DetectedIssue] = []
    for issue_def in KNOWN_ISSUES:
        matched: List[LogEntry] = []
        for entry in all_entries:
            for pattern in issue_def.patterns:
                if pattern.search(entry.message) or pattern.search(entry.raw):
                    matched.append(entry)
                    break
        if matched:
            detected.append(DetectedIssue(definition=issue_def, matched_entries=matched))
    return detected


def group_by_subdir(parsed_logs: List[ParsedLog], base: str) -> Dict[str, List[ParsedLog]]:
    groups: Dict[str, List[ParsedLog]] = {}
    for p in parsed_logs:
        rel = os.path.relpath(p.file_path, base)
        parts = Path(rel).parts
        key = parts[0] if len(parts) > 1 else "."
        groups.setdefault(key, []).append(p)
    return groups
