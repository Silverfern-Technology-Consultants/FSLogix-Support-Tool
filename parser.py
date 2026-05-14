"""FSLogix log file parser."""

import re
import os
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Optional, Dict
from pathlib import Path

from issues import KNOWN_ISSUES, IssueDefinition


# Primary FSLogix log format:
# [YYYY-MM-DD HH:MM:SS.mmm] [PPPPPPPP.TTTTTTTT] LEVEL  message
_LOG_RE = re.compile(
    r'^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\]\s+'
    r'\[([0-9A-Fa-f]+)\.([0-9A-Fa-f]+)\]\s+'
    r'(VERB|INFO|WARN|ERROR)\s+'
    r'(.*)',
    re.IGNORECASE,
)

_LEVEL_NORM = {"VERB": "VERBOSE", "INFO": "INFO", "WARN": "WARNING", "ERROR": "ERROR"}


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


def parse_log_file(file_path: str) -> ParsedLog:
    result = ParsedLog(file_path=file_path)
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            for line_num, raw_line in enumerate(fh, 1):
                line = raw_line.rstrip("\r\n")
                if not line.strip():
                    continue

                m = _LOG_RE.match(line)
                if m:
                    ts_str, pid, tid, level_raw, message = m.groups()
                    try:
                        ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S.%f")
                    except ValueError:
                        ts = None

                    level = _LEVEL_NORM.get(level_raw.upper(), level_raw.upper())
                    entry = LogEntry(
                        timestamp=ts,
                        pid=pid,
                        tid=tid,
                        level=level,
                        message=message.strip(),
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
                    # Continuation / unrecognized — append to previous entry if possible
                    if result.entries:
                        result.entries[-1].message += " " + line.strip()
                        result.entries[-1].raw += "\n" + line

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
