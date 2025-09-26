"""
Log Parser Utility
Parses various log formats (Apache, Nginx, JSON, Syslog, etc.)
"""

import re
import json
from datetime import datetime
import pandas as pd

class LogParser:
    def __init__(self):
        self.patterns = {
            'apache_common': re.compile(
                r'^(\S+)\s+\S+\s+\S+\s+\[([\w:/]+\s[+\-]\d{4})\]\s+"(\S+)\s+(\S+)\s+(\S+)"\s+(\d{3})\s+(\d+)$'
            ),
            'apache_combined': re.compile(
                r'^(\S+)\s+\S+\s+\S+\s+\[([\w:/]+\s[+\-]\d{4})\]\s+"(\S+)\s+(\S+)\s+(\S+)"\s+(\d{3})\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"$'
            ),
            'nginx': re.compile(
                r'^(\S+)\s+-\s+-\s+\[([\w:/]+\s[+\-]\d{4})\]\s+"(\S+)\s+(\S+)\s+(\S+)"\s+(\d{3})\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"'
            ),
            'syslog': re.compile(
                r'^(\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+)\[(\d+)\]:\s+(.*)$'
            ),
            'json': re.compile(r'^\{.*\}$'),
            'windows_event': re.compile(
                r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(\w+)\s+(\w+)\s+(\d+)\s+(.*)$'
            ),
            'custom': re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\s+\[(\w+)\]\s+(.*)$')
        }

        self.severity_keywords = {
            'critical': ['CRITICAL', 'FATAL', 'EMERGENCY', 'PANIC'],
            'error': ['ERROR', 'ERR', 'FAIL', 'FAILED'],
            'warning': ['WARNING', 'WARN', 'ALERT'],
            'info': ['INFO', 'INFORMATION', 'NOTICE'],
            'debug': ['DEBUG', 'TRACE', 'VERBOSE']
        }

    def parse(self, log_content):
        """Parse log content and return structured data"""
        if isinstance(log_content, list):
            return self._parse_list(log_content)
        elif isinstance(log_content, str):
            lines = log_content.strip().split('\n')
            return self._parse_list(lines)
        else:
            return []

    def _parse_list(self, log_lines):
        """Parse a list of log lines"""
        parsed_logs = []

        for line in log_lines:
            if not line or line.strip() == '':
                continue

            parsed = self._parse_line(line)
            if parsed:
                parsed_logs.append(parsed)

        return parsed_logs

    def _parse_line(self, line):
        """Parse a single log line"""
        line = line.strip()

        # Try JSON parsing first
        if self.patterns['json'].match(line):
            try:
                data = json.loads(line)
                return self._normalize_json_log(data)
            except:
                pass

        # Try Apache Combined Log Format
        match = self.patterns['apache_combined'].match(line)
        if match:
            return self._parse_apache_combined(match)

        # Try Apache Common Log Format
        match = self.patterns['apache_common'].match(line)
        if match:
            return self._parse_apache_common(match)

        # Try Nginx format
        match = self.patterns['nginx'].match(line)
        if match:
            return self._parse_nginx(match)

        # Try Syslog format
        match = self.patterns['syslog'].match(line)
        if match:
            return self._parse_syslog(match)

        # Try Windows Event Log format
        match = self.patterns['windows_event'].match(line)
        if match:
            return self._parse_windows_event(match)

        # Try custom format
        match = self.patterns['custom'].match(line)
        if match:
            return self._parse_custom(match)

        # If no pattern matches, return raw log with basic parsing
        return self._parse_generic(line)

    def _parse_apache_combined(self, match):
        """Parse Apache Combined Log Format"""
        return {
            'format': 'apache_combined',
            'ip': match.group(1),
            'timestamp': self._parse_timestamp(match.group(2)),
            'method': match.group(3),
            'path': match.group(4),
            'protocol': match.group(5),
            'status_code': int(match.group(6)),
            'bytes_sent': int(match.group(7)) if match.group(7) != '-' else 0,
            'referrer': match.group(8),
            'user_agent': match.group(9),
            'severity': self._determine_severity_by_status(int(match.group(6)))
        }

    def _parse_apache_common(self, match):
        """Parse Apache Common Log Format"""
        return {
            'format': 'apache_common',
            'ip': match.group(1),
            'timestamp': self._parse_timestamp(match.group(2)),
            'method': match.group(3),
            'path': match.group(4),
            'protocol': match.group(5),
            'status_code': int(match.group(6)),
            'bytes_sent': int(match.group(7)) if match.group(7) != '-' else 0,
            'severity': self._determine_severity_by_status(int(match.group(6)))
        }

    def _parse_nginx(self, match):
        """Parse Nginx Log Format"""
        return {
            'format': 'nginx',
            'ip': match.group(1),
            'timestamp': self._parse_timestamp(match.group(2)),
            'method': match.group(3),
            'path': match.group(4),
            'protocol': match.group(5),
            'status_code': int(match.group(6)),
            'bytes_sent': int(match.group(7)),
            'referrer': match.group(8),
            'user_agent': match.group(9),
            'severity': self._determine_severity_by_status(int(match.group(6)))
        }

    def _parse_syslog(self, match):
        """Parse Syslog Format"""
        return {
            'format': 'syslog',
            'timestamp': match.group(1),
            'hostname': match.group(2),
            'service': match.group(3),
            'pid': int(match.group(4)),
            'message': match.group(5),
            'severity': self._determine_severity(match.group(5))
        }

    def _parse_windows_event(self, match):
        """Parse Windows Event Log Format"""
        return {
            'format': 'windows_event',
            'timestamp': match.group(1),
            'level': match.group(2),
            'source': match.group(3),
            'event_id': int(match.group(4)),
            'message': match.group(5),
            'severity': self._map_windows_level(match.group(2))
        }

    def _parse_custom(self, match):
        """Parse Custom Log Format"""
        return {
            'format': 'custom',
            'timestamp': match.group(1),
            'level': match.group(2),
            'message': match.group(3),
            'severity': match.group(2).lower()
        }

    def _parse_generic(self, line):
        """Parse generic unstructured log line"""
        # Extract timestamp if present
        timestamp = None
        timestamp_patterns = [
            r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}',
            r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}',
            r'\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}'
        ]

        for pattern in timestamp_patterns:
            match = re.search(pattern, line)
            if match:
                timestamp = match.group()
                break

        # Extract IP addresses
        ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', line)

        # Extract URLs
        urls = re.findall(r'https?://[^\s]+', line)

        # Extract email addresses
        emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', line)

        return {
            'format': 'generic',
            'raw': line,
            'timestamp': timestamp,
            'ips': ips,
            'urls': urls,
            'emails': emails,
            'severity': self._determine_severity(line),
            'length': len(line)
        }

    def _normalize_json_log(self, data):
        """Normalize JSON log data"""
        normalized = {
            'format': 'json',
            'data': data
        }

        # Try to extract common fields
        for field in ['timestamp', 'time', 'datetime', '@timestamp']:
            if field in data:
                normalized['timestamp'] = data[field]
                break

        for field in ['level', 'severity', 'priority']:
            if field in data:
                normalized['severity'] = str(data[field]).lower()
                break

        for field in ['message', 'msg', 'text']:
            if field in data:
                normalized['message'] = data[field]
                break

        for field in ['ip', 'client_ip', 'remote_addr', 'src_ip']:
            if field in data:
                normalized['ip'] = data[field]
                break

        if 'severity' not in normalized:
            normalized['severity'] = 'info'

        return normalized

    def _parse_timestamp(self, timestamp_str):
        """Parse various timestamp formats"""
        formats = [
            '%d/%b/%Y:%H:%M:%S %z',
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%dT%H:%M:%S',
            '%b %d %H:%M:%S'
        ]

        for fmt in formats:
            try:
                return datetime.strptime(timestamp_str, fmt).isoformat()
            except:
                continue

        return timestamp_str

    def _determine_severity(self, text):
        """Determine log severity from text content"""
        text_upper = text.upper()

        for severity, keywords in self.severity_keywords.items():
            for keyword in keywords:
                if keyword in text_upper:
                    return severity

        return 'info'

    def _determine_severity_by_status(self, status_code):
        """Determine severity based on HTTP status code"""
        if status_code >= 500:
            return 'error'
        elif status_code >= 400:
            return 'warning'
        elif status_code >= 300:
            return 'info'
        else:
            return 'info'

    def _map_windows_level(self, level):
        """Map Windows event levels to standard severity"""
        mapping = {
            'ERROR': 'error',
            'WARNING': 'warning',
            'INFORMATION': 'info',
            'CRITICAL': 'critical',
            'VERBOSE': 'debug'
        }
        return mapping.get(level.upper(), 'info')

    def extract_statistics(self, parsed_logs):
        """Extract statistics from parsed logs"""
        stats = {
            'total_logs': len(parsed_logs),
            'formats': {},
            'severities': {},
            'status_codes': {},
            'top_ips': {},
            'time_range': None
        }

        timestamps = []

        for log in parsed_logs:
            # Count formats
            fmt = log.get('format', 'unknown')
            stats['formats'][fmt] = stats['formats'].get(fmt, 0) + 1

            # Count severities
            severity = log.get('severity', 'unknown')
            stats['severities'][severity] = stats['severities'].get(severity, 0) + 1

            # Count status codes
            if 'status_code' in log:
                code = str(log['status_code'])
                stats['status_codes'][code] = stats['status_codes'].get(code, 0) + 1

            # Count IPs
            if 'ip' in log:
                ip = log['ip']
                stats['top_ips'][ip] = stats['top_ips'].get(ip, 0) + 1
            elif 'ips' in log and log['ips']:
                for ip in log['ips']:
                    stats['top_ips'][ip] = stats['top_ips'].get(ip, 0) + 1

            # Collect timestamps
            if 'timestamp' in log and log['timestamp']:
                timestamps.append(log['timestamp'])

        # Get top 10 IPs
        if stats['top_ips']:
            stats['top_ips'] = dict(sorted(stats['top_ips'].items(),
                                           key=lambda x: x[1],
                                           reverse=True)[:10])

        # Determine time range
        if timestamps:
            timestamps.sort()
            stats['time_range'] = {
                'start': timestamps[0],
                'end': timestamps[-1]
            }

        return stats