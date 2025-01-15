#!/usr/bin/env python3

import re
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from rich.console import Console
import json
import spacy
from collections import defaultdict

@dataclass
class AnalysisResult:
    """Container for analysis results"""
    success: bool
    key_info: List[str]  # Most important extracted information
    errors: List[str]    # Extracted error messages
    warnings: List[str]  # Extracted warnings
    context: str        # Summarized context
    raw_output: str     # Original output for reference
    gpt_analysis: Dict = None

class ConsoleAnalyzer:
    """Analyzes console output and extracts relevant information"""
    
    def __init__(self):
        # Initialize SpaCy
        try:
            self.nlp = spacy.load('en_core_web_sm')
        except OSError:
            # If model not found, download it
            import subprocess
            subprocess.run(['python', '-m', 'spacy', 'download', 'en_core_web_sm'])
            self.nlp = spacy.load('en_core_web_sm')

        # Add NLP settings
        self.nlp_enabled = True
        self.similarity_threshold = 0.75
        self.unknown_tool_threshold = 0.4
        self.pattern_similarity_threshold = 0.6
        
        # Pattern vectors cache
        self.pattern_vectors = {}
        self.keyword_vectors = {}
        
        # Initialize pattern categories
        self.pattern_categories = {
            'error': self.ERROR_PATTERNS,
            'warning': self.WARNING_PATTERNS,
            'success': self.SUCCESS_PATTERNS,
            'tool_specific': self.TOOL_PATTERNS,
            'ignore': self.COMMON_IGNORE_PATTERNS
        }
        
        # Pre-compute vectors for all patterns
        self._initialize_pattern_vectors()
        
        # Common patterns for different tools/commands
        self.ERROR_PATTERNS = [
            r'error[: ].*',
            r'exception[: ].*',
            r'failed[: ].*',
            r'\[!\].*',  # Common in security tools
            r'fatal[: ].*',
            r'cannot\s+.*',
            r'not found[: ].*',
            r'unable to[: ].*',
            r'invalid[: ].*',
            r'denied[: ].*',
            r'refused[: ].*',
            r'missing[: ].*',
            r'unknown[: ].*',
            r'no such[: ].*',
            r'bad[: ].*',
            r'forbidden[: ].*',
            r'critical[: ].*',
            r'\[-\] error:.*',  # Common in exploitation tools
            r'exploit failed.*',
            r'operation failed.*',
            r'connection failed.*',
            r'authentication failed.*',
            r'access denied.*',
            r'permission denied.*',
            r'segmentation fault.*',  # Common in crashes
            r'core dumped.*',

            # Network-related errors
            r'connection timed? ?out.*',
            r'network (is )?unreachable.*',
            r'no route to host.*',
            r'host unreachable.*',
            r'port unreachable.*',
            r'connection reset.*',
            r'connection refused.*',
            r'network (connection )?dropped.*',
            r'ssl handshake failed.*',
            r'certificate verification failed.*',
            r'dns resolution failed.*',
            r'proxy error.*',
            r'gateway timeout.*',

            # Authentication/Authorization errors
            r'unauthorized.*',
            r'forbidden.*',
            r'invalid credentials.*',
            r'login failed.*',
            r'password incorrect.*',
            r'authentication error.*',
            r'session expired.*',
            r'token (is )?invalid.*',
            r'access token expired.*',
            r'insufficient privileges.*',
            r'permission error.*',

            # File system errors
            r'file not found.*',
            r'directory not found.*',
            r'path not found.*',
            r'no such file.*',
            r'cannot create directory.*',
            r'cannot remove directory.*',
            r'disk full.*',
            r'disk quota exceeded.*',
            r'read-only file system.*',
            r'i/o error.*',
            r'file system error.*',
            r'file exists.*',
            r'file too large.*',

            # Database errors
            r'database error.*',
            r'sql error.*',
            r'deadlock detected.*',
            r'duplicate (key|entry).*',
            r'foreign key constraint.*',
            r'integrity constraint.*',
            r'transaction rollback.*',
            r'connection pool exhausted.*',
            r'database is locked.*',
            r'database timeout.*',

            # Memory/Resource errors
            r'out of memory.*',
            r'memory allocation failed.*',
            r'stack overflow.*',
            r'heap overflow.*',
            r'buffer overflow.*',
            r'resource temporarily unavailable.*',
            r'resource busy.*',
            r'too many open files.*',
            r'process limit reached.*',
            r'cpu limit exceeded.*',

            # Protocol-specific errors
            r'http[:/]?\s*\d{3}.*',  # HTTP errors
            r'smtp error.*',
            r'ftp error.*',
            r'ssh error.*',
            r'ldap error.*',
            r'dns error.*',
            r'protocol error.*',
            r'malformed packet.*',
            r'invalid request.*',
            r'bad protocol.*',

            # Tool-specific errors
            r'metasploit error.*',
            r'meterpreter error.*',
            r'exploit error.*',
            r'payload error.*',
            r'shellcode error.*',
            r'reverse shell error.*',
            r'bind shell error.*',
            r'backdoor error.*',
            r'injection error.*',
            r'enumeration error.*',

            # Security tool errors
            r'scan (failed|error).*',
            r'vulnerability scan.*error.*',
            r'brute force failed.*',
            r'password crack.*failed.*',
            r'hash.*error.*',
            r'encryption.*failed.*',
            r'decryption.*failed.*',
            r'key.*invalid.*',
            r'certificate.*error.*',
            r'signature.*invalid.*',

            # System-level errors
            r'kernel (panic|error).*',
            r'system call failed.*',
            r'process (crashed|terminated).*',
            r'service.*failed.*',
            r'daemon.*failed.*',
            r'driver.*error.*',
            r'hardware.*error.*',
            r'interrupt.*error.*',
            r'boot.*failed.*',
            r'initialization.*failed.*',

            # Configuration errors
            r'config(uration)?\s+error.*',
            r'invalid\s+config.*',
            r'missing\s+config.*',
            r'syntax\s+error.*',
            r'parse\s+error.*',
            r'validation\s+error.*',
            r'parameter\s+error.*',
            r'option\s+error.*',
            r'setting\s+error.*',
            r'environment\s+error.*',

            # Dependency errors
            r'dependency.*not found.*',
            r'module.*not found.*',
            r'library.*not found.*',
            r'package.*not found.*',
            r'import.*error.*',
            r'require.*error.*',
            r'version.*mismatch.*',
            r'compatibility.*error.*',
            r'unsupported.*version.*',
            r'obsolete.*version.*',

            # Encoding/Decoding errors
            r'encoding.*error.*',
            r'decoding.*error.*',
            r'unicode.*error.*',
            r'utf-?8.*error.*',
            r'ascii.*error.*',
            r'character.*error.*',
            r'codec.*error.*',
            r'conversion.*failed.*',
            r'malformed.*data.*',
            r'invalid.*format.*'
        ]
        
        self.WARNING_PATTERNS = [
            r'warning[: ].*',
            r'\[-\].*',  # Common in security tools
            r'deprecated[: ].*',
            r'notice[: ].*',
            r'attention[: ].*',
            r'caution[: ].*',
            r'weak[: ].*',
            r'insecure[: ].*',
            r'vulnerable[: ].*',
            r'potential[: ].*',
            r'possible[: ].*',
            r'\[!\] warning:.*',
            r'\[~\].*',  # Common in exploitation tools
            r'not recommended.*',
            r'outdated.*',
            r'unsafe.*'
        ]
        
        self.SUCCESS_PATTERNS = [
            r'success[: ].*',
            r'completed[: ].*',
            r'\[+\].*',  # Common in security tools
            r'done[: ].*',
            r'finished[: ].*',
            r'established[: ].*',
            r'connected[: ].*',
            r'found[: ].*',
            r'discovered[: ].*',
            r'identified[: ].*',
            r'exploited[: ].*',
            r'gained access[: ].*',
            r'shell opened[: ].*',
            r'session opened[: ].*',
            r'successfully[: ].*',
            r'\[*\] success:.*',
            r'\[√\].*',  # Checkmark in some tools
            r'ok[: ].*'
        ]
        
        # Tool-specific patterns
        self.TOOL_PATTERNS = {
            'nmap': {
                'key_info': [
                    r'(\d+) hosts up',
                    r'PORT\s+STATE\s+SERVICE.*(?:\n.*)*',
                    r'OS details:.*',
                    r'Service Info:.*',
                    r'MAC Address:.*',
                    r'Running:.*',
                    r'OS CPE:.*',
                    r'Device type:.*',
                    r'Running \(JUST GUESSING\):.*',
                    r'Aggressive OS guesses:.*',
                    r'No exact OS matches.*',
                    r'Network Distance:.*',
                    r'TRACEROUTE.*',
                    r'NSE: .*'  # Nmap Script Engine output
                ],
                'ignore': [
                    r'Starting Nmap.*',
                    r'Nmap done:.*',
                    r'Initiating.*',
                    r'Completed.*',
                    r'Stats:.*',
                    r'Post-scan script results:.*',
                    r'Service detection performed.*'
                ]
            },
            'dirb': {
                'key_info': [
                    r'FOUND:.*',
                    r'\+ .*',
                    r'==> DIRECTORY:.*',
                    r'\(!\) .*\..*',  # Found files
                    r'\(=\) Found:.*'
                ],
                'ignore': [
                    r'START_TIME.*',
                    r'END_TIME.*',
                    r'-----------------',
                    r'GENERATED WORDS.*',
                    r'DOWNLOADED:.*'
                ]
            },
            'metasploit': {
                'key_info': [
                    r'\[\*\] Meterpreter session \d+ opened.*',
                    r'\[\+\] .*',
                    r'Command Stager progress:.*',
                    r'Payload size:.*',
                    r'Starting persistent handler.*',
                    r'Attempting to trigger the vulnerability.*',
                    r'Sending stage.*',
                    r'Session.*created.*',
                    r'Found shell.*',
                    r'Exploit completed.*'
                ],
                'ignore': [
                    r'msf\d?> .*',
                    r'msf auxiliary\(.*\) > .*',
                    r'msf exploit\(.*\) > .*',
                    r'msf post\(.*\) > .*'
                ]
            },
            'sqlmap': {
                'key_info': [
                    r'Parameter .* is vulnerable.*',
                    r'Type: .*',
                    r'Title: .*',
                    r'Payload: .*',
                    r'available databases.*',
                    r'Database: .*',
                    r'Table: .*',
                    r'found DB.*',
                    r'\[\d+\] entries.*',
                    r'fetched data logged to.*'
                ],
                'ignore': [
                    r'\[\*\] starting .*',
                    r'\[\*\] ending .*',
                    r'sqlmap identified the following injection point.*',
                    r'do you want to establish.*'
                ]
            },
            'hydra': {
                'key_info': [
                    r'\[.*\]\[.*\] host: .* login: .* password: .*',
                    r'\[\d+\]\[.*\] host: .* login: .* password: .*',
                    r'\[DATA\] .* host: .* login: .* password: .*',
                    r'\[STATUS\] .* tries completed',
                    r'\[ATTEMPT\] target .* - login ".*" - pass ".*"'
                ],
                'ignore': [
                    r'Hydra v.*',
                    r'Created by .*',
                    r'Run at .*'
                ]
            },
            'nikto': {
                'key_info': [
                    r'\+ .*: .*',
                    r'OSVDB-\d+: .*',
                    r'\- Nikto v.*',
                    r'Target IP: .*',
                    r'Target Hostname: .*',
                    r'Target Port: .*',
                    r'\+ SSL Info: .*',
                    r'\+ Start Time: .*'
                ],
                'ignore': [
                    r'- Nikto v.*',
                    r'+ No web server found.*',
                    r'+ ERROR: .*'
                ]
            },
            'wpscan': {
                'key_info': [
                    r'\[\+\] WordPress version \d+\.\d+\.\d+ identified.*',
                    r'\[\+\] WordPress theme in use: .*',
                    r'\[\+\] WordPress plugins in use: .*',
                    r'\[!\] Default WordPress directory .* found',
                    r'\[\+\] Upload directory has listing enabled: .*',
                    r'\[\+\] Interesting header: .*',
                    r'\[\+\] Found .* vulnerabilities?',
                    r'\[i\] User\(s\) Identified:',
                    r'\[\+\] Interesting finding\(s\):',
                    r'\[+\] .* found:'
                ],
                'ignore': [
                    r'_______________',
                    r'\[\+\] Enumerating.*',
                    r'\[\+\] Checking.*',
                    r'\[i\] It seems like.*'
                ]
            },
            'gobuster': {
                'key_info': [
                    r'Found: .*',
                    r'Progress: .*',
                    r'===============================================================',
                    r'Starting gobuster.*',
                    r'Finished.*',
                    r'Starting Gobuster.*',
                    r'Found: .*Status: \d+.*Size: \d+',
                    r'\[\+\] Files found:'
                ],
                'ignore': [
                    r'Gobuster v.*',
                    r'by OJ Reeves.*',
                    r'==============================================================='
                ]
            },
            'enum4linux': {
                'key_info': [
                    r'\[+\] Got domain/workgroup name:.*',
                    r'\[+\] Server.*allows sessions using username.*',
                    r'\[+\] Attempting to map shares on.*',
                    r'\[+\] Enumerating users using SID.*',
                    r'\[+\] Password Info for Domain:.*',
                    r'\[+\] Getting domain group memberships:.*',
                    r'\[+\] Getting local group memberships:.*',
                    r'S-\d+-\d+-\d+.*',  # SID patterns
                    r'user:\[.*\] rid:\[.*\]'
                ],
                'ignore': [
                    r'Starting enum4linux v.*',
                    r' ========================== ',
                    r'\|    Target Information    \|',
                    r' ===================================== '
                ]
            },
            'wireshark': {
                'key_info': [
                    r'Capturing on.*',
                    r'Packets: \d+',
                    r'Dropped packets: \d+',
                    r'Interface statistics:',
                    r'Capture file comments:',
                    r'Frame \d+:.*bytes on wire',
                    r'Ethernet II, Src:.*Dst:.*',
                    r'Internet Protocol Version \d+, Src:.*Dst:.*'
                ],
                'ignore': [
                    r'Running as user.*',
                    r'Resolving addresses...'
                ]
            },
            'aircrack-ng': {
                'key_info': [
                    r'WPA \(.*\) handshake:.*',
                    r'KEY FOUND!.*',
                    r'Passphrase:\s*".*"',
                    r'Master Key\s*:.*',
                    r'Transient Key\s*:.*',
                    r'EAPOL HMAC\s*:.*',
                    r'(\d+) handshake.*captured',
                    r'Current passphrase:\s*.*',
                    r'Time left:\s*(\d+:\d+:\d+)',
                    r'(\d+) keys tested.*',
                    r'(\d+.\d+) keys/s'
                ],
                'ignore': [
                    r'Opening.*',
                    r'Attack will be restarted.*',
                    r'Master Key and Transient Key are not stored.*'
                ]
            },
            'john': {
                'key_info': [
                    r'Loaded \d+ password hash.*',
                    r'Will run \d+ OpenMP threads',
                    r'Press Ctrl-C to abort.*',
                    r'(\w+:\w+) .*',  # Username:Password pairs
                    r'Session completed.*',
                    r'Cracked \d+ password.*',
                    r'Time: .*',
                    r'Remaining: .*',
                    r'Guesses: \d+ ',
                    r'Success: \d+'
                ],
                'ignore': [
                    r'Using default input encoding:.*',
                    r'Rules:.*',
                    r'Default.*',
                    r'Warning: .*'
                ]
            },
            'hashcat': {
                'key_info': [
                    r'Hash\.Mode\.*: .*',
                    r'Hash\.Target\.*: .*',
                    r'Time\.Started\.*: .*',
                    r'Speed\.#\d+\.*: .*',
                    r'Recovered\.*: .*',
                    r'Progress\.*: .*',
                    r'Rejected\.*: .*',
                    r'Restore\.Point\.*: .*',
                    r'\w+:\w+:.*',  # Hash:Password pairs
                    r'Session\.Name\.*: .*',
                    r'Status\.*: .*',
                    r'Guess\.Queue\.*: .*'
                ],
                'ignore': [
                    r'nvmlDeviceGetFanSpeed\(\): .*',
                    r'clBuildProgram\(\): .*',
                    r'Watchdog: .*',
                    r'Cache-hit.*'
                ]
            },
            'msfvenom': {
                'key_info': [
                    r'Payload size: \d+ bytes',
                    r'Final size of .* file: \d+ bytes',
                    r'Saved as: .*',
                    r'Creating \d+ arch injection stagers.*',
                    r'Successfully imported .*',
                    r'Attempting to encode payload with \d+ iterations of .*',
                    r'Found \d+ compatible encoders'
                ],
                'ignore': [
                    r'No platform was selected.*',
                    r'No Arch selected.*',
                    r'Using.*encoder'
                ]
            },
            'responder': {
                'key_info': [
                    r'\[\+\] Listening for events\.*',
                    r'\[\*\] \[(\w+)\] .*',  # Protocol events
                    r'\[\*\] HTTP Request received.*',
                    r'\[\*\] Received .* packet from: .*',
                    r'\[\+\] Poisoned answer sent to .*',
                    r'\[\*\] Username: .* Password: .*',  # Captured credentials
                    r'\[\*\] Client   : .*',
                    r'\[\*\] Requested: .*',
                    r'\[\*\] Hash     : .*'  # Captured hashes
                ],
                'ignore': [
                    r'\[\*\] Responder.*',
                    r'\[\*\] Current Session ID:.*',
                    r'\[\*\] Using .*'
                ]
            },
            'beef': {
                'key_info': [
                    r'\[.*\] Browser Hooked: .*',
                    r'\[.*\] Command successfully executed on.*',
                    r'\[.*\] Zombie \d+ initialized.*',
                    r'\[.*\] Hooked browser \d+ has been terminated.*',
                    r'\[.*\] New Zombie Connection:.*',
                    r'\[.*\] Command Module Results:.*',
                    r'\[.*\] New Browser Detected:.*'
                ],
                'ignore': [
                    r'\[.*\] Starting BeEF.*',
                    r'\[.*\] BeEF is loading.*',
                    r'\[.*\] running on.*'
                ]
            },
            'burpsuite': {
                'key_info': [
                    r'Found \d+ issues.*',
                    r'Vulnerability: .*',
                    r'Severity: .*',
                    r'Confidence: .*',
                    r'Host: .*',
                    r'Path: .*',
                    r'Evidence: .*',
                    r'Request: .*',
                    r'Response: .*'
                ],
                'ignore': [
                    r'Loading.*',
                    r'Starting.*',
                    r'Scanning.*'
                ]
            },
            'zaproxy': {
                'key_info': [
                    r'WARN-\d+: .*',
                    r'ALERT-\d+: .*',
                    r'INFO-\d+: .*',
                    r'FAIL-\d+: .*',
                    r'PASS-\d+: .*',
                    r'URL: .*',
                    r'Method: .*',
                    r'Parameter: .*',
                    r'Evidence: .*',
                    r'Solution: .*',
                    r'CWE: .*',
                    r'WASC: .*'
                ],
                'ignore': [
                    r'ZAP is now listening.*',
                    r'ZAP \d+\.\d+\.\d+',
                    r'For more details see.*'
                ]
            },
            'masscan': {
                'key_info': [
                    r'Discovered open port \d+/\w+ on .*',
                    r'rate: .*',
                    r'Scanning \d+ hosts.*',
                    r'Starting masscan.*',
                    r'found \d+ results.*'
                ],
                'ignore': [
                    r'Starting masscan.*',
                    r'Initiating SYN Stealth Scan',
                    r'Warning:.*'
                ]
            },
            'crackmapexec': {
                'key_info': [
                    r'SMB\s+.*\s+\d+/\w+\s+.*',  # SMB findings
                    r'MSSQL\s+.*\s+\d+/\w+\s+.*',  # MSSQL findings
                    r'HTTP\s+.*\s+\d+/\w+\s+.*',  # HTTP findings
                    r'\[\*\] Windows \d+ Build \d+.*',
                    r'\[\+\] .*',  # Success messages
                    r'\[*\] Dumping password policy.*',
                    r'\[*\] Dumping local users.*',
                    r'\[*\] Dumping SAM hashes.*',
                    r'Administrator:.*',  # Admin credentials
                    r'Guest:.*'  # Guest credentials
                ],
                'ignore': [
                    r'CME \d+\.\d+\.\d+',
                    r'KTHXBYE!',
                    r'\[*\] Connecting to.*'
                ]
            },
            'empire': {
                'key_info': [
                    r'\[\*\] Agent .* checked in',
                    r'\[\*\] Sending agent tasking.*',
                    r'\[\+\] Initial agent .* from .* now active',
                    r'\[\*\] Listener .* successfully started',
                    r'\[\*\] Module .* executed',
                    r'\[\+\] Results from .* module:',
                    r'\[\*\] Agent .* returned results',
                    r'\[\+\] Credentials:',
                    r'\[\+\] KerbTicket:',
                    r'\[\+\] Hash:'
                ],
                'ignore': [
                    r'\[!] Lost agent .*',
                    r'\[!] Agent .* missed checkin',
                    r'\[*\] Loading Empire modules...'
                ]
            },
            'bloodhound': {
                'key_info': [
                    r'Found \d+ computers',
                    r'Found \d+ users',
                    r'Found \d+ groups',
                    r'Found \d+ domains',
                    r'Found \d+ trusts',
                    r'Found \d+ sessions',
                    r'Found \d+ ACLs',
                    r'Found \d+ GPOs',
                    r'Found \d+ OUs',
                    r'Compressing data to .*',
                    r'Writing cache file:.*'
                ],
                'ignore': [
                    r'Info: .*',
                    r'Loading database.*',
                    r'Initializing.*'
                ]
            },
            'mimikatz': {
                'key_info': [
                    r'Username : .*',
                    r'Domain   : .*',
                    r'Password : .*',
                    r'NTLM     : .*',
                    r'SHA1     : .*',
                    r'SID      : .*',
                    r'\* Username : .*',
                    r'\* Domain   : .*',
                    r'\* Password : .*',
                    r'\* NTLM     : .*',
                    r'\* SHA1     : .*',
                    r'Primary:.*',
                    r'Kerberos:.*',
                    r'msv :.*',
                    r'tspkg :.*',
                    r'wdigest :.*',
                    r'kerberos :.*',
                    r'ssp :.*',
                    r'credman :.*'
                ],
                'ignore': [
                    r'Opening : .*',
                    r'ERROR .*',
                    r'\[.*\] Unable to .*'
                ]
            },
            'recon-ng': {
                'key_info': [
                    r'\[.*\] .* module completed\..*',
                    r'\[+\] (\d+) records? added to .*',
                    r'\[*\] Source: .*',
                    r'\[*\] Category: .*',
                    r'\[*\] Updated .*',
                    r'\[*\] Storing data in .*',
                    r'\[+\] .* found: .*'
                ],
                'ignore': [
                    r'\[*\] Loading modules...',
                    r'\[*\] Recon-ng v.*',
                    r'\[*\] Database initialized...'
                ]
            },
            'maltego': {
                'key_info': [
                    r'Found \d+ entities',
                    r'Running transform: .*',
                    r'Entity: .*',
                    r'Properties: .*',
                    r'Relationships: .*',
                    r'Transform completed: .*'
                ],
                'ignore': [
                    r'Loading configuration...',
                    r'Initializing transforms...',
                    r'Starting Maltego...'
                ]
            },
            'fierce': {
                'key_info': [
                    r'Found: .*',
                    r'Zone: .*',
                    r'Nameserver: .*',
                    r'\[\+\] Found IP: .*',
                    r'\[\+\] Found Domain: .*',
                    r'Nearby:',
                    r'\t.*\t.*'  # IP and hostname pairs
                ],
                'ignore': [
                    r'Trying: .*',
                    r'Now trying: .*',
                    r'Searching: .*'
                ]
            },
            'dnsenum': {
                'key_info': [
                    r'Host .* has address .*',
                    r'Host .* has IPv6 address .*',
                    r'Nameserver .* has address .*',
                    r'Mail server .* has address .*',
                    r'Found: .*',
                    r'\(_\) Record: .*',
                    r'Brute forcing with: .*'
                ],
                'ignore': [
                    r'Starting dns enumeration...',
                    r'Checking for wildcard DNS...',
                    r'Trying zone transfer...'
                ]
            },
            'subfinder': {
                'key_info': [
                    r'\[\*\] Enumerating subdomains for .*',
                    r'\[.*\] Discovered .* subdomains',
                    r'\[.*\] Found: .*',
                    r'\[.*\] Source: .*',
                    r'\[.*\] Subdomain: .*'
                ],
                'ignore': [
                    r'\[.*\] Loading configuration...',
                    r'\[.*\] Initializing...',
                    r'\[.*\] Starting enumeration...'
                ]
            },
            'amass': {
                'key_info': [
                    r'\[.*\] .* - .*',  # Domain - IP pairs
                    r'.*\s+\d+\.\d+\.\d+\.\d+\s+.*',  # Domain IP records
                    r'\[.*\] Resolved .*',
                    r'\[.*\] ASN: .*',
                    r'\[.*\] Cert: .*',
                    r'\[.*\] DNS: .*',
                    r'\[.*\] Found: .*'
                ],
                'ignore': [
                    r'\[.*\] Starting enumeration...',
                    r'\[.*\] The enumeration has finished',
                    r'\[.*\] Querying .*'
                ]
            },
            'nuclei': {
                'key_info': [
                    r'\[.*\] \[.*\] \[.*\] .*',  # [severity] [template] [matcher] result
                    r'\[INF\] .*',
                    r'\[WRN\] .*',
                    r'\[ERR\] .*',
                    r'\[.*\] New template added: .*',
                    r'\[.*\] Identified .*'
                ],
                'ignore': [
                    r'\[.*\] Loading templates...',
                    r'\[.*\] Templates loaded: .*',
                    r'\[.*\] Running nuclei with .*'
                ]
            },
            'ffuf': {
                'key_info': [
                    r'.*:\s+\[Status: \d+, Size: \d+, Words: \d+, Lines: \d+\]',
                    r'\[Status: \d+\].*',
                    r'\[Size: \d+\].*',
                    r'\[Words: \d+\].*',
                    r'\[Lines: \d+\].*',
                    r':: Progress: \[.*\]'
                ],
                'ignore': [
                    r':: Method: .*',
                    r':: URL: .*',
                    r':: Wordlist: .*'
                ]
            },
            'feroxbuster': {
                'key_info': [
                    r'\d{3}\s+\d+[KMG]?\s+.*',  # Status Size URL
                    r'Found: .*',
                    r'\[>_\] .*',
                    r'\[\d+\] .*',
                    r'Words: \d+',
                    r'Lines: \d+'
                ],
                'ignore': [
                    r'Starting feroxbuster.*',
                    r'Target URL:.*',
                    r'Threads:.*'
                ]
            },
            'theHarvester': {
                'key_info': [
                    r'\[\*\] Hosts found: \d+',
                    r'\[\*\] IPs found: \d+',
                    r'\[\*\] Emails found: \d+',
                    r'\[\+\] .*',  # Found items
                    r'Searching .*',
                    r'Results found: .*',
                    r'Emails found:',
                    r'Hosts found:'
                ],
                'ignore': [
                    r'\*******************',
                    r'Starting theHarvester.*',
                    r'Please wait while I gather info...'
                ]
            },
            'sherlock': {
                'key_info': [
                    r'\[.*\] .*: .*',  # [status] platform: result
                    r'\[\+\] .*',
                    r'\[✓\] .*',
                    r'\[X\] .*',
                    r'Found .*',
                    r'Username found at: .*'
                ],
                'ignore': [
                    r'Checking username.*',
                    r'Scanning .*',
                    r'Time elapsed:.*'
                ]
            },
            'photon': {
                'key_info': [
                    r'\[.*\] Processing: .*',
                    r'\[.*\] Extracting links: .*',
                    r'\[.*\] Discovered: .*',
                    r'\[.*\] Saved: .*',
                    r'\[\+\] .*: \d+',  # Count of found items
                    r'Links: \d+',
                    r'Scripts: \d+',
                    r'Files: \d+'
                ],
                'ignore': [
                    r'\[.*\] Starting Photon.*',
                    r'\[.*\] Target: .*',
                    r'\[.*\] Initializing.*'
                ]
            }
        }
        
        # Add more tools as needed...
        
        # Common output sections to ignore
        self.COMMON_IGNORE_PATTERNS = [
            r'^\s*$',  # Empty lines
            r'^[-=_]{3,}$',  # Separator lines
            r'^\d+/\d+/\d+\s+\d+:\d+:\d+\s*$',  # Timestamps
            r'^Version:.*$',
            r'^Copyright.*$',
            r'^Author:.*$',
            r'^Usage:.*$',
            r'^Options:.*$'
        ]
        
        # Update version patterns
        self.version_patterns = {
            'nmap': r'Nmap version (\d+\.\d+\.\d+)',
            'metasploit': r'Framework Version: (\d+\.\d+\.\d+)',
            'sqlmap': r'sqlmap version (\d+\.\d+\.\d+)',
            'hydra': r'Hydra v(\d+\.\d+\.\d+)',
            'nikto': r'Nikto v(\d+\.\d+\.\d+)',
            'wpscan': r'WordPress Security Scanner by the WPScan Team\s+Version (\d+\.\d+\.\d+)',
            'gobuster': r'Gobuster v(\d+\.\d+\.\d+)',
            'enum4linux': r'Starting enum4linux v(\d+\.\d+)',
            'wireshark': r'Wireshark (\d+\.\d+\.\d+)',
            'aircrack-ng': r'Aircrack-ng\s+(\d+\.\d+\.\d+)',
            'john': r'John the Ripper\s+(\d+\.\d+\.\d+)',
            'hashcat': r'hashcat\s+v(\d+\.\d+\.\d+)',
            'msfvenom': r'MSFvenom\s+v(\d+\.\d+\.\d+)',
            'responder': r'Responder\s+(\d+\.\d+\.\d+)',
            'beef': r'BeEF\s+(\d+\.\d+\.\d+)',
            'burpsuite': r'Burp Suite\s+(\d+\.\d+\.\d+)',
            'zaproxy': r'ZAP\s+(\d+\.\d+\.\d+)',
            'masscan': r'masscan\s+(\d+\.\d+\.\d+)',
            'crackmapexec': r'CME\s+(\d+\.\d+\.\d+)',
            'empire': r'Empire\s+(\d+\.\d+\.\d+)',
            'bloodhound': r'BloodHound\s+(\d+\.\d+\.\d+)',
            'mimikatz': r'mimikatz\s+(\d+\.\d+\.\d+)',
            'recon-ng': r'Recon-ng v(\d+\.\d+\.\d+)',
            'maltego': r'Maltego v(\d+\.\d+\.\d+)',
            'fierce': r'fierce (\d+\.\d+\.\d+)',
            'dnsenum': r'dnsenum VERSION:(\d+\.\d+\.\d+)',
            'subfinder': r'SubFinder v(\d+\.\d+\.\d+)',
            'amass': r'OWASP Amass v(\d+\.\d+\.\d+)',
            'nuclei': r'nuclei v(\d+\.\d+\.\d+)',
            'ffuf': r'ffuf v(\d+\.\d+\.\d+)',
            'feroxbuster': r'feroxbuster v(\d+\.\d+\.\d+)',
            'theHarvester': r'theHarvester (\d+\.\d+\.\d+)',
            'sherlock': r'sherlock (\d+\.\d+\.\d+)',
            'photon': r'photon (\d+\.\d+\.\d+)'
        }
        
        # Update progress patterns
        self.progress_patterns = {
            'nmap': r'(\d+)% done',
            'sqlmap': r'(\d+/\d+) entries',
            'hydra': r'\[DATA\] (\d+) tasks completed',
            'gobuster': r'Progress: (\d+\.\d+)%',
            'wpscan': r'\[=+\] (\d+)% done',
            'aircrack-ng': r'(\d+\.\d+)% completed',
            'john': r'(\d+\.\d+)% \(\d+/\d+ keys tested\)',
            'hashcat': r'Progress\.+:\s*(\d+/\d+)',
            'masscan': r'Progress:\s*(\d+\.\d+)%',
            'crackmapexec': r'Progress:\s*(\d+/\d+)',
            'empire': r'Progress:\s*(\d+/\d+)',
            'bloodhound': r'Progress:\s*(\d+/\d+)',
            'recon-ng': r'Progress: (\d+/\d+)',
            'maltego': r'Progress: \[(\d+)/(\d+)\]',
            'fierce': r'Progress: (\d+\.\d+)%',
            'dnsenum': r'Progress: \[(\d+)/(\d+)\]',
            'subfinder': r'Progress: \[(\d+)/(\d+)\]',
            'amass': r'Progress: \[(\d+)/(\d+)\]',
            'nuclei': r'Progress: \[(\d+)/(\d+)\]',
            'ffuf': r':: Progress: \[(\d+)/(\d+)\]',
            'feroxbuster': r'Progress: (\d+\.\d+)%',
            'theHarvester': r'Progress: (\d+/\d+)',
            'sherlock': r'Progress: (\d+/\d+)',
            'photon': r'Progress: (\d+/\d+)'
        }
        
        # Update statistics patterns
        self.stats_patterns = {
            'nmap': {
                'hosts_up': r'(\d+) hosts up',
                'ports_open': r'(\d+) ports open',
                'services': r'(\d+) services on (\d+) ports'
            },
            'sqlmap': {
                'databases': r'available databases \[(\d+)\]:',
                'tables': r'Database: .* \[(\d+) tables\]',
                'entries': r'fetched (\d+) entries'
            },
            'hydra': {
                'attempts': r'(\d+) of \d+ tries',
                'valid': r'(\d+) valid passwords found'
            },
            'gobuster': {
                'found': r'Found: (\d+) matches',
                'errors': r'Error: (\d+) errors'
            },
            'aircrack-ng': {
                'handshakes': r'(\d+) handshake.*captured',
                'keys_tested': r'(\d+) keys tested',
                'keys_per_second': r'(\d+.\d+) keys/s'
            },
            'john': {
                'passwords_loaded': r'Loaded (\d+) password hash',
                'passwords_cracked': r'Cracked (\d+) password',
                'guesses': r'Guesses: (\d+)'
            },
            'hashcat': {
                'speed': r'Speed\.#\d+\.+:\s*(\d+)',
                'recovered': r'Recovered\.+:\s*(\d+/\d+)',
                'rejected': r'Rejected\.+:\s*(\d+/\d+)'
            },
            'masscan': {
                'hosts': r'Scanning (\d+) hosts',
                'ports': r'(\d+) ports/host',
                'results': r'found (\d+) results'
            },
            'crackmapexec': {
                'hosts': r'(\d+) hosts successfully',
                'users': r'(\d+) users enumerated',
                'shares': r'(\d+) shares enumerated'
            },
            'bloodhound': {
                'computers': r'Found (\d+) computers',
                'users': r'Found (\d+) users',
                'groups': r'Found (\d+) groups',
                'sessions': r'Found (\d+) sessions'
            },
            'recon-ng': {
                'records': r'(\d+) records? added',
                'modules': r'(\d+) modules? completed'
            },
            'maltego': {
                'entities': r'Found (\d+) entities',
                'relationships': r'Found (\d+) relationships'
            },
            'fierce': {
                'hosts': r'Found (\d+) hosts',
                'nameservers': r'Found (\d+) nameservers'
            },
            'dnsenum': {
                'hosts': r'Found (\d+) hosts',
                'nameservers': r'Found (\d+) nameservers'
            },
            'subfinder': {
                'subdomains': r'Discovered (\d+) subdomains',
                'sources': r'Using (\d+) sources'
            },
            'amass': {
                'domains': r'Discovered (\d+) domains',
                'ips': r'Resolved (\d+) IPs'
            },
            'nuclei': {
                'templates': r'Templates loaded: (\d+)',
                'findings': r'Found (\d+) results'
            },
            'ffuf': {
                'results': r':: Progress: \[(\d+)/(\d+)\]',
                'matches': r':: Matches: (\d+)'
            },
            'feroxbuster': {
                'status': r'(\d{3})',
                'size': r'(\d+[KMG]?)',
                'url': r'(.*?)'
            },
            'theHarvester': {
                'hosts': r'Hosts found: (\d+)',
                'emails': r'Emails found: (\d+)',
                'ips': r'IPs found: (\d+)'
            }
        }
        
        # Update vulnerability patterns
        self.vuln_patterns = {
            'nmap': {
                'pattern': r'(\d+)/(\w+)\s+(\w+)\s+(\w+)\s+(.*?)(?=\n|$)',
                'fields': ['port', 'protocol', 'state', 'service', 'details']
            },
            'sqlmap': {
                'pattern': r'Parameter \'(.*?)\' is vulnerable\. (.+?)(?=\n|$)',
                'fields': ['parameter', 'details']
            },
            'nikto': {
                'pattern': r'\+ (OSVDB-\d+):\s*(.*?)(?=\n|$)',
                'fields': ['id', 'description']
            },
            'wpscan': {
                'pattern': r'\[\+\] (.*?): (.*?)(?=\n|$)',
                'fields': ['type', 'description']
            },
            'aircrack-ng': {
                'pattern': r'WPA \((.*?)\) handshake: (.*?)(?=\n|$)',
                'fields': ['type', 'status']
            },
            'responder': {
                'pattern': r'\[\*\] \[(\w+)\] (.*?) from: (.*?)(?=\n|$)',
                'fields': ['protocol', 'event', 'source']
            },
            'burpsuite': {
                'pattern': r'Vulnerability: (.*?)\nSeverity: (.*?)\nConfidence: (.*?)(?=\n|$)',
                'fields': ['name', 'severity', 'confidence']
            },
            'zaproxy': {
                'pattern': r'(ALERT|WARN)-\d+: (.*?)\nRisk: (.*?)\nConfidence: (.*?)(?=\n|$)',
                'fields': ['type', 'description', 'risk', 'confidence']
            },
            'nuclei': {
                'pattern': r'\[(.*?)\] \[(.*?)\] (.*?) \[(.*?)\] (.*?)(?=\n|$)',
                'fields': ['severity', 'template', 'host', 'matcher', 'details']
            },
            'ffuf': {
                'pattern': r'(.*?):\s+\[Status: (\d+), Size: (\d+), Words: (\d+), Lines: (\d+)\]',
                'fields': ['url', 'status', 'size', 'words', 'lines']
            },
            'feroxbuster': {
                'pattern': r'(\d{3})\s+(\d+[KMG]?)\s+(.*?)(?=\n|$)',
                'fields': ['status', 'size', 'url']
            }
        }
        
        # Add GPT analysis settings
        self.gpt_analysis_enabled = True
        self.unrecognized_threshold = 0.3  # If more than 30% of lines are unrecognized, use GPT
        self.max_context_length = 4000  # Maximum characters to send to GPT
        
        # Add GPT analysis prompt templates
        self.GPT_PROMPTS = {
            'error_analysis': """Analyze this console output for errors:
---
{text}
---
Identify any errors, their severity, and potential solutions. Format as JSON:
{
    "errors": [{"error": "error message", "severity": "high|medium|low", "solution": "potential fix"}],
    "is_error": true|false
}""",
            
            'pattern_analysis': """Analyze this console output pattern:
---
{text}
---
Categorize this output and extract key information. Format as JSON:
{
    "category": "error|warning|success|info",
    "pattern_type": "what kind of pattern this represents",
    "key_information": "important details extracted",
    "suggested_regex": "a regex pattern to catch similar outputs"
}""",
            
            'context_analysis': """Analyze this security tool output:
---
{text}
---
Extract key security findings and context. Format as JSON:
{
    "tool_name": "detected tool name if any",
    "findings": ["list of key findings"],
    "severity": "high|medium|low",
    "recommendations": ["list of recommendations"],
    "context_type": "type of security context"
}"""
        }
        
        # Add tool-specific fixes
        self.TOOL_FIXES = {
            'nmap': {
                r'Failed to resolve': {
                    'fix': 'Check DNS settings or add target to /etc/hosts',
                    'command': 'nmap -Pn {target}'
                },
                r'Permission denied': {
                    'fix': 'Run with sudo or as root',
                    'command': 'sudo nmap {options} {target}'
                },
                r'No targets were specified': {
                    'fix': 'Specify target IP or hostname',
                    'command': 'nmap -p- {target}'
                }
            },
            'metasploit': {
                r'Exploit failed': {
                    'fix': 'Try different payload or target',
                    'command': 'set PAYLOAD {alternate_payload}'
                },
                r'No session created': {
                    'fix': 'Check target compatibility and firewall settings',
                    'command': 'set LHOST {local_ip}'
                },
                r'Handler failed': {
                    'fix': 'Check if port is in use',
                    'command': 'set LPORT {alternate_port}'
                }
            },
            'sqlmap': {
                r'connection timed out': {
                    'fix': 'Increase timeout or reduce threads',
                    'command': 'sqlmap --timeout=30 --threads=1'
                },
                r'WAF detected': {
                    'fix': 'Try using tamper scripts',
                    'command': 'sqlmap --tamper=space2comment,between {options}'
                },
                r'no parameter appears': {
                    'fix': 'Specify parameter manually',
                    'command': 'sqlmap -p {parameter}'
                }
            },
            'hydra': {
                r'target protocol does not exist': {
                    'fix': 'Check protocol specification',
                    'command': 'hydra -L users.txt -P pass.txt {protocol}://{target}'
                },
                r'Error connecting to port': {
                    'fix': 'Verify port is correct and service is running',
                    'command': 'hydra -s {port} {target} {protocol}'
                }
            },
            'nikto': {
                r'no web server found': {
                    'fix': 'Verify target is running web server',
                    'command': 'nikto -h {target} -p {port}'
                },
                r'SSL error': {
                    'fix': 'Try without SSL verification',
                    'command': 'nikto -h {target} -nossl'
                }
            },
            'wpscan': {
                r'The URL supplied.*is not WordPress': {
                    'fix': 'Verify target is WordPress site',
                    'command': 'wpscan --url {target} --force'
                },
                r'API limit reached': {
                    'fix': 'Use API token or wait',
                    'command': 'wpscan --url {target} --api-token {token}'
                }
            },
            'gobuster': {
                r'error on wildcard': {
                    'fix': 'Use -fw flag to force processing',
                    'command': 'gobuster dir -u {target} -w {wordlist} -fw'
                },
                r'Unable to connect': {
                    'fix': 'Check target availability',
                    'command': 'gobuster dir -u {target} -w {wordlist} -t 1'
                }
            },
            'enum4linux': {
                r'Connection refused': {
                    'fix': 'Check if SMB service is running',
                    'command': 'enum4linux -a -u "" -p "" {target}'
                },
                r'NT_STATUS_ACCESS_DENIED': {
                    'fix': 'Try null session',
                    'command': 'enum4linux -a -N {target}'
                }
            },
            'aircrack-ng': {
                r'No such BSSID': {
                    'fix': 'Verify BSSID is correct',
                    'command': 'airodump-ng {interface} --bssid {bssid}'
                },
                r'No such device': {
                    'fix': 'Put interface in monitor mode',
                    'command': 'airmon-ng start {interface}'
                }
            },
            'john': {
                r'No password hashes loaded': {
                    'fix': 'Check hash format',
                    'command': 'john --format={format} {hashfile}'
                },
                r'No such format': {
                    'fix': 'List available formats',
                    'command': 'john --list=formats'
                }
            },
            'hashcat': {
                r'No devices found': {
                    'fix': 'Check OpenCL/CUDA installation',
                    'command': 'hashcat -I'
                },
                r'Separator unmatched': {
                    'fix': 'Check hash format',
                    'command': 'hashcat -m {mode} {hashfile}'
                }
            },
            'msfvenom': {
                r'No platform was selected': {
                    'fix': 'Specify platform',
                    'command': 'msfvenom -p {payload} --platform {platform}'
                },
                r'Invalid format': {
                    'fix': 'List available formats',
                    'command': 'msfvenom --list formats'
                }
            },
            'responder': {
                r'Port already in use': {
                    'fix': 'Kill conflicting services',
                    'command': 'responder -I {interface} --lm'
                },
                r'Permission denied': {
                    'fix': 'Run as root',
                    'command': 'sudo responder -I {interface}'
                }
            },
            'beef': {
                r'Database connection error': {
                    'fix': 'Check database configuration',
                    'command': 'beef-xss --resetdb'
                },
                r'Port already in use': {
                    'fix': 'Change port',
                    'command': 'beef-xss -p {alternate_port}'
                }
            },
            'burpsuite': {
                r'Java heap space': {
                    'fix': 'Increase Java heap size',
                    'command': 'java -jar -Xmx2g burpsuite.jar'
                },
                r'Failed to start proxy': {
                    'fix': 'Check port availability',
                    'command': 'change proxy port in settings'
                }
            },
            'masscan': {
                r'FAILED: failed to create raw socket': {
                    'fix': 'Run as root',
                    'command': 'sudo masscan {target} -p{ports}'
                },
                r'failed to detect route': {
                    'fix': 'Specify interface',
                    'command': 'masscan --interface {interface} {target}'
                }
            },
            'crackmapexec': {
                r'Kerberos SessionError': {
                    'fix': 'Check domain settings',
                    'command': 'crackmapexec smb {target} -d {domain}'
                },
                r'connection refused': {
                    'fix': 'Verify service is running',
                    'command': 'crackmapexec {protocol} {target} -u {user} -p {pass}'
                }
            },
            'empire': {
                r'Listener already exists': {
                    'fix': 'Use different name or kill existing',
                    'command': 'listeners kill {listener_name}'
                },
                r'No listeners': {
                    'fix': 'Start listener first',
                    'command': 'uselistener {listener_type}'
                }
            },
            'bloodhound': {
                r'Neo4j is not running': {
                    'fix': 'Start Neo4j service',
                    'command': 'neo4j start'
                },
                r'Invalid credentials': {
                    'fix': 'Check Neo4j credentials',
                    'command': 'bloodhound --user {neo4j_user} --password {neo4j_pass}'
                }
            },
            'mimikatz': {
                r'ERROR kuhl_m_': {
                    'fix': 'Run as administrator',
                    'command': 'privilege::debug'
                },
                r'Invalid access': {
                    'fix': 'Enable SeDebugPrivilege',
                    'command': 'token::elevate'
                }
            },
            'recon-ng': {
                r'API key not found': {
                    'fix': 'Add API key',
                    'command': 'keys add {keyname} {key}'
                },
                r'module not found': {
                    'fix': 'Install module',
                    'command': 'marketplace install {module}'
                }
            },
            'maltego': {
                r'Transform execution failed': {
                    'fix': 'Check transform settings',
                    'command': 'reconfigure transform settings'
                },
                r'API quota exceeded': {
                    'fix': 'Wait or upgrade API limits',
                    'command': 'check transform properties'
                }
            },
            'fierce': {
                r'Could not resolve': {
                    'fix': 'Check DNS settings',
                    'command': 'fierce --dns-servers {nameserver} -d {domain}'
                },
                r'No nameservers found': {
                    'fix': 'Specify nameserver',
                    'command': 'fierce --dns-servers 8.8.8.8 -d {domain}'
                }
            },
            'subfinder': {
                r'no API keys found': {
                    'fix': 'Add API keys to config',
                    'command': 'subfinder -d {domain} -config config.yaml'
                },
                r'no sources available': {
                    'fix': 'Enable sources in config',
                    'command': 'subfinder -d {domain} -all'
                }
            },
            'amass': {
                r'no DNS resolvers': {
                    'fix': 'Specify resolvers',
                    'command': 'amass enum -d {domain} -rf resolvers.txt'
                },
                r'rate limit': {
                    'fix': 'Add API keys or reduce rate',
                    'command': 'amass enum -d {domain} -config config.ini'
                }
            },
            'nuclei': {
                r'no templates': {
                    'fix': 'Update templates',
                    'command': 'nuclei -ut'
                },
                r'connection refused': {
                    'fix': 'Check target availability',
                    'command': 'nuclei -u {target} -timeout 5'
                }
            },
            'ffuf': {
                r'connection timeout': {
                    'fix': 'Increase timeout or threads',
                    'command': 'ffuf -u {target} -t 1 -timeout 10'
                },
                r'no matches found': {
                    'fix': 'Adjust matching settings',
                    'command': 'ffuf -mc all -u {target}'
                }
            },
            'feroxbuster': {
                r'connection refused': {
                    'fix': 'Check target availability',
                    'command': 'feroxbuster -u {target} --timeout 5'
                },
                r'too many requests': {
                    'fix': 'Reduce scan speed',
                    'command': 'feroxbuster -u {target} --threads 1 --delay 500'
                }
            },
            'theHarvester': {
                r'API key error': {
                    'fix': 'Add API keys to config',
                    'command': 'theHarvester -d {domain} -b all'
                },
                r'source not found': {
                    'fix': 'Check available sources',
                    'command': 'theHarvester -l'
                }
            },
            'sherlock': {
                r'invalid username': {
                    'fix': 'Check username format',
                    'command': 'sherlock {username} --print-found'
                },
                r'rate limited': {
                    'fix': 'Use timeout between requests',
                    'command': 'sherlock {username} --timeout 5'
                }
            },
            'photon': {
                r'invalid URL': {
                    'fix': 'Check URL format',
                    'command': 'photon -u {url} --verify'
                },
                r'connection error': {
                    'fix': 'Check target accessibility',
                    'command': 'photon -u {url} --timeout 10'
                }
            }
        }
        
        # Add NLP settings
        self.nlp_enabled = True
        self.similarity_threshold = 0.75  # Minimum similarity score to consider a match
        self.unknown_tool_threshold = 0.4  # Lower threshold for unknown tools
        
        # Common output keywords by category
        self.CATEGORY_KEYWORDS = {
            'error': [
                'error', 'failed', 'failure', 'invalid', 'denied', 'unable', 
                'cannot', 'timeout', 'exception', 'crash', 'critical'
            ],
            'warning': [
                'warning', 'notice', 'deprecated', 'weak', 'insecure', 
                'vulnerable', 'potential', 'possible'
            ],
            'success': [
                'success', 'completed', 'finished', 'done', 'found', 
                'discovered', 'established', 'connected'
            ],
            'info': [
                'info', 'status', 'progress', 'scanning', 'processing', 
                'analyzing', 'loading', 'starting'
            ]
        }
        
        # Tool categories for context
        self.TOOL_CATEGORIES = {
            'reconnaissance': [
                'nmap', 'masscan', 'recon-ng', 'maltego', 'fierce', 
                'dnsenum', 'subfinder', 'amass', 'theHarvester'
            ],
            'web_scanning': [
                'nikto', 'wpscan', 'gobuster', 'burpsuite', 'zaproxy', 
                'nuclei', 'ffuf', 'feroxbuster'
            ],
            'exploitation': [
                'metasploit', 'sqlmap', 'beef', 'empire', 'responder'
            ],
            'password_attacks': [
                'hydra', 'john', 'hashcat', 'aircrack-ng'
            ],
            'post_exploitation': [
                'mimikatz', 'bloodhound', 'crackmapexec'
            ]
        }
    
    def _initialize_pattern_vectors(self):
        """Pre-compute vectors for all patterns and keywords"""
        # Process regular patterns
        for category, patterns in self.pattern_categories.items():
            if isinstance(patterns, list):
                for pattern in patterns:
                    # Convert regex pattern to text by removing special characters
                    text = self._pattern_to_text(pattern)
                    self.pattern_vectors[pattern] = self.nlp(text)
            elif isinstance(patterns, dict):  # For tool-specific patterns
                for tool, tool_patterns in patterns.items():
                    for pattern_type, pattern_list in tool_patterns.items():
                        for pattern in pattern_list:
                            text = self._pattern_to_text(pattern)
                            self.pattern_vectors[pattern] = self.nlp(text)

        # Process keywords
        for category, keywords in self.CATEGORY_KEYWORDS.items():
            for keyword in keywords:
                self.keyword_vectors[keyword] = self.nlp(keyword)

    def _pattern_to_text(self, pattern: str) -> str:
        """Convert regex pattern to plain text for NLP processing"""
        # Remove common regex special characters
        text = re.sub(r'[\[\]\{\}\(\)\^\$\*\+\?\|\\]', ' ', pattern)
        # Remove regex character classes
        text = re.sub(r'\\[ws]', '', text)
        # Remove common regex groups
        text = re.sub(r'\(\?:.*?\)', '', text)
        # Clean up extra spaces
        text = ' '.join(text.split())
        return text

    def _calculate_similarity(self, doc1: spacy.tokens.Doc, doc2: spacy.tokens.Doc) -> float:
        """Calculate semantic similarity between two SpaCy docs"""
        if not doc1.vector_norm or not doc2.vector_norm:
            return 0.0
        return doc1.similarity(doc2)

    def _analyze_text_with_nlp(self, text: str) -> Dict[str, Any]:
        """
        Analyze text using SpaCy NLP
        """
        doc = self.nlp(text)
        
        # Initialize results
        analysis = {
            'entities': [],
            'key_phrases': [],
            'sentiment': 0.0,
            'categories': defaultdict(float),
            'matched_patterns': [],
            'confidence': 0.0
        }
        
        # Extract entities
        for ent in doc.ents:
            analysis['entities'].append({
                'text': ent.text,
                'label': ent.label_,
                'start': ent.start_char,
                'end': ent.end_char
            })
        
        # Extract key phrases (noun chunks)
        analysis['key_phrases'] = [chunk.text for chunk in doc.noun_chunks]
        
        # Calculate pattern similarities
        for pattern, pattern_vec in self.pattern_vectors.items():
            similarity = self._calculate_similarity(doc, pattern_vec)
            if similarity >= self.pattern_similarity_threshold:
                analysis['matched_patterns'].append({
                    'pattern': pattern,
                    'similarity': similarity
                })
        
        # Calculate category scores
        for category, keywords in self.CATEGORY_KEYWORDS.items():
            max_similarity = 0.0
            for keyword, keyword_vec in self.keyword_vectors.items():
                if keyword in keywords:
                    similarity = self._calculate_similarity(doc, keyword_vec)
                    max_similarity = max(max_similarity, similarity)
            analysis['categories'][category] = max_similarity
        
        # Set overall confidence based on best category match
        analysis['confidence'] = max(analysis['categories'].values()) if analysis['categories'] else 0.0
        
        return analysis

    def _analyze_pattern_matches(self, text: str, tool: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze pattern matches using both regex and NLP
        """
        # Get NLP analysis
        nlp_analysis = self._analyze_text_with_nlp(text)
        
        # Initialize result
        result = {
            'category': 'unknown',
            'confidence': nlp_analysis['confidence'],
            'matched_patterns': [],
            'nlp_entities': nlp_analysis['entities'],
            'key_phrases': nlp_analysis['key_phrases'],
            'needs_gpt': False
        }
        
        # Check regex pattern matches
        regex_matches = []
        for category, patterns in self.pattern_categories.items():
            if isinstance(patterns, list):
                for pattern in patterns:
                    if re.search(pattern, text, re.IGNORECASE):
                        regex_matches.append({
                            'category': category,
                            'pattern': pattern
                        })
            elif isinstance(patterns, dict) and tool:  # Tool-specific patterns
                if tool.lower() in patterns:
                    tool_patterns = patterns[tool.lower()]
                    for pattern_type, pattern_list in tool_patterns.items():
                        for pattern in pattern_list:
                            if re.search(pattern, text, re.IGNORECASE):
                                regex_matches.append({
                                    'category': f'{tool}_{pattern_type}',
                                    'pattern': pattern
                                })
        
        # Combine regex and NLP results
        result['matched_patterns'] = regex_matches + nlp_analysis['matched_patterns']
        
        # Determine category based on both regex and NLP
        if regex_matches:
            # Prioritize regex matches for category
            result['category'] = regex_matches[0]['category']
            result['confidence'] = max(result['confidence'], 0.8)  # High confidence for regex matches
        else:
            # Use NLP category if no regex matches
            best_category = max(nlp_analysis['categories'].items(), key=lambda x: x[1])
            result['category'] = best_category[0]
        
        # Determine if GPT analysis is needed
        result['needs_gpt'] = (
            result['confidence'] < self.similarity_threshold or
            (not result['matched_patterns'] and tool and tool.lower() not in self.TOOL_PATTERNS)
        )
        
        return result

    def _calculate_text_similarity(self, text1: str, text2: str) -> float:
        """
        Calculate similarity between two text strings using basic NLP techniques
        """
        # Convert to lowercase and split into words
        words1 = set(text1.lower().split())
        words2 = set(text2.lower().split())
        
        # Calculate Jaccard similarity
        intersection = len(words1.intersection(words2))
        union = len(words1.union(words2))
        
        return intersection / union if union > 0 else 0.0

    def _get_tool_category(self, tool: str) -> Optional[str]:
        """
        Get the category of a tool
        """
        tool = tool.lower()
        for category, tools in self.TOOL_CATEGORIES.items():
            if tool in tools:
                return category
        return None

    def _analyze_pattern_with_nlp(self, text: str, tool: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze text pattern using NLP techniques
        
        Returns:
            Dict containing analysis results:
            {
                'category': str,          # Detected category
                'confidence': float,      # Confidence score
                'known_tool': bool,       # Whether tool is known
                'needs_gpt': bool,        # Whether GPT analysis is recommended
                'matched_patterns': list   # List of matched pattern types
            }
        """
        # Initialize result
        result = {
            'category': 'unknown',
            'confidence': 0.0,
            'known_tool': False,
            'needs_gpt': False,
            'matched_patterns': []
        }
        
        # Check if tool is known
        if tool:
            tool_category = self._get_tool_category(tool)
            result['known_tool'] = tool_category is not None
            if tool.lower() in self.TOOL_PATTERNS:
                result['known_tool'] = True
        
        # Calculate similarity scores for each category
        category_scores = {}
        for category, keywords in self.CATEGORY_KEYWORDS.items():
            max_similarity = max(
                self._calculate_text_similarity(text, keyword)
                for keyword in keywords
            )
            category_scores[category] = max_similarity
        
        # Get the highest scoring category
        best_category = max(category_scores.items(), key=lambda x: x[1])
        result['category'] = best_category[0]
        result['confidence'] = best_category[1]
        
        # Check pattern matches
        for pattern_type in ['ERROR_PATTERNS', 'WARNING_PATTERNS', 'SUCCESS_PATTERNS']:
            patterns = getattr(self, pattern_type, [])
            if any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns):
                result['matched_patterns'].append(pattern_type.lower())
        
        # Determine if GPT analysis is needed
        threshold = (
            self.unknown_tool_threshold if not result['known_tool'] 
            else self.similarity_threshold
        )
        
        result['needs_gpt'] = (
            result['confidence'] < threshold or
            (not result['matched_patterns'] and not result['known_tool'])
        )
        
        return result

    def _extract_version_info(self, output: str, tool: str) -> Optional[str]:
        """Extract version information for a specific tool"""
        if tool.lower() in self.version_patterns:
            match = re.search(self.version_patterns[tool.lower()], output)
            if match:
                return match.group(1)
        return None
    
    def _extract_progress_info(self, output: str, tool: str) -> Optional[str]:
        """Extract progress information from tool output"""
        if tool.lower() in self.progress_patterns:
            match = re.search(self.progress_patterns[tool.lower()], output)
            if match:
                return match.group(1)
        return None
    
    def _extract_statistics(self, output: str, tool: str) -> Dict[str, str]:
        """Extract statistical information from tool output"""
        stats = {}
        
        if tool.lower() in self.stats_patterns:
            for stat_name, pattern in self.stats_patterns[tool.lower()].items():
                match = re.search(pattern, output)
                if match:
                    stats[stat_name] = match.group(1)
        
        return stats
    
    def _extract_vulnerabilities(self, output: str, tool: str) -> List[Dict[str, str]]:
        """Extract vulnerability information from security tool output"""
        vulns = []
        
        if tool.lower() in self.vuln_patterns:
            pattern_info = self.vuln_patterns[tool.lower()]
            matches = re.finditer(pattern_info['pattern'], output, re.MULTILINE)
            for match in matches:
                vuln = {}
                for i, field in enumerate(pattern_info['fields']):
                    vuln[field] = match.group(i + 1)
                vulns.append(vuln)
        
        return vulns

    def _analyze_with_gpt(self, text: str, analysis_type: str = 'pattern_analysis') -> Dict:
        """
        Send text to GPT-4 for analysis, enhanced with NLP context
        """
        try:
            # Get NLP analysis first
            nlp_analysis = self._analyze_text_with_nlp(text)
            
            # Truncate text if too long
            if len(text) > self.max_context_length:
                text = text[:self.max_context_length] + "..."
            
            # Enhance prompt with NLP insights
            nlp_context = {
                'entities': [e['text'] for e in nlp_analysis['entities']],
                'key_phrases': nlp_analysis['key_phrases'],
                'detected_categories': [k for k, v in nlp_analysis['categories'].items() if v > 0.5]
            }
            
            # Get appropriate prompt template and enhance it with NLP context
            prompt = self.GPT_PROMPTS.get(analysis_type, self.GPT_PROMPTS['pattern_analysis'])
            enhanced_prompt = prompt.format(
                text=text,
                nlp_context=json.dumps(nlp_context, indent=2)
            )
            
            # Use the AI handler to get GPT-4 analysis
            response = self.ai_handler.get_completion(enhanced_prompt)
            
            # Parse JSON response
            try:
                return json.loads(response)
            except json.JSONDecodeError:
                return {"error": "Failed to parse GPT response", "raw_response": response}
                
        except Exception as e:
            return {"error": f"GPT analysis failed: {str(e)}"}

    def _identify_unrecognized_patterns(self, lines: List[str]) -> List[str]:
        """
        Identify lines that don't match any known patterns using both regex and NLP
        """
        unrecognized = []
        for line in lines:
            if not line.strip():
                continue
            
            # Get NLP analysis
            analysis = self._analyze_text_with_nlp(line)
            
            # Check if line has sufficient NLP confidence or regex matches
            recognized = (
                analysis['confidence'] >= self.similarity_threshold or
                any(re.search(pattern, line, re.IGNORECASE) for patterns in self.pattern_categories.values() 
                    for pattern in (patterns if isinstance(patterns, list) else []))
            )
            
            if not recognized:
                unrecognized.append(line)
        
        return unrecognized

    def analyze_output(self, output: str, tool: Optional[str] = None, context_type: str = "security") -> AnalysisResult:
        """
        Analyze console output using enhanced NLP and pattern matching
        """
        # Initialize results
        errors = []
        warnings = []
        key_info = []
        gpt_analysis = None
        nlp_results = []
        
        # Split output into lines
        lines = output.split('\n')
        
        # Analyze each line
        for line in lines:
            if not line.strip():
                continue
            
            # Get combined analysis
            analysis = self._analyze_pattern_matches(line, tool)
            nlp_results.append(analysis)
            
            # Categorize based on analysis
            if analysis['confidence'] >= self.similarity_threshold:
                if analysis['category'] == 'error':
                    errors.append(line)
                elif analysis['category'] == 'warning':
                    warnings.append(line)
                elif analysis['category'] in ['success', 'info']:
                    key_info.append(line)
                
                # Add any extracted entities or key phrases as additional info
                for entity in analysis['nlp_entities']:
                    if entity['label'] in ['ORG', 'PRODUCT', 'GPE', 'IP']:
                        key_info.append(f"Detected {entity['label']}: {entity['text']}")
            
            # Track if GPT analysis is needed
            if analysis['needs_gpt']:
                if not gpt_analysis and self.gpt_analysis_enabled:
                    gpt_analysis = self._analyze_with_gpt(line, 'pattern_analysis')
        
        # If GPT analysis is needed and enabled
        if gpt_analysis and self.gpt_analysis_enabled:
            unrecognized_text = "\n".join(self._identify_unrecognized_patterns(lines))
            gpt_analysis = self._analyze_with_gpt(unrecognized_text, 'pattern_analysis')
            
            # Incorporate GPT findings
            if isinstance(gpt_analysis, dict):
                if gpt_analysis.get('category') == 'error':
                    errors.extend(gpt_analysis.get('findings', []))
                elif gpt_analysis.get('category') == 'warning':
                    warnings.extend(gpt_analysis.get('findings', []))
                
                if 'key_information' in gpt_analysis:
                    key_info.append(f"GPT Analysis: {gpt_analysis['key_information']}")
                
                if 'suggested_regex' in gpt_analysis:
                    key_info.append(f"Suggested Pattern: {gpt_analysis['suggested_regex']}")
        
        # Extract version info if available
        if tool:
            version = self._extract_version_info(output, tool)
            if version:
                key_info.append(f"Version: {version}")
        
        # Extract progress info if available
        if tool:
            progress = self._extract_progress_info(output, tool)
            if progress:
                key_info.append(f"Progress: {progress}")
        
        # Extract statistics if available
        if tool:
            stats = self._extract_statistics(output, tool)
            for stat_name, value in stats.items():
                key_info.append(f"{stat_name.replace('_', ' ').title()}: {value}")
        
        # Extract vulnerabilities if available
        if tool:
            vulns = self._extract_vulnerabilities(output, tool)
            for vuln in vulns:
                vuln_info = " | ".join(f"{k}: {v}" for k, v in vuln.items())
                key_info.append(f"Vulnerability: {vuln_info}")
        
        # Process each line
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Skip common ignore patterns
            if any(re.match(pattern, line) for pattern in self.COMMON_IGNORE_PATTERNS):
                continue
            
            # Check for errors
            for pattern in self.ERROR_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    errors.append(line)
                    break
            
            # Check for warnings
            for pattern in self.WARNING_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    warnings.append(line)
                    break
        
        # Tool-specific analysis
        if tool and tool.lower() in self.TOOL_PATTERNS:
            patterns = self.TOOL_PATTERNS[tool.lower()]
            
            # Extract key information
            for pattern in patterns['key_info']:
                for line in lines:
                    if re.search(pattern, line):
                        key_info.append(line)
            
            # Filter out ignored lines
            filtered_lines = []
            for line in lines:
                ignore = False
                for pattern in patterns['ignore']:
                    if re.search(pattern, line):
                        ignore = True
                        break
                if not ignore and not any(re.match(p, line) for p in self.COMMON_IGNORE_PATTERNS):
                    filtered_lines.append(line)
            
            lines = filtered_lines
        
        # Determine success based on errors and success patterns
        success = len(errors) == 0 and any(
            re.search(pattern, line, re.IGNORECASE)
            for pattern in self.SUCCESS_PATTERNS
            for line in lines
        )
        
        # Add NLP analysis summary to context
        nlp_summary = self._summarize_nlp_results(nlp_results)
        if nlp_summary:
            key_info.extend(nlp_summary)
        
        # Create context summary
        context = self._create_context_summary(
            lines, key_info, errors, warnings,
            tool=tool, context_type=context_type,
            gpt_analysis=gpt_analysis,
            nlp_results=nlp_results
        )
        
        return AnalysisResult(
            success=success,
            key_info=key_info,
            errors=errors,
            warnings=warnings,
            context=context,
            raw_output=output,
            gpt_analysis=gpt_analysis
        )
    
    def _summarize_nlp_results(self, nlp_results: List[Dict]) -> List[str]:
        """
        Create a summary of NLP analysis results
        """
        summary = []
        
        # Count categories
        categories = {}
        confidence_sum = 0
        total_results = len(nlp_results)
        
        for result in nlp_results:
            category = result['category']
            categories[category] = categories.get(category, 0) + 1
            confidence_sum += result['confidence']
        
        # Add category distribution
        if categories:
            summary.append("Pattern Distribution:")
            for category, count in categories.items():
                percentage = (count / total_results) * 100
                summary.append(f"- {category.title()}: {percentage:.1f}% ({count} patterns)")
        
        # Add average confidence
        if total_results > 0:
            avg_confidence = confidence_sum / total_results
            summary.append(f"Average Pattern Confidence: {avg_confidence:.2f}")
        
        return summary

    def _create_context_summary(
        self, 
        lines: List[str],
        key_info: List[str],
        errors: List[str],
        warnings: List[str],
        tool: Optional[str] = None,
        context_type: str = "security",
        gpt_analysis: Dict = None,
        nlp_results: List[Dict] = None
    ) -> str:
        """Create a concise context summary enhanced with NLP insights"""
        summary_parts = []
        
        # Add tool name and category if available
        if tool:
            tool_category = self._get_tool_category(tool)
            summary_parts.append(f"Tool: {tool}")
            if tool_category:
                summary_parts.append(f"Category: {tool_category}")
        
        # Aggregate NLP insights
        if nlp_results:
            entities = defaultdict(set)
            key_phrases = set()
            for result in nlp_results:
                for entity in result.get('nlp_entities', []):
                    entities[entity['label']].add(entity['text'])
                key_phrases.update(result.get('key_phrases', []))
            
            # Add important entities
            if entities:
                summary_parts.append("\nDetected Entities:")
                for label, values in entities.items():
                    if label in ['ORG', 'PRODUCT', 'GPE', 'IP', 'TOOL']:
                        summary_parts.append(f"- {label}: {', '.join(values)}")
            
            # Add important key phrases
            if key_phrases:
                summary_parts.append("\nKey Concepts:")
                summary_parts.extend(f"- {phrase}" for phrase in key_phrases)
        
        # Add pattern recognition summary
        if nlp_results:
            pattern_summary = self._summarize_nlp_results(nlp_results)
            if pattern_summary:
                summary_parts.extend(pattern_summary)
        
        # Add key information
        if key_info:
            summary_parts.append("\nKey Findings:")
            summary_parts.extend(f"- {info}" for info in key_info)
        
        # Add errors if any
        if errors:
            summary_parts.append("\nErrors:")
            summary_parts.extend(f"- {error}" for error in errors)
        
        # Add important warnings
        if warnings:
            summary_parts.append("\nWarnings:")
            summary_parts.extend(f"- {warning}" for warning in warnings)
        
        # Add GPT analysis if available
        if gpt_analysis:
            summary_parts.append("\nGPT Analysis:")
            if isinstance(gpt_analysis, dict):
                for key, value in gpt_analysis.items():
                    if key not in ['error', 'raw_response']:
                        summary_parts.append(f"{key.replace('_', ' ').title()}: {value}")
        
        # Create final summary
        summary = "\n".join(summary_parts)
        
        return summary
    
    def extract_needed_context(
        self,
        output: str,
        objective: str,
        tool: Optional[str] = None
    ) -> Tuple[str, List[str]]:
        """
        Extract only the context needed for the current objective
        
        Args:
            output: Console output to analyze
            objective: Current objective/task being performed
            tool: Specific tool being used
        
        Returns:
            Tuple of (relevant_context, key_points)
        """
        # Analyze the output first
        analysis = self.analyze_output(output, tool)
        
        # Extract relevant lines based on objective keywords
        objective_keywords = set(objective.lower().split())
        relevant_lines = []
        key_points = []
        
        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            # Check if line contains objective-related keywords
            line_keywords = set(line.lower().split())
            if objective_keywords & line_keywords:
                relevant_lines.append(line)
            
            # Add lines with key findings
            if any(re.search(pattern, line) for pattern in self.SUCCESS_PATTERNS):
                key_points.append(line)
            elif tool and tool.lower() in self.TOOL_PATTERNS:
                for pattern in self.TOOL_PATTERNS[tool.lower()]['key_info']:
                    if re.search(pattern, line):
                        key_points.append(line)
        
        # Add error context if present
        if analysis.errors:
            relevant_lines.extend(analysis.errors)
            key_points.extend(analysis.errors)
        
        # Create concise context
        relevant_context = "\n".join(relevant_lines)
        
        return relevant_context, key_points
    
    def suggest_fix(self, error: str, tool: Optional[str] = None) -> str:
        """Suggest fixes for common errors"""
        # Common error patterns and their fixes
        ERROR_FIXES = {
            r'permission denied': "Try running the command with sudo or check file permissions",
            r'command not found': "Ensure the tool is installed and in your PATH",
            r'connection refused': "Check if the target is accessible and the port is open",
            r'timeout': "The operation timed out, consider increasing the timeout value or check connectivity",
            r'no space': "Free up disk space or specify an alternate location",
            r'invalid option': "Check the command syntax and options in the tool's documentation"
        }
        
        # Tool-specific error fixes
        TOOL_FIXES = {
            'nmap': {
                r'failed to resolve': "Check DNS resolution or use IP address directly",
                r'no host up': "Verify target is online or try different scan type"
            },
            'dirb': {
                r'cant connect': "Verify web server is running and accessible",
                r'not found': "Check URL format and server configuration"
            }
        }
        
        # Check tool-specific fixes first
        if tool and tool.lower() in TOOL_FIXES:
            for pattern, fix in TOOL_FIXES[tool.lower()].items():
                if re.search(pattern, error, re.IGNORECASE):
                    return fix
        
        # Check common fixes
        for pattern, fix in ERROR_FIXES.items():
            if re.search(pattern, error, re.IGNORECASE):
                return fix
        
        return "Unable to suggest specific fix. Review error message and tool documentation." 

    def get_fix_for_error(self, tool: str, error_text: str) -> Optional[Dict[str, str]]:
        """Get fix for a specific error in a tool's output"""
        if tool.lower() not in self.TOOL_FIXES:
            return None
            
        tool_fixes = self.TOOL_FIXES[tool.lower()]
        for pattern, fix in tool_fixes.items():
            if re.search(pattern, error_text, re.IGNORECASE):
                return fix
                
        return None

    def suggest_fixes(self, errors: List[str], tool: str) -> List[Dict[str, str]]:
        """Suggest fixes for detected errors using NLP-enhanced analysis"""
        fixes = []
        for error in errors:
            # Get NLP analysis of the error
            error_analysis = self._analyze_text_with_nlp(error)
            
            # Get regex-based fix
            regex_fix = self.get_fix_for_error(tool, error)
            
            if regex_fix:
                # Enhance fix with NLP insights
                enhanced_fix = {
                    'error': error,
                    'fix': regex_fix['fix'],
                    'command': regex_fix['command'],
                    'confidence': 0.9,  # High confidence for regex matches
                    'entities': error_analysis['entities'],
                    'key_concepts': error_analysis['key_phrases']
                }
                fixes.append(enhanced_fix)
            else:
                # Try to generate fix using NLP analysis
                best_category = max(error_analysis['categories'].items(), key=lambda x: x[1])
                if best_category[1] >= self.similarity_threshold:
                    # Generate fix based on category and entities
                    generated_fix = self._generate_fix_from_nlp(
                        error, 
                        best_category[0],
                        error_analysis['entities'],
                        tool
                    )
                    if generated_fix:
                        fixes.append(generated_fix)
        
        return fixes

    def _generate_fix_from_nlp(
        self, 
        error: str, 
        category: str,
        entities: List[Dict],
        tool: str
    ) -> Optional[Dict[str, str]]:
        """Generate a fix suggestion based on NLP analysis"""
        # Extract relevant entities
        paths = [e['text'] for e in entities if e['label'] in ['PATH', 'FILE']]
        ips = [e['text'] for e in entities if e['label'] in ['IP']]
        ports = [e['text'] for e in entities if e['label'] == 'PORT']
        
        # Common fix patterns based on category
        fix_patterns = {
            'permission': {
                'fix': "Insufficient permissions. Try running with elevated privileges.",
                'command': f"sudo {tool} " + "{options}"
            },
            'network': {
                'fix': "Network connectivity issue. Check target availability and firewall settings.",
                'command': f"{tool} -v " + "{target} {options}"
            },
            'configuration': {
                'fix': "Configuration error. Verify settings and syntax.",
                'command': f"{tool} --config {config_file} " + "{options}"
            }
        }
        
        # Generate fix based on category and entities
        if category in fix_patterns:
            fix = fix_patterns[category].copy()
            # Customize command based on entities
            if paths:
                fix['command'] = fix['command'].format(
                    options=f"--path {paths[0]}"
                )
            elif ips:
                fix['command'] = fix['command'].format(
                    target=ips[0],
                    options=f"-p {ports[0]}" if ports else ""
                )
            else:
                fix['command'] = fix['command'].format(
                    options="",
                    config_file="config.yaml"
                )
            
            return {
                'error': error,
                'fix': fix['fix'],
                'command': fix['command'],
                'confidence': 0.7,  # Lower confidence for NLP-generated fixes
                'generated': True
            }
        
        return None