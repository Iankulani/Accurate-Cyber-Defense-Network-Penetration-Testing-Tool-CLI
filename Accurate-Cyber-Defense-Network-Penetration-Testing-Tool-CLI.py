#!/usr/bin/env python3
"""
🔥 Red-Themed Cybersecurity Monitoring Tool with Telegram Integration
Advanced IP monitoring, threat detection, and real-time alerts
No nmap dependency required
"""

import asyncio
import socket
import threading
import time
import json
import requests
import sqlite3
from datetime import datetime, timedelta
import logging
from telegram import Update, Bot
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
import ipaddress
import subprocess
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import select
from typing import Dict, List, Set, Optional
import configparser
import csv
import re
import inspect

# Configuration
CONFIG_FILE = "cyber_monitor_config.ini"
DATABASE_FILE = "monitoring_data.db"
LOG_FILE = "cyber_monitor.log"

# Red Theme Colors
class RedTheme:
    RED = '\033[91m'
    DARK_RED = '\033[31m'
    BOLD_RED = '\033[1;91m'
    RED_BG = '\033[41m'
    YELLOW = '\033[93m'
    ORANGE = '\033[33m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'
    
    # Theme elements
    BANNER = f"""{RED_BG}{BOLD}╔══════════════════════════════════════════════════════════════╗{END}
{RED_BG}{BOLD}║                   🔥 ACCURATE CYBER DEFENSE 🔥                       {END}
{RED_BG}{BOLD}║                                                                       {END}
{RED_BG}{BOLD}╚══════════════════════════════════════════════════════════╝{END}"""

    PROMPT = f"{BOLD_RED}accurate>{END} "
    ERROR = f"{RED}❌ ERROR:{END}"
    WARNING = f"{YELLOW}⚠️  WARNING:{END}"
    SUCCESS = f"{BOLD}✅ SUCCESS:{END}"
    INFO = f"{ORANGE}ℹ️  INFO:{END}"
    ALERT = f"{RED_BG}{BOLD}🚨 ALERT:{END}"

class CyberSecurityMonitor:
    def __init__(self):
        self.config = configparser.ConfigParser()
        self.load_config()
        
        # Monitoring state
        self.monitoring_ips: Set[str] = set()
        self.is_monitoring = False
        self.monitoring_thread = None
        self.telegram_bot = None
        self.telegram_chat_id = None
        
        # Command history
        self.command_history: List[Dict] = []
        self.max_history_size = 100
        
        # Database setup
        self.setup_database()
        
        # Setup logging
        self.setup_logging()
        
        # Thread pool for concurrent operations
        self.thread_pool = ThreadPoolExecutor(max_workers=100)
        
        self.logger.info("CyberSecurityMonitor initialized")

    def setup_logging(self):
        """Setup comprehensive logging"""
        logging.basicConfig(
            level=logging.INFO,
            format=f'{RedTheme.RED}%(asctime)s{RedTheme.END} - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(LOG_FILE),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)

    def load_config(self):
        """Load configuration from file"""
        if os.path.exists(CONFIG_FILE):
            self.config.read(CONFIG_FILE)
        else:
            # Create default config
            self.config['DEFAULT'] = {
                'telegram_token': '',
                'telegram_chat_id': '',
                'scan_timeout': '2',
                'deep_scan_threads': '50',
                'monitoring_interval': '60',
                'max_history_size': '100'
            }
            self.save_config()

    def save_config(self):
        """Save configuration to file"""
        with open(CONFIG_FILE, 'w') as configfile:
            self.config.write(configfile)

    def setup_database(self):
        """Initialize SQLite database for storing monitoring data"""
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        
        # Create tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_addresses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE,
                added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ping_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                response_time REAL,
                status TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS port_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                port INTEGER,
                status TEXT,
                service TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS geo_locations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                country TEXT,
                city TEXT,
                isp TEXT,
                latitude REAL,
                longitude REAL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                alert_type TEXT,
                severity TEXT,
                description TEXT,
                resolved BOOLEAN DEFAULT FALSE
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS command_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                command TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                result TEXT
            )
        ''')
        
        conn.commit()
        conn.close()

    def clear_screen(self):
        """Clear the terminal screen - cross-platform solution :cite[9]:cite[10]"""
        try:
            if os.name == 'nt':  # Windows
                os.system('cls')
            else:  # Linux/Unix/Mac
                os.system('clear')
            print(RedTheme.BANNER)
            print(f"\n{RedTheme.BOLD_RED}🚀 Red-Themed Cyber Security Monitoring Tool{RedTheme.END}")
            print(f"{RedTheme.INFO} Type 'help' for available commands or 'exit' to quit.{RedTheme.END}")
        except Exception as e:
            self.logger.error(f"Error clearing screen: {e}")

    def add_to_history(self, command: str, result: str = ""):
        """Add command to history"""
        self.command_history.append({
            "timestamp": datetime.now(),
            "command": command,
            "result": result
        })
        
        # Trim history if too large
        if len(self.command_history) > self.max_history_size:
            self.command_history.pop(0)
        
        # Also store in database
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO command_history (command, result) VALUES (?, ?)",
            (command, result[:1000])  # Limit result size
        )
        conn.commit()
        conn.close()

    def get_history(self, limit: int = 10) -> List[Dict]:
        """Get command history"""
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT command, timestamp, result 
            FROM command_history 
            ORDER BY timestamp DESC 
            LIMIT ?
        ''', (limit,))
        
        history = []
        for row in cursor.fetchall():
            history.append({
                "command": row[0],
                "timestamp": row[1],
                "result": row[2]
            })
        
        conn.close()
        return history

    def clear_history(self):
        """Clear command history"""
        self.command_history.clear()
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM command_history")
        conn.commit()
        conn.close()
        self.logger.info("Command history cleared")

    def clear_all_data(self):
        """Clear all monitoring data"""
        try:
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            
            # Clear all tables but keep structure
            tables = ['ip_addresses', 'ping_results', 'port_scans', 'geo_locations', 'alerts', 'command_history']
            for table in tables:
                cursor.execute(f"DELETE FROM {table}")
            
            # Reset monitoring state
            self.monitoring_ips.clear()
            
            conn.commit()
            conn.close()
            
            self.logger.info("All monitoring data cleared")
            return True
            
        except Exception as e:
            self.logger.error(f"Error clearing data: {e}")
            return False

    # Core IP Management Functions
    def add_ip(self, ip: str) -> bool:
        """Add IP address to monitoring list"""
        try:
            # Validate IP address
            ipaddress.ip_address(ip)
            
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            
            cursor.execute(
                "INSERT OR IGNORE INTO ip_addresses (ip) VALUES (?)",
                (ip,)
            )
            
            if cursor.rowcount > 0:
                self.monitoring_ips.add(ip)
                conn.commit()
                conn.close()
                self.logger.info(f"Added IP to monitoring: {ip}")
                self.add_to_history(f"add_ip {ip}", "Success")
                return True
            else:
                conn.close()
                self.logger.warning(f"IP already exists: {ip}")
                return False
                
        except ValueError as e:
            self.logger.error(f"Invalid IP address {ip}: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Error adding IP {ip}: {e}")
            return False

    def remove_ip(self, ip: str) -> bool:
        """Remove IP address from monitoring list"""
        try:
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            
            cursor.execute("DELETE FROM ip_addresses WHERE ip = ?", (ip,))
            
            if cursor.rowcount > 0:
                self.monitoring_ips.discard(ip)
                conn.commit()
                conn.close()
                self.logger.info(f"Removed IP from monitoring: {ip}")
                self.add_to_history(f"remove_ip {ip}", "Success")
                return True
            else:
                conn.close()
                self.logger.warning(f"IP not found: {ip}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error removing IP {ip}: {e}")
            return False

    def list_ips(self) -> List[str]:
        """Get list of all monitored IPs"""
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        
        cursor.execute("SELECT ip FROM ip_addresses WHERE is_active = TRUE")
        ips = [row[0] for row in cursor.fetchall()]
        
        conn.close()
        return ips

    # Enhanced Network Operations without nmap
    def ping_ip(self, ip: str) -> Dict:
        """Ping an IP address and return results"""
        try:
            start_time = time.time()
            
            # Use system ping command
            param = "-n" if os.name == "nt" else "-c"
            command = ["ping", param, "3", ip]
            
            result = subprocess.run(
                command, 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            
            response_time = (time.time() - start_time) * 1000  # Convert to ms
            
            if result.returncode == 0:
                status = "online"
                # Extract average response time from ping output
                for line in result.stdout.split('\n'):
                    if "time=" in line:
                        try:
                            time_str = line.split('time=')[1].split(' ')[0]
                            response_time = float(time_str)
                        except:
                            pass
            else:
                status = "offline"
                response_time = 0
            
            # Store result in database
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO ping_results (ip, response_time, status) VALUES (?, ?, ?)",
                (ip, response_time, status)
            )
            conn.commit()
            conn.close()
            
            self.add_to_history(f"ping {ip}", f"Status: {status}, Response: {response_time:.2f}ms")
            
            return {
                "ip": ip,
                "status": status,
                "response_time": response_time,
                "timestamp": datetime.now().isoformat()
            }
            
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Ping timeout for {ip}")
            return {
                "ip": ip,
                "status": "timeout",
                "response_time": 0,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            self.logger.error(f"Error pinging {ip}: {e}")
            return {
                "ip": ip,
                "status": "error",
                "response_time": 0,
                "timestamp": datetime.now().isoformat()
            }

    def get_ip_location(self, ip: str) -> Dict:
        """Get geographical location of IP address using multiple services"""
        services = [
            ("http://ip-api.com/json/", "ip-api.com"),
            ("https://ipapi.co/", "ipapi.co"), 
            ("http://ipinfo.io/", "ipinfo.io")
        ]
        
        location_data = None
        
        for base_url, service_name in services:
            try:
                full_url = f"{base_url}{ip}"
                response = requests.get(full_url, timeout=10)
                data = response.json()
                
                if service_name == "ip-api.com":
                    if data.get("status") == "success":
                        location_data = {
                            "ip": ip,
                            "country": data.get("country", "Unknown"),
                            "city": data.get("city", "Unknown"),
                            "isp": data.get("isp", "Unknown"),
                            "latitude": data.get("lat", 0),
                            "longitude": data.get("lon", 0),
                            "service": service_name,
                            "timestamp": datetime.now().isoformat()
                        }
                        break
                
                elif service_name == "ipapi.co":
                    if data.get("country_code"):
                        location_data = {
                            "ip": ip,
                            "country": data.get("country_name", "Unknown"),
                            "city": data.get("city", "Unknown"),
                            "isp": data.get("org", "Unknown"),
                            "latitude": data.get("latitude", 0),
                            "longitude": data.get("longitude", 0),
                            "service": service_name,
                            "timestamp": datetime.now().isoformat()
                        }
                        break
                
                elif service_name == "ipinfo.io":
                    if data.get("country"):
                        loc = data.get("loc", "0,0").split(",") if data.get("loc") else ["0", "0"]
                        latitude = float(loc[0]) if len(loc) == 2 else 0
                        longitude = float(loc[1]) if len(loc) == 2 else 0
                        
                        location_data = {
                            "ip": ip,
                            "country": data.get("country", "Unknown"),
                            "city": data.get("city", "Unknown"),
                            "isp": data.get("org", "Unknown"),
                            "latitude": latitude,
                            "longitude": longitude,
                            "service": service_name,
                            "timestamp": datetime.now().isoformat()
                        }
                        break
            except Exception as e:
                self.logger.debug(f"Service {service_name} failed: {e}")
                continue
        
        if location_data is None:
            return {"error": "Unable to fetch location data from any service"}
        
        # Store in database
        try:
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO geo_locations 
                (ip, country, city, isp, latitude, longitude) 
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (ip, location_data["country"], location_data["city"], 
                  location_data["isp"], location_data["latitude"], 
                  location_data["longitude"]))
            conn.commit()
            conn.close()
            
            self.add_to_history(f"location {ip}", 
                              f"Country: {location_data['country']}, City: {location_data['city']}")
            
        except Exception as e:
            self.logger.error(f"Error storing location data: {e}")
        
        return location_data

    def scan_ip(self, ip: str, ports: List[int] = None) -> Dict:
        """Perform basic port scan on IP address without nmap"""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995, 3389, 8080, 8443]
        
        self.logger.info(f"Scanning {ip} on ports: {ports}")
        
        scan_results = {
            "ip": ip,
            "scan_start": datetime.now().isoformat(),
            "ports": [],
            "open_ports": 0,
            "closed_ports": 0
        }
        
        def scan_port(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(2)
                    result = sock.connect_ex((ip, port))
                    
                    if result == 0:
                        # Try to get service name
                        try:
                            service = socket.getservbyport(port, 'tcp')
                        except:
                            service = "unknown"
                        
                        return {
                            "port": port,
                            "state": "open",
                            "service": service,
                            "protocol": "tcp"
                        }
                    else:
                        return {
                            "port": port,
                            "state": "closed",
                            "service": "unknown",
                            "protocol": "tcp"
                        }
            except Exception as e:
                return {
                    "port": port,
                    "state": "error",
                    "service": "unknown",
                    "protocol": "tcp",
                    "error": str(e)
                }
        
        # Scan ports concurrently
        futures = [self.thread_pool.submit(scan_port, port) for port in ports]
        
        for future in as_completed(futures):
            try:
                result = future.result(timeout=5)
                scan_results["ports"].append(result)
                
                if result["state"] == "open":
                    scan_results["open_ports"] += 1
                    # Store in database
                    conn = sqlite3.connect(DATABASE_FILE)
                    cursor = conn.cursor()
                    cursor.execute('''
                        INSERT INTO port_scans (ip, port, status, service)
                        VALUES (?, ?, ?, ?)
                    ''', (ip, result["port"], result["state"], result["service"]))
                    conn.commit()
                    conn.close()
                else:
                    scan_results["closed_ports"] += 1
                    
            except Exception as e:
                self.logger.error(f"Error scanning port: {e}")
        
        scan_results["scan_end"] = datetime.now().isoformat()
        scan_results["scan_duration"] = (
            datetime.fromisoformat(scan_results["scan_end"]) - 
            datetime.fromisoformat(scan_results["scan_start"])
        ).total_seconds()
        
        self.add_to_history(f"scan {ip}", 
                          f"Open ports: {scan_results['open_ports']}, Closed: {scan_results['closed_ports']}")
        
        return scan_results

    def deep_scan_ip(self, ip: str, max_ports: int = 1000) -> Dict:
        """Perform deep port scan without nmap (configurable max ports)"""
        self.logger.info(f"Starting deep scan for {ip} (ports 1-{max_ports})")
        
        # Scan most common ports first, then less common ones
        common_ports = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 
                      3389, 5900, 8080, 8443, 8888, 10000]
        
        # Add additional ports up to max_ports
        all_ports = common_ports + [p for p in range(1, max_ports + 1) if p not in common_ports]
        all_ports = all_ports[:max_ports]  # Ensure we don't exceed max_ports
        
        scan_results = {
            "ip": ip,
            "scan_start": datetime.now().isoformat(),
            "total_ports": len(all_ports),
            "ports": [],
            "open_ports": 0,
            "closed_ports": 0
        }
        
        def scan_port(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(1)
                    result = sock.connect_ex((ip, port))
                    
                    if result == 0:
                        # Try to get service name
                        try:
                            service = socket.getservbyport(port, 'tcp')
                        except:
                            service = "unknown"
                        
                        return port, "open", service
                    else:
                        return port, "closed", "unknown"
            except:
                return port, "error", "unknown"
        
        # Scan ports in chunks to avoid overwhelming the system
        chunk_size = 100
        port_chunks = [all_ports[i:i + chunk_size] for i in range(0, len(all_ports), chunk_size)]
        
        for chunk in port_chunks:
            # Check if we should stop scanning
            if not self.is_monitoring and any("monitoring" in frame.function for frame in inspect.stack()):
                break
                
            futures = [self.thread_pool.submit(scan_port, port) for port in chunk]
            
            for future in as_completed(futures):
                try:
                    port, state, service = future.result(timeout=2)
                    result = {
                        "port": port,
                        "state": state,
                        "service": service,
                        "protocol": "tcp"
                    }
                    scan_results["ports"].append(result)
                    
                    if state == "open":
                        scan_results["open_ports"] += 1
                        # Store open ports in database
                        conn = sqlite3.connect(DATABASE_FILE)
                        cursor = conn.cursor()
                        cursor.execute('''
                            INSERT INTO port_scans (ip, port, status, service)
                            VALUES (?, ?, ?, ?)
                        ''', (ip, port, state, service))
                        conn.commit()
                        conn.close()
                    else:
                        scan_results["closed_ports"] += 1
                        
                except Exception as e:
                    self.logger.error(f"Error in deep scan: {e}")
        
        scan_results["scan_end"] = datetime.now().isoformat()
        scan_duration = (
            datetime.fromisoformat(scan_results["scan_end"]) - 
            datetime.fromisoformat(scan_results["scan_start"])
        ).total_seconds()
        scan_results["scan_duration"] = scan_duration
        
        # Sort ports by number
        scan_results["ports"].sort(key=lambda x: x["port"])
        
        self.add_to_history(f"deep_scan {ip}", 
                          f"Open ports: {scan_results['open_ports']}/{scan_results['total_ports']}")
        
        self.logger.info(f"Deep scan completed for {ip}: {scan_results['open_ports']} open ports")
        
        return scan_results

    # Monitoring System
    def start_monitoring(self, ip: str = None):
        """Start monitoring IP addresses"""
        if ip:
            self.add_ip(ip)
        
        if not self.is_monitoring:
            self.is_monitoring = True
            self.monitoring_thread = threading.Thread(target=self._monitoring_loop)
            self.monitoring_thread.daemon = True
            self.monitoring_thread.start()
            self.logger.info("Monitoring started")
            self.add_to_history("start_monitoring", f"IP: {ip if ip else 'all'}")
            return True
        else:
            self.logger.info("Monitoring already running")
            return False

    def stop_monitoring(self):
        """Stop monitoring"""
        self.is_monitoring = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=10)
        self.logger.info("Monitoring stopped")
        self.add_to_history("stop_monitoring", "Success")
        return True

    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.is_monitoring:
            try:
                ips_to_monitor = self.list_ips()
                self.logger.info(f"Monitoring {len(ips_to_monitor)} IPs")
                
                for ip in ips_to_monitor:
                    if not self.is_monitoring:
                        break
                    
                    # Ping check
                    ping_result = self.ping_ip(ip)
                    
                    # Alert if status changed
                    if ping_result["status"] == "offline":
                        self._create_alert(ip, "HOST_DOWN", "medium", 
                                         f"Host {ip} is not responding to ping")
                    elif ping_result["status"] == "online":
                        # Only scan if host is online
                        scan_result = self.scan_ip(ip)
                        open_ports = [p for p in scan_result.get("ports", []) if p["state"] == "open"]
                        
                        if open_ports:
                            # Check for suspicious ports
                            suspicious_ports = [p for p in open_ports if p["port"] in [23, 135, 139, 445, 1433, 1434, 3306, 5432]]
                            if suspicious_ports:
                                port_list = ", ".join([str(p["port"]) for p in suspicious_ports])
                                self._create_alert(ip, "SUSPICIOUS_PORTS", "high",
                                                 f"Suspicious ports open: {port_list}")
                
                # Wait before next monitoring cycle
                interval = int(self.config['DEFAULT'].get('monitoring_interval', '60'))
                for _ in range(interval):
                    if not self.is_monitoring:
                        break
                    time.sleep(1)
                    
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(60)

    def _create_alert(self, ip: str, alert_type: str, severity: str, description: str):
        """Create and log security alert"""
        try:
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO alerts (ip, alert_type, severity, description)
                VALUES (?, ?, ?, ?)
            ''', (ip, alert_type, severity, description))
            conn.commit()
            conn.close()
            
            self.logger.warning(f"ALERT: {severity} - {description}")
            
            # Send Telegram alert if configured
            if self.telegram_bot and self.telegram_chat_id:
                try:
                    message = f"🚨 *Security Alert* 🚨\n\n"
                    message += f"*IP:* `{ip}`\n"
                    message += f"*Type:* {alert_type}\n"
                    message += f"*Severity:* {severity.upper()}\n"
                    message += f"*Description:* {description}\n"
                    message += f"*Time:* {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                    
                    asyncio.create_task(
                        self._send_telegram_message(message)
                    )
                except Exception as e:
                    self.logger.error(f"Failed to send Telegram alert: {e}")
                    
        except Exception as e:
            self.logger.error(f"Error creating alert: {e}")

    async def _send_telegram_message(self, message: str):
        """Send message to Telegram (async) :cite[4]:cite[7]"""
        try:
            await self.telegram_bot.send_message(
                chat_id=self.telegram_chat_id,
                text=message,
                parse_mode='Markdown'
            )
        except Exception as e:
            self.logger.error(f"Error sending Telegram message: {e}")

    # Telegram Configuration
    def config_telegram_token(self, token: str) -> bool:
        """Configure Telegram bot token"""
        try:
            if not token:
                return False
                
            self.config['DEFAULT']['telegram_token'] = token
            self.save_config()
            
            # Test the token
            self.telegram_bot = Bot(token=token)
            self.logger.info("Telegram token configured successfully")
            self.add_to_history("config_telegram_token", "Success")
            return True
            
        except Exception as e:
            self.logger.error(f"Error configuring Telegram token: {e}")
            return False

    def config_telegram_chat_id(self, chat_id: str) -> bool:
        """Configure Telegram chat ID"""
        try:
            if not chat_id:
                return False
                
            self.config['DEFAULT']['telegram_chat_id'] = chat_id
            self.telegram_chat_id = chat_id
            self.save_config()
            self.logger.info("Telegram chat ID configured successfully")
            self.add_to_history("config_telegram_chat_id", "Success")
            return True
            
        except Exception as e:
            self.logger.error(f"Error configuring Telegram chat ID: {e}")
            return False

    def test_telegram_connection(self) -> bool:
        """Test Telegram connection"""
        try:
            if not self.telegram_bot or not self.telegram_chat_id:
                return False
                
            asyncio.run(
                self.telegram_bot.send_message(
                    chat_id=self.telegram_chat_id,
                    text="✅ *Telegram Connection Test*\n\nConnection successful!",
                    parse_mode='Markdown'
                )
            )
            self.logger.info("Telegram connection test successful")
            self.add_to_history("test_telegram_connection", "Success")
            return True
            
        except Exception as e:
            self.logger.error(f"Telegram connection test failed: {e}")
            return False

    def export_data_to_telegram(self, data_type: str = "all") -> bool:
        """Export monitoring data to Telegram"""
        try:
            if not self.telegram_bot or not self.telegram_chat_id:
                return False
            
            message = f"📊 *Monitoring Data Export - {data_type.upper()}*\n\n"
            
            if data_type in ["all", "ips"]:
                ips = self.list_ips()
                message += f"*Monitored IPs:* {len(ips)}\n"
                for ip in ips[:10]:  # Limit to first 10 IPs
                    message += f"  • `{ip}`\n"
                if len(ips) > 10:
                    message += f"  ... and {len(ips) - 10} more\n"
                message += "\n"
            
            if data_type in ["all", "alerts"]:
                conn = sqlite3.connect(DATABASE_FILE)
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT COUNT(*) FROM alerts 
                    WHERE timestamp > datetime('now', '-1 day') AND resolved = FALSE
                ''')
                recent_alerts = cursor.fetchone()[0]
                message += f"*Recent Alerts (24h):* {recent_alerts}\n"
                
                cursor.execute('''
                    SELECT alert_type, severity, COUNT(*) 
                    FROM alerts 
                    WHERE timestamp > datetime('now', '-7 day')
                    GROUP BY alert_type, severity
                    ORDER BY COUNT(*) DESC
                    LIMIT 5
                ''')
                top_alerts = cursor.fetchall()
                if top_alerts:
                    message += "*Top Alerts (7 days):*\n"
                    for alert_type, severity, count in top_alerts:
                        message += f"  • {alert_type} ({severity}): {count}\n"
                conn.close()
                message += "\n"
            
            if data_type in ["all", "stats"]:
                conn = sqlite3.connect(DATABASE_FILE)
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM ip_addresses")
                total_ips = cursor.fetchone()[0]
                
                cursor.execute('''
                    SELECT COUNT(DISTINCT ip) FROM ping_results 
                    WHERE timestamp > datetime('now', '-1 hour') AND status = 'online'
                ''')
                online_ips = cursor.fetchone()[0]
                conn.close()
                
                message += f"*Current Stats:*\n"
                message += f"  • Total IPs: {total_ips}\n"
                message += f"  • Online IPs: {online_ips}\n"
                message += f"  • Monitoring: {'✅ Active' if self.is_monitoring else '❌ Inactive'}\n"

            asyncio.run(
                self.telegram_bot.send_message(
                    chat_id=self.telegram_chat_id,
                    text=message,
                    parse_mode='Markdown'
                )
            )
            
            self.logger.info(f"Data exported to Telegram: {data_type}")
            self.add_to_history(f"export_data {data_type}", "Success")
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting data to Telegram: {e}")
            return False

    # Command Line Interface with Red Theme
    def print_help(self):
        """Display help information with red theme"""
        help_text = f"""
{RedTheme.BOLD_RED}🔥 Enhanced Accurate Cyber Defense 🚀{RedTheme.END}

{RedTheme.BOLD}Basic Network Commands:{RedTheme.END}
  {RedTheme.RED}ping <ip>{RedTheme.END}              - Ping an IP address
  {RedTheme.RED}location <ip>{RedTheme.END}          - Get geographical location of IP
  {RedTheme.RED}scan <ip>{RedTheme.END}              - Perform basic port scan (common ports)
  {RedTheme.RED}deep_scan <ip> [max]{RedTheme.END}   - Deep port scan (1-max_ports, default: 1000)

{RedTheme.BOLD}Monitoring Commands:{RedTheme.END}
  {RedTheme.RED}start_monitoring [ip]{RedTheme.END}  - Start monitoring IP (or all if no IP)
  {RedTheme.RED}stop_monitoring{RedTheme.END}        - Stop all monitoring
  {RedTheme.RED}add_ip <ip>{RedTheme.END}            - Add IP to monitoring list
  {RedTheme.RED}remove_ip <ip>{RedTheme.END}         - Remove IP from monitoring list
  {RedTheme.RED}list_ips{RedTheme.END}               - Show all monitored IPs

{RedTheme.BOLD}Telegram Commands:{RedTheme.END}
  {RedTheme.RED}config_telegram_token <token>{RedTheme.END}    - Set Telegram bot token
  {RedTheme.RED}config_telegram_chat_id <id>{RedTheme.END}     - Set Telegram chat ID
  {RedTheme.RED}test_telegram_connection{RedTheme.END}         - Test Telegram connection
  {RedTheme.RED}export_data [type]{RedTheme.END}               - Export data to Telegram

{RedTheme.BOLD}Data Management:{RedTheme.END}
  {RedTheme.RED}clear{RedTheme.END}                  - Clear terminal screen
  {RedTheme.RED}export_csv <filename>{RedTheme.END}  - Export data to CSV files
  {RedTheme.RED}show_stats{RedTheme.END}             - Show monitoring statistics
  {RedTheme.RED}history [limit]{RedTheme.END}        - Show command history
  {RedTheme.RED}clear_history{RedTheme.END}          - Clear command history
  {RedTheme.RED}clear_data{RedTheme.END}             - Clear all monitoring data
  {RedTheme.RED}help{RedTheme.END}                   - Show this help message
  {RedTheme.RED}exit/quit{RedTheme.END}              - Exit the program

{RedTheme.BOLD}Examples:{RedTheme.END}
  {RedTheme.ORANGE}ping 8.8.8.8{RedTheme.END}
  {RedTheme.ORANGE}scan 192.168.1.1{RedTheme.END}
  {RedTheme.ORANGE}deep_scan 10.0.0.1 500{RedTheme.END}
  {RedTheme.ORANGE}start_monitoring 8.8.8.8{RedTheme.END}
  {RedTheme.ORANGE}export_data alerts{RedTheme.END}
        """
        print(help_text)

    def export_csv(self, filename: str) -> bool:
        """Export monitoring data to CSV file"""
        try:
            conn = sqlite3.connect(DATABASE_FILE)
            
            # Export different tables
            tables = ['ip_addresses', 'ping_results', 'port_scans', 'geo_locations', 'alerts', 'command_history']
            
            for table in tables:
                table_filename = f"{filename}_{table}.csv"
                cursor = conn.cursor()
                cursor.execute(f"SELECT * FROM {table}")
                rows = cursor.fetchall()
                
                with open(table_filename, 'w', newline='', encoding='utf-8') as csvfile:
                    writer = csv.writer(csvfile)
                    # Write headers
                    writer.writerow([description[0] for description in cursor.description])
                    # Write data
                    writer.writerows(rows)
                
                self.logger.info(f"Exported {len(rows)} rows to {table_filename}")
            
            conn.close()
            self.add_to_history(f"export_csv {filename}", f"Exported {len(tables)} tables")
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting CSV: {e}")
            return False

    def show_stats(self):
        """Display monitoring statistics with red theme"""
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM ip_addresses")
        total_ips = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE resolved = FALSE")
        active_alerts = cursor.fetchone()[0]
        
        cursor.execute('''
            SELECT COUNT(DISTINCT ip) FROM ping_results 
            WHERE timestamp > datetime('now', '-1 hour') AND status = 'online'
        ''')
        online_ips = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM command_history")
        history_count = cursor.fetchone()[0]
        
        conn.close()
        
        status_icon = f"{RedTheme.BOLD}🟢{RedTheme.END}" if self.is_monitoring else f"{RedTheme.RED}🔴{RedTheme.END}"
        telegram_icon = f"{RedTheme.BOLD}🟢{RedTheme.END}" if self.telegram_bot and self.telegram_chat_id else f"{RedTheme.RED}🔴{RedTheme.END}"
        
        stats = f"""
{RedTheme.BOLD_RED}📊 Monitoring Statistics:{RedTheme.END}
{RedTheme.RED}──────────────────────────{RedTheme.END}

{RedTheme.BOLD}Total Monitored IPs:{RedTheme.END} {RedTheme.RED}{total_ips}{RedTheme.END}
{RedTheme.BOLD}Currently Online IPs:{RedTheme.END} {RedTheme.RED}{online_ips}{RedTheme.END}
{RedTheme.BOLD}Active Alerts:{RedTheme.END} {RedTheme.RED}{active_alerts}{RedTheme.END}
{RedTheme.BOLD}Command History Entries:{RedTheme.END} {RedTheme.RED}{history_count}{RedTheme.END}

{RedTheme.BOLD}Monitoring Status:{RedTheme.END} {status_icon} {RedTheme.BOLD}{'ACTIVE' if self.is_monitoring else 'INACTIVE'}{RedTheme.END}
{RedTheme.BOLD}Telegram Integration:{RedTheme.END} {telegram_icon} {RedTheme.BOLD}{'CONFIGURED' if self.telegram_bot and self.telegram_chat_id else 'NOT CONFIGURED'}{RedTheme.END}
        """
        print(stats)

    def show_history(self, limit: int = 10):
        """Display command history with red theme"""
        history = self.get_history(limit)
        
        if not history:
            print(f"{RedTheme.WARNING} No command history found.{RedTheme.END}")
            return
        
        print(f"\n{RedTheme.BOLD_RED}📜 Command History (last {len(history)} commands):{RedTheme.END}")
        print(f"{RedTheme.RED}{'─' * 80}{RedTheme.END}")
        
        for i, entry in enumerate(reversed(history), 1):
            print(f"{RedTheme.BOLD_RED}{i:2d}.{RedTheme.END} {entry['timestamp']} - {RedTheme.RED}{entry['command']}{RedTheme.END}")
            if entry['result']:
                result_text = entry['result'][:100] + ('...' if len(entry['result']) > 100 else '')
                print(f"    {RedTheme.ORANGE}Result:{RedTheme.END} {result_text}")
            print()

# Enhanced Telegram Bot Handlers with Red Theme
class TelegramBotHandler:
    def __init__(self, monitor: CyberSecurityMonitor):
        self.monitor = monitor
        self.application = None

    async def start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Send welcome message with red theme"""
        welcome_text = """
🔥 *Accurate Cyber Defense Security Monitor Bot* 🚀

*Available Commands:*

🔍 *Network Tools:*
/start - Show this welcome message  
/ping <ip> - Ping an IP address
/location <ip> - Get IP geographical location
/scan <ip> - Basic port scan
/deep_scan <ip> - Deep port scan (1-1000)

📊 *Monitoring:*
/monitor_start <ip> - Start monitoring IP
/monitor_stop - Stop monitoring
/monitor_add <ip> - Add IP to monitor
/monitor_remove <ip> - Remove IP from monitor
/monitor_list - List monitored IPs

📈 *Data & Stats:*
/stats - Show monitoring statistics
/export <type> - Export data (all/ips/alerts/stats)
/history - Show command history

⚙️ *Configuration:*
/set_token <token> - Set Telegram bot token
/set_chatid <id> - Set Telegram chat ID
/test_connection - Test Telegram connection

*Examples:*
`/ping 8.8.8.8`
`/scan 192.168.1.1`
`/monitor_start 10.0.0.1`
`/stats`
        """
        await update.message.reply_text(welcome_text, parse_mode='Markdown')

    async def ping_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Ping IP address from Telegram"""
        if not context.args:
            await update.message.reply_text("Usage: `/ping <IP_ADDRESS>`", parse_mode='Markdown')
            return
        
        ip = context.args[0]
        await update.message.reply_text(f"🔴 Pinging `{ip}`...", parse_mode='Markdown')
        
        result = self.monitor.ping_ip(ip)
        
        if "error" not in result:
            status_icon = "🟢" if result["status"] == "online" else "🔴"
            response_time = result["response_time"]
            
            response = f"""
{status_icon} *Ping Results for* `{ip}`

*Status:* {result["status"].upper()}
*Response Time:* {response_time:.2f} ms
*Timestamp:* {result["timestamp"][:19]}
            """
        else:
            response = f"🔴 Error pinging `{ip}`: {result['error']}"
        
        await update.message.reply_text(response, parse_mode='Markdown')

    async def location_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Get IP location from Telegram"""
        if not context.args:
            await update.message.reply_text("Usage: `/location <IP_ADDRESS>`", parse_mode='Markdown')
            return
        
        ip = context.args[0]
        await update.message.reply_text(f"🌍 Getting location for `{ip}`...", parse_mode='Markdown')
        
        result = self.monitor.get_ip_location(ip)
        
        if "error" not in result:
            response = f"""
📍 *Location Information for* `{ip}`

*Country:* {result.get("country", "Unknown")}
*City:* {result.get("city", "Unknown")} 
*ISP:* {result.get("isp", "Unknown")}
*Coordinates:* {result.get("latitude", 0):.4f}, {result.get("longitude", 0):.4f}
*Service:* {result.get("service", "Unknown")}
            """
        else:
            response = f"🔴 Error getting location for `{ip}`: {result['error']}"
        
        await update.message.reply_text(response, parse_mode='Markdown')

    async def scan_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Scan IP from Telegram"""
        if not context.args:
            await update.message.reply_text("Usage: `/scan <IP_ADDRESS>`", parse_mode='Markdown')
            return
        
        ip = context.args[0]
        await update.message.reply_text(f"🔍 Scanning `{ip}`...", parse_mode='Markdown')
        
        result = self.monitor.scan_ip(ip)
        
        if "error" not in result:
            open_ports = [p for p in result.get("ports", []) if p["state"] == "open"]
            
            if open_ports:
                ports_text = "\n".join([f"  • Port {p['port']} ({p['service']})" for p in open_ports[:10]])
                if len(open_ports) > 10:
                    ports_text += f"\n  ... and {len(open_ports) - 10} more ports"
                
                response = f"""
🟢 *Scan Results for* `{ip}`

*Open Ports:* {len(open_ports)}
{ports_text}

*Scan Duration:* {result.get("scan_duration", "N/A"):.2f}s
                """
            else:
                response = f"🔒 No open ports found on `{ip}`"
        else:
            response = f"🔴 Error scanning `{ip}`: {result['error']}"
        
        await update.message.reply_text(response, parse_mode='Markdown')

    async def deep_scan_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Deep scan IP from Telegram"""
        if not context.args:
            await update.message.reply_text("Usage: `/deep_scan <IP_ADDRESS> [MAX_PORTS]`", parse_mode='Markdown')
            return
        
        ip = context.args[0]
        max_ports = 1000
        if len(context.args) > 1:
            try:
                max_ports = min(int(context.args[1]), 10000)  # Limit to 10k ports max
            except:
                pass
        
        await update.message.reply_text(
            f"🔍 Starting deep scan on `{ip}` (1-{max_ports} ports)...\n"
            f"*This may take a while...*", 
            parse_mode='Markdown'
        )
        
        result = self.monitor.deep_scan_ip(ip, max_ports)
        
        if "error" not in result:
            open_ports = [p for p in result.get("ports", []) if p["state"] == "open"]
            
            if open_ports:
                ports_text = "\n".join([f"  • Port {p['port']} ({p['service']})" for p in open_ports[:15]])
                if len(open_ports) > 15:
                    ports_text += f"\n  ... and {len(open_ports) - 15} more ports"
                
                response = f"""
🟢 *Deep Scan Results for* `{ip}`

*Open Ports:* {len(open_ports)}/{result['total_ports']}
{ports_text}

*Scan Duration:* {result.get("scan_duration", "N/A"):.2f}s
                """
            else:
                response = f"🔒 No open ports found on `{ip}` (scanned {result['total_ports']} ports)"
        else:
            response = f"🔴 Error deep scanning `{ip}`: {result['error']}"
        
        await update.message.reply_text(response, parse_mode='Markdown')

    async def monitor_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Start monitoring from Telegram"""
        ip = context.args[0] if context.args else None
        
        if self.monitor.start_monitoring(ip):
            response = f"🟢 Monitoring started"
            if ip:
                response += f" for `{ip}`"
            await update.message.reply_text(response, parse_mode='Markdown')
        else:
            await update.message.reply_text("🔴 Monitoring already running or failed to start", parse_mode='Markdown')

    async def monitor_stop(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Stop monitoring from Telegram"""
        if self.monitor.stop_monitoring():
            await update.message.reply_text("🟢 Monitoring stopped", parse_mode='Markdown')
        else:
            await update.message.reply_text("🔴 No monitoring active", parse_mode='Markdown')

    async def monitor_add(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Add IP to monitor from Telegram"""
        if not context.args:
            await update.message.reply_text("Usage: `/monitor_add <IP_ADDRESS>`", parse_mode='Markdown')
            return
        
        ip = context.args[0]
        if self.monitor.add_ip(ip):
            await update.message.reply_text(f"🟢 Added `{ip}` to monitoring", parse_mode='Markdown')
        else:
            await update.message.reply_text(f"🔴 Failed to add `{ip}` to monitoring", parse_mode='Markdown')

    async def monitor_remove(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Remove IP from monitor from Telegram"""
        if not context.args:
            await update.message.reply_text("Usage: `/monitor_remove <IP_ADDRESS>`", parse_mode='Markdown')
            return
        
        ip = context.args[0]
        if self.monitor.remove_ip(ip):
            await update.message.reply_text(f"🟢 Removed `{ip}` from monitoring", parse_mode='Markdown')
        else:
            await update.message.reply_text(f"🔴 Failed to remove `{ip}` from monitoring", parse_mode='Markdown')

    async def monitor_list(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """List monitored IPs from Telegram"""
        ips = self.monitor.list_ips()
        
        if ips:
            ips_text = "\n".join([f"  • `{ip}`" for ip in ips[:20]])
            if len(ips) > 20:
                ips_text += f"\n  ... and {len(ips) - 20} more"
            
            response = f"📋 *Monitored IPs ({len(ips)}):*\n\n{ips_text}"
        else:
            response = "📋 No IPs currently being monitored"
        
        await update.message.reply_text(response, parse_mode='Markdown')

    async def stats_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Show statistics from Telegram"""
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM ip_addresses")
        total_ips = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE resolved = FALSE")
        active_alerts = cursor.fetchone()[0]
        
        cursor.execute('''
            SELECT COUNT(DISTINCT ip) FROM ping_results 
            WHERE timestamp > datetime('now', '-1 hour') AND status = 'online'
        ''')
        online_ips = cursor.fetchone()[0]
        
        conn.close()
        
        status_icon = "🟢" if self.monitor.is_monitoring else "🔴"
        telegram_icon = "🟢" if self.monitor.telegram_bot and self.monitor.telegram_chat_id else "🔴"
        
        response = f"""
📊 *Monitoring Statistics*

*Total Monitored IPs:* {total_ips}
*Currently Online IPs:* {online_ips}
*Active Alerts:* {active_alerts}

*Monitoring Status:* {status_icon} {'ACTIVE' if self.monitor.is_monitoring else 'INACTIVE'}
*Telegram Integration:* {telegram_icon} {'CONFIGURED' if self.monitor.telegram_bot and self.monitor.telegram_chat_id else 'NOT CONFIGURED'}
        """
        
        await update.message.reply_text(response, parse_mode='Markdown')

    async def export_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Export data from Telegram"""
        data_type = context.args[0] if context.args else "all"
        
        if self.monitor.export_data_to_telegram(data_type):
            await update.message.reply_text(f"🟢 Data exported to Telegram: `{data_type}`", parse_mode='Markdown')
        else:
            await update.message.reply_text("🔴 Failed to export data to Telegram", parse_mode='Markdown')

    async def history_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Show command history from Telegram"""
        limit = 10
        if context.args:
            try:
                limit = min(int(context.args[0]), 20)  # Max 20 entries
            except:
                pass
        
        history = self.monitor.get_history(limit)
        
        if not history:
            await update.message.reply_text("📜 No command history found", parse_mode='Markdown')
            return
        
        history_text = "\n".join([f"• `{entry['command']}` - {entry['timestamp'][:19]}" for entry in reversed(history)])
        
        response = f"📜 *Command History (last {len(history)} commands):*\n\n{history_text}"
        await update.message.reply_text(response, parse_mode='Markdown')

    async def set_token(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Set Telegram token from Telegram"""
        if not context.args:
            await update.message.reply_text("Usage: `/set_token <BOT_TOKEN>`", parse_mode='Markdown')
            return
        
        token = context.args[0]
        if self.monitor.config_telegram_token(token):
            await update.message.reply_text("🟢 Telegram token configured successfully", parse_mode='Markdown')
        else:
            await update.message.reply_text("🔴 Failed to configure Telegram token", parse_mode='Markdown')

    async def set_chatid(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Set Telegram chat ID from Telegram"""
        if not context.args:
            await update.message.reply_text("Usage: `/set_chatid <CHAT_ID>`", parse_mode='Markdown')
            return
        
        chat_id = context.args[0]
        if self.monitor.config_telegram_chat_id(chat_id):
            await update.message.reply_text("🟢 Telegram chat ID configured successfully", parse_mode='Markdown')
        else:
            await update.message.reply_text("🔴 Failed to configure Telegram chat ID", parse_mode='Markdown')

    async def test_connection(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Test Telegram connection from Telegram"""
        if self.monitor.test_telegram_connection():
            await update.message.reply_text("🟢 Telegram connection test successful", parse_mode='Markdown')
        else:
            await update.message.reply_text("🔴 Telegram connection test failed", parse_mode='Markdown')

    def setup_bot_handlers(self, application: Application):
        """Setup Telegram bot command handlers :cite[4]:cite[7]"""
        self.application = application
        
        # Command handlers
        application.add_handler(CommandHandler("start", self.start))
        application.add_handler(CommandHandler("ping", self.ping_command))
        application.add_handler(CommandHandler("location", self.location_command))
        application.add_handler(CommandHandler("scan", self.scan_command))
        application.add_handler(CommandHandler("deep_scan", self.deep_scan_command))
        application.add_handler(CommandHandler("monitor_start", self.monitor_start))
        application.add_handler(CommandHandler("monitor_stop", self.monitor_stop))
        application.add_handler(CommandHandler("monitor_add", self.monitor_add))
        application.add_handler(CommandHandler("monitor_remove", self.monitor_remove))
        application.add_handler(CommandHandler("monitor_list", self.monitor_list))
        application.add_handler(CommandHandler("stats", self.stats_command))
        application.add_handler(CommandHandler("export", self.export_command))
        application.add_handler(CommandHandler("history", self.history_command))
        application.add_handler(CommandHandler("set_token", self.set_token))
        application.add_handler(CommandHandler("set_chatid", self.set_chatid))
        application.add_handler(CommandHandler("test_connection", self.test_connection))

# Main Application Class with Red Theme
class CyberSecurityApp:
    def __init__(self):
        self.monitor = CyberSecurityMonitor()
        self.telegram_bot = TelegramBotHandler(self.monitor)
        self.running = True

    def handle_command(self, command: str):
        """Handle command line commands with red theme"""
        parts = command.strip().split()
        if not parts:
            return
        
        cmd = parts[0].lower()
        args = parts[1:]
        
        try:
            if cmd == "help":
                self.monitor.print_help()
                
            elif cmd == "clear":
                self.monitor.clear_screen()
                
            elif cmd == "ping" and args:
                print(f"{RedTheme.INFO} Pinging {args[0]}...{RedTheme.END}")
                result = self.monitor.ping_ip(args[0])
                status_icon = "🟢" if result["status"] == "online" else "🔴"
                print(f"{status_icon} {RedTheme.BOLD}IP:{RedTheme.END} {result['ip']}")
                print(f"{RedTheme.BOLD}Status:{RedTheme.END} {RedTheme.RED if result['status'] != 'online' else RedTheme.BOLD}{result['status'].upper()}{RedTheme.END}")
                print(f"{RedTheme.BOLD}Response Time:{RedTheme.END} {result['response_time']:.2f} ms")
                
            elif cmd == "location" and args:
                print(f"{RedTheme.INFO} Getting location for {args[0]}...{RedTheme.END}")
                result = self.monitor.get_ip_location(args[0])
                if "error" not in result:
                    print(f"📍 {RedTheme.BOLD}Location Information:{RedTheme.END}")
                    print(f"  {RedTheme.BOLD}Country:{RedTheme.END} {result.get('country', 'Unknown')}")
                    print(f"  {RedTheme.BOLD}City:{RedTheme.END} {result.get('city', 'Unknown')}")
                    print(f"  {RedTheme.BOLD}ISP:{RedTheme.END} {result.get('isp', 'Unknown')}")
                    print(f"  {RedTheme.BOLD}Coordinates:{RedTheme.END} {result.get('latitude', 0):.4f}, {result.get('longitude', 0):.4f}")
                else:
                    print(f"{RedTheme.ERROR} {result['error']}{RedTheme.END}")
                
            elif cmd == "scan" and args:
                print(f"{RedTheme.INFO} Scanning {args[0]}...{RedTheme.END}")
                result = self.monitor.scan_ip(args[0])
                open_ports = [p for p in result.get("ports", []) if p["state"] == "open"]
                if open_ports:
                    print(f"🟢 {RedTheme.BOLD}Found {len(open_ports)} open ports:{RedTheme.END}")
                    for port in open_ports:
                        print(f"  {RedTheme.RED}Port {port['port']}{RedTheme.END} ({port['service']})")
                else:
                    print(f"🔒 {RedTheme.WARNING} No open ports found{RedTheme.END}")
                
            elif cmd == "deep_scan" and args:
                max_ports = 1000
                if len(args) > 1:
                    try:
                        max_ports = int(args[1])
                    except:
                        pass
                print(f"{RedTheme.INFO} Starting deep scan on {args[0]} (1-{max_ports} ports)...{RedTheme.END}")
                result = self.monitor.deep_scan_ip(args[0], max_ports)
                open_ports = [p for p in result.get("ports", []) if p["state"] == "open"]
                if open_ports:
                    print(f"🟢 {RedTheme.BOLD}Found {len(open_ports)} open ports out of {result['total_ports']}:{RedTheme.END}")
                    for port in open_ports[:20]:
                        print(f"  {RedTheme.RED}Port {port['port']}{RedTheme.END} ({port['service']})")
                    if len(open_ports) > 20:
                        print(f"  {RedTheme.ORANGE}... and {len(open_ports) - 20} more open ports{RedTheme.END}")
                else:
                    print(f"🔒 {RedTheme.WARNING} No open ports found{RedTheme.END}")
                
            elif cmd == "start_monitoring":
                ip = args[0] if args else None
                if self.monitor.start_monitoring(ip):
                    print(f"🟢 {RedTheme.SUCCESS} Monitoring started{RedTheme.END}" + (f" for {ip}" if ip else ""))
                else:
                    print(f"🔴 {RedTheme.ERROR} Monitoring already running{RedTheme.END}")
                
            elif cmd == "stop_monitoring":
                if self.monitor.stop_monitoring():
                    print(f"🟢 {RedTheme.SUCCESS} Monitoring stopped{RedTheme.END}")
                else:
                    print(f"🔴 {RedTheme.ERROR} No monitoring active{RedTheme.END}")
                
            elif cmd == "add_ip" and args:
                if self.monitor.add_ip(args[0]):
                    print(f"🟢 {RedTheme.SUCCESS} Added {args[0]} to monitoring{RedTheme.END}")
                else:
                    print(f"🔴 {RedTheme.ERROR} Failed to add {args[0]}{RedTheme.END}")
                    
            elif cmd == "remove_ip" and args:
                if self.monitor.remove_ip(args[0]):
                    print(f"🟢 {RedTheme.SUCCESS} Removed {args[0]} from monitoring{RedTheme.END}")
                else:
                    print(f"🔴 {RedTheme.ERROR} Failed to remove {args[0]}{RedTheme.END}")
                    
            elif cmd == "list_ips":
                ips = self.monitor.list_ips()
                print(f"📋 {RedTheme.BOLD}Monitored IPs ({len(ips)}):{RedTheme.END}")
                for ip in ips:
                    print(f"  {RedTheme.RED}{ip}{RedTheme.END}")
                    
            elif cmd == "config_telegram_token" and args:
                if self.monitor.config_telegram_token(args[0]):
                    print(f"🟢 {RedTheme.SUCCESS} Telegram token configured{RedTheme.END}")
                else:
                    print(f"🔴 {RedTheme.ERROR} Failed to configure Telegram token{RedTheme.END}")
                    
            elif cmd == "config_telegram_chat_id" and args:
                if self.monitor.config_telegram_chat_id(args[0]):
                    print(f"🟢 {RedTheme.SUCCESS} Telegram chat ID configured{RedTheme.END}")
                else:
                    print(f"🔴 {RedTheme.ERROR} Failed to configure Telegram chat ID{RedTheme.END}")
                    
            elif cmd == "test_telegram_connection":
                if self.monitor.test_telegram_connection():
                    print(f"🟢 {RedTheme.SUCCESS} Telegram connection test successful{RedTheme.END}")
                else:
                    print(f"🔴 {RedTheme.ERROR} Telegram connection test failed{RedTheme.END}")
                    
            elif cmd == "export_data":
                data_type = args[0] if args else "all"
                if self.monitor.export_data_to_telegram(data_type):
                    print(f"🟢 {RedTheme.SUCCESS} Data exported to Telegram{RedTheme.END}")
                else:
                    print(f"🔴 {RedTheme.ERROR} Failed to export data{RedTheme.END}")
                    
            elif cmd == "export_csv" and args:
                if self.monitor.export_csv(args[0]):
                    print(f"🟢 {RedTheme.SUCCESS} Data exported to {args[0]}_*.csv{RedTheme.END}")
                else:
                    print(f"🔴 {RedTheme.ERROR} Failed to export CSV{RedTheme.END}")
                    
            elif cmd == "show_stats":
                self.monitor.show_stats()
                
            elif cmd == "history":
                limit = 10
                if args:
                    try:
                        limit = int(args[0])
                    except:
                        pass
                self.monitor.show_history(limit)
                
            elif cmd == "clear_history":
                self.monitor.clear_history()
                print(f"🟢 {RedTheme.SUCCESS} Command history cleared{RedTheme.END}")
                
            elif cmd == "clear_data":
                if input(f"{RedTheme.WARNING} Are you sure you want to clear all data? (y/n): {RedTheme.END}").lower() == 'y':
                    self.monitor.clear_all_data()
                    print(f"🟢 {RedTheme.SUCCESS} All monitoring data cleared{RedTheme.END}")
                else:
                    print(f"{RedTheme.INFO} Operation cancelled{RedTheme.END}")
                
            elif cmd == "exit" or cmd == "quit":
                self.running = False
                print(f"{RedTheme.INFO} Shutting down...{RedTheme.END}")
                self.monitor.stop_monitoring()
                
            else:
                print(f"{RedTheme.ERROR} Unknown command: {cmd}. Type 'help' for available commands.{RedTheme.END}")
                
        except Exception as e:
            print(f"{RedTheme.ERROR} Error executing command: {e}{RedTheme.END}")

    def start_telegram_bot(self):
        """Start the Telegram bot in a separate thread"""
        token = self.monitor.config['DEFAULT'].get('telegram_token', '')
        if not token:
            print(f"{RedTheme.WARNING} Telegram token not configured. Use 'config_telegram_token' first.{RedTheme.END}")
            return
        
        try:
            application = Application.builder().token(token).build()
            self.telegram_bot.setup_bot_handlers(application)
            
            # Start polling in a separate thread
            import threading
            bot_thread = threading.Thread(target=application.run_polling)
            bot_thread.daemon = True
            bot_thread.start()
            
            print(f"🟢 {RedTheme.SUCCESS} Telegram bot started successfully{RedTheme.END}")
            
        except Exception as e:
            print(f"🔴 {RedTheme.ERROR} Failed to start Telegram bot: {e}{RedTheme.END}")

    def run(self):
        """Main application loop with red theme"""
        print(RedTheme.BANNER)
        print(f"\n{RedTheme.BOLD_RED}🚀 Red-Themed Cyber Security Monitoring Tool Started!{RedTheme.END}")
        print(f"{RedTheme.INFO} Type 'help' for available commands or 'exit' to quit.{RedTheme.END}")
        
        # Start Telegram bot if token is configured
        token = self.monitor.config['DEFAULT'].get('telegram_token')
        chat_id = self.monitor.config['DEFAULT'].get('telegram_chat_id')
        
        if token and chat_id:
            print(f"{RedTheme.INFO} 🔧 Telegram integration configured - starting bot...{RedTheme.END}")
            self.start_telegram_bot()
        elif token:
            print(f"{RedTheme.WARNING} ⚠️  Telegram token configured but chat ID missing. Use 'config_telegram_chat_id'{RedTheme.END}")
        else:
            print(f"{RedTheme.INFO} ℹ️  Telegram not configured. Use 'config_telegram_token' to enable.{RedTheme.END}")
        
        # Main command loop
        while self.running:
            try:
                command = input(f"\n{RedTheme.PROMPT}").strip()
                if command:
                    self.handle_command(command)
            except KeyboardInterrupt:
                print(f"\n{RedTheme.INFO} Shutting down...{RedTheme.END}")
                self.running = False
            except Exception as e:
                print(f"{RedTheme.ERROR} Unexpected error: {e}{RedTheme.END}")

# Entry point
if __name__ == "__main__":
    # Check for required dependencies
    try:
        import telegram
    except ImportError as e:
        print(f"{RedTheme.ERROR} Missing required dependency: {e}{RedTheme.END}")
        print(f"{RedTheme.INFO} Please install required packages:{RedTheme.END}")
        print(f"{RedTheme.INFO} pip install python-telegram-bot requests{RedTheme.END}")
        sys.exit(1)
    
    # Check if running as root (required for some network operations)
    if os.name != 'nt' and os.geteuid() != 0:
        print(f"{RedTheme.WARNING} ⚠️  Warning: Some features may require root privileges for full functionality{RedTheme.END}")
    
    app = CyberSecurityApp()
    app.run()