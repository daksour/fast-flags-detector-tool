import os
import re
import json
import psutil
import winreg
import time
import logging
import threading
import smtplib
import socket
import uuid
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from tkinter.ttk import Progressbar
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from pathlib import Path
from datetime import datetime

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("fast_flags_detector.log"),
        logging.StreamHandler()
    ]
)

class RobloxFastFlagsDetector:
    def __init__(self):
        self.roblox_paths = []
        self.flag_patterns = [
            r'FFlagS?[A-Z][a-zA-Z0-9]+',  # Standard FFlag pattern
            r'DFFlag[A-Z][a-zA-Z0-9]+',    # Debug FFlag pattern
            r'SFFlag[A-Z][a-zA-Z0-9]+',    # Security FFlag pattern
            r'DFlnt[A-Z][a-zA-Z0-9]+',     # DFlnt fastflag pattern
            r'DFInt[A-Z][a-zA-Z0-9]+'      # DFInt fastflag pattern
        ]
        self.known_flags = set()
        self.detected_flags = {}
        self.standard_roblox_flags = {}
        self.user_added_flags = {}
        self.pc_fast_flags = {}
        self.client_app_settings_flags = {}
        self.bloxstrap_flags = {}
        self.fishstrap_flags = {}
        self.ministrap_flags = {}
        self.other_launcher_flags = {}
        self.log_flags = {}
        self.scan_hidden_files = True
        self.scan_progress = 0
        self.scan_status = ""
        self.is_scanning = False
        self.machine_id = self._get_machine_id()
        
        # Load standard Roblox flags from a predefined list
        self.load_standard_flags()
        
    def _get_machine_id(self):
        """Generate a unique machine identifier"""
        try:
            # Try to get a unique machine identifier
            machine_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, socket.gethostname()))
            return machine_id
        except:
            # Fallback to a random UUID if we can't get the hostname
            return str(uuid.uuid4())

    def find_roblox_installations(self):
        """Find Roblox installation directories"""
        logging.info("Searching for Roblox installations...")
        self.scan_status = "Searching for Roblox installations..."
        
        # Common Roblox installation paths
        potential_paths = [
            os.path.join(os.environ['LOCALAPPDATA'], 'Roblox'),
            os.path.join(os.environ['PROGRAMFILES'], 'Roblox'),
            os.path.join(os.environ['PROGRAMFILES(X86)'], 'Roblox'),
        ]
        
        # Try to find Roblox via registry
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"SOFTWARE\ROBLOX Corporation\Roblox") as key:
                install_path = winreg.QueryValueEx(key, "InstallLocation")[0]
                if install_path and os.path.exists(install_path):
                    potential_paths.append(install_path)
        except (WindowsError, FileNotFoundError):
            pass
            
        # Check if paths exist and contain Roblox
        for path in potential_paths:
            if os.path.exists(path):
                self.roblox_paths.append(path)
                logging.info(f"Found Roblox installation at: {path}")
                self.scan_status = f"Found Roblox installation at: {path}"
                
        if not self.roblox_paths:
            logging.warning("No Roblox installations found")
            self.scan_status = "No Roblox installations found"
            
        return self.roblox_paths
    
    def scan_config_files(self):
        """Scan Roblox configuration files for fast flags"""
        logging.info("Scanning configuration files for fast flags...")
        self.scan_status = "Scanning configuration files for fast flags..."
        
        total_files = 0
        processed_files = 0
        
        # First count total files for progress tracking
        for roblox_path in self.roblox_paths:
            for root, dirs, files in os.walk(roblox_path, topdown=True):
                # Skip hidden directories if not scanning hidden files
                if not self.scan_hidden_files:
                    dirs[:] = [d for d in dirs if not d.startswith('.')]
                    
                for file in files:
                    # Skip hidden files if not scanning them
                    if not self.scan_hidden_files and file.startswith('.'):
                        continue
                        
                    if file.endswith(('.json', '.xml', '.ini', '.txt', '.cfg')):
                        total_files += 1
        
        # Now scan the files
        for roblox_path in self.roblox_paths:
            for root, dirs, files in os.walk(roblox_path, topdown=True):
                # Skip hidden directories if not scanning hidden files
                if not self.scan_hidden_files:
                    dirs[:] = [d for d in dirs if not d.startswith('.')]
                    
                for file in files:
                    # Skip hidden files if not scanning them
                    if not self.scan_hidden_files and file.startswith('.'):
                        continue
                        
                    # Check common config file extensions
                    if file.endswith(('.json', '.xml', '.ini', '.txt', '.cfg')):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                self._extract_flags_from_content(content, file_path)
                        except Exception as e:
                            logging.debug(f"Error reading {file_path}: {e}")
                        
                        processed_files += 1
                        if total_files > 0:
                            self.scan_progress = (processed_files / total_files) * 33  # First third of progress
                            self.scan_status = f"Scanning config files: {processed_files}/{total_files}"
        
        logging.info(f"Found {len(self.known_flags)} potential fast flags in configuration files")
        self.scan_status = f"Found {len(self.known_flags)} potential fast flags in configuration files"
        return self.known_flags
    
    def load_standard_flags(self):
        """Load a list of standard Roblox flags"""
        # This is a small sample of common Roblox flags
        # In a real implementation, this would be a more comprehensive list
        standard_flags = [
            "FFlagDebugGraphicsPreferD3D11",
            "FFlagDisableSomething",
            "DFFlagDebugPauseVoxelizer",
            "FFlagEnableHardwareTelemetry",
            "FFlagDebugDisableTelemetryV2",
            "FFlagEnableInGameMenuV3",
            "FFlagDisableNewIGMinDUA",
            "FFlagEnableMenuControlsABTest",
            "FFlagEnableMenuModernizationABTest",
            "FFlagDebugRenderingSetDeterministic"
        ]
        
        for flag in standard_flags:
            self.standard_roblox_flags[flag] = []
    
    def _extract_flags_from_content(self, content, source, category=None):
        """Extract fast flags from text content"""
        for pattern in self.flag_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                self.known_flags.add(match)
                if match not in self.detected_flags:
                    self.detected_flags[match] = []
                if source not in self.detected_flags[match]:
                    self.detected_flags[match].append(source)
                    logging.info(f"Detected flag: {match} in {source}")
                
                # Add to specific category if provided
                if category:
                    category_dict = getattr(self, category, None)
                    if category_dict is not None:
                        if match not in category_dict:
                            category_dict[match] = []
                        if source not in category_dict[match]:
                            category_dict[match].append(source)
                
                # Categorize based on source type
                if 'ClientAppSettings.json' in source:
                    if match not in self.client_app_settings_flags:
                        self.client_app_settings_flags[match] = []
                    if source not in self.client_app_settings_flags[match]:
                        self.client_app_settings_flags[match].append(source)
                elif 'bloxstrap' in source.lower():
                    if match not in self.bloxstrap_flags:
                        self.bloxstrap_flags[match] = []
                    if source not in self.bloxstrap_flags[match]:
                        self.bloxstrap_flags[match].append(source)
                elif 'fishstrap' in source.lower():
                    if match not in self.fishstrap_flags:
                        self.fishstrap_flags[match] = []
                    if source not in self.fishstrap_flags[match]:
                        self.fishstrap_flags[match].append(source)
                elif 'ministrap' in source.lower():
                    if match not in self.ministrap_flags:
                        self.ministrap_flags[match] = []
                    if source not in self.ministrap_flags[match]:
                        self.ministrap_flags[match].append(source)
                elif '.log' in source.lower():
                    if match not in self.log_flags:
                        self.log_flags[match] = []
                    if source not in self.log_flags[match]:
                        self.log_flags[match].append(source)
                
                # Categorize the flag as standard or user-added
                if match in self.standard_roblox_flags:
                    # Flag is in our predefined list of standard flags
                    if source not in self.standard_roblox_flags[match]:
                        self.standard_roblox_flags[match].append(source)
                else:
                    # Flag is not in our predefined list, so it's user-added
                    if match not in self.user_added_flags:
                        self.user_added_flags[match] = []
                    if source not in self.user_added_flags[match]:
                        self.user_added_flags[match].append(source)
    
    def monitor_roblox_processes(self, duration=60):
        """Monitor running Roblox processes for fast flag usage"""
        logging.info(f"Monitoring Roblox processes for {duration} seconds...")
        self.scan_status = f"Monitoring Roblox processes for {duration} seconds..."
        
        end_time = time.time() + duration
        roblox_processes = []
        start_time = time.time()
        
        while time.time() < end_time and self.is_scanning:
            # Update progress (from 66% to 100%)
            elapsed = time.time() - start_time
            if duration > 0:
                self.scan_progress = 66 + (elapsed / duration) * 34
                self.scan_status = f"Monitoring processes: {int(elapsed)}/{duration} seconds"
            
            # Find all Roblox processes
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    if 'roblox' in proc.info['name'].lower():
                        if proc.pid not in [p.pid for p in roblox_processes]:
                            roblox_processes.append(proc)
                            logging.info(f"Found Roblox process: {proc.info['name']} (PID: {proc.pid})")
                            self.scan_status = f"Found Roblox process: {proc.info['name']} (PID: {proc.pid})"
                            
                            # Check command line arguments for flags
                            if proc.info['cmdline']:
                                cmdline = ' '.join(proc.info['cmdline'])
                                self._extract_flags_from_content(cmdline, f"Process {proc.pid} cmdline")
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            
            # Sleep briefly to avoid high CPU usage
            time.sleep(1)
        
        logging.info(f"Finished monitoring {len(roblox_processes)} Roblox processes")
        self.scan_status = f"Finished monitoring {len(roblox_processes)} Roblox processes"
        return self.detected_flags
    
    def scan_log_files(self):
        """Scan Roblox log files for fast flags"""
        logging.info("Scanning Roblox log files...")
        self.scan_status = "Scanning Roblox log files..."
        
        log_paths = [
            os.path.join(os.environ['LOCALAPPDATA'], 'Roblox', 'logs'),
        ]
        
        for roblox_path in self.roblox_paths:
            log_paths.append(os.path.join(roblox_path, 'logs'))
        
        total_files = 0
        processed_files = 0
        
        # First count total files for progress tracking
        for log_path in log_paths:
            if os.path.exists(log_path):
                for root, dirs, files in os.walk(log_path, topdown=True):
                    # Skip hidden directories if not scanning hidden files
                    if not self.scan_hidden_files:
                        dirs[:] = [d for d in dirs if not d.startswith('.')]
                        
                    for file in files:
                        # Skip hidden files if not scanning them
                        if not self.scan_hidden_files and file.startswith('.'):
                            continue
                            
                        if file.endswith(('.log', '.txt')):
                            total_files += 1
        
        # Now scan the files
        for log_path in log_paths:
            if os.path.exists(log_path):
                logging.info(f"Scanning logs in: {log_path}")
                self.scan_status = f"Scanning logs in: {log_path}"
                
                for root, dirs, files in os.walk(log_path, topdown=True):
                    # Skip hidden directories if not scanning hidden files
                    if not self.scan_hidden_files:
                        dirs[:] = [d for d in dirs if not d.startswith('.')]
                        
                    for file in files:
                        # Skip hidden files if not scanning them
                        if not self.scan_hidden_files and file.startswith('.'):
                            continue
                            
                        if file.endswith(('.log', '.txt')):
                            file_path = os.path.join(root, file)
                            try:
                                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                    content = f.read()
                                    self._extract_flags_from_content(content, file_path)
                            except Exception as e:
                                logging.debug(f"Error reading log {file_path}: {e}")
                            
                            processed_files += 1
                            if total_files > 0:
                                self.scan_progress = 33 + (processed_files / total_files) * 33  # Second third of progress
                                self.scan_status = f"Scanning log files: {processed_files}/{total_files}"
        
        return self.detected_flags
    
    def compare_flags(self):
        """Compare flags between different sources"""
        # Create comparison dictionaries
        log_vs_client_app = {}
        log_vs_bloxstrap = {}
        log_vs_fishstrap = {}
        log_vs_ministrap = {}
        
        # Compare log flags with ClientAppSettings flags
        for flag in self.log_flags:
            if flag in self.client_app_settings_flags:
                log_vs_client_app[flag] = {
                    "in_logs": self.log_flags[flag],
                    "in_client_app": self.client_app_settings_flags[flag]
                }
        
        # Compare log flags with Bloxstrap flags
        for flag in self.log_flags:
            if flag in self.bloxstrap_flags:
                log_vs_bloxstrap[flag] = {
                    "in_logs": self.log_flags[flag],
                    "in_bloxstrap": self.bloxstrap_flags[flag]
                }
        
        # Compare log flags with Fishstrap flags
        for flag in self.log_flags:
            if flag in self.fishstrap_flags:
                log_vs_fishstrap[flag] = {
                    "in_logs": self.log_flags[flag],
                    "in_fishstrap": self.fishstrap_flags[flag]
                }
        
        # Compare log flags with Ministrap flags
        for flag in self.log_flags:
            if flag in self.ministrap_flags:
                log_vs_ministrap[flag] = {
                    "in_logs": self.log_flags[flag],
                    "in_ministrap": self.ministrap_flags[flag]
                }
        
        return {
            "log_vs_client_app": log_vs_client_app,
            "log_vs_bloxstrap": log_vs_bloxstrap,
            "log_vs_fishstrap": log_vs_fishstrap,
            "log_vs_ministrap": log_vs_ministrap
        }
        
    def export_results(self, output_file="detected_fast_flags.json"):
        """Export detected flags to a JSON file"""
        # Get flag comparisons
        comparisons = self.compare_flags()
        
        # Add machine ID and timestamp to the results
        export_data = {
            "machine_id": self.machine_id,
            "timestamp": datetime.now().isoformat(),
            "standard_flags": self.standard_roblox_flags,
            "user_added_flags": self.user_added_flags,
            "pc_fast_flags": self.pc_fast_flags,
            "client_app_settings_flags": self.client_app_settings_flags,
            "bloxstrap_flags": self.bloxstrap_flags,
            "fishstrap_flags": self.fishstrap_flags,
            "ministrap_flags": self.ministrap_flags,
            "other_launcher_flags": self.other_launcher_flags,
            "log_flags": self.log_flags,
            "comparisons": comparisons,
            "all_flags": self.detected_flags
        }
        
        with open(output_file, 'w') as f:
            json.dump(export_data, f, indent=4)
        logging.info(f"Results exported to {output_file}")
        self.scan_status = f"Results exported to {output_file}"
        return output_file
    
    def send_results(self, email, output_file):
        """Send results to the specified email"""
        try:
            # Configure email settings
            sender_email = "your-email@gmail.com"  # Replace with your email
            app_password = "your-app-password"     # Replace with your app password
            receiver_email = email
            
            # Create message
            msg = MIMEMultipart()
            msg['From'] = sender_email
            msg['To'] = receiver_email
            msg['Subject'] = "Roblox Fast Flags Detection Results"
            
            # Add body text
            body = f"Roblox Fast Flags Detection Results\n\n"
            body += f"Detected {len(self.detected_flags)} flags in total\n"
            body += f"Standard Roblox flags: {len([f for f, locs in self.standard_roblox_flags.items() if locs])}\n"
            body += f"User-added flags: {len(self.user_added_flags)}\n"
            body += f"PC fast flags: {len(self.pc_fast_flags)}\n"
            body += f"ClientAppSettings flags: {len(self.client_app_settings_flags)}\n"
            body += f"Bloxstrap flags: {len(self.bloxstrap_flags)}\n"
            body += f"Fishstrap flags: {len(self.fishstrap_flags)}\n"
            body += f"Ministrap flags: {len(self.ministrap_flags)}\n"
            body += f"Other launcher flags: {len(self.other_launcher_flags)}\n\n"
            body += "See attached file for details.\n\n"
            body += "Generated by Roblox Fast Flags Detector\n"
            body += "Made by daksour"
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Attach the results file
            with open(output_file, "rb") as f:
                attachment = MIMEApplication(f.read(), _subtype="json")
                attachment.add_header('Content-Disposition', 'attachment', filename=os.path.basename(output_file))
                msg.attach(attachment)
            
            # Check if credentials are configured
            if sender_email == "your-email@gmail.com" or app_password == "your-app-password":
                logging.error("Email credentials not configured")
                return False
            
            # Actual email sending implementation
            try:
                with smtplib.SMTP('smtp.gmail.com', 587) as server:
                    server.starttls()
                    server.login(sender_email, app_password)
                    server.send_message(msg)
                    logging.info(f"Results sent to {email}")
                    self.scan_status = f"Results sent to {email}"
                    return True
            except Exception as email_error:
                logging.error(f"Failed to send email: {email_error}")
                self.scan_status = f"Failed to send email: {email_error}"
                return False
            
        except Exception as e:
            logging.error(f"Error sending results: {e}")
            self.scan_status = f"Error sending results: {e}"
            return False
    
    def run_detection(self, monitor_duration=60):
        """Run the complete detection process"""
        self.is_scanning = True
        self.scan_progress = 0
        self.known_flags = set()
        self.detected_flags = {}
        self.standard_roblox_flags = {}
        self.user_added_flags = {}
        self.pc_fast_flags = {}
        self.client_app_settings_flags = {}
        self.bloxstrap_flags = {}
        self.fishstrap_flags = {}
        self.ministrap_flags = {}
        self.other_launcher_flags = {}
        self.log_flags = {}
        
        # Load standard flags
        self.load_standard_flags()
        
        logging.info("Starting Roblox Fast Flags detection")
        self.scan_status = "Starting Roblox Fast Flags detection"
        
        self.find_roblox_installations()
        if not self.is_scanning:
            return {}
            
        self.scan_config_files()
        if not self.is_scanning:
            return {}
            
        self.scan_log_files()
        if not self.is_scanning:
            return {}
            
        self.scan_client_app_settings()
        if not self.is_scanning:
            return {}
            
        self.scan_launcher_files()
        if not self.is_scanning:
            return {}
            
        self.scan_pc_for_fast_flags()
        if not self.is_scanning:
            return {}
            
        self.monitor_roblox_processes(monitor_duration)
        
        self.scan_progress = 100
        
    def scan_client_app_settings(self):
        """Scan ClientAppSettings.json files for fast flags"""
        logging.info("Scanning ClientAppSettings.json files for fast flags...")
        self.scan_status = "Scanning ClientAppSettings.json files..."
        
        # Find ClientAppSettings.json files
        client_app_settings_files = self.find_client_app_settings()
        
        if not client_app_settings_files:
            logging.warning("No ClientAppSettings.json files found to scan")
            self.scan_status = "No ClientAppSettings.json files found to scan"
            return {}
        
        # Process each file
        for file_path in client_app_settings_files:
            try:
                # Try to parse as JSON first
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    try:
                        json_data = json.loads(content)
                        # Look for flags in JSON keys
                        for key in json_data.keys():
                            for pattern in self.flag_patterns:
                                if re.match(pattern, key):
                                    # Determine which category to add this flag to
                                    if 'Bloxstrap' in file_path:
                                        category = 'bloxstrap_flags'
                                    elif 'Fishstrap' in file_path:
                                        category = 'fishstrap_flags'
                                    elif 'Ministrap' in file_path:
                                        category = 'ministrap_flags'
                                    else:
                                        category = 'client_app_settings_flags'
                                    
                                    # Extract the flag with its value
                                    self._extract_flags_from_content(f"{key}={json_data[key]}", file_path, category)
                    except json.JSONDecodeError:
                        # If not valid JSON, use regex to find flags in raw content
                        self._extract_flags_from_content(content, file_path)
            except Exception as e:
                logging.error(f"Error processing {file_path}: {e}")
        
        logging.info(f"Found {len(self.client_app_settings_flags)} flags in ClientAppSettings.json files")
        self.scan_status = f"Found {len(self.client_app_settings_flags)} flags in ClientAppSettings.json files"
        
        return self.client_app_settings_flags
    
    def find_client_app_settings(self):
        """Find ClientAppSettings.json files and alternative launcher settings"""
        logging.info("Searching for ClientAppSettings.json and launcher settings...")
        self.scan_status = "Searching for settings files..."
        
        # Common locations for ClientAppSettings.json
        settings_paths = [
            os.path.join(os.environ['LOCALAPPDATA'], 'Roblox', 'ClientSettings', 'ClientAppSettings.json'),
            os.path.join(os.environ['LOCALAPPDATA'], 'Packages', 'ROBLOXCORPORATION.ROBLOX_55nm5eh3cm0pr', 'LocalState', 'ClientAppSettings.json'),
            # Bloxstrap locations
            os.path.join(os.environ['LOCALAPPDATA'], 'Bloxstrap', 'ClientAppSettings.json'),
            os.path.join(os.environ['APPDATA'], 'Bloxstrap', 'ClientAppSettings.json'),
            # Fishstrap locations
            os.path.join(os.environ['LOCALAPPDATA'], 'Fishstrap', 'ClientAppSettings.json'),
            os.path.join(os.environ['APPDATA'], 'Fishstrap', 'ClientAppSettings.json'),
            # Ministrap locations
            os.path.join(os.environ['LOCALAPPDATA'], 'Ministrap', 'ClientAppSettings.json'),
            os.path.join(os.environ['APPDATA'], 'Ministrap', 'ClientAppSettings.json')
        ]
        
        # Add paths from Roblox installations
        for roblox_path in self.roblox_paths:
            settings_paths.append(os.path.join(roblox_path, 'ClientSettings', 'ClientAppSettings.json'))
        
        found_files = []
        for path in settings_paths:
            if os.path.exists(path):
                found_files.append(path)
                logging.info(f"Found settings file at: {path}")
                
                # Categorize the file based on its path
                if 'Bloxstrap' in path:
                    self._extract_flags_from_content(open(path, 'r', encoding='utf-8').read(), path, 'bloxstrap_flags')
                elif 'Fishstrap' in path:
                    self._extract_flags_from_content(open(path, 'r', encoding='utf-8').read(), path, 'fishstrap_flags')
                elif 'Ministrap' in path:
                    self._extract_flags_from_content(open(path, 'r', encoding='utf-8').read(), path, 'ministrap_flags')
                else:
                    self._extract_flags_from_content(open(path, 'r', encoding='utf-8').read(), path, 'client_app_settings_flags')
        
        if not found_files:
            logging.warning("No settings files found")
            self.scan_status = "No settings files found"
        
        return found_files
    
    def scan_launcher_files(self):
        """Scan launcher files (Bloxstrap, Fishstrap, Ministrap) for fast flags"""
        logging.info("Scanning launcher files for fast flags...")
        self.scan_status = "Scanning launcher files for fast flags..."
        
        # Common locations for launcher files
        launcher_paths = {
            'bloxstrap': [
                os.path.join(os.environ['LOCALAPPDATA'], 'Bloxstrap'),
                os.path.join(os.environ['APPDATA'], 'Bloxstrap')
            ],
            'fishstrap': [
                os.path.join(os.environ['LOCALAPPDATA'], 'Fishstrap'),
                os.path.join(os.environ['APPDATA'], 'Fishstrap')
            ],
            'ministrap': [
                os.path.join(os.environ['LOCALAPPDATA'], 'Ministrap'),
                os.path.join(os.environ['APPDATA'], 'Ministrap')
            ]
        }
        
        # Scan each launcher's directory
        for launcher, paths in launcher_paths.items():
            for path in paths:
                if os.path.exists(path):
                    logging.info(f"Scanning {launcher} files in {path}")
                    self.scan_status = f"Scanning {launcher} files in {path}"
                    
                    # Walk through all files in the launcher directory
                    for root, _, files in os.walk(path):
                        for file in files:
                            # Check common config file extensions
                            if file.endswith(('.json', '.xml', '.ini', '.txt', '.cfg')):
                                file_path = os.path.join(root, file)
                                try:
                                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                        content = f.read()
                                        # Determine category based on launcher
                                        if launcher == 'bloxstrap':
                                            self._extract_flags_from_content(content, file_path, 'bloxstrap_flags')
                                        elif launcher == 'fishstrap':
                                            self._extract_flags_from_content(content, file_path, 'fishstrap_flags')
                                        elif launcher == 'ministrap':
                                            self._extract_flags_from_content(content, file_path, 'ministrap_flags')
                                        else:
                                            self._extract_flags_from_content(content, file_path, 'other_launcher_flags')
                                except Exception as e:
                                    logging.debug(f"Error reading {file_path}: {e}")
        
        # Log results
        logging.info(f"Found {len(self.bloxstrap_flags)} Bloxstrap flags")
        logging.info(f"Found {len(self.fishstrap_flags)} Fishstrap flags")
        logging.info(f"Found {len(self.ministrap_flags)} Ministrap flags")
        self.scan_status = f"Found launcher flags: Bloxstrap: {len(self.bloxstrap_flags)}, Fishstrap: {len(self.fishstrap_flags)}, Ministrap: {len(self.ministrap_flags)}"
        
        return {
            'bloxstrap': self.bloxstrap_flags,
            'fishstrap': self.fishstrap_flags,
            'ministrap': self.ministrap_flags,
            'other': self.other_launcher_flags
        }
    
    def _scan_directory_for_flags(self, directory, category):
        """Scan a directory for files that might contain fast flags"""
        if not os.path.exists(directory):
            return
            
        for root, dirs, files in os.walk(directory, topdown=True):
            # Skip hidden directories if not scanning hidden files
            if not self.scan_hidden_files:
                dirs[:] = [d for d in dirs if not d.startswith('.')]
                
            for file in files:
                # Skip hidden files if not scanning them
                if not self.scan_hidden_files and file.startswith('.'):
                    continue
                    
                # Check common config file extensions
                if file.endswith(('.json', '.xml', '.ini', '.txt', '.cfg', '.log', '.config')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                            # Try to parse as JSON to extract flags with their values
                            if file.endswith('.json'):
                                try:
                                    json_data = json.loads(content)
                                    # Look for flags in JSON keys
                                    for key in json_data.keys():
                                        for pattern in self.flag_patterns:
                                            if re.match(pattern, key):
                                                # Add to specific category
                                                category_dict = getattr(self, category, None)
                                                if category_dict is not None:
                                                    if key not in category_dict:
                                                        category_dict[key] = []
                                                    if file_path not in category_dict[key]:
                                                        category_dict[key].append(file_path)
                                                        logging.info(f"Detected {category} flag: {key} = {json_data[key]} in {file_path}")
                                                
                                                # Also add to general detected flags
                                                if key not in self.detected_flags:
                                                    self.detected_flags[key] = []
                                                if file_path not in self.detected_flags[key]:
                                                    self.detected_flags[key].append(file_path)
                                                
                                                # Add to user_added_flags if not a standard flag
                                                if key not in self.standard_roblox_flags:
                                                    if key not in self.user_added_flags:
                                                        self.user_added_flags[key] = []
                                                    if file_path not in self.user_added_flags[key]:
                                                        self.user_added_flags[key].append(file_path)
                                except json.JSONDecodeError:
                                    # If not valid JSON, use regex to find flags
                                    self._extract_flags_from_content(content, file_path, category)
                            else:
                                # For non-JSON files, use regex to find flags
                                self._extract_flags_from_content(content, file_path, category)
                    except Exception as e:
                        logging.debug(f"Error reading {file_path}: {e}")
    
    def scan_pc_for_fast_flags(self):
        """Scan PC for fast flags"""
        logging.info("Scanning PC for fast flags...")
        self.scan_status = "Scanning PC for fast flags..."
        
        # Common locations for fast flags
        pc_flag_paths = [
            os.path.join(os.environ['LOCALAPPDATA'], 'Roblox', 'GlobalSettings_13.xml'),
            os.path.join(os.environ['APPDATA'], 'Roblox', 'GlobalSettings_13.xml'),
            os.path.join(os.environ['LOCALAPPDATA'], 'Roblox', 'FFlags.json'),
            os.path.join(os.environ['APPDATA'], 'Roblox', 'FFlags.json')
        ]
        
        # Add paths from Roblox installations
        for roblox_path in self.roblox_paths:
            pc_flag_paths.append(os.path.join(roblox_path, 'GlobalSettings_13.xml'))
            pc_flag_paths.append(os.path.join(roblox_path, 'FFlags.json'))
        
        for path in pc_flag_paths:
            if os.path.exists(path):
                try:
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        self._extract_flags_from_content(content, path, 'pc_fast_flags')
                        logging.info(f"Scanned PC fast flags at {path}")
                        self.scan_status = f"Scanned PC fast flags at {path}"
                except Exception as e:
                    logging.debug(f"Error reading {path}: {e}")
        
        return self.pc_fast_flags
    
    def scan_pc_for_fast_flags(self):
        """Scan PC registry and other locations for fast flags"""
        logging.info("Scanning PC for fast flags...")
        self.scan_status = "Scanning PC for fast flags..."
        
        # Check registry locations where fast flags might be stored
        registry_locations = [
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\ROBLOX Corporation\Roblox"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\ROBLOX Corporation\Roblox"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Roblox"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Roblox")
        ]
        
        for hkey, key_path in registry_locations:
            try:
                with winreg.OpenKey(hkey, key_path) as key:
                    # Try to enumerate all values
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            # Check if the name matches any flag pattern
                            for pattern in self.flag_patterns:
                                if re.match(pattern, name):
                                    source = f"Registry: {key_path}"
                                    self._extract_flags_from_content(f"{name}={value}", source, 'pc_fast_flags')
                            i += 1
                        except WindowsError:
                            # No more values
                            break
            except (WindowsError, FileNotFoundError):
                # Registry key doesn't exist
                pass
        
        # Check environment variables for fast flags
        for env_var, value in os.environ.items():
            for pattern in self.flag_patterns:
                if re.match(pattern, env_var):
                    source = "Environment Variables"
                    self._extract_flags_from_content(f"{env_var}={value}", source, 'pc_fast_flags')
        
        # Check common locations for Roblox configuration files
        common_config_locations = [
            os.path.join(os.environ['USERPROFILE'], '.roblox'),
            os.path.join(os.environ['USERPROFILE'], 'Documents', 'Roblox'),
            os.path.join(os.environ['USERPROFILE'], 'AppData', 'Roaming', 'Roblox')
        ]
        
        for location in common_config_locations:
            if os.path.exists(location):
                for root, _, files in os.walk(location):
                    for file in files:
                        if file.endswith(('.json', '.xml', '.ini', '.txt', '.cfg')):
                            file_path = os.path.join(root, file)
                            try:
                                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                    content = f.read()
                                    self._extract_flags_from_content(content, file_path, 'pc_fast_flags')
                            except Exception as e:
                                logging.debug(f"Error reading {file_path}: {e}")
        
        logging.info(f"Found {len(self.pc_fast_flags)} fast flags in PC locations")
        self.scan_status = f"Found {len(self.pc_fast_flags)} fast flags in PC locations"
        
        return self.pc_fast_flags
    
    def _scan_directory_for_flags(self, directory, category):
        """Scan a directory for files that might contain fast flags"""
        if not os.path.exists(directory):
            return
            
        for root, dirs, files in os.walk(directory, topdown=True):
            # Skip hidden directories if not scanning hidden files
            if not self.scan_hidden_files:
                dirs[:] = [d for d in dirs if not d.startswith('.')]
                
            for file in files:
                # Skip hidden files if not scanning them
                if not self.scan_hidden_files and file.startswith('.'):
                    continue
                    
                # Check common config file extensions
                if file.endswith(('.json', '.xml', '.ini', '.txt', '.cfg', '.log', '.config')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                            # Try to parse as JSON to extract flags with their values
                            if file.endswith('.json'):
                                try:
                                    json_data = json.loads(content)
                                    # Look for flags in JSON keys
                                    for key in json_data.keys():
                                        for pattern in self.flag_patterns:
                                            if re.match(pattern, key):
                                                # Add to specific category
                                                category_dict = getattr(self, category, None)
                                                if category_dict is not None:
                                                    if key not in category_dict:
                                                        category_dict[key] = []
                                                    if file_path not in category_dict[key]:
                                                        category_dict[key].append(file_path)
                                                        logging.info(f"Detected {category} flag: {key} = {json_data[key]} in {file_path}")
                                                
                                                # Also add to general detected flags
                                                if key not in self.detected_flags:
                                                    self.detected_flags[key] = []
                                                if file_path not in self.detected_flags[key]:
                                                    self.detected_flags[key].append(file_path)
                                                
                                                # Add to user_added_flags if not a standard flag
                                                if key not in self.standard_roblox_flags:
                                                    if key not in self.user_added_flags:
                                                        self.user_added_flags[key] = []
                                                    if file_path not in self.user_added_flags[key]:
                                                        self.user_added_flags[key].append(file_path)
                                except json.JSONDecodeError:
                                    # If not valid JSON, use regex to find flags
                                    self._extract_flags_from_content(content, file_path, category)
                            else:
                                # For non-JSON files, use regex to find flags
                                self._extract_flags_from_content(content, file_path, category)
                    except Exception as e:
                        logging.debug(f"Error reading {file_path}: {e}")
    
    def scan_pc_for_fast_flags(self):
        """Scan PC for fast flags"""
        logging.info("Scanning PC for fast flags...")
        self.scan_status = "Scanning PC for fast flags..."
        
        # Common locations for fast flags
        pc_flag_paths = [
            os.path.join(os.environ['LOCALAPPDATA'], 'Roblox', 'GlobalSettings_13.xml'),
            os.path.join(os.environ['APPDATA'], 'Roblox', 'GlobalSettings_13.xml'),
            os.path.join(os.environ['LOCALAPPDATA'], 'Roblox', 'FFlags.json'),
            os.path.join(os.environ['APPDATA'], 'Roblox', 'FFlags.json')
        ]
        
        # Add paths from Roblox installations
        for roblox_path in self.roblox_paths:
            pc_flag_paths.append(os.path.join(roblox_path, 'GlobalSettings_13.xml'))
            pc_flag_paths.append(os.path.join(roblox_path, 'FFlags.json'))
        
        for path in pc_flag_paths:
            if os.path.exists(path):
                try:
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        self._extract_flags_from_content(content, path, 'pc_fast_flags')
                        logging.info(f"Scanned PC fast flags at {path}")
                        self.scan_status = f"Scanned PC fast flags at {path}"
                except Exception as e:
                    logging.debug(f"Error reading {path}: {e}")
        
        return self.pc_fast_flags
    
    def scan_pc_for_fast_flags(self):
        """Scan common locations on PC for fast flags"""
        logging.info("Scanning PC for fast flags...")
        self.scan_status = "Scanning PC for fast flags..."
        
        # Common locations to scan
        locations = [
            os.path.join(os.environ['APPDATA'], 'Roblox'),
            os.path.join(os.environ['LOCALAPPDATA'], 'Roblox'),
            os.path.join(os.environ['TEMP'], 'Roblox'),
            os.path.join(os.environ['USERPROFILE'], 'Documents', 'Roblox'),
            os.path.join(os.environ['USERPROFILE'], 'Downloads')
        ]
        
        # Add Program Files locations
        if 'PROGRAMFILES' in os.environ:
            locations.append(os.path.join(os.environ['PROGRAMFILES'], 'Roblox'))
        if 'PROGRAMFILES(X86)' in os.environ:
            locations.append(os.path.join(os.environ['PROGRAMFILES(X86)'], 'Roblox'))
        
        # Scan each location
        for location in locations:
            if os.path.exists(location):
                self.scan_status = f"Scanning {location} for fast flags..."
                self._scan_directory_for_flags(location, 'pc_fast_flags')
        
        return self.pc_fast_flags