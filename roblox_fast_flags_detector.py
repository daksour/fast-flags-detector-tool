import os
import re
import json
import psutil
import winreg
from pathlib import Path
import time
import logging

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

    def find_roblox_installations(self):
        """Find Roblox installation directories"""
        logging.info("Searching for Roblox installations...")
        
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
                
        if not self.roblox_paths:
            logging.warning("No Roblox installations found")
            
        return self.roblox_paths
    
    def scan_config_files(self):
        """Scan Roblox configuration files for fast flags"""
        logging.info("Scanning configuration files for fast flags...")
        
        for roblox_path in self.roblox_paths:
            # Walk through all files in the Roblox directory
            for root, _, files in os.walk(roblox_path):
                for file in files:
                    # Check common config file extensions
                    if file.endswith(('.json', '.xml', '.ini', '.txt', '.cfg')):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                self._extract_flags_from_content(content, file_path)
                        except Exception as e:
                            logging.debug(f"Error reading {file_path}: {e}")
        
        logging.info(f"Found {len(self.known_flags)} potential fast flags in configuration files")
        return self.known_flags
    
    def _extract_flags_from_content(self, content, source):
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
    
    def monitor_roblox_processes(self, duration=60):
        """Monitor running Roblox processes for fast flag usage"""
        logging.info(f"Monitoring Roblox processes for {duration} seconds...")
        
        end_time = time.time() + duration
        roblox_processes = []
        
        while time.time() < end_time:
            # Find all Roblox processes
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    if 'roblox' in proc.info['name'].lower():
                        if proc.pid not in [p.pid for p in roblox_processes]:
                            roblox_processes.append(proc)
                            logging.info(f"Found Roblox process: {proc.info['name']} (PID: {proc.pid})")
                            
                            # Check command line arguments for flags
                            if proc.info['cmdline']:
                                cmdline = ' '.join(proc.info['cmdline'])
                                self._extract_flags_from_content(cmdline, f"Process {proc.pid} cmdline")
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            
            # Sleep briefly to avoid high CPU usage
            time.sleep(1)
        
        logging.info(f"Finished monitoring {len(roblox_processes)} Roblox processes")
        return self.detected_flags
    
    def scan_log_files(self):
        """Scan Roblox log files for fast flags"""
        logging.info("Scanning Roblox log files...")
        
        log_paths = [
            os.path.join(os.environ['LOCALAPPDATA'], 'Roblox', 'logs'),
        ]
        
        for roblox_path in self.roblox_paths:
            log_paths.append(os.path.join(roblox_path, 'logs'))
        
        for log_path in log_paths:
            if os.path.exists(log_path):
                logging.info(f"Scanning logs in: {log_path}")
                for root, _, files in os.walk(log_path):
                    for file in files:
                        if file.endswith(('.log', '.txt')):
                            file_path = os.path.join(root, file)
                            try:
                                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                    content = f.read()
                                    self._extract_flags_from_content(content, file_path)
                            except Exception as e:
                                logging.debug(f"Error reading log {file_path}: {e}")
        
        return self.detected_flags
    
    def export_results(self, output_file="detected_fast_flags.json"):
        """Export detected flags to a JSON file"""
        with open(output_file, 'w') as f:
            json.dump(self.detected_flags, f, indent=4)
        logging.info(f"Results exported to {output_file}")
        return output_file
    
    def run_detection(self, monitor_duration=60):
        """Run the complete detection process"""
        logging.info("Starting Roblox Fast Flags detection")
        
        self.find_roblox_installations()
        self.scan_config_files()
        self.scan_log_files()
        self.monitor_roblox_processes(monitor_duration)
        
        if self.detected_flags:
            output_file = self.export_results()
            logging.info(f"Detection complete. Found {len(self.detected_flags)} fast flags.")
            logging.info(f"Results saved to {output_file}")
            return self.detected_flags
        else:
            logging.info("Detection complete. No fast flags detected.")
            return {}


if __name__ == "__main__":
    print("=== Roblox Fast Flags Detector ===\n")
    print("This tool will scan your system for Roblox fast flags usage.")
    print("It will check installation directories, configuration files, and monitor running Roblox processes.\n")
    
    try:
        detector = RobloxFastFlagsDetector()
        duration = 60
        
        print(f"Starting detection (will monitor processes for {duration} seconds)...\n")
        results = detector.run_detection(duration)
        
        if results:
            print(f"\nDetection complete! Found {len(results)} fast flags.")
            print(f"Results have been saved to 'detected_fast_flags.json'")
            
            # Display some of the detected flags
            print("\nSample of detected flags:")
            for i, (flag, sources) in enumerate(list(results.items())[:10]):
                print(f"  {flag}: Found in {len(sources)} location(s)")
                
            if len(results) > 10:
                print(f"  ... and {len(results) - 10} more flags")
        else:
            print("\nDetection complete! No fast flags were detected.")
            print("This could mean either:")
            print("  - Roblox is not installed on this system")
            print("  - No fast flags are currently in use")
            print("  - Fast flags are being used in a way this detector cannot identify")
    
    except Exception as e:
        print(f"\nAn error occurred: {e}")
        logging.error(f"Error in main execution: {e}", exc_info=True)
    
    finally:
        print("\nCheck 'fast_flags_detector.log' for detailed information.")
        input("\nPress Enter to exit...")