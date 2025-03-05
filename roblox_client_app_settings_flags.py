import os
import re
import json
import winreg
import logging

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

class ClientAppSettingsFlagsFinder:
    def __init__(self):
        self.roblox_paths = []
        self.flag_patterns = [
            r'FFlagS?[A-Z][a-zA-Z0-9]+',  # Standard FFlag pattern
            r'DFFlag[A-Z][a-zA-Z0-9]+',    # Debug FFlag pattern
            r'SFFlag[A-Z][a-zA-Z0-9]+'     # Security FFlag pattern
        ]
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
    
    def find_client_app_settings(self):
        """Find ClientAppSettings.json files"""
        logging.info("Searching for ClientAppSettings.json files...")
        
        # Find Roblox installations first
        self.find_roblox_installations()
        
        # Common locations for ClientAppSettings.json
        client_app_settings_paths = [
            os.path.join(os.environ['LOCALAPPDATA'], 'Roblox', 'ClientSettings', 'ClientAppSettings.json'),
            os.path.join(os.environ['LOCALAPPDATA'], 'Packages', 'ROBLOXCORPORATION.ROBLOX_55nm5eh3cm0pr', 'LocalState', 'ClientAppSettings.json')
        ]
        
        # Add paths from Roblox installations
        for roblox_path in self.roblox_paths:
            client_app_settings_paths.append(os.path.join(roblox_path, 'ClientSettings', 'ClientAppSettings.json'))
        
        found_files = []
        for path in client_app_settings_paths:
            if os.path.exists(path):
                found_files.append(path)
                logging.info(f"Found ClientAppSettings.json at: {path}")
        
        if not found_files:
            logging.warning("No ClientAppSettings.json files found")
            
        return found_files
    
    def extract_flags_from_content(self, content, source):
        """Extract fast flags from text content"""
        flags_found = {}
        
        # Try to parse as JSON first
        try:
            json_data = json.loads(content)
            # Look for flags in JSON keys
            for key in json_data.keys():
                for pattern in self.flag_patterns:
                    if re.match(pattern, key):
                        flags_found[key] = json_data[key]
                        if key not in self.detected_flags:
                            self.detected_flags[key] = []
                        if source not in self.detected_flags[key]:
                            self.detected_flags[key].append(source)
                            logging.info(f"Detected flag: {key} = {json_data[key]} in {source}")
        except json.JSONDecodeError:
            # If not valid JSON, use regex to find flags in raw content
            for pattern in self.flag_patterns:
                matches = re.findall(pattern, content)
                for match in matches:
                    if match not in self.detected_flags:
                        self.detected_flags[match] = []
                    if source not in self.detected_flags[match]:
                        self.detected_flags[match].append(source)
                        logging.info(f"Detected flag: {match} in {source}")
                    flags_found[match] = "Unknown value (not in JSON format)"
        
        return flags_found
    
    def scan_client_app_settings(self):
        """Scan ClientAppSettings.json files for fast flags"""
        logging.info("Scanning ClientAppSettings.json files for fast flags...")
        
        # Find ClientAppSettings.json files
        client_app_settings_files = self.find_client_app_settings()
        
        all_flags = {}
        for file_path in client_app_settings_files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    flags = self.extract_flags_from_content(content, file_path)
                    all_flags[file_path] = flags
                    logging.info(f"Scanned {file_path}, found {len(flags)} flags")
            except Exception as e:
                logging.error(f"Error reading {file_path}: {e}")
        
        return all_flags
    
    def display_results(self):
        """Display the detected flags in a readable format"""
        if not self.detected_flags:
            print("\nNo fast flags found in ClientAppSettings.json files.")
            return
        
        print(f"\nFound {len(self.detected_flags)} fast flags in ClientAppSettings.json files:")
        print("-" * 80)
        
        for flag, locations in self.detected_flags.items():
            print(f"Flag: {flag}")
            print(f"Found in {len(locations)} location(s):")
            for location in locations:
                print(f"  - {location}")
            print("-" * 80)
    
    def modify_client_app_settings(self, file_path, flags_to_add):
        """Add or modify fast flags in a ClientAppSettings.json file"""
        if not os.path.exists(file_path):
            # Create new file with empty JSON if it doesn't exist
            data = {}
        else:
            # Read existing file
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    try:
                        data = json.loads(content)
                    except json.JSONDecodeError:
                        logging.error(f"Error parsing {file_path} as JSON. Creating new JSON.")
                        data = {}
            except Exception as e:
                logging.error(f"Error reading {file_path}: {e}")
                return False
        
        # Add or update flags
        for flag, value in flags_to_add.items():
            data[flag] = value
        
        # Write back to file
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4)
            logging.info(f"Successfully updated {file_path} with {len(flags_to_add)} flags")
            return True
        except Exception as e:
            logging.error(f"Error writing to {file_path}: {e}")
            return False

def main():
    print("Roblox ClientAppSettings Fast Flags Finder")
    print("=" * 50)
    
    finder = ClientAppSettingsFlagsFinder()
    
    # Scan for existing flags
    print("\nScanning for ClientAppSettings.json files and fast flags...")
    finder.scan_client_app_settings()
    finder.display_results()
    
    # Ask if user wants to add flags
    while True:
        choice = input("\nDo you want to add or modify fast flags? (y/n): ").lower()
        if choice == 'n':
            break
        elif choice == 'y':
            # Find available ClientAppSettings.json files
            files = finder.find_client_app_settings()
            
            if not files:
                print("No ClientAppSettings.json files found to modify.")
                print("Creating a new one in the default location...")
                default_path = os.path.join(os.environ['LOCALAPPDATA'], 'Roblox', 'ClientSettings')
                os.makedirs(default_path, exist_ok=True)
                files = [os.path.join(default_path, 'ClientAppSettings.json')]
            
            # Let user choose which file to modify
            print("\nAvailable ClientAppSettings.json files:")
            for i, file_path in enumerate(files):
                print(f"{i+1}. {file_path}")
            
            file_index = int(input("\nEnter the number of the file to modify: ")) - 1
            if file_index < 0 or file_index >= len(files):
                print("Invalid selection.")
                continue
            
            selected_file = files[file_index]
            
            # Get flags to add
            flags_to_add = {}
            print("\nEnter fast flags to add (format: FFlag<Name> <value>)")
            print("Enter a blank line when done.")
            
            while True:
                flag_input = input("> ").strip()
                if not flag_input:
                    break
                
                parts = flag_input.split(' ', 1)
                if len(parts) != 2:
                    print("Invalid format. Use: FFlag<Name> <value>")
                    continue
                
                flag_name, flag_value = parts
                
                # Try to convert value to appropriate type
                if flag_value.lower() == 'true':
                    flag_value = True
                elif flag_value.lower() == 'false':
                    flag_value = False
                elif flag_value.isdigit():
                    flag_value = int(flag_value)
                elif flag_value.replace('.', '', 1).isdigit():
                    flag_value = float(flag_value)
                
                flags_to_add[flag_name] = flag_value
            
            if flags_to_add:
                if finder.modify_client_app_settings(selected_file, flags_to_add):
                    print(f"Successfully updated {selected_file}")
                else:
                    print(f"Failed to update {selected_file}")
            else:
                print("No flags provided.")
        else:
            print("Invalid choice. Please enter 'y' or 'n'.")
    
    print("\nThank you for using Roblox ClientAppSettings Fast Flags Finder!")

if __name__ == "__main__":
    main()