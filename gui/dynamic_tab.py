#!/usr/bin/python3

import os
import sys
import re
import subprocess
import psutil
import shutil
import ctypes
import json
from datetime import datetime
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, 
                           QLabel, QPushButton, QFileDialog, QTextEdit, 
                           QSplitter, QComboBox, QListWidget, QTableWidget,
                           QTableWidgetItem, QHeaderView, QAbstractItemView,
                           QMessageBox, QProgressBar, QLineEdit, QTreeWidget,
                           QTreeWidgetItem, QTabWidget)
from PyQt5.QtCore import Qt, QProcess, pyqtSignal, QThread, QTimer
from PyQt5.QtGui import QFont, QIcon, QColor

# MITRE ATT&CK Technique Mappings
MITRE_TECHNIQUES = {
    "T1055": {
        "name": "Process Injection",
        "description": "Process injection is a method of executing arbitrary code in the address space of a separate live process.",
        "detection": ["Multiple threads in a process", "Unusual memory regions", "Remote thread creation"]
    },
    "T1057": {
        "name": "Process Discovery",
        "description": "Adversaries may attempt to get information about running processes on a system.",
        "detection": ["Process enumeration", "System information queries"]
    },
    "T1082": {
        "name": "System Information Discovery",
        "description": "An adversary may attempt to get detailed information about the operating system and hardware.",
        "detection": ["System information queries", "Hardware enumeration"]
    },
    "T1083": {
        "name": "File and Directory Discovery",
        "description": "Adversaries may enumerate files and directories to understand the system.",
        "detection": ["File system enumeration", "Directory listing"]
    },
    "T1106": {
        "name": "Native API",
        "description": "Adversaries may interact with the native OS API to execute behaviors.",
        "detection": ["Unusual API calls", "Direct system calls"]
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
        "detection": ["Use of cmd.exe/powershell.exe", "Script execution", "Command line parameters"]
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "description": "Adversaries may attempt to dump credentials to obtain account login and credential material.",
        "detection": ["Access to LSASS process", "Memory dumping activities", "Credential extraction tools"]
    },
    "T1056": {
        "name": "Input Capture",
        "description": "Adversaries may use methods to capture user input to obtain credentials or other sensitive data.",
        "detection": ["Keyboard hook detection", "API monitoring", "Suspicious DLL loading"]
    },
    "T1070": {
        "name": "Indicator Removal",
        "description": "Adversaries may delete or modify artifacts generated on a system to remove evidence of their presence.",
        "detection": ["Log deletion", "File timestamp modification", "Clear event logs"]
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "description": "Adversaries may attempt to make an executable or file difficult to discover or analyze.",
        "detection": ["Encoded/encrypted content", "Packed executables", "Suspicious file attributes"]
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "description": "Adversaries may transfer tools or other files from an external system into a compromised environment.",
        "detection": ["Suspicious file downloads", "Network file transfers", "Unusual network connections"]
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "description": "Adversaries may communicate using application layer protocols to avoid detection/network filtering.",
        "detection": ["Unusual port usage", "Protocol anomalies", "Suspicious network patterns"]
    },
    "T1074": {
        "name": "Data Staged",
        "description": "Adversaries may stage collected data in a central location for exfiltration.",
        "detection": ["Unusual file aggregation", "Large file operations", "Suspicious directory creation"]
    },
    "T1562": {
        "name": "Impair Defenses",
        "description": "Adversaries may maliciously modify components of a victim environment to hinder or disable defensive mechanisms.",
        "detection": ["Security software manipulation", "Firewall changes", "Defense evasion attempts"]
    },
    "T1036": {
        "name": "Masquerading",
        "description": "Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign.",
        "detection": ["Suspicious file locations", "Misleading names", "False file extensions"]
    }
}

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

class DynamicWorker(QThread):
    """Worker thread for dynamic analysis tasks"""
    update_output = pyqtSignal(str)
    update_process_list = pyqtSignal(list)
    update_network_connections = pyqtSignal(list)
    analysis_complete = pyqtSignal(bool)
    progress_update = pyqtSignal(int, str)  # Value, status message
    
    def __init__(self, command, mode="command", pid=None, cwd=None):
        super().__init__()
        self.command = command
        self.mode = mode
        self.pid = pid
        self.cwd = cwd
        self.running = True
        
    def run(self):
        if self.mode == "command":
            try:
                self.progress_update.emit(10, "Starting command execution...")
                process = QProcess()
                process.setProcessChannelMode(QProcess.MergedChannels)
                
                if self.cwd:
                    process.setWorkingDirectory(self.cwd)
                    
                process.start(self.command)
                self.progress_update.emit(30, "Command running...")
                
                process.waitForFinished(-1)
                self.progress_update.emit(90, "Processing output...")
                
                output = process.readAllStandardOutput().data().decode('utf-8', errors='replace')
                self.update_output.emit(output)
                self.progress_update.emit(100, "Completed")
                self.analysis_complete.emit(True)
            except Exception as e:
                self.update_output.emit(f"Error: {str(e)}")
                self.progress_update.emit(0, "Failed")
                self.analysis_complete.emit(False)
        
        elif self.mode == "process_monitor":
            try:
                self.progress_update.emit(50, "Monitoring processes...")
                while self.running:
                    # Get all processes with their relationships
                    processes = []
                    process_dict = {}
                    
                    for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline', 'ppid']):
                        try:
                            proc_info = {
                                'pid': proc.info['pid'],
                                'name': proc.info['name'],
                                'username': proc.info['username'],
                                'cmdline': ' '.join(proc.info['cmdline'] or []),
                                'ppid': proc.info['ppid'],
                                'children': []
                            }
                            process_dict[proc.info['pid']] = proc_info
                            processes.append(proc_info)
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                    
                    # Build process tree relationships
                    for proc in processes:
                        ppid = proc['ppid']
                        if ppid in process_dict:
                            process_dict[ppid]['children'].append(proc['pid'])
                    
                    self.update_process_list.emit(processes)
                    self.msleep(1000)  # Update every second
            except Exception as e:
                self.update_output.emit(f"Error in process monitoring: {str(e)}")
                self.progress_update.emit(0, "Monitoring failed")
                self.analysis_complete.emit(False)
        
        elif self.mode == "memory_dump":
            try:
                if not self.pid:
                    self.update_output.emit("Error: No PID specified for memory dump")
                    self.progress_update.emit(0, "Failed: No PID specified")
                    self.analysis_complete.emit(False)
                    return
                
                if not is_admin():
                    self.update_output.emit("Error: Administrator privileges required for memory dumping")
                    self.progress_update.emit(0, "Failed: Admin required")
                    self.analysis_complete.emit(False)
                    return
                
                # Get process by PID
                try:
                    self.progress_update.emit(10, "Initializing memory dump...")
                    
                    # First check if process exists and we have permissions
                    process = psutil.Process(self.pid)
                    process_name = process.name()
                    
                    self.update_output.emit(f"Starting memory dump for process: {process_name} (PID: {self.pid})")
                    self.progress_update.emit(20, "Checking memory regions...")
                    
                    # Import the WindowsProcessReader directly
                    sc0pe_path = os.getcwd()
                    sys.path.append(sc0pe_path)
                    
                    try:
                        from Modules.windows_process_reader import WindowsProcessReader
                        
                        self.progress_update.emit(40, "Starting memory dumper...")
                        self.update_output.emit("Dumping memory regions... This may take some time.")
                        
                        reader = WindowsProcessReader(self.pid)
                        self.progress_update.emit(50, "Dumping memory regions...")
                        
                        # Check available disk space
                        process_memory = sum(region.size for region in reader.get_memory_regions())
                        free_space = shutil.disk_usage('.').free
                        
                        if process_memory > free_space:
                            self.update_output.emit(f"Error: Insufficient disk space. Need {process_memory/1024/1024:.2f}MB but only {free_space/1024/1024:.2f}MB available")
                            self.progress_update.emit(0, "Failed: No space")
                            self.analysis_complete.emit(False)
                            return
                        
                        success = reader.dump_memory()
                        
                        if success:
                            dump_file = f"qu1cksc0pe_memory_dump_{self.pid}.bin"
                            if os.path.exists(dump_file):
                                file_size = os.path.getsize(dump_file) / (1024 * 1024)  # Size in MB
                                self.update_output.emit(f"\nMemory dump completed successfully!\nDump file: {dump_file}\nSize: {file_size:.2f} MB")
                                self.progress_update.emit(100, "Memory dump completed")
                                self.analysis_complete.emit(True)
                            else:
                                self.update_output.emit(f"Warning: Memory dump completed but output file {dump_file} was not found.")
                                self.progress_update.emit(0, "Memory dump failed")
                                self.analysis_complete.emit(False)
                        else:
                            self.update_output.emit("Failed to dump process memory. Check if you have sufficient permissions.")
                            self.progress_update.emit(0, "Memory dump failed")
                            self.analysis_complete.emit(False)
                    except ImportError as ie:
                        self.update_output.emit(f"Error importing memory dumper: {str(ie)}\nMake sure the Modules directory exists and contains the required files.")
                        self.progress_update.emit(0, "Import error")
                        self.analysis_complete.emit(False)
                        
                except psutil.NoSuchProcess:
                    self.update_output.emit(f"Error: Process with PID {self.pid} not found")
                    self.progress_update.emit(0, "Process not found")
                    self.analysis_complete.emit(False)
                except psutil.AccessDenied:
                    self.update_output.emit(f"Error: Access denied for process with PID {self.pid}. Try running the application as administrator.")
                    self.progress_update.emit(0, "Access denied")
                    
            except Exception as e:
                import traceback
                error_details = traceback.format_exc()
                self.update_output.emit(f"Error in memory dump: {str(e)}\nDetails:\n{error_details}")
                self.progress_update.emit(0, "Memory dump failed")
                self.analysis_complete.emit(False)
                
        elif self.mode == "network_monitor":
            try:
                self.progress_update.emit(50, "Monitoring network connections...")
                while self.running:
                    connections = []
                    for proc in psutil.process_iter(['pid', 'name']):
                        try:
                            # Get process connections
                            proc_connections = proc.connections(kind='inet')
                            for conn in proc_connections:
                                connection_info = {
                                    'pid': proc.info['pid'],
                                    'name': proc.info['name'],
                                    'status': conn.status,
                                    'laddr': conn.laddr if conn.laddr else ('', ''),
                                    'raddr': conn.raddr if conn.raddr else ('', ''),
                                    'type': conn.type
                                }
                                connections.append(connection_info)
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                    
                    self.update_network_connections.emit(connections)
                    self.msleep(1000)  # Update every second
            except Exception as e:
                self.update_output.emit(f"Error in network monitoring: {str(e)}")
                self.progress_update.emit(0, "Network monitoring failed")
                self.analysis_complete.emit(False)
            except psutil.AccessDenied:
                self.update_output.emit("Error: Access denied for network connections. Try running as administrator.")
                self.progress_update.emit(0, "Access denied")
                self.analysis_complete.emit(False)
    
    def stop(self):
        self.running = False
        self.wait()

class DynamicTab(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(10, 10, 10, 10)
        
        # Initialize monitoring variables first
        self.process_worker = None
        self.network_worker = None
        
        # Check for admin privileges
        if not is_admin():
            warning = QLabel("Warning: Running without administrator privileges. Some features may be limited.")
            warning.setStyleSheet("color: red; font-weight: bold;")
            self.layout.addWidget(warning)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        self.tab_widget.currentChanged.connect(self.on_tab_changed)
        
        # Setup process monitoring tab
        process_tab = QWidget()
        process_layout = QVBoxLayout(process_tab)
        self.setup_process_monitor(process_layout)
        self.tab_widget.addTab(process_tab, "Process Monitor")
        
        # Setup network monitoring tab
        network_tab = QWidget()
        network_layout = QVBoxLayout(network_tab)
        self.setup_network_monitor(network_layout)
        self.tab_widget.addTab(network_tab, "Network Monitor")
        
        # Setup MITRE ATT&CK tab
        mitre_tab = QWidget()
        mitre_layout = QVBoxLayout(mitre_tab)
        self.setup_mitre_analysis(mitre_layout)
        self.tab_widget.addTab(mitre_tab, "MITRE ATT&CK")
        
        # Add tab widget to layout
        self.layout.addWidget(self.tab_widget)
        
        # Status bar for showing current status
        self.status_bar = QLabel()
        self.status_bar.setStyleSheet("color: white;")
        self.layout.addWidget(self.status_bar)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("Ready")
        self.progress_bar.setValue(0)
        self.layout.addWidget(self.progress_bar)
        
    def on_tab_changed(self, index):
        """Handle tab changes"""
        if index == 0:  # Process Monitor tab
            # Don't start monitoring automatically
            pass
            # Show suspicious processes section
            if hasattr(self, 'suspicious_processes_group'):
                self.suspicious_processes_group.show()
        elif index == 1:  # Network Monitor tab
            if self.process_worker and self.process_worker.isRunning():
                self.stop_process_monitoring()
            # Hide suspicious processes section
            if hasattr(self, 'suspicious_processes_group'):
                self.suspicious_processes_group.hide()
        
        # Update UI based on current tab
        self.update_tab_ui(index)

    def update_tab_ui(self, index):
        """Update UI elements based on current tab"""
        # Hide all monitoring-specific elements first
        if hasattr(self, 'suspicious_processes_group'):
            self.suspicious_processes_group.hide()
        if hasattr(self, 'network_stats_group'):
            self.network_stats_group.hide()
        if hasattr(self, 'suspicious_connections_group'):
            self.suspicious_connections_group.hide()
        
        # Show elements specific to current tab
        if index == 0:  # Process Monitor
            if hasattr(self, 'suspicious_processes_group'):
                self.suspicious_processes_group.show()
        elif index == 1:  # Network Monitor
            if hasattr(self, 'network_stats_group'):
                self.network_stats_group.show()
            if hasattr(self, 'suspicious_connections_group'):
                self.suspicious_connections_group.show()

    def setup_process_monitor(self, layout):
        """Setup process monitoring section"""
        # System stats
        stats_layout = QHBoxLayout()
        
        # CPU Usage
        self.cpu_label = QLabel("CPU: 0%")
        self.cpu_label.setStyleSheet("color: white; font-weight: bold;")
        stats_layout.addWidget(self.cpu_label)
        
        # Memory Usage
        self.memory_label = QLabel("Memory: 0%")
        self.memory_label.setStyleSheet("color: white; font-weight: bold;")
        stats_layout.addWidget(self.memory_label)
        
        # Process Count
        self.process_count_label = QLabel("Processes: 0")
        self.process_count_label.setStyleSheet("color: white; font-weight: bold;")
        stats_layout.addWidget(self.process_count_label)
        
        # Add stretch to keep stats left-aligned
        stats_layout.addStretch()
        
        layout.addLayout(stats_layout)
        
        # Controls
        controls_layout = QHBoxLayout()
        
        self.process_filter = QLineEdit()
        self.process_filter.setPlaceholderText("Filter processes...")
        self.process_filter.textChanged.connect(self.filter_processes)
        controls_layout.addWidget(self.process_filter)
        
        self.monitor_button = QPushButton("Start Monitoring")
        self.monitor_button.clicked.connect(self.toggle_monitoring)
        controls_layout.addWidget(self.monitor_button)
        
        layout.addLayout(controls_layout)
        
        # Process tree view
        self.process_tree = QTreeWidget()
        self.process_tree.setHeaderLabels(["PID", "Name", "CPU %", "Memory %", "Username", "Command Line"])
        self.process_tree.setAlternatingRowColors(True)
        self.process_tree.itemSelectionChanged.connect(self.process_selected)
        
        # Set column widths
        self.process_tree.setColumnWidth(0, 80)   # PID
        self.process_tree.setColumnWidth(1, 150)  # Name
        self.process_tree.setColumnWidth(2, 80)   # CPU %
        self.process_tree.setColumnWidth(3, 100)  # Memory %
        self.process_tree.setColumnWidth(4, 120)  # Username
        self.process_tree.header().setStretchLastSection(True)  # Command line stretches
        
        layout.addWidget(self.process_tree)
        
        # Suspicious process indicators group
        self.suspicious_processes_group = QGroupBox("Suspicious Processes")
        suspicious_processes_layout = QVBoxLayout()
        self.suspicious_indicators = QLabel()
        self.suspicious_indicators.setWordWrap(True)
        self.suspicious_indicators.setStyleSheet("color: red;")
        suspicious_processes_layout.addWidget(self.suspicious_indicators)
        self.suspicious_processes_group.setLayout(suspicious_processes_layout)
        layout.addWidget(self.suspicious_processes_group)
        
        # Update timer for system stats
        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self.update_system_stats)
        self.stats_timer.start(1000)  # Update every second

    def start_process_monitoring(self):
        """Start the process monitoring"""
        if not self.process_worker or not self.process_worker.isRunning():
            self.process_worker = DynamicWorker("", mode="process_monitor")
            self.process_worker.update_process_list.connect(self.update_process_tree)
            self.process_worker.progress_update.connect(self.update_progress)
            self.process_worker.start()
            self.monitor_button.setText("Stop Monitoring")

    def stop_process_monitoring(self):
        """Stop the process monitoring"""
        if self.process_worker and self.process_worker.isRunning():
            self.process_worker.stop()
            self.process_worker = None
            self.monitor_button.setText("Start Monitoring")

    def update_system_stats(self):
        """Update system resource statistics"""
        try:
            # CPU Usage
            cpu_percent = psutil.cpu_percent()
            self.cpu_label.setText(f"CPU: {cpu_percent:.1f}%")
            if cpu_percent > 90:
                self.cpu_label.setStyleSheet("color: red; font-weight: bold;")
            elif cpu_percent > 70:
                self.cpu_label.setStyleSheet("color: orange; font-weight: bold;")
            else:
                self.cpu_label.setStyleSheet("color: white; font-weight: bold;")
            
            # Memory Usage
            memory = psutil.virtual_memory()
            self.memory_label.setText(f"Memory: {memory.percent}% ({memory.used/1024/1024/1024:.1f}GB/{memory.total/1024/1024/1024:.1f}GB)")
            if memory.percent > 90:
                self.memory_label.setStyleSheet("color: red; font-weight: bold;")
            elif memory.percent > 70:
                self.memory_label.setStyleSheet("color: orange; font-weight: bold;")
            else:
                self.memory_label.setStyleSheet("color: white; font-weight: bold;")
            
            # Process Count
            process_count = len(list(psutil.process_iter()))
            self.process_count_label.setText(f"Processes: {process_count}")
            
        except Exception as e:
            print(f"Error updating system stats: {e}")
        
    def update_process_tree(self, processes):
        """Update the process tree with the provided list of processes"""
        # Store expanded items before clearing
        expanded_items = self.get_expanded_items()
        self.process_tree.clear()
        
        # Create dictionary of processes by PID
        process_dict = {}
        root_processes = []
        
        # Windows core system processes and their expected hierarchy
        system_hierarchy = {
            'system': [],  # System is always root
            'smss.exe': ['system'],  # Session Manager Subsystem
            'csrss.exe': ['smss.exe'],  # Client Server Runtime Process
            'wininit.exe': ['smss.exe'],  # Windows Start-Up Process
            'winlogon.exe': ['smss.exe'],  # Windows Logon Process
            'services.exe': ['wininit.exe'],  # Service Control Manager
            'lsass.exe': ['wininit.exe'],  # Local Security Authority Process
            'svchost.exe': ['services.exe'],  # Service Host
        }
        
        # Processes that should be treated as root level
        root_level_processes = {
            'explorer.exe',  # Windows Explorer (shell)
            'taskmgr.exe',   # Task Manager
            'brave.exe',     # Browsers
            'chrome.exe',
            'firefox.exe',
            'msedge.exe',
            'code.exe',      # Development tools
            'spotify.exe',   # Media
            'discord.exe',   # Communication
            'steam.exe',     # Gaming
            'signal.exe',
            'cursor.exe',
            'vgtray.exe',
            'idman.exe',
            'securityhealthsystray.exe'
        }
        
        # Suspicious process patterns
        suspicious_processes = {
            'cmd.exe',
            'powershell.exe', 
            'rundll32.exe',
            'regsvr32.exe',
            'mshta.exe',
            'wscript.exe',
            'cscript.exe',
            'certutil.exe',
            'bitsadmin.exe',
            'msiexec.exe',
            'psexec.exe',
            'at.exe',
            'schtasks.exe',
            'net.exe',
            'netsh.exe',
            'whoami.exe',
            'nslookup.exe',
            'qwinsta.exe',
            'systeminfo.exe',
            'tasklist.exe',
            'reg.exe',
            'sc.exe',
            'winrm.exe',
            'wmic.exe',
            'vssadmin.exe',
            'bcdedit.exe',
            'nltest.exe',
            'xcopy.exe',
            'robocopy.exe',
            'cipher.exe'
        }
        
        # First pass: Create all items
        for proc in processes:
            try:
                p = psutil.Process(proc['pid'])
                
                # Get process information
                try:
                    cpu_percent = p.cpu_percent()
                    memory_percent = p.memory_percent()
                    exe_path = p.exe()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    cpu_percent = 0.0
                    memory_percent = 0.0
                    exe_path = proc['cmdline']
                
                # Create tree item
                item = QTreeWidgetItem([
                    str(proc['pid']),
                    proc['name'].lower(),
                    f"{cpu_percent:.1f}",
                    f"{memory_percent:.1f}",
                    proc['username'],
                    exe_path
                ])
                
                # Determine if process is suspicious
                is_suspicious = False
                proc_name = proc['name'].lower()
                
                if proc_name in suspicious_processes:
                    is_suspicious = True
                    item.setForeground(0, QColor(255, 0, 0))
                    item.setForeground(1, QColor(255, 0, 0))
                
                # Store process information
                process_dict[proc['pid']] = {
                    'item': item,
                    'proc': proc,
                    'suspicious': is_suspicious,
                    'added': False,
                    'name': proc_name
                }
                
                # Determine root processes based on Windows process hierarchy
                if (proc_name == 'system' or  # System is always root
                    proc['ppid'] == 0 or      # No parent
                    proc_name in root_level_processes or  # Known root processes
                    (proc_name in system_hierarchy and 
                     not any(p['name'].lower() in system_hierarchy[proc_name] 
                            for p in processes if p['pid'] == proc['ppid']))):
                    root_processes.append(proc['pid'])
                
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                print(f"Error accessing process {proc['pid']}: {str(e)}")
                continue
            except Exception as e:
                print(f"Unexpected error processing process {proc['pid']}: {str(e)}")
                continue
        
        # Second pass: Build the tree following Windows hierarchy
        def add_process_to_tree(pid, parent_item=None):
            if pid not in process_dict or process_dict[pid]['added']:
                return
            
            proc_info = process_dict[pid]
            proc_info['added'] = True
            
            if parent_item:
                parent_item.addChild(proc_info['item'])
            else:
                self.process_tree.addTopLevelItem(proc_info['item'])
            
            # Add child processes
            children = [p['pid'] for p in processes 
                       if p['ppid'] == pid and p['pid'] in process_dict]
            
            for child_pid in children:
                add_process_to_tree(child_pid, proc_info['item'])
        
        # Add root processes first
        for pid in root_processes:
            add_process_to_tree(pid)
        
        # Handle any remaining processes
        for pid in process_dict:
            if not process_dict[pid]['added']:
                proc = process_dict[pid]['proc']
                
                # Try to find the correct parent
                if proc['ppid'] in process_dict:
                    parent_name = process_dict[proc['ppid']]['name']
                    proc_name = process_dict[pid]['name']
                    
                    # Check if this follows system hierarchy
                    if (proc_name in system_hierarchy and 
                        parent_name in system_hierarchy[proc_name]):
                        add_process_to_tree(pid, process_dict[proc['ppid']]['item'])
                    else:
                        # If not in system hierarchy, add as root
                        add_process_to_tree(pid)
                else:
                    # No parent found, add as root
                    add_process_to_tree(pid)
        
        # Update suspicious process indicators with Kill buttons
        suspicious_procs = [p for p in process_dict.values() if p['suspicious']]
        if suspicious_procs:
            # Create widget for suspicious processes
            suspicious_widget = QWidget()
            suspicious_layout = QVBoxLayout(suspicious_widget)
            
            # Add header
            header = QLabel("Suspicious processes detected:")
            header.setStyleSheet("color: red; font-weight: bold;")
            suspicious_layout.addWidget(header)
            
            # Add each suspicious process with a Kill button
            for proc in suspicious_procs:
                proc_widget = QWidget()
                proc_layout = QHBoxLayout(proc_widget)
                
                # Process info label
                proc_label = QLabel(f"- {proc['proc']['name']} (PID: {proc['proc']['pid']}) - Check for malicious activity")
                proc_label.setStyleSheet("color: red;")
                proc_layout.addWidget(proc_label)
                
                # Kill button
                kill_button = QPushButton("Kill")
                kill_button.setFixedWidth(60)
                kill_button.setStyleSheet("""
                    QPushButton {
                        background-color: #d93025;
                        color: white;
                        border: none;
                        padding: 5px;
                        border-radius: 3px;
                    }
                    QPushButton:hover {
                        background-color: #a50e0e;
                    }
                    QPushButton:pressed {
                        background-color: #870000;
                    }
                """)
                kill_button.clicked.connect(lambda checked, pid=proc['proc']['pid']: self.kill_process(pid))
                proc_layout.addWidget(kill_button)
                
                # Add to suspicious layout
                suspicious_layout.addWidget(proc_widget)
            
            # Add stretch to push everything to the top
            suspicious_layout.addStretch()
            
            # Set the widget as the suspicious indicator
            if hasattr(self, 'suspicious_indicators'):
                # Remove old widget if it exists
                self.layout.removeWidget(self.suspicious_indicators)
                self.suspicious_indicators.deleteLater()
            
            self.suspicious_indicators = suspicious_widget
            self.layout.addWidget(suspicious_widget)
        else:
            # No suspicious processes
            if hasattr(self, 'suspicious_indicators'):
                self.layout.removeWidget(self.suspicious_indicators)
                self.suspicious_indicators.deleteLater()
            self.suspicious_indicators = QLabel("")
            self.layout.addWidget(self.suspicious_indicators)
        
        # After building the tree, restore expanded state
        self.restore_expanded_items(expanded_items)
        
        # Restore selection if possible
        if hasattr(self, 'last_selected_pid'):
            self._restore_selection(self.last_selected_pid)
    
    def get_expanded_items(self):
        """Store the expanded state of items"""
        expanded = []
        
        def traverse_items(item):
            if item is None:
                # Handle root level
                root = self.process_tree.invisibleRootItem()
                for i in range(root.childCount()):
                    traverse_items(root.child(i))
            else:
                if item.isExpanded():
                    # Store the path to this item using PID and name
                    path = []
                    current = item
                    while current is not None:
                        pid = current.text(0)  # PID is in first column
                        name = current.text(1)  # Name is in second column
                        path.insert(0, (pid, name))
                        current = current.parent()
                    expanded.append(path)
                
                # Traverse children
                for i in range(item.childCount()):
                    traverse_items(item.child(i))
        
        traverse_items(None)
        return expanded

    def restore_expanded_items(self, expanded_items):
        """Restore the expanded state of items"""
        def find_item_by_path(path):
            """Find an item using its stored path"""
            current_item = None
            
            # For each level in the path
            for pid, name in path:
                if current_item is None:
                    # Search in root items
                    for i in range(self.process_tree.topLevelItemCount()):
                        item = self.process_tree.topLevelItem(i)
                        if item.text(0) == pid and item.text(1) == name:
                            current_item = item
                            break
                else:
                    # Search in children
                    found = False
                    for i in range(current_item.childCount()):
                        item = current_item.child(i)
                        if item.text(0) == pid and item.text(1) == name:
                            current_item = item
                            found = True
                            break
                    if not found:
                        return None
            
            return current_item
        
        # Restore expansion state
        for path in expanded_items:
            item = find_item_by_path(path)
            if item:
                item.setExpanded(True)
    
    def _restore_selection(self, pid):
        """Restore selection to the specified PID"""
        def find_item(pid, parent=None):
            items = self.process_tree.findItems(str(pid), Qt.MatchExactly | Qt.MatchRecursive, 0)
            for item in items:
                if parent is None or item.parent() == parent:
                    return item
            return None
        
        item = find_item(pid)
        if item:
            self.process_tree.setCurrentItem(item)
            item.setSelected(True)
            # Ensure the selected item is visible by expanding its parents
            parent = item.parent()
            while parent:
                parent.setExpanded(True)
                parent = parent.parent()

    def toggle_monitoring(self):
        """Toggle process monitoring"""
        if not hasattr(self, 'process_worker') or not self.process_worker or not self.process_worker.isRunning():
            # Start monitoring
            self.process_worker = DynamicWorker("", mode="process_monitor")
            self.process_worker.update_process_list.connect(self.update_process_tree)
            self.process_worker.progress_update.connect(self.update_progress)
            self.process_worker.start()
            
            self.monitor_button.setText("Stop Monitoring")
        else:
            # Stop monitoring
            self.process_worker.stop()
            self.process_worker = None
            
            self.monitor_button.setText("Start Monitoring")
    
    def process_selected(self):
        """Handle process selection from the tree"""
        selected_items = self.process_tree.selectedItems()
        if selected_items:
            selected_item = selected_items[0]
            pid = int(selected_item.text(0))  # PID is in first column
            process_name = selected_item.text(1)  # Name is in second column
            
            # Store the selected PID for later use
            self.last_selected_pid = pid
            
            # Update status
            self.progress_bar.setValue(0)
            self.progress_bar.setFormat(f"Selected: {process_name} (PID: {pid})")
            self.status_bar.setText(f"Selected process: {process_name} (PID: {pid})")
            
            # Enable MITRE analysis button
            self.analyze_button.setEnabled(True)
        else:
            # Disable buttons
            self.analyze_button.setEnabled(False)

    def toggle_network_monitoring(self):
        """Toggle network connection monitoring"""
        if not hasattr(self, 'network_worker') or not self.network_worker or not self.network_worker.isRunning():
            # Start monitoring
            self.network_worker = DynamicWorker("", mode="network_monitor")
            self.network_worker.update_network_connections.connect(self.update_network_table)
            self.network_worker.progress_update.connect(self.update_progress)
            self.network_worker.start()
            
            self.network_monitor_button.setText("Stop Network Monitoring")
        else:
            # Stop monitoring
            self.network_worker.stop()
            self.network_worker = None
            
            self.network_monitor_button.setText("Start Network Monitoring")
        
    def update_network_table(self, connections):
        """Update the network connections table"""
        # Store current scroll position
        scrollbar = self.network_table.verticalScrollBar()
        current_scroll = scrollbar.value()
        
        # Store current selection
        current_row = self.network_table.currentRow()
        
        self.network_table.setRowCount(0)
        
        total_connections = 0
        listening = 0
        established = 0
        
        for conn in connections:
            try:
                # Get process info
                try:
                    process = psutil.Process(conn['pid'])
                    process_name = process.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied, KeyError):
                    process_name = "Unknown"
                
                # Get connection info
                local_addr = conn.get('laddr', ('', 0))
                remote_addr = conn.get('raddr', ('', 0))
                status = conn.get('status', '')
                pid = conn.get('pid', 0)
                
                # Update statistics
                total_connections += 1
                if status.lower() == 'listen':
                    listening += 1
                elif status.lower() == 'established':
                    established += 1
                
                # Add row to table
                row_position = self.network_table.rowCount()
                self.network_table.insertRow(row_position)
                
                # Create table items
                items = [
                    QTableWidgetItem(str(pid)),
                    QTableWidgetItem(process_name),
                    QTableWidgetItem(str(local_addr[0]) if local_addr else ''),
                    QTableWidgetItem(str(local_addr[1]) if local_addr else ''),
                    QTableWidgetItem(str(remote_addr[0]) if remote_addr else ''),
                    QTableWidgetItem(str(remote_addr[1]) if remote_addr else ''),
                    QTableWidgetItem(status)
                ]
                
                # Add items to table
                for col, item in enumerate(items):
                    self.network_table.setItem(row_position, col, item)
                
                # Add Terminate button
                if status.lower() not in ['listen', 'close_wait', 'closed']:
                    terminate_button = QPushButton("Terminate")
                    terminate_button.setStyleSheet("""
                        QPushButton {
                            background-color: #d93025;
                            color: white;
                            border: none;
                            padding: 5px;
                            border-radius: 3px;
                        }
                        QPushButton:hover {
                            background-color: #a50e0e;
                        }
                    """)
                    terminate_button.clicked.connect(lambda checked, pid=pid: self.kill_process(pid))
                    self.network_table.setCellWidget(row_position, 7, terminate_button)
                
            except Exception as e:
                print(f"Error processing connection: {str(e)}")
                continue
        
        # Update statistics
        self.total_connections_label.setText(f"Total Connections: {total_connections}")
        self.listening_ports_label.setText(f"Listening Ports: {listening}")
        self.established_connections_label.setText(f"Established: {established}")
        
        # Auto-resize columns to content
        self.network_table.resizeColumnsToContents()
        # Ensure minimum column widths
        for col, min_width in enumerate([70, 150, 120, 80, 120, 80, 100, 100]):
            if self.network_table.columnWidth(col) < min_width:
                self.network_table.setColumnWidth(col, min_width)
        
        # Restore scroll position
        scrollbar.setValue(current_scroll)
        
        # Restore selection if possible
        if current_row >= 0 and current_row < self.network_table.rowCount():
            self.network_table.setCurrentCell(current_row, 0)
            self.network_table.selectRow(current_row)

    def filter_connections(self):
        """Filter network connections based on search text"""
        search_text = self.network_filter.text().lower()
        
        for row in range(self.network_table.rowCount()):
            show_row = False
            for col in range(self.network_table.columnCount() - 1):  # Exclude Actions column
                item = self.network_table.item(row, col)
                if item and search_text in item.text().lower():
                    show_row = True
                    break
            self.network_table.setRowHidden(row, not show_row)

    def update_progress(self, value, message):
        """Update the progress bar"""
        self.progress_bar.setValue(value)
        self.progress_bar.setFormat(message)

    def filter_processes(self, text):
        """Filter the process tree based on search text"""
        # Show all items first
        def show_all_items(item):
            for i in range(item.childCount()):
                child = item.child(i)
                child.setHidden(False)
                show_all_items(child)
        
        root = self.process_tree.invisibleRootItem()
        for i in range(root.childCount()):
            item = root.child(i)
            item.setHidden(False)
            show_all_items(item)
        
        if not text:
            return
            
        # Hide items that don't match
        def filter_items(item):
            match = False
            # Check if current item matches
            for col in range(item.columnCount()):
                if text.lower() in item.text(col).lower():
                    match = True
            
            # Check children
            for i in range(item.childCount()):
                child = item.child(i)
                if filter_items(child):  # If any child matches
                    match = True
            
            # Hide if no match found
            item.setHidden(not match)
            return match
        
        # Apply filter to all top-level items
        for i in range(root.childCount()):
            item = root.child(i)
            filter_items(item)
    
    def cancel_operation(self):
        """Cancel the current memory operation"""
        if self.dump_worker and self.dump_worker.isRunning():
            self.dump_worker.stop()
        if self.strings_worker and self.strings_worker.isRunning():
            self.strings_worker.stop()
        if self.carve_worker and self.carve_worker.isRunning():
            self.carve_worker.stop()
        
        self.cancel_button.setEnabled(False)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("Cancelled")
        self.enable_memory_buttons()
    
    def dump_process_memory(self):
        """Dump the memory of the selected process"""
        pid = self.get_selected_pid()
        if not pid:
            QMessageBox.warning(self, "Warning", "Please select a process first.")
            return
        
        if not is_admin():
            reply = QMessageBox.warning(
                self, 
                "Administrator Required",
                "Memory dumping requires administrator privileges. Would you like to restart the application as administrator?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                if sys.platform == "win32":
                    script = os.path.abspath(sys.argv[0])
                    params = ' '.join([script] + sys.argv[1:])
                    shell32 = ctypes.windll.shell32
                    shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
                    sys.exit(0)
            return
        
        # Check if process is still running
        try:
            process = psutil.Process(pid)
            if not process.is_running():
                QMessageBox.warning(self, "Error", f"Process with PID {pid} is no longer running.")
                return
        except psutil.NoSuchProcess:
            QMessageBox.warning(self, "Error", f"Process with PID {pid} not found.")
            return
        except psutil.AccessDenied:
            QMessageBox.warning(self, "Error", f"Access denied for process with PID {pid}.")
            return
        
        # Check available disk space
        try:
            process = psutil.Process(pid)
            memory_info = process.memory_info()
            required_space = memory_info.rss * 2  # Estimate twice the RSS for safety
            free_space = shutil.disk_usage('.').free
            
            if required_space > free_space:
                QMessageBox.warning(
                    self,
                    "Warning",
                    f"Insufficient disk space. Need approximately {required_space/1024/1024:.1f}MB but only {free_space/1024/1024:.1f}MB available."
                )
                return
        except Exception as e:
            QMessageBox.warning(self, "Warning", f"Could not check disk space: {str(e)}")
            return
            
        # Confirm with user
        reply = QMessageBox.question(
            self, 
            "Dump Memory", 
            f"Are you sure you want to dump the memory of process with PID {pid}?\n"
            f"This may take some time and require approximately {required_space/1024/1024:.1f}MB of disk space.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
            
        if reply != QMessageBox.Yes:
            return
            
        # Show progress indicator in output
        self.memory_output.clear()
        self.memory_output.append(f"Starting memory dump for PID {pid}...\n"
                                f"Process: {process.name()}\n"
                                f"Estimated size: {required_space/1024/1024:.1f}MB\n\n"
                                "Please wait...")
        
        # Reset progress bar
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("Preparing...")
        
        # Create memory dump worker
        self.dump_worker = DynamicWorker("", mode="memory_dump", pid=pid)
        self.dump_worker.update_output.connect(self.update_memory_output)
        self.dump_worker.analysis_complete.connect(self.memory_dump_completed)
        self.dump_worker.progress_update.connect(self.update_progress)
        
        # Disable buttons during dump
        self.disable_memory_buttons()
        self.cancel_button.setEnabled(True)
        
        # Start worker
        self.dump_worker.start()
        
    def disable_memory_buttons(self):
        """Disable all memory analysis buttons"""
        self.dump_memory_button.setEnabled(False)
        self.analyze_strings_button.setEnabled(False)
        self.carve_files_button.setEnabled(False)
    
    def enable_memory_buttons(self):
        """Enable memory analysis buttons based on current state"""
        pid = self.get_selected_pid()
        if pid:
            self.dump_memory_button.setEnabled(True)
            dump_file = f"qu1cksc0pe_memory_dump_{pid}.bin"
            if os.path.exists(dump_file):
                self.analyze_strings_button.setEnabled(True)
                self.carve_files_button.setEnabled(True)
            
    def memory_dump_completed(self, success):
        """Handle completion of memory dump operation"""
        self.cancel_button.setEnabled(False)
        
        if success:
            pid = self.get_selected_pid()
            dump_file = f"qu1cksc0pe_memory_dump_{pid}.bin"
            
            if os.path.exists(dump_file):
                file_size = os.path.getsize(dump_file) / (1024 * 1024)  # Size in MB
                self.memory_output.append(f"\nMemory dump completed successfully!\n"
                                       f"Dump file: {dump_file}\n"
                                       f"Size: {file_size:.2f} MB\n\n"
                                       "You can now use 'Extract Strings' or 'Carve Embedded Files' for further analysis.")
                
                self.analyze_strings_button.setEnabled(True)
                self.carve_files_button.setEnabled(True)
            else:
                self.memory_output.append("\nWarning: Memory dump completed but output file not found.")
        
        self.dump_memory_button.setEnabled(True)
        
    def extract_strings(self):
        """Extract strings from memory dump"""
        pid = self.get_selected_pid()
        if not pid:
            QMessageBox.warning(self, "Warning", "Please select a process first.")
            return
            
        dump_file = f"qu1cksc0pe_memory_dump_{pid}.bin"
        
        if not os.path.exists(dump_file):
            QMessageBox.warning(self, "Warning", 
                f"Memory dump file {dump_file} not found.\nPlease dump the process memory first.")
            return
            
        # Check file size - warn if very large
        file_size = os.path.getsize(dump_file) / (1024 * 1024)  # Size in MB
        if file_size > 100:  # Warn if more than 100MB
            reply = QMessageBox.question(
                self, "Large File Warning", 
                f"The memory dump is {file_size:.2f} MB, which may take significant time to process.\nContinue?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
                
            if reply != QMessageBox.Yes:
                return
        
        # Show progress indication
        self.memory_output.setText(f"Extracting strings from memory dump {dump_file}...\n"
                                 f"File size: {file_size:.2f} MB\n"
                                 f"This may take some time for large dumps.\n\nPlease wait...")
        self.progress_bar.setValue(10)
        self.progress_bar.setFormat("Starting extraction...")
        
        # Generate timestamp for output file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"strings_{pid}_{timestamp}.txt"
        
        # Determine command based on platform
        if sys.platform == "win32":
            command = f"powershell.exe \"& {{strings -a \"{dump_file}\" > {output_file}; " + \
                     f"Write-Host 'Extraction complete. Saved to {output_file}'; " + \
                     f"Get-Content {output_file} | Select-Object -First 1000}}\""
        else:
            # On Linux we'll use normal strings but limit output for display
            command = f"bash -c \"strings --all '{dump_file}' > {output_file} && " + \
                     f"echo 'Extraction complete. Saved to {output_file}' && " + \
                     f"head -n 1000 {output_file}\""
            
        # Create worker
        self.strings_worker = DynamicWorker(command)
        self.strings_worker.update_output.connect(self.update_memory_output)
        self.strings_worker.analysis_complete.connect(self.strings_extraction_completed)
        self.strings_worker.progress_update.connect(self.update_progress)
        
        # Disable buttons during extraction
        self.analyze_strings_button.setEnabled(False)
        
        # Start worker
        self.strings_worker.start()
        
    def strings_extraction_completed(self, success):
        """Handle completion of string extraction"""
        self.analyze_strings_button.setEnabled(True)
        
        if success:
            pid = self.get_selected_pid()
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"strings_{pid}_{timestamp}.txt"
            
            # Find the most recent strings file matching the pattern
            matching_files = [f for f in os.listdir('.') if f.startswith(f"strings_{pid}_") and f.endswith(".txt")]
            if matching_files:
                matching_files.sort(reverse=True)  # Sort by name/timestamp descending
                output_file = matching_files[0]
            
            if os.path.exists(output_file):
                file_size = os.path.getsize(output_file) / 1024  # Size in KB
                self.memory_output.append(f"\nStrings extraction completed successfully!"
                                        f"\nOutput saved to: {output_file}"
                                        f"\nFile size: {file_size:.2f} KB"
                                        f"\n\nNote: Only the first 1000 lines are displayed above.")
                self.progress_bar.setValue(100)
                self.progress_bar.setFormat(f"Extracted {int(file_size)} KB of strings")
            else:
                self.memory_output.append("\nStrings extraction completed. Results displayed above.")
                self.progress_bar.setValue(100)
                self.progress_bar.setFormat("Extraction completed")
        else:
            self.memory_output.append("\nFailed to extract strings from memory dump.")
            self.progress_bar.setValue(0)
            self.progress_bar.setFormat("Extraction failed")
            
    def carve_files(self):
        """Carve embedded files from memory dump"""
        pid = self.get_selected_pid()
        if not pid:
            QMessageBox.warning(self, "Warning", "Please select a process first.")
            return
            
        dump_file = f"qu1cksc0pe_memory_dump_{pid}.bin"
        
        if not os.path.exists(dump_file):
            QMessageBox.warning(self, "Warning", 
                f"Memory dump file {dump_file} not found.\nPlease dump the process memory first.")
            return
        
        # Create output directory
        output_dir = f"carved_files_{pid}"
        os.makedirs(output_dir, exist_ok=True)
        
        # Show progress indication
        self.memory_output.setText(f"Carving files from memory dump {dump_file}...\nThis may take some time.\n\nPlease wait...")
        
        # Use foremost or similar tool for file carving if available
        if sys.platform == "win32":
            # Limited options on Windows - use a simple python-based carver or notify user
            self.memory_output.append("File carving support is limited on Windows. Please use a dedicated tool like 'foremost' or 'bulk_extractor'.")
            self.memory_output.append(f"You can manually analyze the memory dump file: {dump_file}")
            self.carve_files_button.setEnabled(True)
            return
        else:
            # Check if foremost is available
            if shutil.which("foremost"):
                command = f"foremost -i \"{dump_file}\" -o {output_dir}"
            elif shutil.which("bulk_extractor"):
                command = f"bulk_extractor -o {output_dir} \"{dump_file}\""
            else:
                self.memory_output.append("File carving tools (foremost or bulk_extractor) not found. Please install them or use a dedicated tool.")
                self.memory_output.append(f"You can manually analyze the memory dump file: {dump_file}")
                self.carve_files_button.setEnabled(True)
                return
        
        # Create worker
        self.carve_worker = DynamicWorker(command)
        self.carve_worker.update_output.connect(self.update_memory_output)
        self.carve_worker.analysis_complete.connect(self.carving_completed)
        
        # Disable buttons during carving
        self.carve_files_button.setEnabled(False)
        
        # Start worker
        self.carve_worker.start()
        
    def carving_completed(self, success):
        """Handle completion of file carving"""
        self.carve_files_button.setEnabled(True)
        
        if success:
            pid = self.get_selected_pid()
            output_dir = f"carved_files_{pid}"
            
            if os.path.exists(output_dir):
                file_count = sum(1 for _ in os.listdir(output_dir) if os.path.isfile(os.path.join(output_dir, _)))
                self.memory_output.append(f"\nFile carving completed successfully!\nExtracted {file_count} files to: {output_dir}")
            else:
                self.memory_output.append("\nFile carving completed but no files were found.")
        else:
            self.memory_output.append("\nFailed to carve files from memory dump.")
    
    def setup_network_monitor(self, layout):
        """Setup network monitoring section"""
        # Network Statistics Group
        self.network_stats_group = QGroupBox("Network Statistics")
        stats_layout = QVBoxLayout()
        
        # Network stats display
        stats_grid = QHBoxLayout()
        
        # Connections count
        self.total_connections_label = QLabel("Total Connections: 0")
        self.total_connections_label.setStyleSheet("color: white; font-weight: bold;")
        stats_grid.addWidget(self.total_connections_label)
        
        # Listening ports
        self.listening_ports_label = QLabel("Listening Ports: 0")
        self.listening_ports_label.setStyleSheet("color: white; font-weight: bold;")
        stats_grid.addWidget(self.listening_ports_label)
        
        # Established connections
        self.established_connections_label = QLabel("Established: 0")
        self.established_connections_label.setStyleSheet("color: white; font-weight: bold;")
        stats_grid.addWidget(self.established_connections_label)
        
        stats_layout.addLayout(stats_grid)
        self.network_stats_group.setLayout(stats_layout)
        layout.addWidget(self.network_stats_group)
        
        # Controls
        controls_layout = QHBoxLayout()
        
        self.network_filter = QLineEdit()
        self.network_filter.setPlaceholderText("Filter connections...")
        self.network_filter.textChanged.connect(self.filter_connections)
        controls_layout.addWidget(self.network_filter)
        
        self.network_monitor_button = QPushButton("Start Network Monitoring")
        self.network_monitor_button.clicked.connect(self.toggle_network_monitoring)
        controls_layout.addWidget(self.network_monitor_button)
        
        layout.addLayout(controls_layout)
        
        # Network connections table
        self.network_table = QTableWidget()
        self.network_table.setColumnCount(8)
        self.network_table.setHorizontalHeaderLabels([
            "PID", "Process", "Local Address", "Local Port", 
            "Remote Address", "Remote Port", "Status", "Actions"
        ])
        
        # Set column widths
        self.network_table.setColumnWidth(0, 70)   # PID
        self.network_table.setColumnWidth(1, 150)  # Process
        self.network_table.setColumnWidth(2, 120)  # Local Address
        self.network_table.setColumnWidth(3, 80)   # Local Port
        self.network_table.setColumnWidth(4, 120)  # Remote Address
        self.network_table.setColumnWidth(5, 80)   # Remote Port
        self.network_table.setColumnWidth(6, 100)  # Status
        self.network_table.setColumnWidth(7, 100)  # Actions
        
        # Set table properties
        self.network_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.network_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.network_table.setAlternatingRowColors(True)
        self.network_table.verticalHeader().setVisible(False)  # Hide row numbers
        
        layout.addWidget(self.network_table)
        
        # Suspicious connections group
        self.suspicious_connections_group = QGroupBox("Suspicious Network Activity")
        suspicious_layout = QVBoxLayout()
        self.suspicious_connections_text = QTextEdit()
        self.suspicious_connections_text.setReadOnly(True)
        self.suspicious_connections_text.setMaximumHeight(100)
        suspicious_layout.addWidget(self.suspicious_connections_text)
        self.suspicious_connections_group.setLayout(suspicious_layout)
        layout.addWidget(self.suspicious_connections_group)

    def setup_memory_analysis(self, layout):
        """Setup memory analysis section"""
        # Memory action buttons
        action_layout = QHBoxLayout()
        
        self.dump_memory_button = QPushButton("Dump Process Memory")
        self.dump_memory_button.clicked.connect(self.dump_process_memory)
        self.dump_memory_button.setEnabled(False)
        action_layout.addWidget(self.dump_memory_button)
        
        self.analyze_strings_button = QPushButton("Extract Strings")
        self.analyze_strings_button.clicked.connect(self.extract_strings)
        self.analyze_strings_button.setEnabled(False)
        action_layout.addWidget(self.analyze_strings_button)
        
        self.carve_files_button = QPushButton("Carve Embedded Files")
        self.carve_files_button.clicked.connect(self.carve_files)
        self.carve_files_button.setEnabled(False)
        action_layout.addWidget(self.carve_files_button)
        
        layout.addLayout(action_layout)
        
        # Memory output
        self.memory_output = QTextEdit()
        self.memory_output.setReadOnly(True)
        self.memory_output.setPlaceholderText("Select a process and click 'Dump Process Memory' to begin analysis")
        layout.addWidget(self.memory_output)
        
        # Progress bar
        progress_layout = QHBoxLayout()
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("Ready")
        self.progress_bar.setValue(0)
        progress_layout.addWidget(self.progress_bar, stretch=4)
        
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.cancel_operation)
        self.cancel_button.setEnabled(False)
        progress_layout.addWidget(self.cancel_button, stretch=1)
        
        layout.addLayout(progress_layout)

    def get_selected_pid(self):
        """Get the PID of the currently selected process"""
        items = self.process_tree.selectedItems()
        if items:
            item = items[0]
            pid_str = item.text(0)  # PID is in first column
            try:
                return int(pid_str)
            except ValueError:
                return None
        return None

    def update_memory_output(self, output):
        """Update the memory output text with analysis results"""
        # Append instead of replace when updating
        self.memory_output.append(output)
        # Scroll to the bottom
        scrollbar = self.memory_output.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def setup_mitre_analysis(self, layout):
        """Setup MITRE ATT&CK analysis tab"""
        # Description
        description = QLabel("MITRE ATT&CK Analysis - Detect potential malicious behavior patterns")
        description.setStyleSheet("font-weight: bold; color: white; padding: 5px;")
        layout.addWidget(description)
        
        # Process selection section
        selection_group = QGroupBox("Process Selection")
        selection_layout = QHBoxLayout()
        
        self.process_selector = QComboBox()
        self.process_selector.setStyleSheet("color: white;")
        self.process_selector.setMinimumWidth(300)
        selection_layout.addWidget(self.process_selector)
        
        self.analyze_button = QPushButton("Analyze Process")
        self.analyze_button.setStyleSheet("""
            QPushButton {
                background-color: #0d6efd;
                color: white;
                border: none;
                padding: 5px 15px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #0b5ed7;
            }
            QPushButton:disabled {
                background-color: #6c757d;
            }
        """)
        self.analyze_button.clicked.connect(self.analyze_mitre_techniques)
        self.analyze_button.setEnabled(False)
        selection_layout.addWidget(self.analyze_button)
        
        self.refresh_processes_button = QPushButton("Refresh Process List")
        self.refresh_processes_button.setStyleSheet("""
            QPushButton {
                background-color: #198754;
                color: white;
                border: none;
                padding: 5px 15px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #157347;
            }
        """)
        self.refresh_processes_button.clicked.connect(self.refresh_process_list)
        selection_layout.addWidget(self.refresh_processes_button)
        
        selection_group.setLayout(selection_layout)
        layout.addWidget(selection_group)
        
        # Create splitter for results
        results_splitter = QSplitter(Qt.Vertical)
        
        # Techniques table
        table_group = QGroupBox("Detected Techniques")
        table_layout = QVBoxLayout()
        
        self.mitre_table = QTableWidget()
        self.mitre_table.setColumnCount(4)
        self.mitre_table.setHorizontalHeaderLabels([
            "Technique ID", "Name", "Description", "Detection Methods"
        ])
        
        # Set column widths
        self.mitre_table.setColumnWidth(0, 100)   # Technique ID
        self.mitre_table.setColumnWidth(1, 150)   # Name
        self.mitre_table.setColumnWidth(2, 300)   # Description
        self.mitre_table.setColumnWidth(3, 200)   # Detection Methods
        
        self.mitre_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.mitre_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.mitre_table.setAlternatingRowColors(True)
        self.mitre_table.itemSelectionChanged.connect(self.technique_selected)
        
        table_layout.addWidget(self.mitre_table)
        table_group.setLayout(table_layout)
        results_splitter.addWidget(table_group)
        
        # Details section
        details_group = QGroupBox("Technique Details")
        details_layout = QVBoxLayout()
        
        self.mitre_details = QTextEdit()
        self.mitre_details.setReadOnly(True)
        self.mitre_details.setStyleSheet("""
            QTextEdit {
                background-color: #2b2b2b;
                color: white;
                border: 1px solid #3d3d3d;
            }
        """)
        self.mitre_details.setPlaceholderText("Select a technique from the table above to view detailed information")
        
        details_layout.addWidget(self.mitre_details)
        details_group.setLayout(details_layout)
        results_splitter.addWidget(details_group)
        
        # Add splitter to layout
        layout.addWidget(results_splitter)
        
        # Initialize process list
        self.refresh_process_list()
    
    def refresh_process_list(self):
        """Refresh the process selector with current running processes"""
        self.process_selector.clear()
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    proc_info = proc.info
                    name = proc_info['name']
                    pid = proc_info['pid']
                    cmdline = ' '.join(proc_info['cmdline'] or [])
                    display_text = f"{name} (PID: {pid})"
                    if cmdline:
                        display_text += f" - {cmdline[:50]}..."
                    processes.append((display_text, pid))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Sort processes by name
            processes.sort(key=lambda x: x[0].lower())
            
            # Add to combo box
            for display_text, pid in processes:
                self.process_selector.addItem(display_text, pid)
            
            # Enable analyze button if we have processes
            self.analyze_button.setEnabled(self.process_selector.count() > 0)
            
        except Exception as e:
            print(f"Error refreshing process list: {str(e)}")
    
    def technique_selected(self):
        """Handle selection change in MITRE table"""
        selected_items = self.mitre_table.selectedItems()
        if not selected_items:
            return
        
        # Get technique ID from first column
        technique_id = self.mitre_table.item(selected_items[0].row(), 0).text()
        
        if technique_id in MITRE_TECHNIQUES:
            technique = MITRE_TECHNIQUES[technique_id]
            
            # Format detailed information
            details = f"""<h3>{technique_id}: {technique['name']}</h3>
            
<p><b>Description:</b><br>
{technique['description']}</p>

<p><b>Detection Methods:</b></p>
<ul>
{"".join(f"<li>{method}</li>" for method in technique['detection'])}
</ul>

<p><b>Potential Impact:</b><br>
This technique may indicate malicious activity and should be investigated, especially if combined with other suspicious behaviors.</p>
"""
            
            self.mitre_details.setHtml(details)
        else:
            self.mitre_details.setPlainText("No detailed information available for this technique.")
    
    def analyze_mitre_techniques(self):
        """Analyze the selected process for MITRE ATT&CK techniques"""
        # Get selected process
        if self.process_selector.currentData() is None:
            return
            
        pid = self.process_selector.currentData()
        
        try:
            process = psutil.Process(pid)
            
            # Clear previous results
            self.mitre_table.setRowCount(0)
            self.mitre_details.clear()
            
            detected_techniques = []
            detection_context = {}  # Store context for why each technique was detected
            
            # Initialize variables with default values
            cmdline = ""
            proc_name = ""
            exe_path = ""
            parent_name = ""
            parent = None
            open_files = []
            connections = []
            num_threads = 0
            creation_time = 0
            memory_maps = []
            
            # Gather basic process information with individual try-except blocks
            try:
                cmdline = ' '.join(process.cmdline()).lower()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                cmdline = ""
            
            try:
                proc_name = process.name().lower()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                proc_name = ""
            
            try:
                exe_path = process.exe().lower()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                exe_path = ""
            
            try:
                parent = process.parent()
                if parent:
                    parent_name = parent.name().lower()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                parent_name = ""
            
            try:
                open_files = process.open_files()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                open_files = []
            
            try:
                connections = process.connections()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                connections = []
            
            try:
                num_threads = len(process.threads())
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                num_threads = 0
            
            try:
                creation_time = process.create_time()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                creation_time = 0
            
            try:
                memory_maps = process.memory_maps()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                memory_maps = []
            
            # Now perform the analysis with the safely gathered information
            
            # Process Discovery (T1057) - More specific criteria
            if any(cmd in cmdline for cmd in ['tasklist', 'get-process', 'ps -ef']) and \
               proc_name in ['cmd.exe', 'powershell.exe', 'bash.exe']:
                detected_techniques.append("T1057")
                detection_context["T1057"] = f"Process enumeration command detected: {cmdline}"
            
            # System Information Discovery (T1082) - More specific criteria
            system_info_cmds = ['systeminfo', 'ver', 'uname -a', 'hostname', 'whoami', 'net config workstation']
            if any(cmd in cmdline for cmd in system_info_cmds) and \
               proc_name in ['cmd.exe', 'powershell.exe', 'bash.exe']:
                detected_techniques.append("T1082")
                detection_context["T1082"] = f"System information command detected: {cmdline}"
            
            # File and Directory Discovery (T1083) - More specific criteria
            file_enum_cmds = ['dir /s', 'ls -R', 'find .', 'tree /f', 'get-childitem -recurse']
            if any(cmd in cmdline for cmd in file_enum_cmds) and \
               proc_name in ['cmd.exe', 'powershell.exe', 'bash.exe']:
                detected_techniques.append("T1083")
                detection_context["T1083"] = f"File enumeration command detected: {cmdline}"
            
            # Process Injection (T1055) - More sophisticated detection
            if num_threads > 50 and memory_maps and \
               any(region.path.endswith('.dll') for region in memory_maps):
                detected_techniques.append("T1055")
                detection_context["T1055"] = f"High thread count ({num_threads}) with multiple DLLs loaded"
            
            # Native API usage (T1106) - More specific criteria
            if proc_name in ['rundll32.exe', 'regsvr32.exe'] and \
               exe_path and not exe_path.startswith(('c:\\windows\\system32', 'c:\\windows\\syswow64')):
                detected_techniques.append("T1106")
                detection_context["T1106"] = f"Suspicious {proc_name} execution from non-standard path"
            
            # Command and Scripting Interpreter (T1059) - More specific criteria
            suspicious_args = ['downloadstring', 'invoke-expression', 'iex', 'eval', '-enc', '-encodedcommand']
            if proc_name in ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe'] and \
               (any(arg in cmdline for arg in suspicious_args) or \
                parent_name not in ['explorer.exe', 'cmd.exe', 'powershell.exe']):
                detected_techniques.append("T1059")
                detection_context["T1059"] = f"Suspicious script execution: {cmdline}"
            
            # OS Credential Dumping (T1003) - More specific criteria
            if "lsass.exe" in cmdline or \
               proc_name in ['mimikatz.exe', 'gsecdump.exe', 'wce.exe', 'pwdump.exe']:
                detected_techniques.append("T1003")
                detection_context["T1003"] = "Potential credential dumping activity detected"
            
            # Input Capture (T1056) - More specific criteria
            keyboard_apis = ['SetWindowsHookEx', 'GetAsyncKeyState', 'GetKeyState']
            if any(api in cmdline for api in keyboard_apis) or \
               (num_threads > 20 and any('hook' in f.path.lower() for f in open_files)):
                detected_techniques.append("T1056")
                detection_context["T1056"] = "Potential keyboard hooking detected"
            
            # Indicator Removal (T1070) - More specific criteria
            log_deletion_cmds = ['wevtutil cl', 'clear-eventlog', 'rm -rf /var/log']
            if any(cmd in cmdline for cmd in log_deletion_cmds) or \
               (proc_name in ['wevtutil.exe'] and 'cl' in cmdline):
                detected_techniques.append("T1070")
                detection_context["T1070"] = f"Log deletion attempt detected: {cmdline}"
            
            # Obfuscated Files or Information (T1027) - More specific criteria
            if exe_path and exe_path.endswith(('.tmp', '.dat', '.bin')) and \
               not exe_path.startswith(('c:\\windows\\', 'c:\\program files')):
                detected_techniques.append("T1027")
                detection_context["T1027"] = f"Suspicious executable path: {exe_path}"
            
            # Ingress Tool Transfer (T1105) - More specific criteria
            download_indicators = ['wget', 'curl', 'certutil -urlcache', 'start-bitstransfer']
            if any(ind in cmdline for ind in download_indicators) or \
               any(conn.status == 'ESTABLISHED' and conn.raddr[1] in [21, 22, 80, 443] 
                   for conn in connections):
                detected_techniques.append("T1105")
                detection_context["T1105"] = "File download activity detected"
            
            # Application Layer Protocol (T1071) - More specific criteria
            suspicious_ports = [6666, 4444, 1337, 31337]  # Common malware ports
            if any(conn.raddr and conn.raddr[1] in suspicious_ports for conn in connections):
                detected_techniques.append("T1071")
                detection_context["T1071"] = "Connection to suspicious port detected"
            
            # Data Staged (T1074) - More specific criteria
            suspicious_dirs = ['\\temp\\', '\\tmp\\', '\\downloads\\']
            large_file_ops = sum(1 for f in open_files if any(d in f.path.lower() for d in suspicious_dirs))
            if large_file_ops > 5:  # Multiple files in suspicious locations
                detected_techniques.append("T1074")
                detection_context["T1074"] = f"Multiple file operations in suspicious directories: {large_file_ops} files"
            
            # Impair Defenses (T1562) - More specific criteria
            defense_commands = ['sc stop', 'net stop', 'taskkill /im']
            security_services = ['antivirus', 'firewall', 'defender', 'security']
            if any(cmd in cmdline for cmd in defense_commands) and \
               any(svc in cmdline for svc in security_services):
                detected_techniques.append("T1562")
                detection_context["T1562"] = f"Attempt to disable security service: {cmdline}"
            
            # Masquerading (T1036) - More specific criteria
            system_paths = ['c:\\windows\\system32\\', 'c:\\windows\\syswow64\\']
            legitimate_names = ['svchost.exe', 'lsass.exe', 'services.exe', 'csrss.exe']
            if any(legit in proc_name for legit in legitimate_names) and \
               exe_path and not any(sys_path in exe_path.lower() for sys_path in system_paths):
                detected_techniques.append("T1036")
                detection_context["T1036"] = f"System process name from non-standard location: {exe_path}"
            
            # Update the table with detected techniques
            for technique_id in detected_techniques:
                technique = MITRE_TECHNIQUES[technique_id]
                row_position = self.mitre_table.rowCount()
                self.mitre_table.insertRow(row_position)
                
                # Add items to the row
                items = [
                    QTableWidgetItem(technique_id),
                    QTableWidgetItem(technique["name"]),
                    QTableWidgetItem(technique["description"]),
                    QTableWidgetItem(detection_context.get(technique_id, "Detection criteria met"))
                ]
                
                # Color high-risk techniques
                high_risk_techniques = ["T1055", "T1003", "T1562", "T1070"]
                medium_risk_techniques = ["T1059", "T1056", "T1027", "T1036"]
                
                if technique_id in high_risk_techniques:
                    for item in items:
                        # Dark red background with white text for high risk
                        item.setBackground(QColor(220, 53, 69))  # Bootstrap danger red
                        item.setForeground(QColor(255, 255, 255))  # White text
                elif technique_id in medium_risk_techniques:
                    for item in items:
                        # Orange background for medium risk
                        item.setBackground(QColor(255, 193, 7))  # Bootstrap warning yellow
                        item.setForeground(QColor(33, 37, 41))  # Dark text
                else:
                    for item in items:
                        # Light blue background for low risk
                        item.setBackground(QColor(13, 110, 253))  # Bootstrap primary blue
                        item.setForeground(QColor(255, 255, 255))  # White text
                
                # Add items to table
                for col, item in enumerate(items):
                    self.mitre_table.setItem(row_position, col, item)
            
            # Update details with enhanced process information
            try:
                memory_info = process.memory_info()
                cpu_percent = process.cpu_percent()
                status = process.status()
                
                # Add color indicators to the risk summary
                process_details = f"""<h3>Analysis Results for Process: {proc_name} (PID: {pid})</h3>

<p><b>Process Information:</b></p>
<ul>
<li>Command Line: {cmdline}</li>
<li>Executable Path: {exe_path}</li>
<li>Parent Process: {parent_name} (PID: {parent.pid if parent else 'N/A'})</li>
<li>Status: {status}</li>
<li>CPU Usage: {cpu_percent}%</li>
<li>Memory Usage: {memory_info.rss / 1024 / 1024:.2f} MB</li>
<li>Number of Threads: {num_threads}</li>
<li>Number of Open Files: {len(open_files)}</li>
<li>Number of Network Connections: {len(connections)}</li>
<li>Creation Time: {datetime.fromtimestamp(creation_time).strftime('%Y-%m-%d %H:%M:%S') if creation_time else 'Unknown'}</li>
</ul>

<p><b>Detection Summary:</b></p>
<ul>
<li style="color: #DC3545;"><b>High Risk Techniques: {len([t for t in detected_techniques if t in high_risk_techniques])}</b></li>
<li style="color: #FFC107;"><b>Medium Risk Techniques: {len([t for t in detected_techniques if t in medium_risk_techniques])}</b></li>
<li style="color: #0D6EFD;"><b>Low Risk Techniques: {len([t for t in detected_techniques if t not in high_risk_techniques + medium_risk_techniques])}</b></li>
</ul>

<p><b>Detection Details:</b></p>
<ul>
{"".join(f'<li style="color: {"#DC3545" if t in high_risk_techniques else "#FFC107" if t in medium_risk_techniques else "#0D6EFD"}"><b>{t}:</b> {detection_context.get(t, "Detection criteria met")}</li>' for t in detected_techniques)}
</ul>

<p>Select a technique from the table above for detailed information.</p>
"""
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                process_details = f"<p>Error getting detailed process information: {str(e)}</p>"
            
            self.mitre_details.setHtml(process_details)
            
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            self.mitre_details.setPlainText(f"Error analyzing process: {str(e)}")
        except Exception as e:
            self.mitre_details.setPlainText(f"Analysis failed: {str(e)}")

    def kill_process(self, pid):
        """Kill a process by PID"""
        try:
            # Get process name before killing it
            process = psutil.Process(pid)
            process_name = process.name()
            
            # Confirm with user
            reply = QMessageBox.question(
                self,
                "Kill Process",
                f"Are you sure you want to kill process {process_name} (PID: {pid})?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                # Try to kill the process
                process.kill()
                
                # Show success message
                QMessageBox.information(
                    self,
                    "Success",
                    f"Process {process_name} (PID: {pid}) has been terminated."
                )
                
                # Update the process tree
                if self.process_worker and self.process_worker.isRunning():
                    # Process tree will update automatically on next refresh
                    pass
                else:
                    # If monitoring is stopped, force an update
                    self.start_process_monitoring()
                    
        except psutil.NoSuchProcess:
            QMessageBox.warning(
                self,
                "Error",
                f"Process with PID {pid} no longer exists."
            )
        except psutil.AccessDenied:
            QMessageBox.warning(
                self,
                "Error",
                f"Access denied when trying to kill process {pid}. Try running as administrator."
            )
        except Exception as e:
            QMessageBox.warning(
                self,
                "Error",
                f"Failed to kill process {pid}: {str(e)}"
            ) 