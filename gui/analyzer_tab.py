#!/usr/bin/python3

import os
import sys
import re
import subprocess
import puremagic as pr
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, 
                            QLabel, QPushButton, QFileDialog, QTextEdit, 
                            QSplitter, QComboBox, QTableWidget, QTableWidgetItem,
                            QHeaderView, QMessageBox, QProgressBar)
from PyQt5.QtCore import Qt, QProcess, pyqtSignal, QThread
from PyQt5.QtGui import QFont

class AnalysisWorker(QThread):
    """Worker thread for running analysis tasks"""
    update_output = pyqtSignal(str)
    analysis_complete = pyqtSignal(bool)
    
    def __init__(self, command, cwd=None):
        super().__init__()
        self.command = command
        self.cwd = cwd
        
    def run(self):
        try:
            process = QProcess()
            process.setProcessChannelMode(QProcess.MergedChannels)
            
            if self.cwd:
                process.setWorkingDirectory(self.cwd)
                
            process.start(self.command)
            process.waitForFinished(-1)
            
            output = process.readAllStandardOutput().data().decode('utf-8', errors='replace')
            self.update_output.emit(output)
            self.analysis_complete.emit(True)
        except Exception as e:
            self.update_output.emit(f"Error: {str(e)}")
            self.analysis_complete.emit(False)

class AnalyzerTab(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(10, 10, 10, 10)
        
        # Target info section
        self.setup_target_section()
        
        # Analysis options
        self.setup_analysis_options()
        
        # Results section with splitter
        self.setup_results_section()
        
    def setup_target_section(self):
        target_group = QGroupBox("Target")
        target_layout = QHBoxLayout()
        
        # Target file path display
        self.target_path_label = QLabel("No file selected")
        target_layout.addWidget(self.target_path_label, 1)
        
        # Browse button
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self.browse_file)
        target_layout.addWidget(browse_button)
        
        target_group.setLayout(target_layout)
        self.layout.addWidget(target_group)
        
    def setup_analysis_options(self):
        options_group = QGroupBox("Analysis Options")
        options_layout = QHBoxLayout()
        
        # Analysis type selector
        self.analysis_type = QComboBox()
        self.analysis_type.addItems([
            "Basic Analysis", 
            "Static Analysis", 
            "Extract Strings", 
            "Check Signatures",
            "Resource Analysis",
            "Check Packer",
            "Find Domains/URLs",
            "Create MITRE ATT&CK Table"
        ])
        options_layout.addWidget(self.analysis_type)
        
        # Run analysis button
        self.run_button = QPushButton("Run Analysis")
        self.run_button.clicked.connect(self.run_analysis)
        options_layout.addWidget(self.run_button)
        
        # Export report button
        export_button = QPushButton("Export Report")
        export_button.clicked.connect(self.export_report)
        options_layout.addWidget(export_button)
        
        options_group.setLayout(options_layout)
        self.layout.addWidget(options_group)
        
    def setup_results_section(self):
        # Create a splitter for resizable sections
        splitter = QSplitter(Qt.Vertical)
        
        # Analysis output
        output_group = QGroupBox("Analysis Output")
        output_layout = QVBoxLayout()
        
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        output_layout.addWidget(self.output_text)
        
        output_group.setLayout(output_layout)
        splitter.addWidget(output_group)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("Ready")
        self.progress_bar.setValue(0)
        
        # Add progress bar and splitter to layout
        self.layout.addWidget(self.progress_bar)
        self.layout.addWidget(splitter, 1)  # Stretch factor of 1
        
    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select File for Analysis", "", "All Files (*)")
        
        if file_path:
            self.load_file(file_path)
            
    def load_file(self, file_path):
        """Load a file for analysis"""
        if not os.path.exists(file_path):
            self.output_text.setText(f"Error: File {file_path} not found.")
            return
            
        self.current_file = file_path
        self.target_path_label.setText(file_path)
        
        # Store selected file path
        with open(".target-file.txt", "w") as f:
            f.write(file_path)
            
        # Show file info
        try:
            file_type = str(pr.magic_file(file_path))
            file_size = os.path.getsize(file_path) / 1024  # KB
            
            info_text = f"File: {os.path.basename(file_path)}\n"
            info_text += f"Path: {file_path}\n"
            info_text += f"Type: {file_type}\n"
            info_text += f"Size: {file_size:.2f} KB\n"
            
            self.output_text.setText(info_text)
        except Exception as e:
            self.output_text.setText(f"Error getting file info: {str(e)}")
            
    def load_folder(self, folder_path):
        """Load a folder for analysis"""
        if not os.path.exists(folder_path):
            self.output_text.setText(f"Error: Folder {folder_path} not found.")
            return
            
        self.current_folder = folder_path
        self.target_path_label.setText(folder_path)
        
        # Store selected folder path
        with open(".target-folder.txt", "w") as f:
            f.write(folder_path)
            
        # Show folder info
        try:
            file_count = len([f for f in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, f))])
            
            info_text = f"Folder: {os.path.basename(folder_path)}\n"
            info_text += f"Path: {folder_path}\n"
            info_text += f"Files: {file_count}\n"
            
            self.output_text.setText(info_text)
        except Exception as e:
            self.output_text.setText(f"Error getting folder info: {str(e)}")
            
    def get_analysis_command(self, analysis_type):
        """Generate the appropriate command based on analysis type"""
        if not hasattr(self, 'current_file'):
            return None
            
        file_path = self.current_file
        sc0pe_path = self.main_window.sc0pe_path
        py_binary = self.main_window.py_binary
        path_separator = self.main_window.path_separator
        
        # Check if we're running in a frozen/bundled environment (PyInstaller)
        is_frozen = getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS')
        
        # If running as standalone executable, use the CLI executable instead of Python
        if is_frozen:
            # Use the executable in the same directory
            cli_exe = os.path.join(sc0pe_path, "qu1cksc0pe.exe") if sys.platform == "win32" else os.path.join(sc0pe_path, "qu1cksc0pe")
            if os.path.exists(cli_exe):
                # Basic analysis
                if analysis_type == "Basic Analysis":
                    return f"\"{cli_exe}\" --file \"{file_path}\" --analyze"
                
                # For module-specific commands, we still use the executable with proper arguments
                # Since the modules are now bundled into the executable
                # Static analysis (depends on file type)
                elif analysis_type == "Static Analysis":
                    file_type = str(pr.magic_file(file_path))
                    
                    if "Windows Executable" in file_type or ".msi" in file_type or ".dll" in file_type or ".exe" in file_type:
                        return f"\"{cli_exe}\" --module windows_static_analyzer --file \"{file_path}\""
                    elif "ELF" in file_type:
                        return f"\"{cli_exe}\" --module linux_static_analyzer --file \"{file_path}\""
                    elif "Mach-O" in file_type:
                        return f"\"{cli_exe}\" --module apple_analyzer --file \"{file_path}\""
                    elif "PK" in file_type and "Java archive" in file_type:
                        return f"\"{cli_exe}\" --module apkAnalyzer --file \"{file_path}\" --mode APK"
                    else:
                        return None
                    
                # Check signatures
                elif analysis_type == "Check Signatures":
                    return f"\"{cli_exe}\" --module sigChecker --file \"{file_path}\""
                
                # Resource analysis
                elif analysis_type == "Resource Analysis":
                    return f"\"{cli_exe}\" --module resourceChecker --file \"{file_path}\""
                
                # Check packer
                elif analysis_type == "Check Packer":
                    return f"\"{cli_exe}\" --module packerAnalyzer --single --file \"{file_path}\""
                
                # Find domains/URLs
                elif analysis_type == "Find Domains/URLs":
                    return f"\"{cli_exe}\" --module domainCatcher --file \"{file_path}\""
                
                # MITRE ATT&CK Table
                elif analysis_type == "Create MITRE ATT&CK Table":
                    return f"\"{cli_exe}\" --module mitre --file \"{file_path}\""
                
                # Extract strings (special case)
                elif analysis_type == "Extract Strings":
                    # Windows
                    if sys.platform == "win32":
                        return f"powershell.exe \"& {{strings -a \"{file_path}\" > strings_output.txt; Get-Content strings_output.txt}}\""
                    # Linux and others
                    else:
                        return f"strings --all \"{file_path}\""
            
            # Fallback to normal command structure if executable not found
            else:
                self.output_text.setText(f"Warning: CLI executable not found at {cli_exe}. Using Python scripts instead.")
        
        # Standard Python script commands (for non-frozen environment or fallback)
        # Basic analysis
        if analysis_type == "Basic Analysis":
            return f"{py_binary} {sc0pe_path}{path_separator}qu1cksc0pe.py --file \"{file_path}\" --analyze"
            
        # Static analysis (depends on file type)
        elif analysis_type == "Static Analysis":
            file_type = str(pr.magic_file(file_path))
            
            if "Windows Executable" in file_type or ".msi" in file_type or ".dll" in file_type or ".exe" in file_type:
                return f"{py_binary} {sc0pe_path}{path_separator}Modules{path_separator}windows_static_analyzer.py \"{file_path}\""
            elif "ELF" in file_type:
                return f"{py_binary} {sc0pe_path}{path_separator}Modules{path_separator}linux_static_analyzer.py \"{file_path}\""
            elif "Mach-O" in file_type:
                return f"{py_binary} {sc0pe_path}{path_separator}Modules{path_separator}apple_analyzer.py \"{file_path}\""
            elif "PK" in file_type and "Java archive" in file_type:
                return f"{py_binary} {sc0pe_path}{path_separator}Modules{path_separator}apkAnalyzer.py \"{file_path}\" False APK"
            else:
                return None
                
        # Extract strings
        elif analysis_type == "Extract Strings":
            # Windows
            if sys.platform == "win32":
                return f"powershell.exe \"& {{strings -a \"{file_path}\" > strings_output.txt; Get-Content strings_output.txt}}\""
            # Linux and others
            else:
                return f"strings --all \"{file_path}\""
                
        # Check signatures
        elif analysis_type == "Check Signatures":
            return f"{py_binary} {sc0pe_path}{path_separator}Modules{path_separator}sigChecker.py \"{file_path}\""
            
        # Resource analysis
        elif analysis_type == "Resource Analysis":
            return f"{py_binary} {sc0pe_path}{path_separator}Modules{path_separator}resourceChecker.py \"{file_path}\""
            
        # Check packer
        elif analysis_type == "Check Packer":
            return f"{py_binary} {sc0pe_path}{path_separator}Modules{path_separator}packerAnalyzer.py --single \"{file_path}\""
            
        # Find domains/URLs
        elif analysis_type == "Find Domains/URLs":
            return f"{py_binary} {sc0pe_path}{path_separator}Modules{path_separator}domainCatcher.py \"{file_path}\""
            
        # MITRE ATT&CK Table
        elif analysis_type == "Create MITRE ATT&CK Table":
            return f"{py_binary} {sc0pe_path}{path_separator}Modules{path_separator}mitre.py \"{file_path}\""
            
        return None
            
    def run_analysis(self):
        """Run the selected analysis on the current file"""
        if not hasattr(self, 'current_file'):
            QMessageBox.warning(self, "Warning", "No file selected for analysis.")
            return
            
        analysis_type = self.analysis_type.currentText()
        command = self.get_analysis_command(analysis_type)
        
        if not command:
            QMessageBox.warning(self, "Warning", "Analysis type not supported for this file.")
            return
            
        # Update UI
        self.run_button.setEnabled(False)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("Analyzing...")
        self.output_text.clear()
        self.output_text.setText(f"Running {analysis_type}...\nCommand: {command}\n\n")
        
        # Create and start worker thread
        self.worker = AnalysisWorker(command)
        self.worker.update_output.connect(self.update_analysis_output)
        self.worker.analysis_complete.connect(self.analysis_completed)
        self.worker.start()
        
        # Set progress bar to indeterminate
        self.progress_bar.setRange(0, 0)
        
    def update_analysis_output(self, output):
        """Update the output text with analysis results"""
        current_text = self.output_text.toPlainText()
        self.output_text.setText(current_text + output)
        # Scroll to the bottom
        scrollbar = self.output_text.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
        
    def analysis_completed(self, success):
        """Handle completion of analysis"""
        self.run_button.setEnabled(True)
        self.progress_bar.setRange(0, 100)
        
        if success:
            self.progress_bar.setValue(100)
            self.progress_bar.setFormat("Analysis completed")
        else:
            self.progress_bar.setValue(0)
            self.progress_bar.setFormat("Analysis failed")
            
    def export_report(self):
        """Export analysis report to a file"""
        if not hasattr(self, 'current_file'):
            QMessageBox.warning(self, "Warning", "No file analyzed yet.")
            return
            
        # Get output text
        report_content = self.output_text.toPlainText()
        
        if not report_content:
            QMessageBox.warning(self, "Warning", "No analysis results to export.")
            return
            
        # Ask for save location
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Report", "", "Text Files (*.txt);;JSON Files (*.json);;All Files (*)")
            
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(report_content)
                QMessageBox.information(self, "Success", f"Report exported to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export report: {str(e)}") 