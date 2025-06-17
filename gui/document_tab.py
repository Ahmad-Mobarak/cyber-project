#!/usr/bin/python3

import os
import sys
import subprocess
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, 
                           QLabel, QPushButton, QFileDialog, QTextEdit, 
                           QSplitter, QComboBox, QTableWidget, QTabWidget,
                           QTableWidgetItem, QHeaderView, QMessageBox, QProgressBar)
from PyQt5.QtCore import Qt, QProcess, pyqtSignal, QThread
from PyQt5.QtGui import QFont

class DocumentWorker(QThread):
    """Worker thread for document analysis tasks"""
    update_output = pyqtSignal(str)
    analysis_complete = pyqtSignal(bool)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, command, cwd=None):
        super().__init__()
        self.command = command
        self.cwd = cwd
        self.process = None
        
    def run(self):
        try:
            self.process = QProcess()
            self.process.setProcessChannelMode(QProcess.MergedChannels)
            
            if self.cwd:
                self.process.setWorkingDirectory(self.cwd)
            
            # Split command into program and arguments
            if isinstance(self.command, str):
                import shlex
                args = shlex.split(self.command)
                program = args[0]
                arguments = args[1:]
            else:
                program = self.command[0]
                arguments = self.command[1:]
                
            self.process.start(program, arguments)
            
            if not self.process.waitForStarted(5000):  # 5 second timeout
                raise Exception("Process failed to start")
                
            if not self.process.waitForFinished(-1):  # No timeout
                raise Exception("Process failed to complete")
            
            if self.process.exitCode() != 0:
                error = self.process.readAllStandardError().data().decode('utf-8', errors='replace')
                raise Exception(f"Process exited with code {self.process.exitCode()}: {error}")
                
            output = self.process.readAllStandardOutput().data().decode('utf-8', errors='replace')
            self.update_output.emit(output)
            self.analysis_complete.emit(True)
            
        except Exception as e:
            self.error_occurred.emit(str(e))
            self.analysis_complete.emit(False)
        finally:
            if self.process:
                self.process.kill()  # Ensure process is terminated
                
    def stop(self):
        """Stop the current process if running"""
        if self.process and self.process.state() != QProcess.NotRunning:
            self.process.kill()
            self.process.waitForFinished()

class DocumentTab(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(10, 10, 10, 10)
        
        # Find Python binary
        self.python_binary = self.find_python_binary()
        
        # File selection section
        self.setup_file_selection()
        
        # Analysis options and document info
        self.setup_analysis_options()
        
        # Results section
        self.setup_results_section()
        
        # Current file
        self.current_file = None
        
    def find_python_binary(self):
        """Find the Python binary to use for running scripts"""
        try:
            # First try sys.executable (current Python interpreter)
            if sys.executable and os.path.exists(sys.executable):
                return sys.executable
                
            # Try common Python binary names
            python_names = ['python3', 'python', 'py']
            if sys.platform == "win32":
                python_names.extend(['py.exe', 'python.exe', 'python3.exe'])
            
            for name in python_names:
                # Try using 'where' on Windows or 'which' on Unix
                try:
                    if sys.platform == "win32":
                        result = subprocess.run(['where', name], capture_output=True, text=True)
                    else:
                        result = subprocess.run(['which', name], capture_output=True, text=True)
                        
                    if result.returncode == 0:
                        path = result.stdout.strip().split('\n')[0]  # Take first result
                        if os.path.exists(path):
                            return path
                except:
                    continue
            
            # If we get here, try to find Python in common locations
            common_paths = []
            if sys.platform == "win32":
                program_files = os.environ.get("ProgramFiles", "C:\\Program Files")
                program_files_x86 = os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")
                common_paths.extend([
                    os.path.join(program_files, "Python*", "python.exe"),
                    os.path.join(program_files_x86, "Python*", "python.exe"),
                    "C:\\Python*\\python.exe"
                ])
            else:
                common_paths.extend([
                    "/usr/bin/python3",
                    "/usr/local/bin/python3",
                    "/usr/bin/python",
                    "/usr/local/bin/python"
                ])
            
            for path_pattern in common_paths:
                if '*' in path_pattern:
                    # Handle wildcard paths
                    import glob
                    matches = sorted(glob.glob(path_pattern), reverse=True)  # Latest version first
                    if matches:
                        return matches[0]
                elif os.path.exists(path_pattern):
                    return path_pattern
            
            raise Exception("Could not find Python binary")
            
        except Exception as e:
            QMessageBox.critical(None, "Error", f"Failed to find Python binary: {str(e)}\n"
                               "Please make sure Python is installed and in your PATH.")
            return None

    def setup_file_selection(self):
        """Setup file selection area"""
        file_group = QGroupBox("Document Selection")
        file_layout = QHBoxLayout()
        
        # File path display
        self.file_path_label = QLabel("No document selected")
        file_layout.addWidget(self.file_path_label, 1)
        
        # Browse button
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self.browse_document)
        file_layout.addWidget(browse_button)
        
        file_group.setLayout(file_layout)
        self.layout.addWidget(file_group)
        
    def setup_analysis_options(self):
        """Setup analysis options area"""
        options_group = QGroupBox("Analysis Options")
        options_layout = QVBoxLayout()
        
        # Document type info
        self.doc_type_label = QLabel("Document Type: N/A")
        self.doc_size_label = QLabel("Size: N/A")
        
        info_layout = QHBoxLayout()
        info_layout.addWidget(self.doc_type_label)
        info_layout.addWidget(self.doc_size_label)
        info_layout.addStretch(1)
        
        options_layout.addLayout(info_layout)
        
        # Analysis buttons
        button_layout = QHBoxLayout()
        
        # Full document analysis
        analyze_button = QPushButton("Analyze Document")
        analyze_button.clicked.connect(self.analyze_document)
        button_layout.addWidget(analyze_button)
        
        # Extract macros
        macro_button = QPushButton("Extract Macros")
        macro_button.clicked.connect(self.extract_macros)
        button_layout.addWidget(macro_button)
        
        # YARA scan
        yara_button = QPushButton("YARA Scan")
        yara_button.clicked.connect(self.yara_scan)
        button_layout.addWidget(yara_button)
        
        options_layout.addLayout(button_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("Ready")
        self.progress_bar.setValue(0)
        options_layout.addWidget(self.progress_bar)
        
        options_group.setLayout(options_layout)
        self.layout.addWidget(options_group)
        
    def setup_results_section(self):
        """Setup results section with tabs for different result types"""
        self.results_tabs = QTabWidget()
        
        # General analysis results
        self.analysis_text = QTextEdit()
        self.analysis_text.setReadOnly(True)
        self.results_tabs.addTab(self.analysis_text, "Analysis Results")
        
        # Macros tab
        self.macros_text = QTextEdit()
        self.macros_text.setReadOnly(True)
        self.results_tabs.addTab(self.macros_text, "Macros")
        
        # URLs and suspicious content tab
        self.urls_text = QTextEdit()
        self.urls_text.setReadOnly(True)
        self.results_tabs.addTab(self.urls_text, "URLs & Suspicious Content")
        
        # YARA results tab
        self.yara_text = QTextEdit()
        self.yara_text.setReadOnly(True)
        self.results_tabs.addTab(self.yara_text, "YARA Results")
        
        self.layout.addWidget(self.results_tabs, 1)  # Add stretch factor
    
    def browse_document(self):
        """Browse for a document file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Document", "", 
            "Documents (*.pdf *.doc *.docx *.xls *.xlsx *.ppt *.pptx *.rtf *.odt *.ods *.html *.htm *.one);;"
            "PDF Files (*.pdf);;"
            "Word Documents (*.doc *.docx);;"
            "Excel Spreadsheets (*.xls *.xlsx);;"
            "PowerPoint Presentations (*.ppt *.pptx);;"
            "Rich Text Format (*.rtf);;"
            "OpenDocument (*.odt *.ods);;"
            "HTML (*.html *.htm);;"
            "OneNote (*.one);;"
            "All Files (*)")
        
        if file_path:
            self.load_document(file_path)
    
    def load_document(self, file_path):
        """Load a document for analysis"""
        if not os.path.exists(file_path):
            QMessageBox.warning(self, "Warning", f"File {file_path} not found.")
            return
            
        self.current_file = file_path
        self.file_path_label.setText(file_path)
        
        # Store selected file path
        with open(".target-file.txt", "w") as f:
            f.write(file_path)
            
        # Get file info
        try:
            # Get file type using 'file' command
            process = subprocess.run(["file", "-b", "--mime-type", file_path], capture_output=True, text=True)
            mime_type = process.stdout.strip()
            
            process = subprocess.run(["file", "-b", file_path], capture_output=True, text=True)
            file_type = process.stdout.strip()
            
            file_size = os.path.getsize(file_path) / 1024  # KB
            
            # Validate file type
            supported_types = {
                'application/pdf': 'PDF Document',
                'application/msword': 'Microsoft Word Document',
                'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'Microsoft Word Document (DOCX)',
                'application/vnd.ms-excel': 'Microsoft Excel Spreadsheet',
                'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'Microsoft Excel Spreadsheet (XLSX)',
                'application/vnd.ms-powerpoint': 'Microsoft PowerPoint Presentation',
                'application/vnd.openxmlformats-officedocument.presentationml.presentation': 'Microsoft PowerPoint Presentation (PPTX)',
                'application/rtf': 'Rich Text Format',
                'text/html': 'HTML Document',
                'application/onenote': 'Microsoft OneNote Document',
                'application/vnd.oasis.opendocument.text': 'OpenDocument Text',
                'application/vnd.oasis.opendocument.spreadsheet': 'OpenDocument Spreadsheet'
            }
            
            # Check if file type is supported
            if mime_type not in supported_types and not any(type_desc.lower() in file_type.lower() for type_desc in supported_types.values()):
                QMessageBox.warning(self, "Warning", 
                    f"File type '{file_type}' may not be supported.\n"
                    "Only the following document types are supported:\n"
                    "- PDF Documents\n"
                    "- Microsoft Office Documents (Word, Excel, PowerPoint)\n"
                    "- Rich Text Format (RTF)\n"
                    "- HTML Documents\n"
                    "- OneNote Documents\n"
                    "- OpenDocument Format")
            
            # Update UI
            self.doc_type_label.setText(f"Document Type: {file_type}")
            self.doc_size_label.setText(f"Size: {file_size:.2f} KB")
            
            # Clear previous results
            self.analysis_text.clear()
            self.macros_text.clear()
            self.urls_text.clear()
            self.yara_text.clear()
            
            # Basic info in analysis tab
            self.analysis_text.setText(f"File: {os.path.basename(file_path)}\n")
            self.analysis_text.append(f"Path: {file_path}\n")
            self.analysis_text.append(f"MIME Type: {mime_type}\n")
            self.analysis_text.append(f"Type: {file_type}\n")
            self.analysis_text.append(f"Size: {file_size:.2f} KB\n")
            
        except subprocess.CalledProcessError as e:
            QMessageBox.critical(self, "Error", f"Failed to determine file type: {str(e)}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to get file info: {str(e)}")
    
    def analyze_document(self):
        """Run full document analysis"""
        if not self.current_file:
            QMessageBox.warning(self, "Warning", "No document selected.")
            return
            
        if not os.path.exists(self.current_file):
            QMessageBox.critical(self, "Error", f"File no longer exists: {self.current_file}")
            return
            
        # Update UI
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("Analyzing document...")
        self.analysis_text.clear()
        self.analysis_text.append(f"Analyzing {self.current_file}...\n\n")
        
        try:
            # Generate command
            sc0pe_path = self.main_window.sc0pe_path
            py_binary = self.python_binary or self.main_window.py_binary
            
            # Validate paths
            if not os.path.exists(sc0pe_path):
                raise Exception(f"Qu1cksc0pe path not found: {sc0pe_path}")
                
            if not py_binary or not os.path.exists(py_binary):
                raise Exception("Python binary not found. Please make sure Python is installed and in your PATH.")
            
            # Check if we're running in a frozen/bundled environment (PyInstaller)
            is_frozen = getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS')
            
            # Construct module path
            module_path = os.path.join(sc0pe_path, "Modules", "document_analyzer.py")
            
            # Verify module exists
            if not os.path.exists(module_path):
                raise Exception(f"Document analyzer module not found: {module_path}")
            
            if is_frozen:
                # Use the executable in the same directory
                cli_exe = os.path.join(sc0pe_path, "qu1cksc0pe.exe" if sys.platform == "win32" else "qu1cksc0pe")
                if os.path.exists(cli_exe):
                    command = [cli_exe, "--module", "document_analyzer", "--file", self.current_file]
                else:
                    self.analysis_text.append(f"Warning: CLI executable not found at {cli_exe}. Using Python scripts instead.\n")
                    command = [py_binary, module_path, self.current_file]
            else:
                command = [py_binary, module_path, self.current_file]
            
            # Set progress bar to indeterminate
            self.progress_bar.setRange(0, 0)
            
            # Create and start worker thread
            self.worker = DocumentWorker(command)
            self.worker.update_output.connect(self.update_analysis_output)
            self.worker.analysis_complete.connect(self.analysis_completed)
            self.worker.error_occurred.connect(self.handle_error)
            self.worker.start()
            
        except Exception as e:
            self.handle_error(str(e))
            self.analysis_completed(False)
    
    def extract_macros(self):
        """Extract macros from document"""
        if not self.current_file:
            QMessageBox.warning(self, "Warning", "No document selected.")
            return
            
        if not os.path.exists(self.current_file):
            QMessageBox.critical(self, "Error", f"File no longer exists: {self.current_file}")
            return
            
        # Only certain file types support macros
        file_ext = os.path.splitext(self.current_file)[1].lower()
        macro_formats = ['.doc', '.docm', '.docx', '.xls', '.xlsm', '.xlsx', '.ppt', '.pptm', '.pptx']
        
        if file_ext not in macro_formats:
            QMessageBox.warning(self, "Warning", "Selected file format does not support macros.")
            return
        
        try:
            # Update UI
            self.progress_bar.setValue(0)
            self.progress_bar.setFormat("Extracting macros...")
            self.macros_text.clear()
            self.macros_text.append(f"Extracting macros from {self.current_file}...\n\n")
            
            # Generate command
            sc0pe_path = self.main_window.sc0pe_path
            py_binary = self.python_binary or self.main_window.py_binary
            
            # Validate paths
            if not os.path.exists(sc0pe_path):
                raise Exception(f"Qu1cksc0pe path not found: {sc0pe_path}")
                
            if not py_binary or not os.path.exists(py_binary):
                raise Exception("Python binary not found. Please make sure Python is installed and in your PATH.")
                
            # Ensure Systems directory exists with correct structure
            systems_dir = os.path.join(sc0pe_path, "Systems")
            multiple_dir = os.path.join(systems_dir, "Multiple")
            os.makedirs(multiple_dir, exist_ok=True)
            
            # Create whitelist file if it doesn't exist
            whitelist_path = os.path.join(multiple_dir, "whitelist_domains.txt")
            if not os.path.exists(whitelist_path):
                try:
                    with open(whitelist_path, "w") as f:
                        f.write("# Whitelist domains - one domain per line\n")
                        f.write("# Example:\n")
                        f.write("microsoft.com\n")
                        f.write("google.com\n")
                        f.write("office.com\n")
                    self.macros_text.append(f"Created new whitelist file at: {whitelist_path}\n\n")
                except Exception as e:
                    self.macros_text.append(f"Warning: Could not create whitelist file: {str(e)}\n\n")
            
            # Construct module path
            module_path = os.path.join(sc0pe_path, "Modules", "document_analyzer.py")
            
            # Verify module exists
            if not os.path.exists(module_path):
                raise Exception(f"Document analyzer module not found: {module_path}")
            
            # Build command with macro extraction flag
            command = [py_binary, module_path, self.current_file, "--extract-macros"]
            
            # Set environment variables for paths
            env = os.environ.copy()
            env["QUICKSCOPE_PATH"] = sc0pe_path
            env["SYSTEMS_PATH"] = systems_dir
            env["WHITELIST_PATH"] = whitelist_path
            
            # Log command and paths for debugging
            self.macros_text.append("=== Debug Information ===\n")
            self.macros_text.append(f"Qu1cksc0pe Path: {sc0pe_path}\n")
            self.macros_text.append(f"Systems Path: {systems_dir}\n")
            self.macros_text.append(f"Whitelist Path: {whitelist_path}\n")
            self.macros_text.append(f"Command: {' '.join(command)}\n\n")
            
            # Set working directory to Qu1cksc0pe path
            working_dir = sc0pe_path
            
            # Set progress bar to indeterminate
            self.progress_bar.setRange(0, 0)
            
            # Create and start worker thread with environment
            self.macro_worker = DocumentWorker(command, cwd=working_dir)
            self.macro_worker.update_output.connect(self.update_macro_output)
            self.macro_worker.analysis_complete.connect(self.macro_extraction_completed)
            self.macro_worker.error_occurred.connect(self.handle_error)
            self.macro_worker.start()
            
        except Exception as e:
            error_msg = str(e)
            if "Process failed to start" in error_msg:
                error_msg += "\nPossible causes:\n" \
                           "1. Python or required modules are not installed\n" \
                           "2. The oletools module may not be installed (pip install oletools)\n" \
                           "3. Insufficient permissions to execute the command\n" \
                           "4. The file path contains special characters\n" \
                           f"5. The module path is incorrect: {module_path}"
            self.handle_error(error_msg)
            self.macro_extraction_completed(False)
    
    def extract_objects(self):
        """Extract embedded objects from document"""
        if not self.current_file:
            QMessageBox.warning(self, "Warning", "No document selected.")
            return
            
        if not os.path.exists(self.current_file):
            QMessageBox.critical(self, "Error", f"File no longer exists: {self.current_file}")
            return
            
        try:
            # Update UI
            self.progress_bar.setValue(0)
            self.progress_bar.setFormat("Extracting objects...")
            self.objects_text.clear()
            self.objects_text.append(f"Extracting embedded objects from {self.current_file}...\n\n")
            
            # Generate command
            sc0pe_path = self.main_window.sc0pe_path
            py_binary = self.python_binary or self.main_window.py_binary
            
            # Validate paths
            if not os.path.exists(sc0pe_path):
                raise Exception(f"Qu1cksc0pe path not found: {sc0pe_path}")
                
            if not py_binary or not os.path.exists(py_binary):
                raise Exception("Python binary not found. Please make sure Python is installed and in your PATH.")
            
            # Check if we're running in a frozen/bundled environment (PyInstaller)
            is_frozen = getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS')
            
            # Construct module path - using document_analyzer.py which contains the object extraction code
            module_path = os.path.join(sc0pe_path, "Modules", "document_analyzer.py")
            
            # Verify module exists
            if not os.path.exists(module_path):
                raise Exception(f"Document analyzer module not found: {module_path}")
            
            if is_frozen:
                # Use the executable in the same directory
                cli_exe = os.path.join(sc0pe_path, "qu1cksc0pe.exe" if sys.platform == "win32" else "qu1cksc0pe")
                if os.path.exists(cli_exe):
                    command = [cli_exe, "--module", "document_analyzer", "--file", self.current_file, "--extract-objects"]
                else:
                    self.objects_text.append(f"Warning: CLI executable not found at {cli_exe}. Using Python scripts instead.\n")
                    command = [py_binary, module_path, self.current_file, "--extract-objects"]
            else:
                command = [py_binary, module_path, self.current_file, "--extract-objects"]
            
            # Log the command being executed
            self.objects_text.append(f"Executing command: {' '.join(command)}\n\n")
            
            # Create output directory if it doesn't exist
            output_dir = os.path.join(os.path.dirname(self.current_file), "extracted_objects")
            os.makedirs(output_dir, exist_ok=True)
            
            # Set working directory to where the file is
            working_dir = os.path.dirname(self.current_file)
            
            # Set progress bar to indeterminate
            self.progress_bar.setRange(0, 0)
            
            # Create and start worker thread
            self.objects_worker = DocumentWorker(command, cwd=working_dir)
            self.objects_worker.update_output.connect(self.update_objects_output)
            self.objects_worker.analysis_complete.connect(self.objects_extraction_completed)
            self.objects_worker.error_occurred.connect(self.handle_error)
            self.objects_worker.start()
            
        except Exception as e:
            error_msg = str(e)
            if "Process failed to start" in error_msg:
                error_msg += "\nPossible causes:\n" \
                           "1. Python or required modules are not installed\n" \
                           "2. Insufficient permissions to execute the command\n" \
                           "3. The file path contains special characters\n" \
                           f"4. The module path is incorrect: {module_path}"
            self.handle_error(error_msg)
            self.objects_extraction_completed(False)

    def update_objects_output(self, output):
        """Update objects output with results"""
        try:
            # Check if output indicates no objects found
            if "no embedded" in output.lower() or not output.strip():
                self.objects_text.append("No embedded objects were found in this document.\n")
                return
                
            # Format the output
            formatted_output = []
            for line in output.split('\n'):
                line = line.strip()
                if not line:
                    continue
                    
                # Highlight extracted files
                if "extracted" in line.lower() or "saved" in line.lower():
                    formatted_output.append(f"✅ {line}")
                # Highlight errors
                elif "error" in line.lower() or "failed" in line.lower():
                    formatted_output.append(f"❌ {line}")
                # Highlight warnings
                elif "warning" in line.lower():
                    formatted_output.append(f"⚠️ {line}")
                else:
                    formatted_output.append(line)
            
            # Add formatted output
            self.objects_text.append('\n'.join(formatted_output))
            
        except Exception as e:
            self.objects_text.append(f"\n❌ Error formatting output: {str(e)}\n")
        finally:
            # Scroll to bottom
            scrollbar = self.objects_text.verticalScrollBar()
            scrollbar.setValue(scrollbar.maximum())

    def yara_scan(self):
        """Scan document with YARA rules"""
        if not self.current_file:
            QMessageBox.warning(self, "Warning", "No document selected.")
            return
            
        if not os.path.exists(self.current_file):
            QMessageBox.critical(self, "Error", f"File no longer exists: {self.current_file}")
            return
            
        try:
            # Update UI
            self.progress_bar.setValue(0)
            self.progress_bar.setFormat("Running YARA scan...")
            self.yara_text.clear()
            self.yara_text.append(f"Scanning {self.current_file} with YARA rules...\n\n")
            
            # Generate command
            sc0pe_path = self.main_window.sc0pe_path
            py_binary = self.python_binary or self.main_window.py_binary
            
            # Validate paths
            if not os.path.exists(sc0pe_path):
                raise Exception(f"Qu1cksc0pe path not found: {sc0pe_path}")
                
            if not py_binary or not os.path.exists(py_binary):
                raise Exception("Python binary not found. Please make sure Python is installed and in your PATH.")
            
            # Check if we're running in a frozen/bundled environment (PyInstaller)
            is_frozen = getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS')
            
            # Construct module path
            module_path = os.path.join(sc0pe_path, "Modules", "document_analyzer.py")
            
            # Verify module exists
            if not os.path.exists(module_path):
                raise Exception(f"Document analyzer module not found: {module_path}")
            
            # Check all possible YARA rules locations
            rules_locations = [
                os.path.join(sc0pe_path, "rules"),
                os.path.join(sc0pe_path, "Systems", "Multiple", "yara_rules"),
                os.path.join(sc0pe_path, "Systems", "Multiple", "YaraRules_Multiple"),
                os.path.join(sc0pe_path, "Systems", "rules")
            ]
            
            rules_dir = None
            for location in rules_locations:
                if os.path.exists(location) and os.path.isdir(location):
                    rules_dir = location
                    break
            
            if not rules_dir:
                # Try to create and initialize rules directory
                rules_dir = os.path.join(sc0pe_path, "Systems", "Multiple", "yara_rules")
                try:
                    os.makedirs(rules_dir, exist_ok=True)
                    # Create a basic YARA rule for testing
                    basic_rule = '''
rule suspicious_document {
    meta:
        description = "Detect common suspicious patterns in documents"
        author = "Qu1cksc0pe"
    strings:
        $s1 = "powershell" nocase
        $s2 = "cmd.exe" nocase
        $s3 = "eval(" nocase
        $s4 = "ActiveX" nocase
        $s5 = "shell" nocase
        $s6 = "http://" nocase
        $s7 = "https://" nocase
        $s8 = "base64" nocase
    condition:
        any of them
}'''
                    with open(os.path.join(rules_dir, "document_rules.yar"), "w") as f:
                        f.write(basic_rule)
                    self.yara_text.append(f"Created new YARA rules directory at: {rules_dir}\n")
                except Exception as e:
                    raise Exception(f"Failed to create YARA rules directory: {str(e)}")
            
            # Build command with the correct rules path
            if is_frozen:
                # Use the executable in the same directory
                cli_exe = os.path.join(sc0pe_path, "qu1cksc0pe.exe" if sys.platform == "win32" else "qu1cksc0pe")
                if os.path.exists(cli_exe):
                    command = [cli_exe, "--module", "document_analyzer", "--file", self.current_file, "--yara"]
                else:
                    self.yara_text.append(f"Warning: CLI executable not found at {cli_exe}. Using Python scripts instead.\n")
                    command = [py_binary, module_path, self.current_file, "--yara"]
            else:
                command = [py_binary, module_path, self.current_file, "--yara"]
            
            # Add rules directory to environment variables
            env = os.environ.copy()
            env["YARA_RULES_DIR"] = rules_dir
            
            # Log command and rules directory for debugging
            self.yara_text.append(f"Debug: Using YARA rules from: {rules_dir}\n")
            self.yara_text.append(f"Debug: Executing command: {' '.join(command)}\n\n")
            
            # Set working directory to Qu1cksc0pe path to ensure rules are found
            working_dir = sc0pe_path
            
            # Set progress bar to indeterminate
            self.progress_bar.setRange(0, 0)
            
            # Create and start worker thread
            self.yara_worker = DocumentWorker(command, cwd=working_dir)
            self.yara_worker.update_output.connect(self.update_yara_output)
            self.yara_worker.analysis_complete.connect(self.yara_scan_completed)
            self.yara_worker.error_occurred.connect(self.handle_error)
            self.yara_worker.start()
            
        except Exception as e:
            error_msg = str(e)
            if "Process failed to start" in error_msg:
                error_msg += "\nPossible causes:\n" \
                           "1. Python or required modules are not installed\n" \
                           "2. YARA rules directory not found or inaccessible\n" \
                           "3. Insufficient permissions to execute the command\n" \
                           "4. The file path contains special characters\n" \
                           f"5. The module path is incorrect: {module_path}"
            self.handle_error(error_msg)
            self.yara_scan_completed(False)

    def update_analysis_output(self, output):
        """Update analysis output with results"""
        # Parse and format the output
        formatted_output = self.format_analysis_output(output)
        
        # Update analysis tab
        self.analysis_text.append(formatted_output)
        
        # Extract and categorize results
        self.extract_and_categorize_results(output)
        
        # Scroll to bottom
        scrollbar = self.analysis_text.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def format_analysis_output(self, output):
        """Format analysis output for better readability"""
        formatted = []
        
        # Split output into lines
        lines = output.split('\n')
        
        for line in lines:
            # Format error messages
            if "error" in line.lower():
                formatted.append(f"❌ {line}")
            # Format warnings
            elif "warning" in line.lower():
                formatted.append(f"⚠️ {line}")
            # Format success messages
            elif any(s in line.lower() for s in ["found", "detected", "extracted", "completed"]):
                formatted.append(f"✅ {line}")
            # Format info messages
            elif "info" in line.lower():
                formatted.append(f"ℹ️ {line}")
            else:
                formatted.append(line)
                
        return "\n".join(formatted)

    def extract_and_categorize_results(self, output):
        """Extract and categorize analysis results"""
        # Extract URLs and suspicious content
        self.extract_urls_from_output(output)
        
        # Extract macro information
        if "macro" in output.lower():
            macro_lines = []
            in_macro_section = False
            for line in output.split('\n'):
                if "macro" in line.lower():
                    in_macro_section = True
                if in_macro_section:
                    macro_lines.append(line)
                if in_macro_section and line.strip() == "":
                    in_macro_section = False
            
            if macro_lines:
                self.macros_text.append("\n".join(macro_lines))
        
        # Extract YARA matches
        if "yara" in output.lower():
            yara_lines = []
            in_yara_section = False
            for line in output.split('\n'):
                if "yara" in line.lower():
                    in_yara_section = True
                if in_yara_section:
                    yara_lines.append(line)
                if in_yara_section and line.strip() == "":
                    in_yara_section = False
            
            if yara_lines:
                self.yara_text.append("\n".join(yara_lines))

    def extract_urls_from_output(self, output):
        """Extract URLs and suspicious content from analysis output"""
        # Simple regex to find URLs
        import re
        urls = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\.-]*(?:\?\S+)?', output)
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', output)
        domains = re.findall(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b', output)
        
        # Suspicious strings to look for
        suspicious = [
            'powershell', 'cmd.exe', 'rundll32', 'invoke-expression', 
            'iex', 'download', 'javascript', 'vbscript', 'ActiveX',
            'eval(', 'fromCharCode', 'exec(', 'shellcode', 'payload',
            'obfuscated', 'base64', 'encoded', 'hidden', 'encrypt',
            'decode', 'decrypt', 'http.get', 'http.post', 'wget',
            'curl', 'certutil', 'bitsadmin', 'regsvr32', 'wscript'
        ]
        
        suspicious_lines = []
        for line in output.splitlines():
            if any(s.lower() in line.lower() for s in suspicious):
                suspicious_lines.append(line)
        
        # Update URLs & Suspicious Content tab
        content = []
        
        if urls:
            content.append("=== URLs ===")
            for url in sorted(set(urls)):  # Remove duplicates
                content.append(f"- {url}")
            content.append("")
            
        if domains:
            content.append("=== Domains ===")
            for domain in sorted(set(domains)):  # Remove duplicates
                if not any(url.startswith(f"http://{domain}") or url.startswith(f"https://{domain}") for url in urls):
                    content.append(f"- {domain}")
            content.append("")
            
        if ips:
            content.append("=== IP Addresses ===")
            for ip in sorted(set(ips)):  # Remove duplicates
                content.append(f"- {ip}")
            content.append("")
            
        if suspicious_lines:
            content.append("=== Suspicious Content ===")
            seen = set()  # Track unique suspicious lines
            for line in suspicious_lines:
                line = line.strip()
                if line and line not in seen:
                    content.append(f"- {line}")
                    seen.add(line)
                    
        if content:
            self.urls_text.setText("\n".join(content))
        else:
            self.urls_text.setText("No URLs or suspicious content found.")
    
    def update_macro_output(self, output):
        """Update macro output with results"""
        try:
            # Check if output indicates no macros
            if not output.strip() or "no macro" in output.lower():
                self.macros_text.append("No macros were found in this document.\n")
                return
            
            # Format the output
            formatted_output = []
            for line in output.split('\n'):
                line = line.strip()
                if not line:
                    continue
                
                # Skip whitelist warning as we handle it
                if "Whitelist file not found" in line:
                    continue
                
                # Highlight macro detections
                if "macro" in line.lower():
                    formatted_output.append(f"✅ {line}")
                # Highlight suspicious content
                elif any(s in line.lower() for s in ["shell", "powershell", "cmd", "http", "eval", "exec"]):
                    formatted_output.append(f"⚠️ {line}")
                # Highlight errors
                elif "error" in line.lower():
                    formatted_output.append(f"❌ {line}")
                else:
                    formatted_output.append(line)
            
            # Add formatted output
            self.macros_text.append('\n'.join(formatted_output))
            
        except Exception as e:
            self.macros_text.append(f"\n❌ Error formatting output: {str(e)}\n")
        finally:
            # Scroll to bottom
            scrollbar = self.macros_text.verticalScrollBar()
            scrollbar.setValue(scrollbar.maximum())
    
    def update_yara_output(self, output):
        """Update YARA output with results"""
        try:
            # Check if output indicates no matches
            if not output.strip() or "no rules matched" in output.lower():
                self.yara_text.append("No YARA rules matched this document.\n")
                return
                
            # Format the output
            formatted_output = []
            for line in output.split('\n'):
                line = line.strip()
                if not line:
                    continue
                    
                # Highlight matches
                if "match" in line.lower():
                    formatted_output.append(f"✅ {line}")
                # Highlight errors
                elif "error" in line.lower():
                    formatted_output.append(f"❌ {line}")
                # Highlight warnings
                elif "warning" in line.lower():
                    formatted_output.append(f"⚠️ {line}")
                else:
                    formatted_output.append(line)
            
            # Add formatted output
            self.yara_text.append('\n'.join(formatted_output))
            
        except Exception as e:
            self.yara_text.append(f"\n❌ Error formatting output: {str(e)}\n")
        finally:
            # Scroll to bottom
            scrollbar = self.yara_text.verticalScrollBar()
            scrollbar.setValue(scrollbar.maximum())
    
    def analysis_completed(self, success):
        """Handle document analysis completion"""
        self.progress_bar.setRange(0, 100)
        
        if success:
            self.progress_bar.setValue(100)
            self.progress_bar.setFormat("Analysis completed")
        else:
            self.progress_bar.setValue(0)
            self.progress_bar.setFormat("Analysis failed")
    
    def macro_extraction_completed(self, success):
        """Handle macro extraction completion"""
        self.progress_bar.setRange(0, 100)
        
        if success:
            self.progress_bar.setValue(100)
            self.progress_bar.setFormat("Macro extraction completed")
            
            # If no macros were found
            if "no macro" in self.macros_text.toPlainText().lower():
                self.macros_text.append("\nNo macros detected in this document.")
        else:
            self.progress_bar.setValue(0)
            self.progress_bar.setFormat("Macro extraction failed")
    
    def objects_extraction_completed(self, success):
        """Handle object extraction completion"""
        self.progress_bar.setRange(0, 100)
        
        if success:
            self.progress_bar.setValue(100)
            self.progress_bar.setFormat("Object extraction completed")
            
            # If no objects were found
            if "no embedded" in self.objects_text.toPlainText().lower():
                self.objects_text.append("\nNo embedded objects detected in this document.")
        else:
            self.progress_bar.setValue(0)
            self.progress_bar.setFormat("Object extraction failed")
    
    def yara_scan_completed(self, success):
        """Handle YARA scan completion"""
        self.progress_bar.setRange(0, 100)
        
        if success:
            self.progress_bar.setValue(100)
            self.progress_bar.setFormat("YARA scan completed")
        else:
            self.progress_bar.setValue(0)
            self.progress_bar.setFormat("YARA scan failed")
    
    def handle_error(self, error):
        """Handle errors that occur during analysis"""
        error_msg = str(error)
        
        # Format the error message for better readability
        formatted_msg = "An error occurred during analysis:\n\n"
        
        # Split the error message into sections
        if "Process exited with code" in error_msg:
            sections = error_msg.split("\n\n")
            for section in sections:
                if section.strip():
                    if "Output:" in section:
                        formatted_msg += "=== Command Output ===\n"
                        formatted_msg += section.replace("Output:", "").strip() + "\n\n"
                    elif "Error output:" in section:
                        formatted_msg += "=== Error Details ===\n"
                        formatted_msg += section.replace("Error output:", "").strip() + "\n\n"
                    elif "Possible causes:" in section:
                        formatted_msg += "=== Troubleshooting ===\n"
                        formatted_msg += section.strip() + "\n\n"
                    else:
                        formatted_msg += section.strip() + "\n\n"
        else:
            formatted_msg += error_msg
        
        # Show error dialog with formatted message
        error_dialog = QMessageBox()
        error_dialog.setIcon(QMessageBox.Critical)
        error_dialog.setWindowTitle("Error")
        error_dialog.setText("Analysis Failed")
        error_dialog.setInformativeText("The document analysis process encountered an error.")
        error_dialog.setDetailedText(formatted_msg)
        error_dialog.setStandardButtons(QMessageBox.Ok)
        error_dialog.exec_()
        
        # Log error to analysis text
        self.analysis_text.append(f"\n❌ Error Details:\n{formatted_msg}\n")
        
        # Update progress bar
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("Analysis failed") 