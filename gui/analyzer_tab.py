#!/usr/bin/python3

import os
import sys
import re
import subprocess
try:
    import puremagic as pr
except ImportError:
    pr = None # Handle missing puremagic gracefully
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, 
                            QLabel, QPushButton, QFileDialog, QTextEdit, 
                            QSplitter, QComboBox, QTableWidget, QTableWidgetItem,
                            QHeaderView, QMessageBox, QProgressBar)
from PyQt5.QtCore import Qt, QProcess, pyqtSignal, QThread, QTextCursor
from PyQt5.QtGui import QFont

class AnalysisWorker(QThread):
    """Worker thread for running analysis tasks"""
    update_output = pyqtSignal(str)
    analysis_complete = pyqtSignal(bool)
    
    def __init__(self, command_info, cwd=None):
        super().__init__()
        self.command_info = command_info
        self.cwd = cwd
        self.process = None
        
    def run(self):
        try:
            self.process = QProcess()
            self.process.setProcessChannelMode(QProcess.MergedChannels)
            
            if self.cwd:
                self.process.setWorkingDirectory(self.cwd)

            if isinstance(self.command_info, list):
                program = self.command_info[0]
                arguments = self.command_info[1:]
                self.process.start(program, arguments)
            elif isinstance(self.command_info, str):
                if sys.platform == "win32" and any(op in self.command_info for op in ["&", "|", ">", "<", ".ps1", "strings "]):
                    self.process.start("cmd.exe", ["/c", self.command_info])
                else:
                    self.process.start(self.command_info)
            else:
                self.update_output.emit("Error: Invalid command type provided to AnalysisWorker.")
                self.analysis_complete.emit(False)
                return

            if not self.process.waitForStarted(7000):
                err_msg = f"Error: Process failed to start command: {' '.join(self.command_info) if isinstance(self.command_info, list) else self.command_info}"
                self.update_output.emit(err_msg)
                self.analysis_complete.emit(False)
                return
                
            self.process.waitForFinished(-1)

            output = self.process.readAll().data().decode('utf-8', errors='replace')
            
            self.update_output.emit(output)
            self.analysis_complete.emit(self.process.exitCode() == 0)
        except Exception as e:
            self.update_output.emit(f"Error in AnalysisWorker: {str(e)}")
            self.analysis_complete.emit(False)
        finally:
            if self.process and self.process.state() != QProcess.NotRunning:
                try:
                    self.process.kill()
                    self.process.waitForFinished(2000)
                except Exception:
                    pass

    def stop(self):
        if self.process and self.process.state() != QProcess.NotRunning:
            try:
                self.process.kill()
            except Exception:
                pass

class AnalyzerTab(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(10, 10, 10, 10)
        
        self.setup_target_section()
        self.setup_analysis_options()
        self.setup_results_section()
        
        self.worker = None
        self.current_path = None # Used for both file and directory paths

    def setup_target_section(self):
        target_group = QGroupBox("Target File or Directory")
        target_layout = QVBoxLayout()

        path_input_layout = QHBoxLayout()
        self.target_path_lineedit = QLineEdit()
        self.target_path_lineedit.setPlaceholderText("Enter path or use browse buttons...")
        self.target_path_lineedit.textChanged.connect(self.update_current_path_from_lineedit)
        path_input_layout.addWidget(self.target_path_lineedit)
        target_layout.addLayout(path_input_layout)

        browse_buttons_layout = QHBoxLayout()
        browse_file_button = QPushButton("Browse File")
        browse_file_button.clicked.connect(self.browse_file)
        browse_buttons_layout.addWidget(browse_file_button)

        browse_dir_button = QPushButton("Browse Directory")
        browse_dir_button.clicked.connect(self.browse_directory)
        browse_buttons_layout.addWidget(browse_dir_button)
        target_layout.addLayout(browse_buttons_layout)

        self.target_display_label = QLabel("No file or directory selected")
        self.target_display_label.setStyleSheet("color: white; padding-top: 5px;")
        target_layout.addWidget(self.target_display_label)

        target_group.setLayout(target_layout)
        self.layout.addWidget(target_group)

    def update_current_path_from_lineedit(self, text):
        self.current_path = text.strip()
        if self.current_path:
            self.target_display_label.setText(f"Selected: {os.path.basename(self.current_path) if self.current_path else 'N/A'}")
        else:
            self.target_display_label.setText("No file or directory selected")

    def setup_analysis_options(self):
        options_group = QGroupBox("Analysis Options")
        options_layout = QHBoxLayout()
        
        self.analysis_type = QComboBox()
        self.analysis_type.addItems([
            "Basic Analysis", 
            "Static Analysis", 
            "Extract Strings", 
            "Check Signatures",
            "Resource Analysis",
            "Check Packer",
            "Find Domains/URLs",
            "Create MITRE ATT&CK Table",
            "PowerShell Script Analysis"
        ])
        options_layout.addWidget(self.analysis_type)
        
        self.run_button = QPushButton("Run Analysis")
        self.run_button.clicked.connect(self.run_analysis)
        options_layout.addWidget(self.run_button)
        
        export_button = QPushButton("Export Report")
        export_button.clicked.connect(self.export_report)
        options_layout.addWidget(export_button)
        
        options_group.setLayout(options_layout)
        self.layout.addWidget(options_group)
        
    def setup_results_section(self):
        splitter = QSplitter(Qt.Vertical)
        output_group = QGroupBox("Analysis Output")
        output_layout = QVBoxLayout()
        
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        font = QFont("Monospace")
        font.setStyleHint(QFont.TypeWriter)
        font.setPointSize(9)
        self.output_text.setFont(font)
        self.output_text.setLineWrapMode(QTextEdit.NoWrap)
        output_layout.addWidget(self.output_text)
        
        output_group.setLayout(output_layout)
        splitter.addWidget(output_group)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("Ready")
        self.progress_bar.setValue(0)
        
        self.layout.addWidget(self.progress_bar)
        self.layout.addWidget(splitter, 1)

    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select File for Analysis", "",
            "All Executables (*.exe *.dll *.sys *.elf *.dylib *.macho);;"
            "Windows Files (*.exe *.dll *.msi);;"
            "Linux Files (*.elf);;"
            "Apple Files (*.dylib *.macho);;"
            "Android/Java (*.apk *.jar *.dex);;"
            "PowerShell Scripts (*.ps1);;"
            "All Files (*)")
        if file_path:
            self.load_path(file_path)

    def browse_directory(self):
        dir_path = QFileDialog.getExistingDirectory(self, "Select Directory for Analysis")
        if dir_path:
            self.load_path(dir_path)
            
    def load_path(self, path_str):
        path_str = path_str.strip()
        if not os.path.exists(path_str):
            self.output_text.setText(f"Error: Path {path_str} not found.")
            self.current_path = None
            self.target_path_lineedit.clear()
            self.target_display_label.setText("No file or directory selected")
            return
            
        self.current_path = path_str
        self.target_path_lineedit.setText(path_str)
        self.target_display_label.setText(f"Selected: {os.path.basename(path_str)}")
        
        sc0pe_p = getattr(self.main_window, 'sc0pe_path', os.getcwd())
        # .target-file.txt is legacy, consider removing if not used by CLI scripts directly
        target_indicator_file = os.path.join(sc0pe_p, ".target-file.txt")
        try:
            with open(target_indicator_file, "w", encoding='utf-8') as f:
                f.write(path_str)
        except Exception as e:
            print(f"Warning: Could not write {target_indicator_file}: {e}")
        
        if os.path.isfile(path_str):
            try:
                file_type_info = "N/A (puremagic not available)"
                if pr:
                    try: file_type_info = str(pr.magic_file(path_str))
                    except Exception as pe: file_type_info = f"puremagic error: {pe}"
                file_size = os.path.getsize(path_str) / 1024 # in KB
                info_text = f"File: {os.path.basename(path_str)}\n"
                info_text += f"Path: {path_str}\n"
                info_text += f"Type: {file_type_info}\n"
                info_text += f"Size: {file_size:.2f} KB\n"
                self.output_text.setText(info_text)
            except Exception as e:
                self.output_text.setText(f"Error getting file info: {str(e)}")
        elif os.path.isdir(path_str):
            info_text = f"Directory: {os.path.basename(path_str)}\n"
            info_text += f"Path: {path_str}\n"
            try:
                num_files = len([name for name in os.listdir(path_str) if os.path.isfile(os.path.join(path_str, name))])
                info_text += f"Files in directory: {num_files}\n"
            except Exception as e:
                info_text += f"Could not count files: {e}\n"
            self.output_text.setText(info_text)
        else:
            self.output_text.setText(f"Selected path is neither a file nor a directory: {path_str}")

            
    def get_analysis_command(self, analysis_type):
        if not self.current_path:
            # This case should ideally be prevented by disabling the run button if no path is set
            QMessageBox.warning(self, "Setup Error", "No target file or directory has been loaded.")
            return None
            
        target_path = self.current_path
        sc0pe_path = getattr(self.main_window, 'sc0pe_path', os.getcwd())
        py_binary = getattr(self.main_window, 'py_binary', sys.executable)
        
        is_frozen = getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS')
        cli_exe_name = "qu1cksc0pe.exe" if sys.platform == "win32" else "qu1cksc0pe"
        cli_exe = os.path.join(sc0pe_path, cli_exe_name)

        def _get_script_path(script_name):
            return os.path.join(sc0pe_path, "Modules", script_name)
        
        main_cli_script = os.path.join(sc0pe_path, "qu1cksc0pe.py")

        # Define command structures
        # These maps help manage commands for non-frozen (direct script) vs frozen (CLI executable) app states
        base_commands = { # Commands for running scripts directly
            "Basic Analysis": [py_binary, main_cli_script, "--file", target_path, "--analyze"],
            "Check Signatures": [py_binary, _get_script_path("sigChecker.py"), target_path],
            "Resource Analysis": [py_binary, _get_script_path("resourceChecker.py"), target_path],
            "Find Domains/URLs": [py_binary, _get_script_path("domainCatcher.py"), target_path],
            "Create MITRE ATT&CK Table": [py_binary, _get_script_path("mitre.py"), target_path],
            "PowerShell Script Analysis": [py_binary, _get_script_path("powershell_analyzer.py"), target_path]
        }

        frozen_commands = { # Commands for the frozen CLI application
            "Basic Analysis": [cli_exe, "--file", target_path, "--analyze"],
            "Check Signatures": [cli_exe, "--module", "sigChecker", "--file", target_path],
            "Resource Analysis": [cli_exe, "--module", "resourceChecker", "--file", target_path],
            "Find Domains/URLs": [cli_exe, "--module", "domainCatcher", "--file", target_path],
            "Create MITRE ATT&CK Table": [cli_exe, "--module", "mitre", "--file", target_path],
            "PowerShell Script Analysis": [cli_exe, "--module", "powershell_analyzer", "--file", target_path]
        }

        cmd_map_to_use = base_commands
        # Check if running as a frozen app and if the CLI executable exists and supports the module
        # The 'cli_supports_module' is a hypothetical check on main_window, replace with actual mechanism if exists
        if is_frozen and os.path.exists(cli_exe):
            # Simplified: Assume CLI supports all modules listed in frozen_commands if it exists
            # A more robust check might involve querying the CLI or having a capabilities list.
            if analysis_type in frozen_commands: # and getattr(self.main_window, 'cli_supports_module', lambda x: True)(analysis_type_to_cli_module_name.get(analysis_type)):
                 cmd_map_to_use = frozen_commands


        # Handle "Check Packer" separately due to file/directory logic
        if analysis_type == "Check Packer":
            packer_script = _get_script_path("packerAnalyzer.py")
            packer_module_name_for_cli = "packerAnalyzer" # Assuming this is the module name for CLI
            
            if os.path.isdir(target_path):
                if is_frozen and os.path.exists(cli_exe) and getattr(self.main_window, 'cli_supports_module', lambda x: True)(packer_module_name_for_cli):
                    return [cli_exe, "--module", packer_module_name_for_cli, "--multiscan", target_path]
                else:
                    return [py_binary, packer_script, "--multiscan", target_path]
            else: # It's a file
                if is_frozen and os.path.exists(cli_exe) and getattr(self.main_window, 'cli_supports_module', lambda x: True)(packer_module_name_for_cli):
                    return [cli_exe, "--module", packer_module_name_for_cli, "--single", target_path]
                else:
                    return [py_binary, packer_script, "--single", target_path]

        # Handle commands that generally require a file target
        if analysis_type in cmd_map_to_use:
            if not os.path.isfile(target_path):
                 # Example: PowerShell Script Analysis might be intended for files only.
                 # Add more specific checks if some of these can operate on directories.
                 if analysis_type not in []: # Empty list means all in cmd_map_to_use are file-only
                    QMessageBox.warning(self, "Type Error", f"'{analysis_type}' requires a file, but a directory was provided.")
                    return None
            return cmd_map_to_use[analysis_type]

        # Handle "Static Analysis" which has complex conditions based on file type
        elif analysis_type == "Static Analysis":
            if not os.path.isfile(target_path):
                QMessageBox.warning(self, "Type Error", "Static Analysis requires a file, but a directory was provided.")
                return None
            
            file_type_info = ""
            if pr:
                try: file_type_info = str(pr.magic_file(target_path))
                except Exception: pass # puremagic can fail on some files
            
            # Module names for CLI
            win_module = "windows_static_analyzer"
            linux_module = "linux_static_analyzer"
            apple_module = "apple_analyzer"
            apk_module = "apkAnalyzer"

            # Check if CLI supports these modules (hypothetical check)
            cli_supports_win = getattr(self.main_window, 'cli_supports_module', lambda x: True)(win_module)
            cli_supports_linux = getattr(self.main_window, 'cli_supports_module', lambda x: True)(linux_module)
            cli_supports_apple = getattr(self.main_window, 'cli_supports_module', lambda x: True)(apple_module)
            cli_supports_apk = getattr(self.main_window, 'cli_supports_module', lambda x: True)(apk_module)

            if is_frozen and os.path.exists(cli_exe):
                if ("Windows Executable" in file_type_info or any(target_path.lower().endswith(ext) for ext in [".exe", ".dll", ".msi"])) and cli_supports_win:
                    return [cli_exe, "--module", win_module, "--file", target_path]
                elif "ELF" in file_type_info and cli_supports_linux: return [cli_exe, "--module", linux_module, "--file", target_path]
                elif "Mach-O" in file_type_info and cli_supports_apple: return [cli_exe, "--module", apple_module, "--file", target_path]
                elif (("PK" in file_type_info and "Java archive" in file_type_info) or \
                     any(target_path.lower().endswith(ext) for ext in [".apk", ".jar", ".dex"])) and cli_supports_apk:
                    mode = "DEX" if target_path.lower().endswith(".dex") else "APK"
                    return [cli_exe, "--module", apk_module, "--file", target_path, "--mode", mode]
            
            # Fallback to direct script execution if not frozen, CLI doesn't exist, or module not supported by CLI via hypothetical check
            if "Windows Executable" in file_type_info or any(target_path.lower().endswith(ext) for ext in [".exe", ".dll", ".msi"]):
                return [py_binary, _get_script_path("windows_static_analyzer.py"), target_path, "True"] # Assuming "True" is for report flag
            elif "ELF" in file_type_info: return [py_binary, _get_script_path("linux_static_analyzer.py"), target_path, "True"]
            elif "Mach-O" in file_type_info: return [py_binary, _get_script_path("apple_analyzer.py"), target_path] # apple_analyzer.py might not take report flag
            elif ("PK" in file_type_info and "Java archive" in file_type_info) or \
                    any(target_path.lower().endswith(ext) for ext in [".apk", ".jar", ".dex"]):
                mode = "DEX" if target_path.lower().endswith(".dex") else "APK"
                # apkAnalyzer.py has different signature in provided example (target, is_report_export, mode)
                return [py_binary, _get_script_path("apkAnalyzer.py"), target_path, "False", mode]
            
            QMessageBox.information(self, "Info", "Static analysis for this file type is not specifically supported or identifiable. Attempting basic analysis.")
            return cmd_map_to_use.get("Basic Analysis") # Fallback to Basic Analysis for unknown file types

        # Handle "Extract Strings" which uses system `strings` command or bundled `strings.exe`
        elif analysis_type == "Extract Strings":
            if not os.path.isfile(target_path):
                QMessageBox.warning(self, "Type Error", "Extract Strings requires a file.")
                return None
            if sys.platform == "win32":
                strings_exe_path = os.path.join(sc0pe_path, "strings.exe") # Check for bundled strings.exe
                if not os.path.exists(strings_exe_path): strings_exe_path = "strings" # Fallback to system path
                return [strings_exe_path, "-a", target_path]
            else: # Linux/macOS
                return ["strings", "--all", target_path] # System strings command

        QMessageBox.warning(self, "Command Error", f"Could not determine command for analysis type: {analysis_type}")
        return None
            
    def run_analysis(self):
        if not self.current_path:
            QMessageBox.warning(self, "Warning", "No file or directory selected for analysis.")
            return
            
        analysis_type = self.analysis_type.currentText()
        command_info = self.get_analysis_command(analysis_type)
        
        if not command_info:
            # Error message should have been shown by get_analysis_command
            return
            
        self.run_button.setEnabled(False)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat(f"Starting {analysis_type}...")
        self.output_text.clear()
        
        # Construct a display string for the command
        command_display_str = ""
        if isinstance(command_info, list):
            # Quote parts of the command if they contain spaces, for display purposes
            quoted_parts = []
            for part in command_info:
                part_str = str(part)
                if ' ' in part_str and not (part_str.startswith('"') and part_str.endswith('"')):
                    quoted_parts.append(f'"{part_str}"')
                else:
                    quoted_parts.append(part_str)
            command_display_str = ' '.join(quoted_parts)
        elif isinstance(command_info, str):
            command_display_str = command_info # This case is for cmd.exe /c ...

        self.output_text.setText(f"Running {analysis_type}...\nTarget: {self.current_path}\nCommand: {command_display_str}\nWorking Dir: {getattr(self.main_window, 'sc0pe_path', os.getcwd())}\n\n")

        if self.worker and self.worker.isRunning():
            self.worker.stop()
            if not self.worker.wait(3000): # Wait up to 3 seconds for the worker to finish
                print("Warning: Previous worker did not terminate cleanly after stop signal.")
                # Consider more forceful termination or user notification if needed

        self.worker = AnalysisWorker(command_info, cwd=getattr(self.main_window, 'sc0pe_path', os.getcwd()))
        self.worker.update_output.connect(self.update_analysis_output)
        self.worker.analysis_complete.connect(self.analysis_completed)
        self.worker.start()
        self.progress_bar.setRange(0, 0) # Set to indeterminate progress
        
    def update_analysis_output(self, output):
        cursor = self.output_text.textCursor()
        cursor.movePosition(QTextCursor.End)
        cursor.insertText(output)
        self.output_text.ensureCursorVisible() # Auto-scroll to the bottom
        
    def analysis_completed(self, success):
        self.run_button.setEnabled(True)
        self.progress_bar.setRange(0, 100) # Set back to determinate range
        if success:
            self.progress_bar.setValue(100)
            self.progress_bar.setFormat("Analysis completed successfully")
        else:
            self.progress_bar.setValue(100) # Show full bar even on failure, but format indicates error
            self.progress_bar.setFormat("Analysis failed, was interrupted, or script error.")
            # Optionally, style the progress bar red on failure
            # self.progress_bar.setStyleSheet("QProgressBar::chunk { background-color: red; border-radius: 2px; }")
            
    def export_report(self):
        if not self.current_path:
            QMessageBox.warning(self, "Warning", "No file or directory analyzed yet.")
            return
        report_content = self.output_text.toPlainText()
        # A more robust check for meaningful content might be needed
        if not report_content or report_content.count('\n') < 5 : # Basic check: at least a few lines of output
            QMessageBox.warning(self, "Warning", "No substantial analysis results to export.")
            return
            
        base_name = os.path.basename(self.current_path)
        analysis_name_part = self.analysis_type.currentText().replace(' ', '_').replace('/', '_') # Sanitize for filename
        suggested_filename = f"{os.path.splitext(base_name)[0]}_{analysis_name_part}_report.txt"

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Report", suggested_filename,
            "Text Files (*.txt);;All Files (*)")
            
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(report_content)
                QMessageBox.information(self, "Success", f"Report exported to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export report: {str(e)}")

    # This is typically for QMainWindow or QDialog. For a QWidget tab, cleanup is handled by parent.
    # def closeEvent(self, event):
    #     if self.worker and self.worker.isRunning():
    #         self.worker.stop()
    #         self.worker.wait()
    #     super().closeEvent(event) # Ensure to call super if this widget were a top-level window

if __name__ == '__main__':
    app = QApplication(sys.argv)
    # DummyMainWindow setup for testing AnalyzerTab
    class DummyMainWindow(QWidget):
        def __init__(self):
            super().__init__()
            # Determine sc0pe_path assuming this script is in 'gui/' and project root is its parent
            current_script_path = os.path.dirname(os.path.abspath(__file__))
            self.sc0pe_path = os.path.dirname(current_script_path)
            self.py_binary = sys.executable

            # Ensure .path_handler exists in the determined sc0pe_path for modules
            path_h_file = os.path.join(self.sc0pe_path, ".path_handler")
            if not os.path.exists(path_h_file):
                try:
                    with open(path_h_file, "w", encoding='utf-8') as f:
                        f.write(self.sc0pe_path)
                except Exception as e:
                    print(f"Test Warning: Could not create .path_handler in {self.sc0pe_path}: {e}")
            print(f"Test mode: sc0pe_path set to {self.sc0pe_path}")

        # Dummy method to simulate checking CLI capabilities for frozen app scenarios
        def cli_supports_module(self, module_name_for_cli_arg):
            # In a real application, this might check a capabilities list of the frozen CLI.
            # For testing purposes, let's assume it supports some common ones.
            supported_modules_by_cli = ["packerAnalyzer", "windows_static_analyzer", "sigChecker", "resourceChecker", "domainCatcher", "mitre"]
            if module_name_for_cli_arg in supported_modules_by_cli:
                 # print(f"Dummy cli_supports_module: Claiming support for {module_name_for_cli_arg}")
                 return True
            # print(f"Dummy cli_supports_module: Claiming NO support for {module_name_for_cli_arg}")
            return False

    main_win_instance = DummyMainWindow()
    analyzer_tab = AnalyzerTab(main_win_instance)

    # Embed AnalyzerTab in a simple QWidget window for testing
    test_window = QWidget()
    layout = QVBoxLayout(test_window)
    layout.addWidget(analyzer_tab)
    test_window.setWindowTitle("AnalyzerTab Test Standalone")
    test_window.resize(900, 700)
    test_window.show()

    sys.exit(app.exec_())
