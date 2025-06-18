#!/usr/bin/python3

import os
import sys
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGroupBox,
                           QLabel, QPushButton, QFileDialog, QTextEdit,
                           QLineEdit, QMessageBox, QListWidget, QListWidgetItem)
from PyQt5.QtCore import QProcess, Qt # Added Qt

class EmailTab(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(10, 10, 10, 10)

        # File selection section
        self.setup_file_selection()

        # Results section (includes general output and attachments)
        self.setup_results_section()

        self.process = QProcess(self)
        self.process.readyReadStandardOutput.connect(self.handle_stdout)
        self.process.readyReadStandardError.connect(self.handle_stderr)
        self.process.finished.connect(self.analysis_finished)

        self.current_file = None
        self.attachments_list = [] # To store paths of extracted attachments

    def setup_file_selection(self):
        file_group = QGroupBox("Email File (.eml)")
        file_layout = QHBoxLayout()

        self.file_path_lineedit = QLineEdit()
        self.file_path_lineedit.setPlaceholderText("Select .eml file to analyze...")
        file_layout.addWidget(self.file_path_lineedit)

        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self.browse_file)
        file_layout.addWidget(browse_button)

        analyze_button = QPushButton("Analyze Email")
        analyze_button.clicked.connect(self.start_analysis)
        file_layout.addWidget(analyze_button)

        file_group.setLayout(file_layout)
        self.layout.addWidget(file_group)

    def setup_results_section(self):
        results_main_group = QGroupBox("Analysis Results")
        results_main_layout = QVBoxLayout()

        self.output_textedit = QTextEdit()
        self.output_textedit.setReadOnly(True)
        results_main_layout.addWidget(self.output_textedit, 3) # Give more space to general output

        attachments_group = QGroupBox("Extracted Attachments (if any)")
        attachments_layout = QVBoxLayout()
        self.attachments_widget = QListWidget()
        self.attachments_widget.itemDoubleClicked.connect(self.handle_attachment_click)
        attachments_layout.addWidget(self.attachments_widget)
        attachments_group.setLayout(attachments_layout)

        results_main_layout.addWidget(attachments_group, 1) # Less space for attachment list initially

        results_main_group.setLayout(results_main_layout)
        self.layout.addWidget(results_main_group)

    def browse_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Select Email File", "",
                                                 "Email Files (*.eml);;All Files (*)")
        if file_name:
            self.file_path_lineedit.setText(file_name)
            self.current_file = file_name
            # Clear previous results when a new file is selected
            self.output_textedit.clear()
            self.attachments_widget.clear()
            self.attachments_list = []


    def start_analysis(self):
        if not self.current_file:
            QMessageBox.warning(self, "Warning", "Please select an .eml file to analyze.")
            return

        if not os.path.exists(self.current_file):
            QMessageBox.critical(self, "Error", f"File not found: {self.current_file}")
            return

        self.output_textedit.clear()
        self.attachments_widget.clear()
        self.attachments_list = []
        self.output_textedit.append(f"Starting email analysis for: {self.current_file}\n" + "="*50 + "\n")

        script_path = os.path.join(self.main_window.sc0pe_path, "Modules", "email_analyzer.py")

        if not os.path.exists(script_path):
            QMessageBox.critical(self, "Error", f"Analysis script not found: {script_path}")
            self.output_textedit.append(f"Error: Analysis script not found at {script_path}\nMake sure QuickScope is installed correctly.")
            return

        python_executable = sys.executable
        command = f'"{python_executable}" "{script_path}" "{self.current_file}"'
        self.output_textedit.append(f"Executing command: {command}\n\n")

        self.process.setWorkingDirectory(self.main_window.sc0pe_path)
        self.process.start(command)

    def handle_stdout(self):
        data = self.process.readAllStandardOutput().data().decode(errors='ignore')
        self.output_textedit.append(data)
        # Check for attachment extraction messages from email_analyzer.py
        # This is a simple heuristic; a more robust way would be structured output (e.g., JSON) from the script
        if "Attachment Name:" in data: # Assuming email_analyzer.py prints this
            lines = data.splitlines()
            for line in lines:
                if "Attachment Name:" in line:
                    try:
                        # Attempt to parse out the filename. This is fragile.
                        # Example line: "[*] Attachment Name: suspicious.docx"
                        attachment_name = line.split("Attachment Name:")[1].strip()
                        if attachment_name and not self.attachments_widget.findItems(attachment_name, Qt.MatchExactly):
                            # Construct full path if Modules/email_analyzer.py saves attachments in sc0pe_path
                            full_attachment_path = os.path.join(self.main_window.sc0pe_path, attachment_name)
                            if os.path.exists(full_attachment_path):
                                self.attachments_list.append(full_attachment_path)
                                list_item = QListWidgetItem(attachment_name)
                                list_item.setData(Qt.UserRole, full_attachment_path) # Store full path
                                self.attachments_widget.addItem(list_item)
                            else:
                                # If not in sc0pe_path, it might be relative to where email_analyzer.py ran
                                # This part might need adjustment based on how email_analyzer.py saves files
                                # Check current dir (which is sc0pe_path because CWD for QProcess is set)
                                if os.path.exists(os.path.join(self.main_window.sc0pe_path, attachment_name)):
                                     self.attachments_list.append(os.path.join(self.main_window.sc0pe_path, attachment_name))
                                     list_item = QListWidgetItem(attachment_name)
                                     list_item.setData(Qt.UserRole, os.path.join(self.main_window.sc0pe_path, attachment_name))
                                     self.attachments_widget.addItem(list_item)
                    except Exception as e:
                        self.output_textedit.append(f"<font color='orange'>Could not parse attachment line: {line} (Error: {e})</font>")


    def handle_stderr(self):
        data = self.process.readAllStandardError().data().decode(errors='ignore')
        self.output_textedit.append(f"<font color='red'>{data}</font>")

    def analysis_finished(self):
        self.output_textedit.append("\n" + "="*50 + "\nEmail analysis finished.")
        exit_code = self.process.exitCode()
        if exit_code != 0:
            self.output_textedit.append(f"<font color='red'>Analysis process exited with code: {exit_code}</font>")

        # After analysis, explicitly list attachments if email_analyzer.py saves them
        # and prints their names in a predictable way or if we can find them in the working dir.
        # The current handle_stdout tries to catch them as they are printed.
        # We might need a more robust way if email_analyzer.py changes its output.
        # For now, the current handle_stdout attempts to populate this.

    def handle_attachment_click(self, item):
        attachment_path = item.data(Qt.UserRole)
        if attachment_path and os.path.exists(attachment_path):
            reply = QMessageBox.information(self, "Attachment Selected",
                                         f"Selected attachment: {item.text()}\nPath: {attachment_path}\n\n"
                                         "What would you like to do with this attachment?\n\n"
                                         "(Functionality to analyze attachments further needs to be implemented, "
                                         "e.g., by sending to the appropriate analysis tab).",
                                         QMessageBox.Ok)
            # Future: Implement logic to send 'attachment_path' to another tab
            # For example, if it's a .zip, open ArchiveTab with this file.
            # Or, if it's a .exe, open AnalyzerTab.
            # self.main_window.open_file_in_analyzer_tab(attachment_path) # Example
        else:
            QMessageBox.warning(self, "Attachment Error", f"Could not find attachment at path: {attachment_path}")


if __name__ == '__main__':
    from PyQt5.QtWidgets import QApplication, QMainWindow
    app = QApplication(sys.argv)
    class DummyMainWindow(QMainWindow):
        def __init__(self):
            super().__init__()
            # Try to get path from existing .path_handler or set a sensible default for testing
            self.sc0pe_path = ""
            # Determine path relative to this script file for testing
            script_dir = os.path.dirname(os.path.abspath(__file__)) # gui directory
            project_root_candidate = os.path.dirname(script_dir) # one level up from gui

            path_handler_in_project_root = os.path.join(project_root_candidate, ".path_handler")

            if os.path.exists(path_handler_in_project_root):
                with open(path_handler_in_project_root, "r") as f_path:
                    self.sc0pe_path = f_path.read().strip()

            if not self.sc0pe_path or not os.path.isdir(self.sc0pe_path):
                 self.sc0pe_path = project_root_candidate # Fallback

            # Ensure .path_handler exists in the determined sc0pe_path for the module to read
            final_path_handler = os.path.join(self.sc0pe_path, ".path_handler")
            if not os.path.exists(final_path_handler) or (os.path.exists(final_path_handler) and open(final_path_handler).read().strip() != self.sc0pe_path):
                 try:
                    with open(final_path_handler, "w") as f:
                        f.write(self.sc0pe_path)
                 except Exception as e:
                    print(f"Test mode: Could not create/update .path_handler in {self.sc0pe_path}: {e}")


    main_win = DummyMainWindow()
    tab = EmailTab(main_win)
    main_win.setCentralWidget(tab)
    main_win.setWindowTitle("Email Analysis Tab Test")
    main_win.show()
    sys.exit(app.exec_())
