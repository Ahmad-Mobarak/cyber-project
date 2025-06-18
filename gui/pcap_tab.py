#!/usr/bin/python3

import os
import sys
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGroupBox,
                           QLabel, QPushButton, QFileDialog, QTextEdit,
                           QLineEdit, QMessageBox, QScrollArea)
from PyQt5.QtCore import QProcess, Qt
from PyQt5.QtGui import QFont # Added QFont

class PCAPTab(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(10, 10, 10, 10)

        # File selection section
        self.setup_file_selection()

        # Results section
        self.setup_results_section()

        self.process = QProcess(self)
        self.process.readyReadStandardOutput.connect(self.handle_stdout)
        self.process.readyReadStandardError.connect(self.handle_stderr)
        self.process.finished.connect(self.analysis_finished)

        self.current_file = None

    def setup_file_selection(self):
        file_group = QGroupBox("PCAP File (.pcap, .pcapng)")
        file_layout = QHBoxLayout()

        self.file_path_lineedit = QLineEdit()
        self.file_path_lineedit.setPlaceholderText("Select PCAP file to analyze...")
        file_layout.addWidget(self.file_path_lineedit)

        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self.browse_file)
        file_layout.addWidget(browse_button)

        analyze_button = QPushButton("Analyze PCAP")
        analyze_button.clicked.connect(self.start_analysis)
        file_layout.addWidget(analyze_button)

        file_group.setLayout(file_layout)
        self.layout.addWidget(file_group)

    def setup_results_section(self):
        results_group = QGroupBox("Analysis Results")
        results_layout = QVBoxLayout()

        # Using QScrollArea for potentially long output
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)

        self.output_textedit = QTextEdit()
        self.output_textedit.setReadOnly(True)
        self.output_textedit.setFont(QFont("Monospace", 9)) # Monospaced font for tables
        self.output_textedit.setLineWrapMode(QTextEdit.NoWrap) # pcap_analyzer uses tables

        scroll_area.setWidget(self.output_textedit)
        results_layout.addWidget(scroll_area)
        results_group.setLayout(results_layout)
        self.layout.addWidget(results_group)

    def browse_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Select PCAP File", "",
                                                 "PCAP Files (*.pcap *.pcapng);;All Files (*)")
        if file_name:
            self.file_path_lineedit.setText(file_name)
            self.current_file = file_name
            self.output_textedit.clear()


    def start_analysis(self):
        if not self.current_file:
            QMessageBox.warning(self, "Warning", "Please select a PCAP file to analyze.")
            return

        if not os.path.exists(self.current_file):
            QMessageBox.critical(self, "Error", f"File not found: {self.current_file}")
            return

        self.output_textedit.clear()
        self.output_textedit.append(f"Starting PCAP analysis for: {self.current_file}\n" + "="*50 + "\n")

        script_path = os.path.join(self.main_window.sc0pe_path, "Modules", "pcap_analyzer.py")

        if not os.path.exists(script_path):
            QMessageBox.critical(self, "Error", f"Analysis script not found: {script_path}")
            self.output_textedit.append(f"Error: Analysis script not found at {script_path}\nMake sure QuickScope is installed correctly.")
            return

        python_executable = sys.executable
        # Add --non-interactive flag, assuming pcap_analyzer.py will support it to avoid prompts
        command_parts = [python_executable, script_path, self.current_file, "--non-interactive"]

        command_str_display = ' '.join(f'"{part}"' if ' ' in part else part for part in command_parts)
        self.output_textedit.append(f"Executing command: {command_str_display}\n\n")

        self.process.setWorkingDirectory(self.main_window.sc0pe_path)
        # For QProcess.start(), command and arguments are passed separately if not using a single string shell command
        self.process.start(python_executable, command_parts[1:])


    def handle_stdout(self):
        data = self.process.readAllStandardOutput().data().decode(errors='ignore')
        self.output_textedit.moveCursor(QTextEdit.End)
        self.output_textedit.insertPlainText(data)
        self.output_textedit.moveCursor(QTextEdit.End)


    def handle_stderr(self):
        data = self.process.readAllStandardError().data().decode(errors='ignore')
        self.output_textedit.moveCursor(QTextEdit.End)
        # stderr from rich might be progress bars, or actual errors.
        # For now, just append. Could format as red if confirmed to be only errors.
        self.output_textedit.insertPlainText(data)
        self.output_textedit.moveCursor(QTextEdit.End)

    def analysis_finished(self):
        self.output_textedit.append("\n" + "="*50 + "\nPCAP analysis finished.")
        exit_code = self.process.exitCode()
        if exit_code != 0:
            self.output_textedit.append(f"<font color='red'>Analysis process exited with code: {exit_code}</font>")

        temp_json_path = os.path.join(self.main_window.sc0pe_path, "out.json")
        if os.path.exists(temp_json_path):
            try:
                os.remove(temp_json_path)
                self.output_textedit.append(f"\nCleaned up temporary file: {temp_json_path}")
            except OSError as e:
                self.output_textedit.append(f"\n<font color='orange'>Warning: Could not clean up temporary file {temp_json_path}: {e}</font>")


if __name__ == '__main__':
    from PyQt5.QtWidgets import QApplication, QMainWindow
    from PyQt5.QtGui import QTextCursor # Import QTextCursor for the test
    app = QApplication(sys.argv)
    class DummyMainWindow(QMainWindow):
        def __init__(self):
            super().__init__()
            self.sc0pe_path = ""
            current_dir = os.path.dirname(os.path.abspath(__file__))
            project_root_candidate = os.path.dirname(current_dir)

            if os.path.exists(os.path.join(project_root_candidate, "Modules")):
                self.sc0pe_path = project_root_candidate
            else:
                path_handler_file_local = os.path.join(project_root_candidate, ".path_handler") # Check one level up
                if os.path.exists(path_handler_file_local):
                     with open(path_handler_file_local, "r") as f_path:
                        self.sc0pe_path = f_path.read().strip()
                elif os.path.exists(".path_handler"): # Check current dir (if test run from project root)
                    with open(".path_handler", "r") as f_path:
                        self.sc0pe_path = f_path.read().strip()
                else:
                    self.sc0pe_path = project_root_candidate # Fallback to parent of current script dir
                    print(f"Warning: .path_handler not found, defaulting sc0pe_path to: {self.sc0pe_path}")


            path_handler_to_create = os.path.join(self.sc0pe_path, ".path_handler")
            if not os.path.exists(path_handler_to_create) or (os.path.exists(path_handler_to_create) and open(path_handler_to_create).read().strip() != self.sc0pe_path) :
                 try:
                    with open(path_handler_to_create, "w") as f:
                        f.write(self.sc0pe_path)
                 except Exception as e:
                    print(f"Test mode: Could not create/update .path_handler in {self.sc0pe_path}: {e}")
            print(f"Test mode: sc0pe_path set to {self.sc0pe_path}")


    main_win = DummyMainWindow()
    tab = PCAPTab(main_win)
    main_win.setCentralWidget(tab)
    main_win.setWindowTitle("PCAP Analysis Tab Test")
    main_win.resize(800,600)
    main_win.show()
    sys.exit(app.exec_())
