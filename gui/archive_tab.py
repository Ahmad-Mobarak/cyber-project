#!/usr/bin/python3

import os
import sys
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGroupBox,
                           QLabel, QPushButton, QFileDialog, QTextEdit,
                           QLineEdit, QMessageBox)
from PyQt5.QtCore import QProcess

class ArchiveTab(QWidget):
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
        file_group = QGroupBox("Archive File")
        file_layout = QHBoxLayout()

        self.file_path_lineedit = QLineEdit()
        self.file_path_lineedit.setPlaceholderText("Select archive file (zip, rar, ace)...")
        file_layout.addWidget(self.file_path_lineedit)

        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self.browse_file)
        file_layout.addWidget(browse_button)

        analyze_button = QPushButton("Analyze Archive")
        analyze_button.clicked.connect(self.start_analysis)
        file_layout.addWidget(analyze_button)

        file_group.setLayout(file_layout)
        self.layout.addWidget(file_group)

    def setup_results_section(self):
        results_group = QGroupBox("Analysis Results")
        results_layout = QVBoxLayout()

        self.output_textedit = QTextEdit()
        self.output_textedit.setReadOnly(True)
        results_layout.addWidget(self.output_textedit)

        results_group.setLayout(results_layout)
        self.layout.addWidget(results_group)

    def browse_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Select Archive File", "",
                                                 "Archive Files (*.zip *.rar *.ace);;All Files (*)")
        if file_name:
            self.file_path_lineedit.setText(file_name)
            self.current_file = file_name

    def start_analysis(self):
        if not self.current_file:
            QMessageBox.warning(self, "Warning", "Please select an archive file to analyze.")
            return

        if not os.path.exists(self.current_file):
            QMessageBox.critical(self, "Error", f"File not found: {self.current_file}")
            return

        self.output_textedit.clear()
        self.output_textedit.append(f"Starting analysis for: {self.current_file}\n" + "="*50 + "\n")

        # Determine path to archiveAnalyzer.py
        # Assuming Modules directory is in the same directory as QuickScope_GUI.py or in sys.path
        script_path = os.path.join(self.main_window.sc0pe_path, "Modules", "archiveAnalyzer.py")

        if not os.path.exists(script_path):
            QMessageBox.critical(self, "Error", f"Analysis script not found: {script_path}")
            self.output_textedit.append(f"Error: Analysis script not found at {script_path}\nMake sure QuickScope is installed correctly.")
            return

        python_executable = sys.executable # Use the same python interpreter that runs the GUI

        command = f'"{python_executable}" "{script_path}" "{self.current_file}"'
        self.output_textedit.append(f"Executing command: {command}\n\n")

        self.process.setWorkingDirectory(self.main_window.sc0pe_path) # Ensure scripts run from the project root
        self.process.start(command)

    def handle_stdout(self):
        data = self.process.readAllStandardOutput().data().decode(errors='ignore')
        self.output_textedit.append(data)

    def handle_stderr(self):
        data = self.process.readAllStandardError().data().decode(errors='ignore')
        self.output_textedit.append(f"<font color='red'>{data}</font>")

    def analysis_finished(self):
        self.output_textedit.append("\n" + "="*50 + "\nAnalysis finished.")
        exit_code = self.process.exitCode()
        if exit_code != 0:
            self.output_textedit.append(f"<font color='red'>Analysis process exited with code: {exit_code}</font>")

if __name__ == '__main__':
    # This part is for testing the tab independently if needed
    from PyQt5.QtWidgets import QApplication, QMainWindow
    app = QApplication(sys.argv)
    # Dummy main window for testing
    class DummyMainWindow(QMainWindow):
        def __init__(self):
            super().__init__()
            self.sc0pe_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) # Assumes script is in gui/
            if not os.path.exists(os.path.join(self.sc0pe_path, ".path_handler")):
                 with open(os.path.join(self.sc0pe_path, ".path_handler"), "w") as f:
                    f.write(self.sc0pe_path)


    main_win = DummyMainWindow()
    tab = ArchiveTab(main_win)
    main_win.setCentralWidget(tab)
    main_win.setWindowTitle("Archive Analysis Tab Test")
    main_win.show()
    sys.exit(app.exec_())
