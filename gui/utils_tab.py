#!/usr/bin/python3

import os
import sys
import subprocess
import hashlib
import requests
import json
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, 
                           QLabel, QPushButton, QTextEdit, QTabWidget, 
                           QLineEdit, QComboBox, QCheckBox, QFileDialog, 
                           QMessageBox, QProgressBar, QFrame, QScrollArea)
from PyQt5.QtCore import Qt, QProcess, pyqtSignal, QThread, QTimer
from PyQt5.QtGui import QFont, QColor, QPalette, QTextCursor

class CopyButton(QPushButton):
    def __init__(self, text_to_copy, parent=None):
        super().__init__(parent)
        self.setText("Copy")
        self.setFixedWidth(60)
        self.setCursor(Qt.PointingHandCursor)
        self.text_to_copy = text_to_copy
        self.clicked.connect(self.copy_to_clipboard)
        self.setStyleSheet("""
            QPushButton {
                background-color: #333;
                color: white;
                border: 1px solid #555;
                border-radius: 3px;
                padding: 5px;
            }
            QPushButton:hover {
                background-color: #444;
            }
            QPushButton:pressed {
                background-color: #222;
            }
        """)
        
    def copy_to_clipboard(self):
        from PyQt5.QtWidgets import QApplication
        QApplication.clipboard().setText(self.text_to_copy)
        original_text = self.text()
        self.setText("Copied!")
        self.setEnabled(False)
        QTimer.singleShot(1000, lambda: self.reset_button(original_text))
    
    def reset_button(self, original_text):
        self.setText(original_text)
        self.setEnabled(True)

class ResultCard(QFrame):
    def __init__(self, title, content, parent=None, copyable=True):
        super().__init__(parent)
        self.setFrameStyle(QFrame.StyledPanel | QFrame.Raised)
        self.setLineWidth(2)
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        header_layout = QHBoxLayout()
        title_label = QLabel(title)
        title_label.setFont(QFont("Arial", 10, QFont.Bold))
        header_layout.addWidget(title_label)
        if copyable:
            copy_button = CopyButton(content)
            header_layout.addWidget(copy_button)
        header_layout.addStretch()
        layout.addLayout(header_layout)
        content_label = QLabel(content)
        content_label.setFont(QFont("Arial", 9))
        content_label.setWordWrap(True)
        layout.addWidget(content_label)
        self.setStyleSheet("""
            ResultCard {
                background-color: black;
                border: 1px solid #ddd;
                border-radius: 5px;
                padding: 10px;
            }
            QLabel {
                color: white;
            }
        """)

class DetectionCard(QFrame):
    def __init__(self, av_name, result, parent=None):
        super().__init__(parent)
        self.setFrameStyle(QFrame.StyledPanel | QFrame.Raised)
        self.setLineWidth(2)
        layout = QHBoxLayout(self)
        layout.setSpacing(15)
        info_layout = QHBoxLayout()
        av_label = QLabel(av_name)
        av_label.setFont(QFont("Arial", 9, QFont.Bold))
        info_layout.addWidget(av_label)
        result_label = QLabel(result)
        result_label.setFont(QFont("Arial", 9))
        result_label.setStyleSheet("color: #ff6666;")
        info_layout.addWidget(result_label)
        info_layout.addStretch()
        layout.addLayout(info_layout, stretch=1)
        copy_text = f"{av_name}: {result}"
        copy_button = CopyButton(copy_text)
        layout.addWidget(copy_button)
        self.setStyleSheet("""
            DetectionCard {
                background-color: #1a1a1a;
                border: 1px solid #333;
                border-radius: 5px;
                padding: 8px;
            }
            QLabel {
                color: white;
            }
        """)

class UtilsTab(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(10, 10, 10, 10)
        
        # VirusTotal Section
        self.vt_section = self.create_virustotal_section()
        self.layout.addWidget(self.vt_section)

        # Hash Scanner Section
        self.hash_scanner_section_widget = self.create_hash_scanner_section()
        self.layout.addWidget(self.hash_scanner_section_widget)

        self.hash_process = QProcess(self)
        self.hash_process.readyReadStandardOutput.connect(self.handle_hash_stdout)
        self.hash_process.readyReadStandardError.connect(self.handle_hash_stderr)
        self.hash_process.finished.connect(self.hash_process_finished)
        
        self.current_hash_output_target = None # To direct QProcess output to the correct QTextEdit

    def create_virustotal_section(self):
        section = QWidget()
        layout = QVBoxLayout(section)
        key_group = QGroupBox("VirusTotal API Key")
        key_layout = QHBoxLayout()
        self.vt_api_key = QLineEdit()
        self.vt_api_key.setPlaceholderText("Enter your VirusTotal API key...")
        self.vt_api_key.setEchoMode(QLineEdit.Password)
        key_layout.addWidget(self.vt_api_key, 1)
        save_key_button = QPushButton("Save Key")
        save_key_button.clicked.connect(self.save_vt_api_key)
        key_layout.addWidget(save_key_button)
        key_group.setLayout(key_layout)
        scan_group = QGroupBox("Scan File with VirusTotal")
        scan_layout = QHBoxLayout()
        self.vt_file_path = QLineEdit()
        self.vt_file_path.setPlaceholderText("Select a file to scan...")
        scan_layout.addWidget(self.vt_file_path, 1)
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self.browse_vt_file)
        scan_layout.addWidget(browse_button)
        scan_button = QPushButton("Scan with VT")
        scan_button.clicked.connect(self.scan_vt_file)
        scan_layout.addWidget(scan_button)
        scan_group.setLayout(scan_layout)
        results_group = QGroupBox("VirusTotal Scan Results")
        results_scroll = QScrollArea()
        results_scroll.setWidgetResizable(True)
        results_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        results_widget = QWidget()
        self.vt_results_layout = QVBoxLayout(results_widget)
        self.vt_results_layout.setSpacing(10)
        self.vt_results_layout.setAlignment(Qt.AlignTop)
        results_scroll.setWidget(results_widget)
        results_layout_inner = QVBoxLayout()
        results_layout_inner.addWidget(results_scroll)
        results_group.setLayout(results_layout_inner)
        layout.addWidget(key_group)
        layout.addWidget(scan_group)
        layout.addWidget(results_group, 1)
        try:
            # Look for API key in main_window.sc0pe_path for better portability
            key_file_path = os.path.join(self.main_window.sc0pe_path, ".vt_api_key")
            if os.path.exists(key_file_path):
                with open(key_file_path, "r") as f:
                    self.vt_api_key.setText(f.read().strip())
        except Exception as e:
            print(f"Error loading VT API key: {e}") # Log error, but don't crash
            pass
        return section

    def create_hash_scanner_section(self):
        section = QWidget()
        section_layout = QVBoxLayout(section)

        scanner_group = QGroupBox("Local Hash Scanner (MalwareHashDB)")
        scanner_group_layout = QVBoxLayout()

        path_selection_layout = QHBoxLayout()
        self.hash_scan_path_lineedit = QLineEdit()
        self.hash_scan_path_lineedit.setPlaceholderText("Select file or directory for hash scan...")
        path_selection_layout.addWidget(self.hash_scan_path_lineedit)

        browse_file_button = QPushButton("Browse File")
        browse_file_button.clicked.connect(self.browse_hash_scan_file)
        path_selection_layout.addWidget(browse_file_button)

        browse_dir_button = QPushButton("Browse Directory")
        browse_dir_button.clicked.connect(self.browse_hash_scan_directory)
        path_selection_layout.addWidget(browse_dir_button)
        scanner_group_layout.addLayout(path_selection_layout)

        scan_controls_layout = QHBoxLayout()
        scan_file_button = QPushButton("Scan File")
        scan_file_button.clicked.connect(self.start_hash_scan_file)
        scan_controls_layout.addWidget(scan_file_button)

        scan_dir_button = QPushButton("Scan Directory")
        scan_dir_button.clicked.connect(self.start_hash_scan_directory)
        scan_controls_layout.addWidget(scan_dir_button)
        scanner_group_layout.addLayout(scan_controls_layout)
        scanner_group.setLayout(scanner_group_layout)
        section_layout.addWidget(scanner_group)

        results_group = QGroupBox("Hash Scan Results")
        results_layout = QVBoxLayout()
        self.hash_scan_results_textedit = QTextEdit()
        self.hash_scan_results_textedit.setReadOnly(True)
        self.hash_scan_results_textedit.setFont(QFont("Monospace", 9)) # Monospaced font for table-like output
        self.hash_scan_results_textedit.setLineWrapMode(QTextEdit.NoWrap)
        results_layout.addWidget(self.hash_scan_results_textedit)
        results_group.setLayout(results_layout)
        section_layout.addWidget(results_group)

        db_manage_group = QGroupBox("Hash Database Management")
        db_manage_layout = QVBoxLayout()

        update_db_button = QPushButton("Download/Update Hash DB")
        update_db_button.clicked.connect(self.update_hash_database)
        db_manage_layout.addWidget(update_db_button)

        self.hash_db_manage_output_textedit = QTextEdit()
        self.hash_db_manage_output_textedit.setReadOnly(True)
        self.hash_db_manage_output_textedit.setFont(QFont("Monospace", 9))
        self.hash_db_manage_output_textedit.setLineWrapMode(QTextEdit.NoWrap)
        self.hash_db_manage_output_textedit.setMaximumHeight(150) # Keep it relatively small
        db_manage_layout.addWidget(self.hash_db_manage_output_textedit)
        db_manage_group.setLayout(db_manage_layout)
        section_layout.addWidget(db_manage_group)

        return section

    def browse_hash_scan_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Select File for Hash Scan", "", "All Files (*)")
        if file_name:
            self.hash_scan_path_lineedit.setText(file_name)

    def browse_hash_scan_directory(self):
        dir_name = QFileDialog.getExistingDirectory(self, "Select Directory for Hash Scan")
        if dir_name:
            self.hash_scan_path_lineedit.setText(dir_name)

    def _execute_hash_scanner_command(self, command_args, output_target_textedit):
        if self.hash_process.state() == QProcess.Running:
            QMessageBox.warning(self, "Busy", "Another hash scanning or DB update process is already running.")
            return

        self.current_hash_output_target = output_target_textedit
        self.current_hash_output_target.clear()
        self.current_hash_output_target.append("Starting process...\n" + "="*50 + "\n")

        script_path = os.path.join(self.main_window.sc0pe_path, "Modules", "hashScanner.py")
        if not os.path.exists(script_path):
            error_msg = f"Error: Analysis script not found at {script_path}"
            QMessageBox.critical(self, "Error", error_msg)
            self.current_hash_output_target.append(error_msg)
            return

        python_executable = sys.executable

        full_command_list = [script_path] + [str(arg) for arg in command_args]

        # For display, quote arguments with spaces
        command_str_display_parts = [f'"{python_executable}"', f'"{script_path}"']
        for arg in command_args:
            arg_str = str(arg)
            if ' ' in arg_str:
                command_str_display_parts.append(f'"{arg_str}"')
            else:
                command_str_display_parts.append(arg_str)
        command_str_display = ' '.join(command_str_display_parts)

        self.current_hash_output_target.append(f"Executing: {command_str_display}\n\n")

        self.hash_process.setWorkingDirectory(self.main_window.sc0pe_path)
        self.hash_process.start(python_executable, full_command_list)

    def start_hash_scan_file(self):
        target_path = self.hash_scan_path_lineedit.text().strip()
        if not target_path:
            QMessageBox.warning(self, "Input Error", "Please enter a file path.")
            return
        if not os.path.isfile(target_path):
            QMessageBox.warning(self, "Input Error", f"File not found: {target_path}")
            return
        self._execute_hash_scanner_command([target_path, "--normal"], self.hash_scan_results_textedit)

    def start_hash_scan_directory(self):
        target_path = self.hash_scan_path_lineedit.text().strip()
        if not target_path:
            QMessageBox.warning(self, "Input Error", "Please enter a directory path.")
            return
        if not os.path.isdir(target_path):
            QMessageBox.warning(self, "Input Error", f"Directory not found: {target_path}")
            return
        self._execute_hash_scanner_command([target_path, "--multiscan"], self.hash_scan_results_textedit)

    def update_hash_database(self):
        self._execute_hash_scanner_command(["--db_update"], self.hash_db_manage_output_textedit)

    def handle_hash_stdout(self):
        if self.current_hash_output_target:
            data = self.hash_process.readAllStandardOutput().data().decode(errors='ignore')
            cursor = self.current_hash_output_target.textCursor()
            cursor.movePosition(QTextCursor.End)
            cursor.insertText(data)
            self.current_hash_output_target.setTextCursor(cursor) # Ensure scroll to end


    def handle_hash_stderr(self):
        if self.current_hash_output_target:
            data = self.hash_process.readAllStandardError().data().decode(errors='ignore')
            cursor = self.current_hash_output_target.textCursor()
            cursor.movePosition(QTextCursor.End)
            # Potentially format as error, but Rich uses stderr for progress bars.
            # For now, just append. If actual errors need specific formatting, this could change.
            # A simple way to make it red:
            # formatted_data = f"<font color='red'>{data.replace('<', '&lt;').replace('>', '&gt;')}</font>"
            # self.current_hash_output_target.insertHtml(formatted_data)
            # However, since Rich output can be complex, sticking to plain text to avoid HTML issues.
            cursor.insertText(data)
            self.current_hash_output_target.setTextCursor(cursor)


    def hash_process_finished(self):
        if self.current_hash_output_target:
            self.current_hash_output_target.append("\n" + "="*50 + "\nProcess finished.")
            exit_code = self.hash_process.exitCode()
            if exit_code != 0:
                # Append error message in red HTML
                error_html = f"<font color='red'>Process exited with code: {exit_code}</font>"
                self.current_hash_output_target.moveCursor(QTextCursor.End)
                self.current_hash_output_target.insertHtml(error_html)
                self.current_hash_output_target.moveCursor(QTextCursor.End)

        self.current_hash_output_target = None # Reset target

    def save_vt_api_key(self):
        api_key = self.vt_api_key.text().strip()
        if not api_key:
            QMessageBox.warning(self, "Warning", "Please enter a valid API key.")
            return
        try:
            key_file_path = os.path.join(self.main_window.sc0pe_path, ".vt_api_key")
            with open(key_file_path, "w") as f:
                f.write(api_key)
            QMessageBox.information(self, "Success", f"API key saved to {key_file_path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save API key: {str(e)}")

    def browse_vt_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File for VirusTotal Scan", "", "All Files (*)")
        if file_path:
            self.vt_file_path.setText(file_path)

    def scan_vt_file(self):
        file_path = self.vt_file_path.text().strip()
        if not file_path or not os.path.exists(file_path):
            QMessageBox.warning(self, "Warning", "Please select a valid file to scan.")
            return
        api_key = self.vt_api_key.text().strip()
        if not api_key:
            QMessageBox.warning(self, "Warning", "Please enter your VirusTotal API key (save it first).")
            return

        # Clear previous results
        for i in reversed(range(self.vt_results_layout.count())):
            widget = self.vt_results_layout.itemAt(i).widget()
            if widget is not None:
                widget.setParent(None) # Correct way to remove widgets

        try:
            file_info = ResultCard("File Information", 
                                 f"Path: {file_path}\nSize: {os.path.getsize(file_path):,} bytes", 
                                 self, copyable=True)
            self.vt_results_layout.addWidget(file_info)
            
            sha256_hash = hashlib.sha256()
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    sha256_hash.update(chunk)
            file_hash = sha256_hash.hexdigest()
            hash_card = ResultCard("File Hash (SHA256)", file_hash, self, copyable=True)
            self.vt_results_layout.addWidget(hash_card)
            
            url = 'https://www.virustotal.com/vtapi/v2/file/report'
            params = {'apikey': api_key, 'resource': file_hash}
            headers = {'Accept': 'application/json'}

            response = requests.get(url, params=params, headers=headers)
            response.raise_for_status()
            
            result = response.json()

            if result.get('response_code') == 1:
                scan_info_card = ResultCard("Scan Information",
                                       f"Scan Date: {result.get('scan_date', 'N/A')}\n"
                                       f"Detection Ratio: {result.get('positives', 0)}/{result.get('total', 0)}",
                                       self, copyable=True)
                self.vt_results_layout.addWidget(scan_info_card)

                detections_group = QGroupBox("Detections")
                detections_scroll = QScrollArea()
                detections_scroll.setWidgetResizable(True)
                detections_scroll.setFixedHeight(200)
                detections_widget = QWidget()
                detections_layout_inner = QVBoxLayout(detections_widget)
                
                scans = result.get('scans', {})
                has_detections = False
                for av, scan_result_data in scans.items():
                    if scan_result_data.get('detected'):
                        has_detections = True
                        detection_card = DetectionCard(av, scan_result_data.get('result', 'N/A'), self)
                        detections_layout_inner.addWidget(detection_card)

                if not has_detections:
                    no_detections_label = QLabel("No malicious detections found by any AV engine.")
                    no_detections_label.setStyleSheet("color: #44aa44; font-weight: bold;")
                    detections_layout_inner.addWidget(no_detections_label)

                detections_layout_inner.addStretch()
                detections_scroll.setWidget(detections_widget)
                detections_group_layout = QVBoxLayout()
                detections_group_layout.addWidget(detections_scroll)
                detections_group.setLayout(detections_group_layout)
                self.vt_results_layout.addWidget(detections_group)

            elif result.get('response_code') == 0:
                msg = result.get('verbose_msg', 'File not found in VirusTotal. You may need to upload it first.')
                status_card = ResultCard("Status", msg, self, copyable=False)
                self.vt_results_layout.addWidget(status_card)
            else:
                msg = result.get('verbose_msg', f'Unknown response_code: {result.get("response_code")}')
                error_card = ResultCard("Notice", msg, self, copyable=False)
                self.vt_results_layout.addWidget(error_card)

        except requests.exceptions.HTTPError as http_err:
            error_msg = f"HTTP error occurred: {http_err} - {response.text if 'response' in locals() else 'No response text'}"
            error_card = ResultCard("Error", error_msg, self, copyable=False)
            self.vt_results_layout.addWidget(error_card)
            QMessageBox.critical(self, "HTTP Error", error_msg)
        except Exception as e:
            error_msg = str(e)
            error_card = ResultCard("Error", f"Error during scan: {error_msg}", self, copyable=False)
            self.vt_results_layout.addWidget(error_card)
            QMessageBox.critical(self, "Error", f"Failed to scan file: {error_msg}")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    class DummyMainWindow(QMainWindow):
        def __init__(self):
            super().__init__()
            self.sc0pe_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            path_handler_file = os.path.join(self.sc0pe_path, ".path_handler")
            if not os.path.exists(path_handler_file):
                 try:
                     with open(path_handler_file, "w") as f:
                        f.write(self.sc0pe_path)
                 except Exception as e:
                     print(f"DummyMain: Could not create .path_handler: {e}")


    main_win = DummyMainWindow()
    tab = UtilsTab(main_win)
    main_win.setCentralWidget(tab)
    main_win.setWindowTitle("Utils Tab Test")
    main_win.resize(800, 700)
    main_win.show()
    sys.exit(app.exec_())
