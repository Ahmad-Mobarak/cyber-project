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
from PyQt5.QtGui import QFont, QColor, QPalette

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
        
        # Change text temporarily to show feedback
        original_text = self.text()
        self.setText("Copied!")
        self.setEnabled(False)
        
        # Reset after 1 second
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
        
        # Header layout with title and copy button
        header_layout = QHBoxLayout()
        
        # Title
        title_label = QLabel(title)
        title_label.setFont(QFont("Arial", 10, QFont.Bold))
        header_layout.addWidget(title_label)
        
        if copyable:
            # Copy button
            copy_button = CopyButton(content)
            header_layout.addWidget(copy_button)
        
        header_layout.addStretch()
        layout.addLayout(header_layout)
        
        # Content
        content_label = QLabel(content)
        content_label.setFont(QFont("Arial", 9))
        content_label.setWordWrap(True)
        layout.addWidget(content_label)
        
        # Style
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
        
        # Left side with AV name and result
        info_layout = QHBoxLayout()
        
        # AV Name
        av_label = QLabel(av_name)
        av_label.setFont(QFont("Arial", 9, QFont.Bold))
        info_layout.addWidget(av_label)
        
        # Result
        result_label = QLabel(result)
        result_label.setFont(QFont("Arial", 9))
        result_label.setStyleSheet("color: #ff6666;")  # Brighter red for better contrast on black
        info_layout.addWidget(result_label)
        
        info_layout.addStretch()
        layout.addLayout(info_layout, stretch=1)
        
        # Copy button for the full detection info
        copy_text = f"{av_name}: {result}"
        copy_button = CopyButton(copy_text)
        layout.addWidget(copy_button)
        
        # Style
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
        
        # Create layout
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(10, 10, 10, 10)
        
        # Create VirusTotal section
        self.vt_section = self.create_virustotal_section()
        self.layout.addWidget(self.vt_section)
        
    def create_virustotal_section(self):
        """Create VirusTotal section"""
        section = QWidget()
        layout = QVBoxLayout(section)
        
        # API Key section
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
        
        # File scanning section
        scan_group = QGroupBox("Scan File")
        scan_layout = QHBoxLayout()
        
        self.vt_file_path = QLineEdit()
        self.vt_file_path.setPlaceholderText("Select a file to scan...")
        scan_layout.addWidget(self.vt_file_path, 1)
        
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self.browse_vt_file)
        scan_layout.addWidget(browse_button)
        
        scan_button = QPushButton("Scan")
        scan_button.clicked.connect(self.scan_vt_file)
        scan_layout.addWidget(scan_button)
        
        scan_group.setLayout(scan_layout)
        
        # Results section with scroll area
        results_group = QGroupBox("Scan Results")
        results_scroll = QScrollArea()
        results_scroll.setWidgetResizable(True)
        results_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        
        results_widget = QWidget()
        self.vt_results_layout = QVBoxLayout(results_widget)
        self.vt_results_layout.setSpacing(10)
        self.vt_results_layout.setAlignment(Qt.AlignTop)
        
        results_scroll.setWidget(results_widget)
        
        results_layout = QVBoxLayout()
        results_layout.addWidget(results_scroll)
        results_group.setLayout(results_layout)
        
        # Add to layout
        layout.addWidget(key_group)
        layout.addWidget(scan_group)
        layout.addWidget(results_group, 1)
        
        # Load saved API key if available
        try:
            if os.path.exists(".vt_api_key"):
                with open(".vt_api_key", "r") as f:
                    self.vt_api_key.setText(f.read().strip())
        except:
            pass
            
        return section
    
    def save_vt_api_key(self):
        """Save VirusTotal API key"""
        api_key = self.vt_api_key.text().strip()
        if not api_key:
            QMessageBox.warning(self, "Warning", "Please enter a valid API key.")
            return
            
        try:
            with open(".vt_api_key", "w") as f:
                f.write(api_key)
            QMessageBox.information(self, "Success", "API key saved successfully.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save API key: {str(e)}")
    
    def browse_vt_file(self):
        """Browse for a file to scan with VirusTotal"""
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File for VirusTotal Scan", "", "All Files (*)")
        if file_path:
            self.vt_file_path.setText(file_path)
    
    def scan_vt_file(self):
        """Scan a file with VirusTotal"""
        file_path = self.vt_file_path.text().strip()
        if not file_path or not os.path.exists(file_path):
            QMessageBox.warning(self, "Warning", "Please select a valid file to scan.")
            return
            
        api_key = self.vt_api_key.text().strip()
        if not api_key:
            QMessageBox.warning(self, "Warning", "Please enter your VirusTotal API key.")
            return
            
        try:
            # Clear previous results
            for i in reversed(range(self.vt_results_layout.count())): 
                self.vt_results_layout.itemAt(i).widget().setParent(None)
            
            # Add file info card
            file_info = ResultCard("File Information", 
                                 f"Path: {file_path}\nSize: {os.path.getsize(file_path):,} bytes", 
                                 self,
                                 copyable=True)
            self.vt_results_layout.addWidget(file_info)
            
            # Calculate file hash
            sha256_hash = hashlib.sha256()
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    sha256_hash.update(chunk)
            file_hash = sha256_hash.hexdigest()
            
            # Add hash card
            hash_card = ResultCard("File Hash (SHA256)", 
                                 file_hash,
                                 self,
                                 copyable=True)
            self.vt_results_layout.addWidget(hash_card)
            
            # Query VirusTotal
            headers = {
                'x-apikey': api_key
            }
            
            url = f'https://www.virustotal.com/vtapi/v2/file/report'
            params = {'apikey': api_key, 'resource': file_hash}
            
            response = requests.get(url, params=params)
            result = response.json()
            
            if response.status_code == 200:
                if result.get('response_code') == 1:  # File exists in VT database
                    # Add scan info card
                    scan_info = ResultCard(
                        "Scan Information",
                        f"Scan Date: {result.get('scan_date', 'N/A')}\n"
                        f"Detection Ratio: {result.get('positives', 0)}/{result.get('total', 0)}",
                        self,
                        copyable=True
                    )
                    self.vt_results_layout.addWidget(scan_info)
                    
                    # Add detections group
                    detections_group = QGroupBox("Detections")
                    detections_layout = QVBoxLayout()
                    
                    scans = result.get('scans', {})
                    has_detections = False
                    
                    for av, scan in scans.items():
                        if scan.get('detected'):
                            has_detections = True
                            detection_card = DetectionCard(av, scan.get('result', 'N/A'), self)
                            detections_layout.addWidget(detection_card)
                    
                    if not has_detections:
                        no_detections = QLabel("No malicious detections found!")
                        no_detections.setStyleSheet("color: #44aa44; font-weight: bold;")  # Green color
                        detections_layout.addWidget(no_detections)
                    
                    detections_group.setLayout(detections_layout)
                    self.vt_results_layout.addWidget(detections_group)
                    
                else:  # File needs to be uploaded
                    status_card = ResultCard("Status", "File not found in database. Uploading for scanning...", self)
                    self.vt_results_layout.addWidget(status_card)
                    
                    # Get upload URL and upload file
                    url = 'https://www.virustotal.com/vtapi/v2/file/scan/upload_url'
                    response = requests.get(url, headers=headers)
                    upload_url = response.json().get('upload_url')
                    
                    files = {'file': (os.path.basename(file_path), open(file_path, 'rb'))}
                    response = requests.post(upload_url, files=files, headers=headers)
                    
                    if response.status_code == 200:
                        upload_card = ResultCard(
                            "Upload Status",
                            "File uploaded successfully!\nThe scan has been queued. Please check back later with the file hash.",
                            self,
                            copyable=True
                        )
                        self.vt_results_layout.addWidget(upload_card)
                    else:
                        error_card = ResultCard("Error", f"Error uploading file: {response.text}", self)
                        self.vt_results_layout.addWidget(error_card)
            else:
                error_card = ResultCard("Error", result.get('verbose_msg', 'Unknown error occurred'), self)
                self.vt_results_layout.addWidget(error_card)
                
        except Exception as e:
            error_msg = str(e)
            error_card = ResultCard("Error", f"Error during scan: {error_msg}", self)
            self.vt_results_layout.addWidget(error_card)
            QMessageBox.critical(self, "Error", f"Failed to scan file: {error_msg}")