#!/usr/bin/python3

import os
import sys
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QLabel, QGroupBox, 
                           QHBoxLayout, QPushButton, QFileDialog)
from PyQt5.QtGui import QFont, QPixmap, QIcon
from PyQt5.QtCore import Qt, QSize

class ActionButton(QPushButton):
    """Simple styled button with hover effect"""
    def __init__(self, text, icon_name=None, parent=None):
        super().__init__(text, parent)
        self.setMinimumHeight(40)
        self.setCursor(Qt.PointingHandCursor)
        
        if icon_name:
            icon_path = os.path.join("icons", f"{icon_name}.png")
            if os.path.exists(icon_path):
                self.setIcon(QIcon(icon_path))
                self.setIconSize(QSize(20, 20))
        
        self.setStyleSheet("""
            QPushButton {
                background-color: #2D2D30;
                border: 1px solid #3E3E42;
                border-radius: 4px;
                color: #FFFFFF;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #3E3E42;
                border-color: #64B5F6;
            }
        """)

class FeatureBox(QGroupBox):
    """Simple feature box with title and description"""
    def __init__(self, title, description, parent=None):
        super().__init__(title, parent)
        self.setStyleSheet("""
            QGroupBox {
                border: 1px solid #3E3E42;
                border-radius: 4px;
                margin-top: 1em;
                padding: 15px;
                color: #64B5F6;
                font-weight: bold;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
            QLabel {
                color: #FFFFFF;
            }
        """)
        
        layout = QVBoxLayout(self)
        desc_label = QLabel(description)
        desc_label.setWordWrap(True)
        layout.addWidget(desc_label)

class HomeTab(QWidget):
    def __init__(self, parent=None):
        super().__init__()
        self.parent = parent
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        layout.setContentsMargins(15, 15, 15, 15)
        
        # Welcome section
        self.setup_welcome_section(layout)
        
        # Quick actions
        self.setup_quick_actions(layout)
        
        # Features
        self.setup_features(layout)
        
        # Add stretch at the end
        layout.addStretch()

    def setup_welcome_section(self, layout):
        welcome_frame = QGroupBox()
        welcome_frame.setStyleSheet("""
            QGroupBox {
                border: 1px solid #3E3E42;
                border-radius: 4px;
                padding: 15px;
            }
        """)
        
        welcome_layout = QHBoxLayout(welcome_frame)
        
        # Logo
        logo_label = QLabel()
        logo_path = os.path.join("icons", "logo.png")
        if os.path.exists(logo_path):
            pixmap = QPixmap(logo_path)
            logo_label.setPixmap(pixmap.scaled(100, 100, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        else:
            logo_label.setText("🔍")
            logo_label.setFont(QFont("Arial", 48))
            logo_label.setStyleSheet("color: #64B5F6;")
        
        logo_label.setFixedSize(100, 100)
        logo_label.setAlignment(Qt.AlignCenter)
        welcome_layout.addWidget(logo_label)
        
        # Text section
        text_layout = QVBoxLayout()
        
        title_label = QLabel("Qu1cksc0pe")
        title_label.setStyleSheet("""
            color: #FFFFFF;
            font-size: 32px;
            font-weight: bold;
        """)
        text_layout.addWidget(title_label)
        
        desc_label = QLabel("Professional Malware Analysis Toolkit")
        desc_label.setStyleSheet("color: #64B5F6; font-size: 16px;")
        text_layout.addWidget(desc_label)
        
        welcome_layout.addLayout(text_layout, 1)
        layout.addWidget(welcome_frame)

    def setup_quick_actions(self, layout):
        actions_layout = QHBoxLayout()
        
        analyze_btn = ActionButton("Analyze File", "analyze")
        analyze_btn.clicked.connect(self.select_file_for_analysis)
        actions_layout.addWidget(analyze_btn)
        
        folder_btn = ActionButton("Analyze Folder", "folder")
        folder_btn.clicked.connect(self.select_folder_for_analysis)
        actions_layout.addWidget(folder_btn)
        
        console_btn = ActionButton("Open Console", "console")
        console_btn.clicked.connect(self.open_console)
        actions_layout.addWidget(console_btn)
        
        layout.addLayout(actions_layout)

    def setup_features(self, layout):
        features_layout = QVBoxLayout()
        
        features = [
            {
                "title": "Static Analysis",
                "desc": "Analyze file structure, strings, and headers without execution"
            },
            {
                "title": "Dynamic Analysis",
                "desc": "Monitor runtime behavior in a controlled environment"
            },
            {
                "title": "Document Analysis",
                "desc": "Extract and analyze content from documents"
            }
        ]
        
        for feature in features:
            box = FeatureBox(feature["title"], feature["desc"])
            features_layout.addWidget(box)
        
        layout.addLayout(features_layout)

    def select_file_for_analysis(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Select File for Analysis")
        if file_name:
            if hasattr(self.parent, 'analyze_file'):
                self.parent.analyze_file(file_name)

    def select_folder_for_analysis(self):
        folder_name = QFileDialog.getExistingDirectory(self, "Select Folder for Analysis")
        if folder_name:
            if hasattr(self.parent, 'analyze_folder'):
                self.parent.analyze_folder(folder_name)

    def open_console(self):
        if hasattr(self.parent, 'switch_to_console'):
            self.parent.switch_to_console() 