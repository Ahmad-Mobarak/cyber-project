#!/usr/bin/python3

import os
import sys
import getpass
import subprocess
import configparser
import shutil
import time
import json
import base64
import hashlib
import re
from datetime import datetime, timedelta
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, 
                             QPushButton, QLabel, QFileDialog, QLineEdit, QTextEdit, 
                             QHBoxLayout, QGroupBox, QScrollArea, QSplitter, QStatusBar, 
                             QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox,
                             QDialog, QDialogButtonBox, QPlainTextEdit, QComboBox)
from PyQt5.QtCore import Qt, QProcess, pyqtSignal, QThread
from PyQt5.QtGui import QIcon, QPixmap, QFont, QTextCursor, QColor, QTextCharFormat, QSyntaxHighlighter

# Import custom style
from gui.style import get_stylesheet, get_palette

# Import app modules
from gui.home_tab import HomeTab
from gui.utils_tab import UtilsTab
from gui.dynamic_tab import DynamicTab
from gui.document_tab import DocumentTab
from gui.archive_tab import ArchiveTab
from gui.email_tab import EmailTab
from gui.pcap_tab import PCAPTab

class AnsiToHtmlConverter:
    def __init__(self):
        self.ansi_color_codes = {
            '30': '#000000',  # Black
            '31': '#FF0000',  # Red
            '32': '#00FF00',  # Green
            '33': '#FFFF00',  # Yellow
            '34': '#0000FF',  # Blue
            '35': '#FF00FF',  # Magenta
            '36': '#00FFFF',  # Cyan
            '37': '#FFFFFF',  # White
            '90': '#808080',  # Bright Black (Gray)
            '91': '#FF8080',  # Bright Red
            '92': '#80FF80',  # Bright Green
            '93': '#FFFF80',  # Bright Yellow
            '94': '#8080FF',  # Bright Blue
            '95': '#FF80FF',  # Bright Magenta
            '96': '#80FFFF',  # Bright Cyan
            '97': '#FFFFFF'   # Bright White
        }
        
    def convert(self, text):
        # First convert ANSI color codes to HTML
        pattern = r'\033\[(\d+)m(.*?)(?=\033|\Z)'
        
        def replace_color(match):
            code = match.group(1)
            text = match.group(2)
            color = self.ansi_color_codes.get(code, '#FFFFFF')
            return f'<span style="color: {color}">{text}</span>'
        
        text = re.sub(pattern, replace_color, text)
        
        # Replace command markers with styled versions
        text = text.replace('[*]', '<span style="color: #00FFFF; font-weight: bold">[</span><span style="color: #FF0000; font-weight: bold">*</span><span style="color: #00FFFF; font-weight: bold">]</span>')
        text = text.replace('[+]', '<span style="color: #00FFFF; font-weight: bold">[</span><span style="color: #FF0000; font-weight: bold">+</span><span style="color: #00FFFF; font-weight: bold">]</span>')
        text = text.replace('[!]', '<span style="color: #00FFFF; font-weight: bold">[</span><span style="color: #FF0000; font-weight: bold">!</span><span style="color: #00FFFF; font-weight: bold">]</span>')
        
        # Preserve newlines by converting them to <br> tags
        text = text.replace('\n', '<br>')
        
        # Format tables before other formatting
        text = self.format_tables(text)
        
        # Handle memory addresses
        text = self.highlight_addresses(text)
        
        # Handle file paths
        text = self.highlight_file_paths(text)
        
        return text
    
    def highlight_addresses(self, text):
        pattern = r'(0x[0-9a-fA-F]+)'
        return re.sub(pattern, r'<span style="color: #FFA500; font-family: monospace; font-weight: bold">\1</span>', text)
    
    def highlight_file_paths(self, text):
        pattern = r'([a-zA-Z]:\\[^<>:"/\\|?*]+)'
        return re.sub(pattern, r'<span style="color: #98FB98; font-style: italic">\1</span>', text)
    
    def format_tables(self, text):
        def format_table_row(row):
            if row.startswith('+--'):
                # Format separator lines
                return f'<div style="color: #666; font-family: monospace; border-bottom: 1px solid #444">{row}</div>'
            elif row.startswith('|'):
                # Split and clean cells
                cells = [cell.strip() for cell in row.split('|')[1:-1]]
                
                # Handle different table types
                if len(cells) == 2:  # Two-column tables (name and address)
                    name, addr = cells
                    # Special handling for address cells that may already have formatting
                    if '<span' in addr:
                        addr_cell = addr
                    else:
                        addr_cell = f'<span style="color: #FFA500; font-family: monospace; font-weight: bold">{addr}</span>'
                    
                    return f'''<div style="display: flex; padding: 4px 0">
                        <div style="flex: 2; padding: 4px 8px; color: #E0E0E0">{name}</div>
                        <div style="flex: 1; padding: 4px 8px; text-align: right">{addr_cell}</div>
                    </div>'''
                elif len(cells) == 3:  # Three-column tables
                    return f'''<div style="display: flex; padding: 4px 0">
                        <div style="flex: 2; padding: 4px 8px; color: #E0E0E0">{cells[0]}</div>
                        <div style="flex: 2; padding: 4px 8px; color: #E0E0E0">{cells[1]}</div>
                        <div style="flex: 1; padding: 4px 8px; text-align: right">{cells[2]}</div>
                    </div>'''
                else:  # Other table formats
                    row_html = '<div style="display: flex; padding: 4px 0">'
                    flex = 1 if len(cells) > 0 else 0
                    for cell in cells:
                        row_html += f'<div style="flex: {flex}; padding: 4px 8px; color: #E0E0E0">{cell}</div>'
                    row_html += '</div>'
                    return row_html
            return row

        # Split text into lines while preserving newlines
        lines = text.split('\n')
        formatted_lines = []
        in_table = False
        table_buffer = []
        
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('+--') or stripped.startswith('|'):
                if not in_table:
                    in_table = True
                    table_buffer = ['<div style="margin: 10px 0; border: 1px solid #444; background-color: #1E1E1E; border-radius: 4px">']
                
                # Handle table headers (lines with all uppercase or containing "Address")
                if stripped.startswith('|') and ('Address' in stripped or stripped.isupper()):
                    cells = [cell.strip() for cell in stripped.split('|')[1:-1]]
                    header_html = '<div style="display: flex; padding: 4px 0; border-bottom: 1px solid #444; background-color: #2D2D30">'
                    flex = 1 if len(cells) > 0 else 0
                    for cell in cells:
                        header_html += f'<div style="flex: {flex}; padding: 4px 8px; color: #FFD700">{cell}</div>'
                    header_html += '</div>'
                    table_buffer.append(header_html)
                else:
                    table_buffer.append(format_table_row(stripped))
            else:
                if in_table:
                    in_table = False
                    table_buffer.append('</div>')
                    formatted_lines.append('\n'.join(table_buffer))
                    table_buffer = []
                formatted_lines.append(line)

        if table_buffer:
            table_buffer.append('</div>')
            formatted_lines.append('\n'.join(table_buffer))

        return '\n'.join(formatted_lines)

class ColoredTextEdit(QTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.converter = AnsiToHtmlConverter()
        self.setReadOnly(True)
        self.setFont(QFont("Courier New", 10))
        # Enable HTML rendering
        self.setAcceptRichText(True)
        self.document().setDefaultStyleSheet("""
            body {
                color: #FFFFFF;
                font-family: 'Courier New';
                line-height: 1.4;
            }
            div {
                margin: 0;
                padding: 0;
            }
            table {
                border-collapse: collapse;
                width: 100%;
                margin: 10px 0;
            }
            th, td {
                padding: 4px 8px;
                text-align: left;
                border: 1px solid #444;
            }
            th {
                background-color: #2D2D30;
                color: #FFD700;
            }
            pre {
                margin: 0;
                white-space: pre-wrap;
            }
            code {
                font-family: 'Courier New';
                color: #E0E0E0;
            }
            .warning {
                color: #FFA500;
                font-weight: bold;
            }
            .error {
                color: #FF0000;
                font-weight: bold;
            }
            .success {
                color: #00FF00;
                font-weight: bold;
            }
        """)
        self.setStyleSheet("""
            QTextEdit {
                background-color: #1E1E1E;
                color: #FFFFFF;
                border: 1px solid #333333;
                padding: 8px;
                line-height: 1.4;
            }
            QTextEdit QScrollBar:vertical {
                background: #2D2D30;
                width: 12px;
            }
            QTextEdit QScrollBar::handle:vertical {
                background: #3E3E42;
                min-height: 20px;
            }
            QTextEdit QScrollBar::add-line:vertical,
            QTextEdit QScrollBar::sub-line:vertical {
                border: none;
                background: none;
            }
        """)
    
    def append_colored_text(self, text):
        # Convert ANSI and custom formatting to HTML
        html_text = self.converter.convert(text)
        # Add explicit line breaks and preserve whitespace
        html_text = f'<pre style="margin: 0; white-space: pre-wrap">{html_text}</pre>'
        # Set HTML content
        self.insertHtml(html_text + "<br>")
        # Move cursor to end
        cursor = self.textCursor()
        cursor.movePosition(QTextCursor.End)
        self.setTextCursor(cursor)
        
    def append_html(self, html):
        # Add explicit line breaks and preserve whitespace
        html = f'<pre style="margin: 0; white-space: pre-wrap">{html}</pre>'
        # Directly append HTML content
        self.insertHtml(html + "<br>")
        cursor = self.textCursor()
        cursor.movePosition(QTextCursor.End)
        self.setTextCursor(cursor)

class AnalyzerTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # File selection area
        file_group = QGroupBox("Analysis File")
        file_layout = QHBoxLayout()
        
        self.file_path = QLineEdit()
        self.file_path.setPlaceholderText("Select file to analyze...")
        
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_file)
        
        file_layout.addWidget(self.file_path)
        file_layout.addWidget(browse_btn)
        file_group.setLayout(file_layout)
        
        # Analysis type selection
        analysis_group = QGroupBox("Analysis Type")
        analysis_layout = QHBoxLayout()
        
        self.analysis_type = QComboBox()
        self.analysis_type.addItems([
            "Basic Analysis",
            "Strings Analysis",
            "Header Analysis",
            "Import Analysis",
            "Section Analysis",
            "Resource Analysis",
            "Packer Analysis",
            "YARA Analysis"
        ])
        
        analyze_btn = QPushButton("Analyze")
        analyze_btn.clicked.connect(self.start_analysis)
        
        analysis_layout.addWidget(self.analysis_type)
        analysis_layout.addWidget(analyze_btn)
        analysis_group.setLayout(analysis_layout)
        
        # Results area
        results_group = QGroupBox("Analysis Results")
        results_layout = QVBoxLayout()
        
        # Replace QPlainTextEdit with our custom ColoredTextEdit
        self.output_text = ColoredTextEdit()
        
        results_layout.addWidget(self.output_text)
        results_group.setLayout(results_layout)
        
        # Add all groups to main layout
        layout.addWidget(file_group)
        layout.addWidget(analysis_group)
        layout.addWidget(results_group)
        
        self.process = QProcess()
        self.process.readyReadStandardOutput.connect(self.handle_stdout)
        self.process.readyReadStandardError.connect(self.handle_stderr)
        self.process.finished.connect(self.analysis_finished)
        
    def browse_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Select File", "", 
                                                 "All Files (*);;Executable Files (*.exe *.dll)")
        if file_name:
            self.file_path.setText(file_name)
            
    def get_analysis_command(self):
        analysis_type = self.analysis_type.currentText()
        file_path = self.file_path.text()
        
        commands = {
            "Basic Analysis": f'--file "{file_path}" --analyze',
            "Strings Analysis": f'--file "{file_path}" --strings',
            "Header Analysis": f'--file "{file_path}" --pe',
            "Import Analysis": f'--file "{file_path}" --imports',
            "Section Analysis": f'--file "{file_path}" --sections',
            "Resource Analysis": f'--file "{file_path}" --resource',
            "Packer Analysis": f'--file "{file_path}" --packer',
            "YARA Analysis": f'--file "{file_path}" --yara'
        }
        
        return f'python qu1cksc0pe.py {commands[analysis_type]}'
            
    def start_analysis(self):
        if not self.file_path.text():
            QMessageBox.warning(self, "Warning", "Please select a file to analyze")
            return
            
        self.output_text.clear()
        self.output_text.append_colored_text("Starting analysis...\n")
        
        command = self.get_analysis_command()
        self.process.start(command)
        
    def handle_stdout(self):
        try:
            data = self.process.readAllStandardOutput().data().decode('utf-8', errors='replace')
            self.output_text.append_colored_text(data)
        except Exception as e:
            self.output_text.append_colored_text(f"Error processing output: {str(e)}\n")
        
    def handle_stderr(self):
        try:
            data = self.process.readAllStandardError().data().decode('utf-8', errors='replace')
            self.output_text.append_colored_text(data)
        except Exception as e:
            self.output_text.append_colored_text(f"Error processing error output: {str(e)}\n")
        
    def analysis_finished(self):
        self.output_text.append_colored_text("\nAnalysis completed")

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Qu1cksc0pe - Malware Analysis Tool")
        self.resize(1200, 800)
        
        # Set up environment variables and paths
        self.setup_environment()
        
        # Create the main widget and layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        # Create main layout
        self.main_layout = QVBoxLayout(self.central_widget)
        self.main_layout.setContentsMargins(10, 10, 10, 10)
        
        # Create tab widget
        self.tabs = QTabWidget()
        
        # Add tabs
        self.home_tab = HomeTab(self)
        self.analyzer_tab = AnalyzerTab(self)
        self.dynamic_tab = DynamicTab(self)
        self.document_tab = DocumentTab(self)
        self.utils_tab = UtilsTab(self)
        self.archive_tab = ArchiveTab(self)
        self.email_tab = EmailTab(self)
        self.pcap_tab = PCAPTab(self)
        
        self.tabs.addTab(self.home_tab, "الرئيسية")
        self.tabs.addTab(self.analyzer_tab, "التحليل الثابت")
        self.tabs.addTab(self.dynamic_tab, "التحليل الديناميكي")
        self.tabs.addTab(self.document_tab, "تحليل المستندات")
        self.tabs.addTab(self.utils_tab, "الأدوات")
        self.tabs.addTab(self.archive_tab, "Archive Analysis")
        self.tabs.addTab(self.email_tab, "Email Analysis")
        self.tabs.addTab(self.pcap_tab, "PCAP Analysis")
        
        # Add tabs to main layout
        self.main_layout.addWidget(self.tabs)
        
        # Create status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("جاهز")
        
        # Apply dark theme by default
        self.apply_style()

    def setup_environment(self):
        """Set up environment variables and paths"""
        # Get current user
        self.current_user = getpass.getuser()
        
        # Set paths
        if sys.platform == "win32":
            self.py_binary = "python"
            self.path_separator = "\\"
        else:
            self.py_binary = "python3"
            self.path_separator = "/"
            
        # Get Qu1cksc0pe path
        self.sc0pe_path = os.getcwd()

        # Ensure .path_handler file exists for modules that might need it
        path_handler_file = os.path.join(self.sc0pe_path, ".path_handler")
        try:
            with open(path_handler_file, "w") as f:
                f.write(self.sc0pe_path)
        except IOError as e:
            print(f"Error: Could not write .path_handler file: {e}")
            # Optionally, show a QMessageBox to the user if this is critical
            # QMessageBox.critical(self, "Error", f"Could not write .path_handler file at {path_handler_file}.\nSome functionalities might not work correctly.")

    def apply_style(self):
        """Apply dark theme styling"""
        self.setStyleSheet(get_stylesheet())
        QApplication.setPalette(get_palette())

def main():
    app = QApplication(sys.argv)
    
    # Set application attributes for better UI rendering
    app.setAttribute(Qt.AA_UseHighDpiPixmaps)
    
    # Create and show the main window
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main() 