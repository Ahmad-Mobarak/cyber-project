#!/usr/bin/python3

from PyQt5.QtGui import QColor, QPalette
from PyQt5.QtCore import Qt

MAIN_THEME = {
    # Primary colors
    "primary": "#1976D2",       # Blue
    "primary_light": "#64B5F6",
    "primary_dark": "#0D47A1",
    
    # Accent colors
    "accent": "#FF5722",        # Deep Orange
    "accent_light": "#FF8A65",
    "accent_dark": "#D84315",
    
    # Background colors
    "background_dark": "#1E1E1E",
    "background_medium": "#2D2D30",
    "background_light": "#3E3E42",
    
    # Text colors
    "text_primary": "#FFFFFF",
    "text_secondary": "#BBBBBB",
    "text_disabled": "#6D6D6D",
    
    # Status colors
    "success": "#4CAF50",
    "warning": "#FFC107",
    "error": "#F44336",
    "info": "#2196F3",
}

def get_stylesheet():
    return f"""
    /* Global Styles */
    QWidget {{
        background-color: {MAIN_THEME["background_dark"]};
        color: {MAIN_THEME["text_primary"]};
        font-family: 'Segoe UI', 'Arial', sans-serif;
        font-size: 10pt;
    }}
    
    /* Main Window */
    QMainWindow {{
        background-color: {MAIN_THEME["background_dark"]};
    }}
    
    /* Tab Widget */
    QTabWidget::pane {{
        border: 1px solid {MAIN_THEME["background_light"]};
        background-color: {MAIN_THEME["background_medium"]};
        border-radius: 5px;
    }}
    
    QTabBar::tab {{
        background-color: {MAIN_THEME["background_medium"]};
        color: {MAIN_THEME["text_secondary"]};
        border-top-left-radius: 4px;
        border-top-right-radius: 4px;
        padding: 8px 16px;
        margin-right: 2px;
    }}
    
    QTabBar::tab:selected {{
        background-color: {MAIN_THEME["primary"]};
        color: {MAIN_THEME["text_primary"]};
        font-weight: bold;
    }}
    
    QTabBar::tab:hover:!selected {{
        background-color: {MAIN_THEME["background_light"]};
    }}
    
    /* Group Box */
    QGroupBox {{
        font-weight: bold;
        border: 1px solid {MAIN_THEME["background_light"]};
        border-radius: 6px;
        margin-top: 12px;
        padding-top: 12px;
    }}
    
    QGroupBox::title {{
        subcontrol-origin: margin;
        subcontrol-position: top left;
        left: 10px;
        padding: 0 5px;
        color: {MAIN_THEME["primary_light"]};
    }}
    
    /* Buttons */
    QPushButton {{
        background-color: {MAIN_THEME["primary"]};
        color: {MAIN_THEME["text_primary"]};
        border: none;
        border-radius: 4px;
        padding: 8px 16px;
        font-weight: bold;
    }}
    
    QPushButton:hover {{
        background-color: {MAIN_THEME["primary_light"]};
    }}
    
    QPushButton:pressed {{
        background-color: {MAIN_THEME["primary_dark"]};
    }}
    
    QPushButton:disabled {{
        background-color: {MAIN_THEME["background_light"]};
        color: {MAIN_THEME["text_disabled"]};
    }}
    
    /* Action Buttons */
    QPushButton#action_button {{
        background-color: {MAIN_THEME["accent"]};
        font-size: 11pt;
    }}
    
    QPushButton#action_button:hover {{
        background-color: {MAIN_THEME["accent_light"]};
    }}
    
    QPushButton#action_button:pressed {{
        background-color: {MAIN_THEME["accent_dark"]};
    }}
    
    /* Line Edit */
    QLineEdit {{
        background-color: {MAIN_THEME["background_light"]};
        color: {MAIN_THEME["text_primary"]};
        border: 1px solid {MAIN_THEME["background_light"]};
        border-radius: 4px;
        padding: 6px;
    }}
    
    QLineEdit:focus {{
        border: 1px solid {MAIN_THEME["primary"]};
    }}
    
    /* Text Edit */
    QTextEdit {{
        background-color: {MAIN_THEME["background_light"]};
        color: {MAIN_THEME["text_primary"]};
        border: 1px solid {MAIN_THEME["background_light"]};
        border-radius: 4px;
    }}
    
    /* Combo Box */
    QComboBox {{
        background-color: {MAIN_THEME["background_light"]};
        color: {MAIN_THEME["text_primary"]};
        border: 1px solid {MAIN_THEME["background_light"]};
        border-radius: 4px;
        padding: 6px;
    }}
    
    QComboBox:hover {{
        border: 1px solid {MAIN_THEME["primary"]};
    }}
    
    QComboBox::drop-down {{
        subcontrol-origin: padding;
        subcontrol-position: center right;
        width: 20px;
        border-left-width: 1px;
        border-left-color: {MAIN_THEME["background_light"]};
        border-left-style: solid;
    }}
    
    /* Scroll Area */
    QScrollArea {{
        border: none;
        background-color: transparent;
    }}
    
    /* Scroll Bar */
    QScrollBar:vertical {{
        border: none;
        background-color: {MAIN_THEME["background_light"]};
        width: 12px;
        margin: 16px 0 16px 0;
        border-radius: 6px;
    }}
    
    QScrollBar::handle:vertical {{
        background-color: {MAIN_THEME["primary"]};
        min-height: 20px;
        border-radius: 6px;
    }}
    
    QScrollBar::handle:vertical:hover {{
        background-color: {MAIN_THEME["primary_light"]};
    }}
    
    QScrollBar::sub-line:vertical, QScrollBar::add-line:vertical {{
        border: none;
        background: none;
        height: 0px;
    }}
    
    QScrollBar:horizontal {{
        border: none;
        background-color: {MAIN_THEME["background_light"]};
        height: 12px;
        margin: 0 16px 0 16px;
        border-radius: 6px;
    }}
    
    QScrollBar::handle:horizontal {{
        background-color: {MAIN_THEME["primary"]};
        min-width: 20px;
        border-radius: 6px;
    }}
    
    QScrollBar::handle:horizontal:hover {{
        background-color: {MAIN_THEME["primary_light"]};
    }}
    
    QScrollBar::sub-line:horizontal, QScrollBar::add-line:horizontal {{
        border: none;
        background: none;
        width: 0px;
    }}
    
    /* Status Bar */
    QStatusBar {{
        background-color: {MAIN_THEME["background_medium"]};
        color: {MAIN_THEME["text_secondary"]};
    }}
    
    /* Table Widget */
    QTableWidget {{
        background-color: {MAIN_THEME["background_medium"]};
        alternate-background-color: {MAIN_THEME["background_light"]};
        gridline-color: {MAIN_THEME["background_light"]};
    }}
    
    QTableWidget::item {{
        padding: 4px;
    }}
    
    QTableWidget::item:selected {{
        background-color: {MAIN_THEME["primary"]};
        color: {MAIN_THEME["text_primary"]};
    }}
    
    QHeaderView::section {{
        background-color: {MAIN_THEME["primary_dark"]};
        color: {MAIN_THEME["text_primary"]};
        padding: 6px;
        font-weight: bold;
        border: none;
    }}
    
    /* Labels */
    QLabel#title_label {{
        font-size: 24pt;
        font-weight: bold;
        color: {MAIN_THEME["primary_light"]};
    }}
    
    QLabel#desc_label {{
        font-size: 12pt;
        color: {MAIN_THEME["text_secondary"]};
    }}
    
    /* Dialog buttons */
    QDialogButtonBox QPushButton {{
        min-width: 80px;
    }}
    """

def get_palette():
    palette = QPalette()
    palette.setColor(QPalette.Window, QColor(MAIN_THEME["background_dark"]))
    palette.setColor(QPalette.WindowText, QColor(MAIN_THEME["text_primary"]))
    palette.setColor(QPalette.Base, QColor(MAIN_THEME["background_medium"]))
    palette.setColor(QPalette.AlternateBase, QColor(MAIN_THEME["background_light"]))
    palette.setColor(QPalette.ToolTipBase, QColor(MAIN_THEME["text_primary"]))
    palette.setColor(QPalette.ToolTipText, QColor(MAIN_THEME["background_dark"]))
    palette.setColor(QPalette.Text, QColor(MAIN_THEME["text_primary"]))
    palette.setColor(QPalette.Button, QColor(MAIN_THEME["primary"]))
    palette.setColor(QPalette.ButtonText, QColor(MAIN_THEME["text_primary"]))
    palette.setColor(QPalette.BrightText, Qt.red)
    palette.setColor(QPalette.Link, QColor(MAIN_THEME["primary_light"]))
    palette.setColor(QPalette.Highlight, QColor(MAIN_THEME["primary"]))
    palette.setColor(QPalette.HighlightedText, QColor(MAIN_THEME["text_primary"]))
    return palette 