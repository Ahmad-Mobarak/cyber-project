# QuickScope GUI

A modern GUI wrapper for QuickScope malware analysis tool with dark mode.

## Features

- **Modern Interface**: Clean, dark-themed interface using PyQt5 and QDarkStyle.
- **All Existing Functionality**: Retains all analysis capabilities of the original QuickScope tool.
- **Tab-Based Organization**: Features organized logically across multiple tabs.
- **Improved Workflow**: Enhanced workflow for analyzing files and reviewing results.
- **Dynamic Analysis**: Live process and network monitoring, memory analysis, and file carving.
- **Document Analysis**: Specialized analysis for document-based malware including macros and embedded objects.
- **MITRE ATT&CK Integration**: Automated attack technique identification and mapping.

## Tabs

### Home Tab
- Welcome screen with quick actions
- Easy access to main functionality
- Recent files tracking

### Static Analysis Tab
- File and folder selection
- Various analysis options
- Visual output display
- Progress tracking
- Report export

### Dynamic Analysis Tab
- Process monitoring and listing
- Network connection tracking
- Memory dumping and analysis
- Embedded file carving
- MITRE ATT&CK technique mapping

### Document Analysis Tab
- Specialized analysis for PDF, Office files, HTML, and other document formats
- Macro extraction and analysis
- Embedded object detection
- URL and suspicious content extraction
- YARA rule scanning

### Utilities Tab
- Console interface for command-line operations
- VirusTotal integration
- Hash scanning tools
- String extraction and analysis

### Settings Tab
- Theme customization
- API key management
- System maintenance options
- About information

## Installation

1. Ensure you have the original QuickScope tool installed
2. Install the additional dependencies:
   ```
   pip install -r gui_requirements.txt
   ```
3. Run the GUI application:
   ```
   python QuickScope_GUI.py
   ```

## Requirements

- Python 3.6+
- PyQt5
- qdarkstyle
- psutil (for process monitoring)
- All original QuickScope dependencies

## Usage

1. Start the application with `python QuickScope_GUI.py`
2. Use the Home tab to quickly access analysis features
3. Select files for analysis through the file browser
4. Choose analysis types from the available options
5. View and export results

### Dynamic Analysis Usage

1. Go to the Dynamic Analysis tab
2. Click "Refresh Processes" to list running processes
3. Select a process to analyze from the list
4. Click "Start Monitoring" to begin monitoring processes
5. Click "Start Network Monitoring" to track network connections
6. Use the memory analysis tools to dump and analyze process memory
7. Generate MITRE ATT&CK maps for selected processes

### Document Analysis Usage

1. Go to the Document Analysis tab
2. Select a document file using the Browse button
3. Choose from the analysis options:
   - Analyze Document: Run full document analysis
   - Extract Macros: Find and display embedded macros
   - Extract Embedded Objects: Identify embedded files and objects
   - YARA Scan: Scan document with YARA rules
4. View results in the appropriate tab section

## License

GPL-3.0 License - Same as the original QuickScope tool 