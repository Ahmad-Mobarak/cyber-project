#!/usr/bin/python3

import os
import sys

from utils import err_exit

try:
    from rich import print
    from rich.table import Table
except:
    err_exit("Error: >rich< module not found.")

try:
    import yara
except:
    err_exit("Error: >yara< module not found.")

# Module for progressbar
try:
    from tqdm import tqdm
except:
    err_exit("Module: >tqdm< not found.")

# Compatibility
path_seperator = "/"
if sys.platform == "win32":
    path_seperator = "\\"

# Path variable
sc0pe_path = open(".path_handler", "r").read()

# Legends
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"

# Target file - Fix for index error
if len(sys.argv) < 2:
    err_exit("Usage: python packerAnalyzer.py [--single|--multiscan] [file_or_directory_path]")
    
if len(sys.argv) < 3:
    err_exit(f"{infoS} Error: Missing file or directory path argument")

# Get the target file from the correct argument index
targetFile = sys.argv[2]

# File signatures
file_sigs = {
    'UPX': 'UPX0',
    'AsPack': '.aspack',
    'ConfuserEx v0.6.0': 'ConfuserEx v0.6.0',
    'UPX!': 'UPX!',
    'Confuser v1.9.0.0': 'Confuser v1.9.0.0',
    'PEtite': 'petite',
    'MPRESS_1': 'MPRESS1',
    'MPRESS_2': 'MPRESS2H',
    'ASProtect': '.ASPack',
    'Themida': 'Themida',
    'VMProtect': 'VMProtect',
    'PECompact': 'PECompact2',
    'FSG': 'FSG!',
    'MEW': 'MEW',
    'Y0da': 'Y0da'
}

def check_file_exists(file_path):
    if not os.path.exists(file_path):
        err_exit(f"{infoS} Error: File not found: {file_path}")
    if not os.path.isfile(file_path):
        err_exit(f"{infoS} Error: Not a file: {file_path}")

def check_directory_exists(dir_path):
    if not os.path.exists(dir_path):
        err_exit(f"{infoS} Error: Directory not found: {dir_path}")
    if not os.path.isdir(dir_path):
        err_exit(f"{infoS} Error: Not a directory: {dir_path}")

def get_yara_rules_path():
    """Get the path to YARA rules file, creating directories if needed"""
    rules_dir = os.path.join(sc0pe_path, "Modules", "rules")
    rules_file = os.path.join(rules_dir, "packer_rules.yar")
    
    # Create rules directory if it doesn't exist
    if not os.path.exists(rules_dir):
        try:
            os.makedirs(rules_dir)
            print(f"{infoS} Created rules directory: {rules_dir}")
        except Exception as e:
            print(f"{infoS} Warning: Could not create rules directory: {str(e)}")
            return None
            
    # Check if rules file exists
    if not os.path.exists(rules_file):
        print(f"{infoS} Warning: YARA rules file not found at {rules_file}")
        return None
        
    return rules_file

def Analyzer():
    """Analyze a single file for packer signatures"""
    check_file_exists(targetFile)
    
    try:
        print(f"\n{infoS} Analyzing file for packer signatures...")
        
        # Create results table
        results = Table(title="* Packer Detection Results *", title_style="bold italic cyan", title_justify="center")
        results.add_column("[bold green]Packer", justify="center")
        results.add_column("[bold red]Found", justify="center")
        
        found_packers = []
        
        # Check file content for signatures
        with open(targetFile, 'rb') as f:
            content = f.read()
            
        for packer, signature in file_sigs.items():
            if signature.encode() in content:
                results.add_row(packer, "✓")
                found_packers.append(packer)
                
        # Run YARA rules if available
        rules_path = get_yara_rules_path()
        if rules_path:
            try:
                rules = yara.compile(filepath=rules_path)
                matches = rules.match(targetFile)
                
                for match in matches:
                    if match.rule not in found_packers:
                        results.add_row(match.rule, "✓")
                        found_packers.append(match.rule)
            except Exception as e:
                print(f"{infoS} Warning: YARA rules check failed: {str(e)}")
        else:
            print(f"{infoS} Warning: Skipping YARA analysis - rules file not available")
            
        if found_packers:
            print(results)
            print(f"\n{infoS} Found {len(found_packers)} packer signatures")
        else:
            print(f"{infoS} No known packer signatures found")
            
    except Exception as e:
        err_exit(f"{infoS} Error analyzing file: {str(e)}")

def MultiAnalyzer():
    """Analyze multiple files in a directory for packer signatures"""
    check_directory_exists(targetFile)
    
    try:
        print(f"\n{infoS} Analyzing files in directory for packer signatures...")
        
        files = [f for f in os.listdir(targetFile) if os.path.isfile(os.path.join(targetFile, f))]
        if not files:
            err_exit(f"{infoS} Error: No files found in directory")
            
        # Get YARA rules path once for all files
        rules_path = get_yara_rules_path()
        if rules_path:
            try:
                rules = yara.compile(filepath=rules_path)
            except Exception as e:
                print(f"{infoS} Warning: YARA rules compilation failed: {str(e)}")
                rules = None
        else:
            rules = None
            
        for file in tqdm(files, desc="Analyzing files"):
            file_path = os.path.join(targetFile, file)
            print(f"\n{infoS} Analyzing: {file}")
            
            try:
                # Create results table for each file
                results = Table(title=f"* Packer Detection Results: {file} *", 
                              title_style="bold italic cyan", 
                              title_justify="center")
                results.add_column("[bold green]Packer", justify="center")
                results.add_column("[bold red]Found", justify="center")
                
                found_packers = []
                
                # Check file content for signatures
                with open(file_path, 'rb') as f:
                    content = f.read()
                    
                for packer, signature in file_sigs.items():
                    if signature.encode() in content:
                        results.add_row(packer, "✓")
                        found_packers.append(packer)
                        
                # Run YARA rules if available
                if rules:
                    try:
                        matches = rules.match(file_path)
                        for match in matches:
                            if match.rule not in found_packers:
                                results.add_row(match.rule, "✓")
                                found_packers.append(match.rule)
                    except Exception as e:
                        print(f"{infoS} Warning: YARA rules check failed for {file}: {str(e)}")
                    
                if found_packers:
                    print(results)
                    print(f"{infoS} Found {len(found_packers)} packer signatures")
                else:
                    print(f"{infoS} No known packer signatures found")
                    
            except Exception as e:
                print(f"{infoS} Error analyzing {file}: {str(e)}")
                continue
                
    except Exception as e:
        err_exit(f"{infoS} Error scanning directory: {str(e)}")

# Execute and clean up
if __name__ == '__main__':
    if len(sys.argv) < 2:
        err_exit("Usage: python packerAnalyzer.py [--single|--multiscan] [file_or_directory_path]")
        
    if str(sys.argv[1]) == '--single':
        try:
            Analyzer()
        except Exception as e:
            err_exit(f"{infoS} Program terminated: {str(e)}")
    elif str(sys.argv[1]) == '--multiscan':
        try:
            MultiAnalyzer()
        except Exception as e:
            err_exit(f"{infoS} Program terminated: {str(e)}")
    else:
        err_exit(f"Invalid option: {sys.argv[1]}\nUsage: python packerAnalyzer.py [--single|--multiscan] [file_or_directory_path]")