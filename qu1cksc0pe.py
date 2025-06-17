#!/usr/bin/python3

# module checking
try:
    import os
    import sys
    import argparse
    import getpass
    import configparser
    import shutil
    import warnings
    import time
    import json
    import base64
    import hashlib
    import subprocess
    from datetime import datetime
except Exception as e:
    print(f"Missing modules detected!: {e}")
    sys.exit(1)

# Check python version
if sys.version_info[0] == 2:
    print(f"{errorS} Looks like you are using Python 2. But we need Python 3!")
    sys.exit(1)

# Testing rich existence and importing required components
try:
    from rich import print
    from rich.table import Table
    from rich.progress import Progress
    from rich.console import Console
except ModuleNotFoundError as e:
    print("Error: >rich< module not found.")
    raise e

# Testing puremagic existence
try:
    import puremagic as pr
except ModuleNotFoundError as e:
    print("Error: >puremagic< module not found.")
    raise e

try:
    from colorama import Fore, Style
except ModuleNotFoundError as e:
    print("Error: >colorama< module not found.")
    raise e

# Add PE analysis imports
try:
    import pefile
except ImportError:
    print(f"pefile module not found. Installing...")
    os.system(f"{py_binary} -m pip install pefile")
    import pefile

# Colors
red = Fore.LIGHTRED_EX
cyan = Fore.LIGHTCYAN_EX
white = Style.RESET_ALL
green = Fore.LIGHTGREEN_EX

# Legends
infoC = f"{cyan}[{red}*{cyan}]{white}"
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
foundS = f"[bold cyan][[bold red]+[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"

# Initialize rich console
console = Console()

# Gathering username
username = getpass.getuser()

# Get python binary
if shutil.which("python"):
    py_binary = "python"
else:
    py_binary = "python3"

# Make Qu1cksc0pe work on Windows, Linux, OSX
homeD = os.path.expanduser("~")
path_seperator = "/"
if sys.platform == "win32":
    path_seperator = "\\"

# Is Qu1cksc0pe installed??
if os.name != "nt":
    if os.path.exists("/usr/bin/qu1cksc0pe") == True and os.path.exists(f"/etc/qu1cksc0pe.conf") == True:
        # Parsing new path and write into handler
        sc0peConf = configparser.ConfigParser()
        sc0peConf.read(f"/etc/qu1cksc0pe.conf")
        sc0pe_path = str(sc0peConf["Qu1cksc0pe_PATH"]["sc0pe"])
        sys.path.append(sc0pe_path)
        path_handler = open(".path_handler", "w")
        path_handler.write(sc0pe_path)
        path_handler.close()
    else:
        # Parsing current path and write into handler
        sc0pe_path = str(os.getcwd())
        path_handler = open(".path_handler", "w")
        path_handler.write(sc0pe_path)
        path_handler.close()
        libscan = configparser.ConfigParser()
else:
    sc0pe_path = str(os.getcwd())
    path_handler = open(".path_handler", "w")
    path_handler.write(sc0pe_path)
    path_handler.close()
    libscan = configparser.ConfigParser()

# License verification functions - Now just stubs for compatibility
def _get_machine_key():
    """No longer needed - kept for compatibility"""
    return "FREE_VERSION"

def _xor_decode_license_data():
    """No longer needed - always returns a valid license"""
    return {"license_type": "full", "key": "FREE_VERSION"}

def check_license():
    """License check removed - Qu1cksc0pe is now free"""
    print(f"{infoS} [bold green]Malware analysis Tool Project[white]")
    return True

# Always passes the license check
check_license()

# Utility functions
from Modules.utils import err_exit

MODULE_PREFIX = f"{sc0pe_path}{path_seperator}Modules{path_seperator}"
def execute_module(target, path=MODULE_PREFIX, invoker=py_binary):
    if "python" in invoker or ".py" in target:
        # TODO in the future, raise a ValueError/OSError (and remove the additional code below)
        # instead of warning with a PendingDeprecationWarning
        DEV_NOTE = "[DEV NOTE]: when switching to import statements, remember to adjust any downstream imports! (e.g. `from .utils import err_exit` vs `from utils import err_exit`)"
        warnings.warn("Direct execution of Python files won't be supported much longer." + f" {DEV_NOTE}", PendingDeprecationWarning)

    os.system(f"{invoker} {path}{target}")

import Modules.banners # show a banner

# Add PE analysis arguments
ARG_NAMES_TO_KWARG_OPTS = {
    "file": {"help": "Specify a file to scan or analyze."},
    "folder": {"help": "Specify a folder to scan or analyze."},
    "analyze": {"help": "Analyze target file.", "action": "store_true"},
    "archive": {"help": "Analyze archive files.", "action": "store_true"},
    "console": {"help": "Use Qu1cksc0pe on interactive shell.", "action": "store_true"},
    "db_update": {"help": "Update malware hash database.", "action": "store_true"},
    "docs": {"help": "Analyze document files.", "action": "store_true"},
    "domain": {"help": "Extract URLs and IP addresses from file.", "action": "store_true"},
    "hashscan": {"help": "Scan target file's hash in local database.", "action": "store_true"},
    "install": {"help": "Install or Uninstall Qu1cksc0pe.", "action": "store_true"},
    "key_init": {"help": "Enter your VirusTotal API key.", "action": "store_true"},
    "lang": {"help": "Detect programming language.", "action": "store_true"},
    "mitre": {"help": "Generate MITRE ATT&CK table for target sample (Windows samples for now.).", "action": "store_true"},
    "packer": {"help": "Check if your file is packed with common packers.", "action": "store_true"},
    "resource": {"help": "Analyze resources in target file", "action": "store_true"},
    "report": {"help": "Export analysis reports into a file (JSON Format for now).", "action": "store_true"},
    "watch": {"help": "Perform dynamic analysis against Windows/Android files. (Linux will coming soon!!)", "action": "store_true"},
    "sigcheck": {"help": "Scan file signatures in target file.", "action": "store_true"},
    "vtFile": {"help": "Scan your file with VirusTotal API.", "action": "store_true"},
    "strings": {"help": "Extract strings from the file", "action": "store_true"},
    "yara": {"help": "Scan file with custom YARA rules", "action": "store_true"},
    "pe": {"help": "Show basic PE file information", "action": "store_true"},
    "imports": {"help": "Show PE file imports", "action": "store_true"},
    "exports": {"help": "Show PE file exports", "action": "store_true"},
    "sections": {"help": "Show PE file sections", "action": "store_true"},
    "resources": {"help": "Show PE file resources", "action": "store_true"},
    "tls": {"help": "Show PE file TLS callbacks", "action": "store_true"},
    "debug": {"help": "Show PE file debug information", "action": "store_true"},
}

parser = argparse.ArgumentParser()
for arg_name, cfg in ARG_NAMES_TO_KWARG_OPTS.items():
    cfg["required"] = cfg.get("required", False)
    parser.add_argument("--" + arg_name, **cfg)
args = parser.parse_args()

# Basic analyzer function that handles single and multiple scans
def BasicAnalyzer(analyzeFile):
    if not os.path.exists(analyzeFile):
        err_exit(f"{errorS} File not found: {analyzeFile}")
        
    print(f"{infoS} Analyzing: [bold green]{analyzeFile}[white]")
    try:
        fileType = str(pr.magic_file(analyzeFile))
    except Exception as e:
        err_exit(f"{errorS} Failed to determine file type: {str(e)}")
    
    print(f"{infoS} File Type: [bold green]{fileType}[white]\n")
    
    # Windows Analysis
    if "Windows Executable" in fileType or any(ext in fileType.lower() for ext in [".msi", ".dll", ".exe"]):
        print(f"{infoS} Target OS: [bold green]Windows[white]\n")
        try:
            if args.report:
                execute_module(f"windows_static_analyzer.py \"{analyzeFile}\" True")
            else:
                execute_module(f"windows_static_analyzer.py \"{analyzeFile}\" False")
        except Exception as e:
            err_exit(f"{errorS} Windows analysis failed: {str(e)}")

    # Linux Analysis
    elif "ELF" in fileType:
        print(f"{infoS} Target OS: [bold green]Linux[white]\n")
        try:
            import Modules.linux_static_analyzer as lina
            lina.run(sc0pe_path, analyzeFile, emit_report=args.report)
        except Exception as e:
            err_exit(f"{errorS} Linux analysis failed: {str(e)}")

    # MacOSX Analysis
    elif "Mach-O" in fileType or '\\xca\\xfe\\xba\\xbe' in fileType:
        print(f"{infoS} Target OS: [bold green]OSX[white]\n")
        try:
            if args.report:
                execute_module(f"apple_analyzer.py \"{analyzeFile}\" True")
            else:
                execute_module(f"apple_analyzer.py \"{analyzeFile}\" False")
        except Exception as e:
            err_exit(f"{errorS} OSX analysis failed: {str(e)}")
    
    # Document Analysis
    elif any(doc_type in fileType.lower() for doc_type in ["microsoft word", "pdf", "rtf", "onenote", "html"]):
        print(f"{infoS} File Type: [bold green]Document[white]\n")
        try:
            execute_module(f"document_analyzer.py \"{analyzeFile}\"")
        except Exception as e:
            err_exit(f"{errorS} Document analysis failed: {str(e)}")
    
    else:
        err_exit(f"\n{errorS} Unsupported file type: {fileType}\n[bold]>>> For document analysis, use the [bold green][i]--docs[/i][white] argument.")

# Add strings analysis function
def analyze_strings(file_path):
    try:
        print(f"\n{infoS} Extracting strings from the file...")
        if not os.path.exists(file_path):
            err_exit(f"{errorS} File not found: {file_path}")
            
        if sys.platform == "win32":
            strings_param = "-a"
            # Check if strings.exe exists in Windows
            if not shutil.which("strings"):
                err_exit(f"{errorS} 'strings' command not found. Please install SysInternals Suite.")
        else:
            strings_param = "--all"
            if not shutil.which("strings"):
                err_exit(f"{errorS} 'strings' command not found. Please install binutils.")
        
        strings_cmd = f"strings {strings_param} \"{file_path}\""
        result = subprocess.run(strings_cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode != 0:
            err_exit(f"{errorS} Failed to extract strings: {result.stderr}")
            
        if result.stdout:
            print("\n+------------------------------------------+")
            print("|            Extracted Strings             |")
            print("+------------------------------------------+\n")
            print(result.stdout)
        else:
            print(f"{infoS} No strings found in the file.")
    except Exception as e:
        err_exit(f"{errorS} Error during strings analysis: {str(e)}")

# Add YARA scanning function
def yara_scan(file_path):
    """Perform YARA rule scanning on a file"""
    try:
        print(f"\n{infoS} Performing YARA rule scanning...")
        
        # Check rules directory
        rules_dir = os.path.join(sc0pe_path, "Modules", "rules")
        if not os.path.exists(rules_dir):
            err_exit(f"{errorS} Rules directory not found at: {rules_dir}")
            
        # Get all .yar files
        yara_files = []
        for file in os.listdir(rules_dir):
            if file.endswith('.yar') or file.endswith('.yara'):
                yara_files.append(os.path.join(rules_dir, file))
                
        if not yara_files:
            err_exit(f"{errorS} No YARA rule files found in {rules_dir}")
            
        # Create results table
        results = Table(title="* YARA Scan Results *", title_style="bold italic cyan", title_justify="center")
        results.add_column("[bold green]Rule File", justify="center")
        results.add_column("[bold green]Matched Rules", justify="center")
        results.add_column("[bold green]Description", justify="center")
        
        match_found = False
        
        # Scan with each rule file
        for rule_file in yara_files:
            try:
                rules = yara.compile(filepath=rule_file)
                matches = rules.match(file_path)
                
                if matches:
                    match_found = True
                    for match in matches:
                        # Get rule description if available
                        description = ""
                        if hasattr(match, 'meta') and 'description' in match.meta:
                            description = match.meta['description']
                            
                        results.add_row(
                            os.path.basename(rule_file),
                            match.rule,
                            description
                        )
                        
            except Exception as e:
                print(f"{errorS} Error scanning with {rule_file}: {str(e)}")
                continue
                
        if match_found:
            print(results)
        else:
            print(f"{infoS} No YARA rules matched.")
            
    except Exception as e:
        err_exit(f"{errorS} YARA scanning failed: {str(e)}")

# Add PE analysis function
def analyze_pe_file(file_path, args):
    """Analyze PE file structure and characteristics"""
    try:
        pe = pefile.PE(file_path)
        
        if args.pe:
            console.print(f"\n{infoS} Basic PE Information:")
            basic_info = Table(title="* PE File Information *", title_style="bold italic cyan", title_justify="center")
            basic_info.add_column("[bold green]Property", justify="center")
            basic_info.add_column("[bold green]Value", justify="center")
            
            # Machine type
            machine_types = {
                0x14c: "x86 (32-bit)",
                0x8664: "x64 (64-bit)",
                0x1c0: "ARM",
                0xaa64: "ARM64"
            }
            machine = machine_types.get(pe.FILE_HEADER.Machine, f"Unknown (0x{pe.FILE_HEADER.Machine:04x})")
            
            # Characteristics
            characteristics = []
            if pe.FILE_HEADER.Characteristics & 0x0002:
                characteristics.append("Executable")
            if pe.FILE_HEADER.Characteristics & 0x2000:
                characteristics.append("DLL")
            if pe.FILE_HEADER.Characteristics & 0x0020:
                characteristics.append("Large Address Aware")
            
            # Subsystem
            subsystems = {
                1: "Native",
                2: "Windows GUI",
                3: "Windows Console",
                5: "OS/2 Console",
                7: "POSIX Console",
                9: "Windows CE GUI",
                10: "EFI Application",
                11: "EFI Boot Service",
                12: "EFI Runtime",
                13: "EFI ROM",
                14: "XBOX",
                16: "Windows Boot Application"
            }
            subsystem = subsystems.get(pe.OPTIONAL_HEADER.Subsystem, "Unknown")
            
            basic_info.add_row("Machine", machine)
            basic_info.add_row("Characteristics", ", ".join(characteristics))
            basic_info.add_row("Subsystem", subsystem)
            basic_info.add_row("Image Base", f"0x{pe.OPTIONAL_HEADER.ImageBase:08x}")
            basic_info.add_row("Entry Point", f"0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:08x}")
            basic_info.add_row("Linker Version", f"{pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}")
            basic_info.add_row("OS Version", f"{pe.OPTIONAL_HEADER.MajorOperatingSystemVersion}.{pe.OPTIONAL_HEADER.MinorOperatingSystemVersion}")
            
            console.print(basic_info)
            
        if args.imports:
            console.print(f"\n{infoS} PE Import Analysis:")
            import_table = Table(title="* Import Directory *", title_style="bold italic cyan", title_justify="center")
            import_table.add_column("[bold green]DLL", justify="center")
            import_table.add_column("[bold green]Function", justify="center")
            import_table.add_column("[bold green]Address", justify="center")
            
            try:
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        name = imp.name.decode() if imp.name else "ordinal-" + str(imp.ordinal)
                        import_table.add_row(
                            entry.dll.decode(),
                            name,
                            f"0x{imp.address:08x}"
                        )
                console.print(import_table)
            except Exception as e:
                console.print(f"{errorS} Error parsing imports: {str(e)}")
                
        if args.exports:
            console.print(f"\n{infoS} PE Export Analysis:")
            export_table = Table(title="* Export Directory *", title_style="bold italic cyan", title_justify="center")
            export_table.add_column("[bold green]Ordinal", justify="center")
            export_table.add_column("[bold green]Function", justify="center")
            export_table.add_column("[bold green]Address", justify="center")
            
            try:
                if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                        name = exp.name.decode() if exp.name else "unnamed"
                        export_table.add_row(
                            str(exp.ordinal),
                            name,
                            f"0x{pe.OPTIONAL_HEADER.ImageBase + exp.address:08x}"
                        )
                    console.print(export_table)
                else:
                    console.print(f"{infoS} No exports found")
            except Exception as e:
                console.print(f"{errorS} Error parsing exports: {str(e)}")
                
        if args.sections:
            console.print(f"\n{infoS} PE Section Analysis:")
            section_table = Table(title="* Section Table *", title_style="bold italic cyan", title_justify="center")
            section_table.add_column("[bold green]Name", justify="center")
            section_table.add_column("[bold green]Virtual Address", justify="center")
            section_table.add_column("[bold green]Virtual Size", justify="center")
            section_table.add_column("[bold green]Raw Size", justify="center")
            section_table.add_column("[bold green]Characteristics", justify="center")
            
            for section in pe.sections:
                name = section.Name.decode().rstrip('\x00')
                chars = []
                if section.Characteristics & 0x20:
                    chars.append("CODE")
                if section.Characteristics & 0x40:
                    chars.append("INITIALIZED")
                if section.Characteristics & 0x80:
                    chars.append("UNINITIALIZED")
                if section.Characteristics & 0x20000000:
                    chars.append("EXECUTE")
                if section.Characteristics & 0x40000000:
                    chars.append("READ")
                if section.Characteristics & 0x80000000:
                    chars.append("WRITE")
                    
                section_table.add_row(
                    name,
                    f"0x{section.VirtualAddress:08x}",
                    f"0x{section.Misc_VirtualSize:08x}",
                    f"0x{section.SizeOfRawData:08x}",
                    ", ".join(chars)
                )
            console.print(section_table)
            
        if args.resources:
            console.print(f"\n{infoS} PE Resource Analysis:")
            resource_table = Table(title="* Resource Directory *", title_style="bold italic cyan", title_justify="center")
            resource_table.add_column("[bold green]Type", justify="center")
            resource_table.add_column("[bold green]Name/ID", justify="center")
            resource_table.add_column("[bold green]Language", justify="center")
            resource_table.add_column("[bold green]Size", justify="center")
            
            try:
                if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                    for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                        try:
                            res_type = pefile.RESOURCE_TYPE.get(resource_type.struct.Id, str(resource_type.struct.Id))
                        except:
                            res_type = str(resource_type.struct.Id)
                            
                        if hasattr(resource_type, 'directory'):
                            for resource_id in resource_type.directory.entries:
                                if hasattr(resource_id, 'directory'):
                                    for resource_lang in resource_id.directory.entries:
                                        resource_table.add_row(
                                            res_type,
                                            str(resource_id.struct.Id),
                                            str(resource_lang.struct.Id),
                                            str(resource_lang.data.struct.Size)
                                        )
                    console.print(resource_table)
                else:
                    console.print(f"{infoS} No resources found")
            except Exception as e:
                console.print(f"{errorS} Error parsing resources: {str(e)}")
                
        if args.tls:
            console.print(f"\n{infoS} PE TLS Callback Analysis:")
            if hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
                tls_table = Table(title="* TLS Callbacks *", title_style="bold italic cyan", title_justify="center")
                tls_table.add_column("[bold green]Index", justify="center")
                tls_table.add_column("[bold green]Address", justify="center")
                
                try:
                    callbacks = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks
                    if callbacks:
                        callback_array = pe.get_dword_from_data(pe.get_data(callbacks, 4), 0)
                        idx = 0
                        while callback_array:
                            tls_table.add_row(str(idx), f"0x{callback_array:08x}")
                            idx += 1
                            callback_array = pe.get_dword_from_data(pe.get_data(callbacks + 4 * idx, 4), 0)
                        console.print(tls_table)
                    else:
                        console.print(f"{infoS} No TLS callbacks found")
                except Exception as e:
                    console.print(f"{errorS} Error parsing TLS callbacks: {str(e)}")
            else:
                console.print(f"{infoS} No TLS directory found")
                
        if args.debug:
            console.print(f"\n{infoS} PE Debug Information:")
            if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
                debug_table = Table(title="* Debug Directory *", title_style="bold italic cyan", title_justify="center")
                debug_table.add_column("[bold green]Type", justify="center")
                debug_table.add_column("[bold green]Timestamp", justify="center")
                debug_table.add_column("[bold green]Version", justify="center")
                debug_table.add_column("[bold green]Size", justify="center")
                
                for debug_entry in pe.DIRECTORY_ENTRY_DEBUG:
                    debug_type = pefile.DEBUG_TYPE.get(debug_entry.struct.Type, str(debug_entry.struct.Type))
                    timestamp = datetime.fromtimestamp(debug_entry.struct.TimeDateStamp).strftime('%Y-%m-%d %H:%M:%S')
                    version = f"{debug_entry.struct.MajorVersion}.{debug_entry.struct.MinorVersion}"
                    
                    debug_table.add_row(
                        debug_type,
                        timestamp,
                        version,
                        str(debug_entry.struct.SizeOfData)
                    )
                console.print(debug_table)
            else:
                console.print(f"{infoS} No debug information found")
                
        pe.close()
        
    except pefile.PEFormatError as e:
        err_exit(f"{errorS} Not a valid PE file: {str(e)}")
    except Exception as e:
        err_exit(f"{errorS} Error analyzing PE file: {str(e)}")

# Main function
def Qu1cksc0pe():
    # Getting all strings from the file if the target file exists.
    if args.file:
        if os.path.exists(args.file):
            # Before doing something we need to check file size
            file_size = os.path.getsize(args.file)
            if file_size < 52428800: # If given file smaller than 100MB
                if not shutil.which("strings"):
                    err_exit("[bold white on red][blink]strings[/blink] command not found. You need to install it.")
            else:
                print(f"{infoS} Whoa!! Looks like we have a large file here.")
                if args.analyze:
                    choice = str(input(f"\n{infoC} Do you want to analyze this file anyway [y/N]?: "))
                    if choice == "Y" or choice == "y":
                        BasicAnalyzer(analyzeFile=args.file)
                        sys.exit(0)

                if args.archive:
                    # Because why not!
                    print(f"{infoS} Analyzing: [bold green]{args.file}[white]")
                    execute_module(f"archiveAnalyzer.py \"{args.file}\"")
                    sys.exit(0)

                # Check for embedded executables by default!
                if not args.sigcheck:
                    print(f"{infoS} Executing [bold green]SignatureAnalyzer[white] module...")
                    execute_module(f"sigChecker.py \"{args.file}\"")
                    sys.exit(0)
        else:
            err_exit("[bold white on red]Target file not found!\n")

    # Analyze the target file
    if args.analyze:
        # Handling --file argument
        if args.file is not None:
            BasicAnalyzer(analyzeFile=args.file)
        # Handling --folder argument
        if args.folder is not None:
            err_exit("[bold white on red][blink]--analyze[/blink] argument is not supported for folder analyzing!\n")

    # Analyze archive files
    if args.archive:
        # Handling --file argument
        if args.file is not None:
            print(f"{infoS} Analyzing: [bold green]{args.file}[white]")
            execute_module(f"archiveAnalyzer.py \"{args.file}\"")
        # Handling --folder argument
        if args.folder is not None:
            err_exit("[bold white on red][blink]--docs[/blink] argument is not supported for folder analyzing!\n")

    # Analyze document files
    if args.docs:
        # Handling --file argument
        if args.file is not None:
            print(f"{infoS} Analyzing: [bold green]{args.file}[white]")
            execute_module(f"document_analyzer.py \"{args.file}\"")
        # Handling --folder argument
        if args.folder is not None:
            err_exit("[bold white on red][blink]--docs[/blink] argument is not supported for folder analyzing!\n")

    # Hash Scanning
    if args.hashscan:
        # Handling --file argument
        if args.file is not None:
            execute_module(f"hashScanner.py \"{args.file}\" --normal")
        # Handling --folder argument
        if args.folder is not None:
            execute_module(f"hashScanner.py {args.folder} --multiscan")

    # File signature scanner
    if args.sigcheck:
        # Handling --file argument
        if args.file is not None:
            execute_module(f"sigChecker.py \"{args.file}\"")
        # Handling --folder argument
        if args.folder is not None:
            err_exit("[bold white on red][blink]--sigcheck[/blink] argument is not supported for folder analyzing!\n")

    # Resource analyzer
    if args.resource:
        # Handling --file argument
        if args.file is not None:
            execute_module(f"resourceChecker.py \"{args.file}\"")
        # Handling --folder argument
        if args.folder is not None:
            err_exit("[bold white on red][blink]--resource[/blink] argument is not supported for folder analyzing!\n")

    # MITRE ATT&CK
    if args.mitre:
        # Handling --file argument
        if args.file is not None:
            execute_module(f"mitre.py \"{args.file}\"")
        # Handling --folder argument
        if args.folder is not None:
            err_exit("[bold white on red][blink]--mitre[/blink] argument is not supported for folder analyzing!\n")

    # Language detection
    if args.lang:
        # Handling --file argument
        if args.file is not None:
            execute_module(f"languageDetect.py \"{args.file}\"")
        # Handling --folder argument
        if args.folder is not None:
            err_exit("[bold white on red][blink]--lang[/blink] argument is not supported for folder analyzing!\n")

    # VT File scanner
    if args.vtFile:
        # Handling --file argument
        if args.file is not None:
            # if there is no key quit
            try:
                directory = f"{homeD}{path_seperator}sc0pe_Base{path_seperator}sc0pe_VT_apikey.txt"
                apik = open(directory, "r").read().split("\n")
            except:
                err_exit("[bold white on red]Use [blink]--key_init[/blink] to enter your key!\n")
            # if key is not valid quit
            if apik[0] == '' or apik[0] is None or len(apik[0]) != 64:
                err_exit("[bold]Please get your API key from -> [bold green][a]https://www.virustotal.com/[/a]\n")
            else:
                execute_module(f"VTwrapper.py {apik[0]} \"{args.file}\"")
        # Handling --folder argument
        if args.folder is not None:
            err_exit("[bold white on red]If you want to get banned from VirusTotal then do that :).\n")

    # packer detection
    if args.packer:
        # Handling --file argument
        if args.file is not None:
            execute_module(f"packerAnalyzer.py --single \"{args.file}\"")
        # Handling --folder argument
        if args.folder is not None:
            execute_module(f"packerAnalyzer.py --multiscan {args.folder}")

    # domain extraction
    if args.domain:
        # Handling --file argument
        if args.file is not None:
            execute_module(f"domainCatcher.py \"{args.file}\"")
        # Handling --folder argument
        if args.folder is not None:
            err_exit("[bold white on red][blink]--domain[/blink] argument is not supported for folder analyzing!\n")

    # Dynamic analysis
    if args.watch:
        execute_module(f"emulator.py")

    # Interactive shell
    if args.console:
        execute_module(f"console.py")

    # Database update
    if args.db_update:
        execute_module(f"hashScanner.py --db_update")

    # entering VT API key
    if args.key_init:
        try:
            if os.path.exists(f"{homeD}{path_seperator}sc0pe_Base"):
                pass
            else:
                os.system(f"mkdir {homeD}{path_seperator}sc0pe_Base")

            apikey = str(input(f"{infoC} Enter your VirusTotal API key: "))
            apifile = open(f"{homeD}{path_seperator}sc0pe_Base{path_seperator}sc0pe_VT_apikey.txt", "w")
            apifile.write(apikey)
            print(f"{foundS} Your VirusTotal API key saved.")
        except KeyboardInterrupt:
            print("\n[bold white on red]Program terminated by user.\n")

    # Install Qu1cksc0pe on your system!!
    if args.install:
        if sys.platform == "win32":
            err_exit(f"{errorS} This feature is not suitable for Windows systems for now!")

        execute_module(f"installer.sh {sc0pe_path} {username}", invoker="sudo bash")

    # Strings analysis
    if args.strings:
        if not args.file:
            err_exit(f"{errorS} --file argument is required for strings analysis")
        analyze_strings(args.file)

    # Add YARA scanning
    if args.yara:
        if args.file:
            yara_scan(args.file)
        elif args.folder:
            err_exit(f"{errorS} YARA scanning of folders not yet supported")
        else:
            err_exit(f"{errorS} Please specify a file to scan with --file")

    # Add PE analysis
    if any([args.pe, args.imports, args.exports, args.sections, args.resources, args.tls, args.debug]):
        if args.file:
            analyze_pe_file(args.file, args)
        elif args.folder:
            err_exit(f"{errorS} PE analysis of folders not yet supported")
        else:
            err_exit(f"{errorS} Please specify a file to analyze with --file")

def cleanup_junks():
    junkFiles = ["temp.txt", ".path_handler", ".target-file.txt", ".target-folder.txt", "TargetAPK/", "TargetSource/"]
    for junk in junkFiles:
        if os.path.exists(junk):
            try: # assume simple file
                os.unlink(junk)
            except OSError: # try this for directories
                shutil.rmtree(junk)

def main():
    try:
        Qu1cksc0pe()
    finally: # ensure cleanup irrespective of errors
        cleanup_junks()


# This is the entrypoint when directly running
# this module as a standalone program
# (as opposed to it being imported/ran like a lib)
if __name__ == "__main__":
    main()
