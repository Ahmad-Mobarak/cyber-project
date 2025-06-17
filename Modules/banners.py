#!/usr/bin/python3

import sys
import random

from .utils import err_exit

# Module for colors
try:
    from rich import print
except:
    err_exit("Error: >rich< module not found.")

# Colors
re = "[bold red]"
cy = "[bold cyan]"
wh = "[white]"
gr = "[bold green]"
ma = "[bold magenta]"
ye = "[bold yellow]"
bl = "[bold blue]"

banner1 = f"""
 {cy}+------------------------------------------+
 |                                          |
 |     {gr}MALWARE ANALYSIS TOOLKIT{cy}             |
 |                                          |
 |     {wh}Free and Open Source Software{cy}        |
 |                                          |
 +------------------------------------------+

 {wh}A comprehensive toolkit for analyzing malicious software
 {ye}--------------------------------------------------
"""

banner2=f"""
 {cy}+------------------------------------------+
 |                                          |
 |  {ma}MALWARE ANALYSIS{cy}                      |
 |                                          |
 |  {wh}Analyze suspicious files safely{cy}        |
 |                                          |
 +------------------------------------------+

 {wh}Static and dynamic analysis for various file types
 {ye}--------------------------------------------------
"""

banner3=f"""
 {re}+------------------------------------------+
 |                                          |
 |  {wh}WARNING: HANDLE WITH CARE{re}              |
 |                                          |
 |  {wh}Malware analysis can be dangerous{re}      |
 |                                          |
 +------------------------------------------+

 {wh}Always use proper isolation when analyzing samples
 {gr}--------------------------------------------------
"""

banner4=f"""
 {ye}+------------------------------------------+
 |                                          |
 |  {re}MALWARE ANALYSIS TOOL{ye}                 |
 |                                          |
 |  {wh}Free & Open Source{ye}                    |
 |                                          |
 +------------------------------------------+

 {wh}Identify threats and understand malicious behavior
 {gr}--------------------------------------------------
"""

banner5=f"""
 {gr}+------------------------------------------+
 |                                          |
 |  {wh}STATIC ANALYSIS{gr}                       |
 |                                          |
 |  {wh}Examine without execution{gr}             |
 |                                          |
 +------------------------------------------+

 {wh}Extract indicators and detect suspicious patterns
 {ye}--------------------------------------------------
"""

banner6=f"""
 {cy}+------------------------------------------+
 |                                          |
 |  {wh}DYNAMIC ANALYSIS{cy}                     |
 |                                          |
 |  {wh}Monitor runtime behavior{cy}             |
 |                                          |
 +------------------------------------------+

 {wh}Track system changes and network communications
 {gr}--------------------------------------------------
"""

banner7=f"""
 {re}+------------------------------------------+
 |                                          |
 |  {wh}SECURITY RESEARCH{re}                    |
 |                                          |
 |  {wh}For educational purposes only{re}        |
 |                                          |
 +------------------------------------------+

 {wh}Use responsibly and ethically
 {gr}--------------------------------------------------
"""

banner8=f"""
 {ma}+------------------------------------------+
 |                                          |
 |  {wh}FILE ANALYSIS{ma}                        |
 |                                          |
 |  {wh}Windows, Linux, MacOS & Android{ma}      |
 |                                          |
 +------------------------------------------+

 {wh}Multi-platform malware analysis capabilities
 {cy}--------------------------------------------------
"""

banner9=f"""
 {ye}+------------------------------------------+
 |                                          |
 |  {wh}THREAT INTELLIGENCE{ye}                  |
 |                                          |
 |  {wh}Knowledge is power{ye}                   |
 |                                          |
 +------------------------------------------+

 {wh}Understand techniques, tactics and procedures
 {gr}--------------------------------------------------
"""

banner10=f"""
 {gr}+------------------------------------------+
 |                                          |
 |  {re}CYBERSECURITY TOOLKIT{gr}                |
 |                                          |
 |  {wh}Defend through understanding{gr}         |
 |                                          |
 +------------------------------------------+

 {wh}Analyze potentially malicious files safely
 {ye}--------------------------------------------------
"""

randomBanner = random.randint(1, 10)
if randomBanner == 1:
    print(banner1)
elif randomBanner == 2:
    print(banner2)
elif randomBanner == 3:
    print(banner3)
elif randomBanner == 4:
    print(banner4)
elif randomBanner == 5:
    print(banner5)
elif randomBanner == 6:
    print(banner6)
elif randomBanner == 7:
    print(banner7)
elif randomBanner == 8:
    print(banner8)
elif randomBanner == 9:
    print(banner9)
elif randomBanner == 10:
    print(banner10)
else:
    pass
