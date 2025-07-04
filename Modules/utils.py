import re
import os
import sys

from rich import print
from rich.table import Table
from rich.text import Text


TABLE_TITLE_DEFAULTS = dict(
    title_justify="center",
    title_style="bold italic cyan",
)

# Compatibility
path_seperator = "/"
strings_param = "-a"
if sys.platform == "win32":
    path_seperator = "\\"

# Gathering Qu1cksc0pe path variable
try:
    # Try to determine if we're running in a PyInstaller bundle
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        # We are running in a PyInstaller bundle
        sc0pe_path = os.path.dirname(sys.executable)
        # Create a path_handler file in the executable directory if it doesn't exist
        path_handler_file = os.path.join(sc0pe_path, ".path_handler")
        if not os.path.exists(path_handler_file):
            with open(path_handler_file, "w") as f:
                f.write(sc0pe_path)
    else:
        # We are running in a normal Python environment, read from .path_handler
        sc0pe_path = open(".path_handler", "r").read().strip()
except Exception as e:
    # Fallback: use current directory
    sc0pe_path = os.getcwd()
    print(f"[bold red]Warning: Could not determine Qu1cksc0pe path. Using current directory: {sc0pe_path}[/bold red]")
    # Create path_handler in current directory
    with open(".path_handler", "w") as f:
        f.write(sc0pe_path)

# Get whitelist domains for "chk_wlist" method
try:
    whitelist_path = f"{sc0pe_path}{path_seperator}Systems{path_seperator}Multiple{path_seperator}whitelist_domains.txt"
    if os.path.exists(whitelist_path):
        whitelist_domains = open(whitelist_path, "r").read().split("\n")
    else:
        print(f"[bold red]Warning: Whitelist file not found at {whitelist_path}[/bold red]")
        whitelist_domains = []
except Exception as e:
    print(f"[bold red]Warning: Could not load whitelist domains: {str(e)}[/bold red]")
    whitelist_domains = []

def get_argv(idx, default=None):
    """Return the `sys.argv` value for the given index, defaulting on `None` or a supplied custom value."""
    try:
        return sys.argv[int(idx)]
    except IndexError:
        return default

def err_exit(message, arg_override=1):
    print(message)
    sys.exit(arg_override)

def emit_table(
    item_li, item_name, *col_names,
    row_extractor=lambda x:(x,), warn_on_empty=True,
    **tinit_kwargs
):
    """
    High level convenience util which entirely manages construction and subsequent display of a table.
    """
    if len(item_li) == 0:
        if warn_on_empty:
            print(f"\n[bold red]>>>[white] No {item_name}s found\n")
        return

    t = init_table(*col_names, **tinit_kwargs, title=f"* {item_name.title()}s *")
    for item in item_li:
        t.add_row(*row_extractor(item))
    print(t)

def init_table(*col_names, style=None, col_prefix="", justify="center", **title_kwargs):
    """
    Initialize a `rich.table` `Table`, with defaults common for this project.

    If you want, you can pass any number of column names as positional arguments;
    corresponding columns will be added for you.

    The keyword arguments specifically listed in the signature get applied
    to the internal `add_column` calls. All other, additional keyword arguments
    will be passed to `Table.__init__` (overriding defaults in case of collisions).

    If no additional keyword arguments meant for the title get passed,
    a `Table` object without a title is created.
    """
    t = Table() if len(title_kwargs) == 0 else Table(**{**TABLE_TITLE_DEFAULTS, **title_kwargs})
    for name in col_names:
        t.add_column(col_prefix+name, style=style, justify=justify)
    return t

def no_blanks(str_li):
    return (x for x in str_li if len(x.strip()) > 0)

def user_confirm(question_text):
    return str(input(question_text)).lower() == "y"

def stylize_bool(b, invert_style=False):
    prefix = "[bold green]" if b ^ invert_style else "[bold red]"
    return prefix + repr(b)

def chk_wlist(target_string):
    for pat in whitelist_domains:
        matched = re.findall(pat, target_string)
        if matched:
            return False # Whitelist found
    return True

def recursive_dir_scan(target_directory):
    fnames = []
    for root, d_names, f_names in os.walk(target_directory):
        for ff in f_names:
            fnames.append(os.path.join(root, ff))
    return fnames

def update_table(table, row_size, *args):
    if len(table.columns[0]._cells) < row_size:
        table.add_row(*args)
    else:
        ans_ind = len(table.columns[0]._cells)
        for i, arg in enumerate(args):
            table.columns[i]._cells[ans_ind-1] = Text(str(arg), style="bold italic cyan")