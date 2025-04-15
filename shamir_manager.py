#!/usr/bin/env python3
"""
shamir_manager.py

A comprehensive, terminal-based Shamir Secret Manager that lets you:
  1. Create new shares from a valid 12- or 24-word BIP-39 seed phrase.
  2. Recover a secret from share files.
  3. Run a sanity check to verify share consistency.
  4. View instructions on how to use this program.
  5. Exit.

Each share is stored as a JSON file (with a .json extension) that embeds necessary metadata:
  - A "magic" marker, protocol, and version.
  - A unique set_id, total_shares, threshold, and creation_date.
  - The share's data: share_index and share_hex (the share bytes as HEX).
  - A checksum (SHA-256 of the share bytes).

Dependencies:
  pip install mnemonic pycryptodome inquirer
"""

import sys, json, uuid, hashlib, re, itertools, os, getpass
from pathlib import Path
from datetime import datetime, timezone
from mnemonic import Mnemonic
from Crypto.Protocol.SecretSharing import Shamir
import inquirer

MAGIC = "SSS-MANAGER-1"
PROTOCOL = "ShamirSecretSharing"
VERSION = "1.0"

# ================== Terminal Display Helpers ==================

def clear_screen():
    """
    Clears the terminal screen.
    Works on both Unix-like (clear) and Windows (cls) systems.
    """
    os.system('cls' if os.name == 'nt' else 'clear')

# ================== Input Helpers ==================

def input_with_mask(prompt=""):
    """
    Read input from the user while displaying asterisks.
    Supports both Unix-like and Windows platforms.
    """
    if sys.platform == 'win32':
        import msvcrt
        sys.stdout.write(prompt)
        sys.stdout.flush()
        chars = []
        while True:
            ch = msvcrt.getch()
            if ch in {b'\r', b'\n'}:
                sys.stdout.write("\n")
                break
            elif ch == b'\x03':  # Ctrl-C
                raise KeyboardInterrupt
            elif ch == b'\x08':  # Backspace
                if chars:
                    chars.pop()
                    sys.stdout.write("\b \b")
            else:
                chars.append(ch.decode("utf-8", "ignore"))
                sys.stdout.write("*")
            sys.stdout.flush()
        return "".join(chars)
    else:
        import tty, termios
        sys.stdout.write(prompt)
        sys.stdout.flush()
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            chars = []
            while True:
                ch = sys.stdin.read(1)
                if ch in ("\r", "\n"):
                    sys.stdout.write("\n")
                    break
                elif ch == "\x03":  # Ctrl-C
                    raise KeyboardInterrupt
                elif ch == "\x7f":  # Backspace
                    if chars:
                        chars.pop()
                        sys.stdout.write("\b \b")
                else:
                    chars.append(ch)
                    sys.stdout.write("*")
                sys.stdout.flush()
            return "".join(chars)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

def get_seed_phrase(seed_type: int) -> str:
    """
    Prompt the user to choose whether to mask the seed phrase input.
    If masked is chosen, the input is echoed as asterisks;
    otherwise, the input appears in clear text.
    """
    question = [
        inquirer.List(
            "seed_entry_mode",
            message="Choose seed entry mode:",
            choices=[
                ("Show input as asterisk (masked)", True),
                ("Show clear text", False)
            ],
        )
    ]
    answer = inquirer.prompt(question)
    use_mask = answer.get("seed_entry_mode")
    prompt_text = f"Enter your valid {seed_type}-word BIP-39 seed phrase:\n> "
    if use_mask:
        return input_with_mask(prompt_text)
    else:
        return input(prompt_text).strip()

# ================== Core Functions ==================

def main_menu():
    choices = [
        ("Create new shares from a seed phrase", "create"),
        ("Recover secret from share files", "recover"),
        ("Sanity check share consistency", "sanity"),
        ("How to use this", "instructions"),
        ("Exit", "exit")
    ]
    question = [
        inquirer.List(
            "action",
            message="Shamir Secret Manager – Select an option:",
            choices=choices,
        )
    ]
    answers = inquirer.prompt(question)
    return answers.get("action")

def show_instructions():
    instructions = """
How to Use Shamir Secret Manager

This program securely splits your BIP-39 seed phrase into multiple share files using Shamir's Secret Sharing.
You can choose between a 12-word seed (128-bit entropy) and a 24-word seed (256-bit entropy).
Before entering the seed phrase, choose whether to show clear text or have it masked with asterisks.
The share files include complete metadata, and file permissions are enforced to protect your data locally.
After creation, you can securely distribute the shares to designated recipients for future recovery.
    """
    print(instructions)

def choose_seed_type():
    question = [
        inquirer.List(
            "seed_type",
            message="Select seed type:",
            choices=[
                ("12-word seed (128-bit entropy)", 12),
                ("24-word seed (256-bit entropy)", 24)
            ],
        )
    ]
    answer = inquirer.prompt(question)
    return answer.get("seed_type")

def choose_share_parameters():
    presets = [
        ("3 shares, threshold 2 (default)", (3, 2)),
        ("5 shares, threshold 3", (5, 3)),
        ("6 shares, threshold 4", (6, 4)),
        ("Enter values manually", None)
    ]
    question = [
        inquirer.List(
            "config",
            message="Select a share configuration:",
            choices=[(label, config) for label, config in presets],
            default="3 shares, threshold 2 (default)"
        )
    ]
    answer = inquirer.prompt(question)
    config = answer.get("config")
    if config is None:
        try:
            n = int(input("Enter total number of shares (default 3):\n> ") or "3")
            k = int(input("Enter threshold required to recover (default 2):\n> ") or "2")
        except ValueError:
            print("Invalid input. Using defaults (3 shares, threshold 2).")
            n, k = 3, 2
    else:
        n, k = config
    if k > n or k <= 0 or n <= 0:
        print("Invalid parameters provided. Using defaults (3 shares, threshold 2).")
        n, k = 3, 2
    return n, k

def choose_output_folder(n=None, k=None):
    question = [
        inquirer.List(
            "folder_option",
            message="Select an option for storing share files:",
            choices=[
                ("Use default folder 'shares'", "default"),
                ("Enter folder name manually", "manual")
            ],
        )
    ]
    answer = inquirer.prompt(question)
    option = answer.get("folder_option")
    if option == "default":
        now = datetime.now(timezone.utc).strftime("%d-%m-%Y")
        folder_name = f"shares_{n}s-{k}t_{now}" if n and k else f"shares_{now}"
        default_folder = Path(folder_name)
        if default_folder.exists():
            print(f"Folder '{default_folder}' already exists. Please enter a new folder name:")
            folder_name = input("> ").strip()
            return Path(folder_name)
        else:
            return default_folder
    else:
        folder_name = input("Enter the folder name to store share files:\n> ").strip()
        return Path(folder_name)

def create_shares():
    clear_screen()  # Clear terminal before starting share creation
    print("\n== Create New Shares ==")
    seed_type = choose_seed_type()
    seed_phrase = get_seed_phrase(seed_type)
    words = seed_phrase.split()
    if len(words) != seed_type:
        print(f"Warning: Expected {seed_type} words but got {len(words)}. Aborting.")
        return
    mnemo = Mnemonic("english")
    if not mnemo.check(seed_phrase):
        print("❌ Invalid seed phrase. Aborting.")
        return
    entropy = mnemo.to_entropy(seed_phrase)
    print("Seed phrase is valid.\nEntropy (hex):", entropy.hex())
    n, k = choose_share_parameters()
    now_utc = datetime.now(timezone.utc)
    set_id = f"SSS-{now_utc.strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
    folder = choose_output_folder(n, k)
    folder.mkdir(parents=True, exist_ok=True)
    creation_date = now_utc.isoformat().replace("+00:00", "Z")
    print(f"\nCreating {n} shares with threshold {k} in folder: {folder.resolve()}")
    shares = Shamir.split(k=k, n=n, secret=entropy, ssss=False)
    for (share_index, share_bytes) in shares:
        share_hex = share_bytes.hex()
        checksum = hashlib.sha256(share_bytes).hexdigest()
        share_data = {
            "magic": MAGIC,
            "protocol": PROTOCOL,
            "version": VERSION,
            "set_id": set_id,
            "total_shares": n,
            "threshold": k,
            "creation_date": creation_date,
            "share": {
                "share_index": share_index,
                "share_hex": share_hex
            },
            "checksum": checksum
        }
        filename = f"SSS_{set_id}_share_{share_index}.json"
        filepath = folder / filename
        with filepath.open("w", encoding="utf-8") as f:
            json.dump(share_data, f, indent=2)
        # Set file permissions to -rw------- (600) to restrict access locally.
        os.chmod(filepath, 0o600)
        print(f"Created: {filepath.resolve()}")
    print("\nShare creation complete.")
    print(f"Keep these files secure. Any {k} shares will recover your secret.\n")
    question = [
        inquirer.Confirm("autotest", message="Run an automatic recovery test on these shares now?", default=True)
    ]
    answer = inquirer.prompt(question)
    if answer.get("autotest"):
        test_shares_in_folder(folder)

def extract_index_from_filename(filename):
    m = re.search(r"(\d+)", filename)
    if m:
        return int(m.group(1))
    return None

def load_share(file_path):
    try:
        with file_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if data.get("magic") != MAGIC:
            raise ValueError("Invalid magic marker.")
        share = data.get("share")
        if not isinstance(share, dict):
            raise ValueError("Share data missing or malformed.")
        share_index = int(share["share_index"])
        share_hex = share["share_hex"]
        share_bytes = bytes.fromhex(share_hex)
        threshold = data.get("threshold")
        expected = data.get("checksum", "")
        calc = hashlib.sha256(share_bytes).hexdigest()
        if expected and expected != calc:
            raise ValueError("Checksum mismatch in " + file_path.name)
        return (share_index, share_bytes, threshold)
    except (json.JSONDecodeError, KeyError, ValueError) as e:
        print(f"Warning: Failed to load JSON from {file_path.name} due to error: {e}")
        with file_path.open("r", encoding="utf-8") as f:
            raw = f.read().strip()
        try:
            share_bytes = bytes.fromhex(raw)
        except ValueError:
            raise ValueError(f"File {file_path.name} does not contain valid HEX data.")
        idx = extract_index_from_filename(file_path.name)
        if idx is None:
            idx = int(input(f"Enter the share index for file {file_path.name}: "))
        return (idx, share_bytes, None)

def choose_share_folder(default_root="."):
    root = Path(default_root)
    subfolders = [f for f in root.iterdir() if f.is_dir() and not f.name.startswith('.')]
    if not subfolders:
        return None
    choices = [(folder.name, folder) for folder in subfolders]
    question = [
        inquirer.List(
            "selected_folder",
            message="Select the folder containing your share files:",
            choices=choices,
        )
    ]
    answer = inquirer.prompt(question)
    if answer:
        return answer.get("selected_folder")
    return None

def recover_secret():
    clear_screen()  # Clear the screen before starting recovery
    print("\n== Recover Secret ==")
    auto_folder = choose_share_folder(".")
    if auto_folder:
        print(f"Auto-detected folder: {auto_folder.resolve()}")
        folder_path = auto_folder
    else:
        folder_path = Path(input("Enter the folder where your share files are stored (default 'shares'):\n> ").strip() or "shares")
    if not folder_path.is_dir():
        print(f"Folder '{folder_path}' does not exist. Aborting recovery.")
        return
    share_files = sorted(list(folder_path.glob("*.json")) + list(folder_path.glob("*.hex.txt")))
    if len(share_files) < 1:
        print("No share files found in folder. Aborting.")
        return
    choices = [(f.name, f) for f in share_files]
    question = [
        inquirer.Checkbox(
            "selected_files",
            message="Select share files to combine (use arrow keys and space bar):",
            choices=choices,
        )
    ]
    answers = inquirer.prompt(question)
    selected_files = answers.get("selected_files", [])
    if not selected_files:
        print("No files selected. Aborting recovery.")
        return
    shares = []
    detected_threshold = None
    for f in selected_files:
        idx, share_bytes, thr = load_share(f)
        shares.append((idx, share_bytes))
        if thr is not None and detected_threshold is None:
            detected_threshold = int(thr)
    if detected_threshold is not None and len(shares) < detected_threshold:
        print(f"Insufficient shares selected. {detected_threshold} are required, but only {len(shares)} were selected.")
        return
    try:
        recovered_entropy = Shamir.combine(shares)
    except Exception as e:
        print("Error during Shamir recovery:", e)
        return
    print("\nRecovered Entropy (hex):", recovered_entropy.hex())
    mnemo = Mnemonic("english")
    recovered_phrase = mnemo.to_mnemonic(recovered_entropy)
    valid = mnemo.check(recovered_phrase)
    # First print a multi-line warning so it doesn't get truncated in a narrow terminal
    print("\nWARNING: The recovered seed phrase is highly sensitive.\n"
          "Display it only if you are in a private environment and fully aware of the risks.\n")
    # Then ask a short confirmation prompt to show the recovered seed phrase
    warning_question = [
        inquirer.Confirm("display", message="Show the recovered seed phrase?", default=False)
    ]
    answer = inquirer.prompt(warning_question)
    if answer.get("display"):
        print("\nRecovered seed phrase:", recovered_phrase)
    else:
        print("\nRecovered seed phrase display suppressed by user.")
    print("BIP-39 Validity check:", valid)
    print("\nIf this matches your original seed, your shares are correct.\n")

def test_shares_in_folder(folder: Path):
    share_files = sorted(list(folder.glob("*.json")) + list(folder.glob("*.hex.txt")))
    if len(share_files) < 1:
        print("No share files found for testing.")
        return
    shares_full = []
    for f in share_files:
        try:
            idx, share_bytes, thr = load_share(f)
            shares_full.append((idx, share_bytes))
            if thr is not None:
                threshold = int(thr)
        except Exception as e:
            print(f"Error loading {f.name}: {e}")
            return
    if not shares_full:
        print("No valid shares loaded for testing.")
        return
    required = threshold if 'threshold' in locals() else 2
    if len(shares_full) < required:
        print(f"Not enough shares for sanity test (need {required}).")
        return
    print(f"\nRunning sanity check using all combinations of {required} shares...")
    recovered_set = set()
    for comb in itertools.combinations(shares_full, required):
        try:
            secret = Shamir.combine(list(comb))
            recovered_set.add(secret.hex())
        except Exception as e:
            print("Combination error:", e)
            return
    if len(recovered_set) == 1:
        print("Sanity check passed: All combinations recovered the same secret.")
        print("Recovered secret (hex):", recovered_set.pop())
    else:
        print("Sanity check FAILED: Different secret values recovered from different combinations.")

def sanity_check():
    clear_screen()  # Clear screen before running sanity check
    print("\n== Sanity Check for Share Consistency ==")
    auto_folder = choose_share_folder(".")
    if auto_folder:
        folder_path = auto_folder
    else:
        folder_path = Path(input("Enter the folder for sanity check (default 'shares'):\n> ").strip() or "shares")
    if not folder_path.is_dir():
        print(f"Folder '{folder_path}' does not exist. Aborting sanity check.")
        return
    test_shares_in_folder(folder_path)

def main():
    while True:
        clear_screen()  # Clear terminal before showing main menu
        action = main_menu()
        if action == "create":
            create_shares()
        elif action == "recover":
            recover_secret()
        elif action == "sanity":
            sanity_check()
        elif action == "instructions":
            clear_screen()
            show_instructions()
            input("\nPress Enter to return to the main menu...")
        elif action == "exit" or action is None:
            clear_screen()
            print("Exiting. Stay safe!")
            sys.exit(0)
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
