# Shamir Secret Manager

A robust, terminal-based Python tool for securely splitting a 12- or 24-word BIP-39 seed phrase into multiple share files using Shamir's Secret Sharing—and for reliably recovering the original secret from a subset of those shares. Originally designed to protect cryptocurrency wallet seeds, this tool now features enhanced input options, an improved terminal interface, and additional safeguards to support long-term distribution among trusted parties.

![Shamir Secret Manager – Dark Mode](dark-mode.png#gh-dark-mode-only)
![Shamir Secret Manager – Light Mode](light-mode.png#gh-light-mode-only)

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [How It Works](#how-it-works)
- [Installation](#installation)
- [Usage](#usage)
  - [Main Menu Options](#main-menu-options)
  - [Creating Shares](#creating-shares)
  - [Folder Naming & File Permissions](#folder-naming--file-permissions)
  - [Recovering the Secret](#recovering-the-secret)
  - [Sanity Check](#sanity-check)
  - [Terminal Interaction](#terminal-interaction)
- [File Format and Metadata](#file-format-and-metadata)
- [Contributing](#contributing)
- [License](#license)
- [Disclaimer](#disclaimer)

## Overview

Shamir Secret Manager is a command‑line application built with Python 3.13+ that employs Shamir's Secret Sharing to protect your cryptocurrency wallet seed phrase. It splits a sensitive 12‑ or 24‑word BIP‑39 seed into multiple share files. A defined threshold of shares is required to reconstruct the secret, ensuring that no single file is sufficient for recovery. This layered approach enhances security while providing an option to distribute shares among family members or trusted parties for long‑term recovery.

## Features

- **Dual Seed Support:**
  Choose between a 12‑word seed (128‑bit entropy) and a 24‑word seed (256‑bit entropy).

- **Preset Share Configurations:**
  The default configuration is "3 shares, threshold 2" for ease of use. Other options include "5 shares, threshold 3", "6 shares, threshold 4," and an option for manual configuration.

- **Optional Masked Input:**
  Before entering your seed phrase, choose whether the input should be masked (displayed as asterisks that still provide visual feedback) or shown in clear text, allowing you to verify your typing in trusted environments.

- **Robust Metadata & Security:**
  Each share is stored as a JSON file that embeds vital metadata such as:
  - A unique set identifier.
  - Share index, total shares, and recovery threshold.
  - A timezone‑aware UTC creation date.
  - A SHA‑256 checksum of the share bytes for integrity.

- **Automatic Folder Naming & Secure File Permissions:**
  When using the default option, share files are saved within an auto‑generated folder named in the format:
  ```
  shares_<n>s-<k>t_<DD-MM-YYYY>
  ```
  Files are written with restrictive permissions (0o600) to protect them on your computer. Permissions can later be relaxed or re‑applied when distributing shares securely.

- **Interactive, Minimal CLI:**
  The tool uses the inquirer library to provide an intuitive interface with arrow‑key navigation and checkboxes, reducing the need for manual input.

- **Recovery & Sanity Checks:**
  Recover your secret by interactively selecting share files. A built‑in sanity check tests every valid combination of the required shares to ensure each combination yields the same secret, thereby confirming the integrity of your backup.

- **Terminal Interface Improvements:**
  The interface clears previous outputs before key operations, ensuring that only current inputs and messages are visible. Multi‑line warning messages, especially during secret recovery, prevent important notices from being truncated in narrow terminal windows.

- **Instruction Mode:**
  On‑demand instructions describe how to operate the tool and secure your share files.

## How It Works

1. **Creating Shares:**
   - **Seed Entry:**
     Select the seed type and decide if the input will be masked or shown as clear text. The tool validates that the entered seed phrase matches the expected word count and structure.
   - **Share Configuration:**
     The default "3 shares, threshold 2" is pre‑selected. You may choose from other presets or enter custom values.
   - **Folder Output:**
     Choose between a default folder (auto‑named to include share configuration and current date) or specify a custom folder.
   - **Output:**
     Your seed phrase is converted to entropy, split using Shamir's algorithm, and each share is saved in a JSON file with embedded metadata and enforced file permissions.

2. **Recovering the Secret:**
   - **Folder Detection:**
     The program scans for non‑hidden subfolders (or uses a specified folder) that contain your share files.
   - **Share Selection:**
     Use checkboxes to select the share files required for recovery.
   - **Multi‑Line Warning & Recovery:**
     The tool prints a full warning (ensuring it is not truncated) before asking for confirmation to display the sensitive recovered seed phrase. The recovered secret is shown as both HEX and the original seed phrase (if confirmed).
   - **Note:** The recovery process can also work with share files that contain only the raw HEX data (even if they do not follow the JSON format).


3. **Sanity Check:**
   - The sanity check option tests all valid combinations of the required shares to verify that each combination recovers the identical secret, ensuring backup integrity.

4. **Instruction Mode:**
   - Displays detailed instructions and best practices for using the tool and securing your share files.

## Installation

Ensure you have Python 3.13 or later installed. Then install the required dependencies:

```
pip install mnemonic pycryptodome inquirer
```

Clone the repository or download the project source, and launch the tool from your terminal:

```
python3 shamir_manager.py
```

## Usage

### Main Menu Options

When you launch the program, you are presented with a menu (navigable via arrow keys) that allows you to:
- Create new shares from a seed phrase.
- Recover secret from share files.
- Perform a sanity check for share consistency.
- View detailed instructions.
- Exit the application.

### Creating Shares
- **Seed Type Selection:**
  Choose between a 12‑word seed (128‑bit entropy) or a 24‑word seed (256‑bit entropy).
- **Seed Entry:**
  Decide whether to mask the seed phrase (with asterisks) or to display it in clear text. The tool verifies that the word count is correct and that the seed is valid.
- **Share Configuration:**
  Accept the default configuration ("3 shares, threshold 2") or select from other presets/custom values.
- **Folder Output:**
  Select whether to use a default folder (automatically named like `shares_3s-2t_15-04-2023`) or to manually specify a folder name.
- **Output:**
  The seed is converted to entropy and split into shares. Each share is saved as a JSON file containing all necessary metadata and is protected with strict file permissions (0o600) to secure the local copy.

### Folder Naming & File Permissions
- **Folder Naming Convention:**
  Default folder names follow this format:
  ```
  shares_<n>s-<k>t_<DD-MM-YYYY>
  ```
- **File Permissions:**
  Each share file is written with permissions set to 0o600 (readable and writable only by your user), ensuring that the files remain protected on your computer. When distributing the shares (e.g., copying to external media or sending them via secure channels), be sure to adjust or wrap the files in an encrypted archive as necessary.

### Recovering the Secret
- **Folder Detection & Share Selection:**
  The program scans for visible subfolders containing share files and allows you to select one. Then, select the share files to combine via an interactive checklist.
- **Multi‑Line Warning:**
  Before revealing the recovered seed phrase, a multi‑line warning is printed to ensure you understand the sensitivity. A shorter confirmation prompt then asks if you wish to display the seed, preventing truncation issues in small terminal windows.
- **Output:**
  The recovered secret is shown as both HEX and (after confirmation) as the clear-text seed phrase.

### Sanity Check
- **Functionality:**
  The sanity check option tests every valid combination of the minimum required shares to ensure each combination recovers the same secret, thereby validating the integrity of your backup.

### Terminal Interaction
- **Clearing the Screen:**
  At key steps (e.g., returning to the main menu, initiating share creation, recovery, or sanity checks), the terminal is cleared. This ensures that only the current input and output are visible, keeping the interface clean and reducing the risk of exposing prior sensitive commands or responses.

## File Format and Metadata

Each share is stored in JSON format and contains the following fields:
- `magic`: "SSS-MANAGER-1"
- `protocol`: "ShamirSecretSharing"
- `version`: "1.0"
- `set_id`: A unique identifier for the share set.
- `total_shares`: The total number of shares generated.
- `threshold`: The number of shares required for recovery.
- `creation_date`: A timezone‑aware UTC timestamp marking when the shares were created.
- `share`:
  - `share_index`: The index identifying the individual share (used during recovery).
  - `share_hex`: The share's secret data in hexadecimal format.
- `checksum`: A SHA‑256 checksum of the share bytes to detect any tampering or corruption.

This metadata ensures that recovery functions correctly even if files are renamed or only the raw hexadecimal is available.

## Contributing

Contributions are welcome! Please fork the repository and submit pull requests with improvements, new features, or bug fixes. Adhere to the project coding standards and document your changes clearly.

## License

This project is licensed under the MIT License. See the LICENSE file for more details.

## Disclaimer

This tool is provided "as is" without any warranty. Use it at your own risk. The developers are not liable for any loss of funds or data resulting from the use of this program. Always test the recovery process in a safe environment before relying on it for critical applications.
