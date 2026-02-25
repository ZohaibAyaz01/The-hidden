# The Hidden

`TheHidden.sh` is an interactive Bash-based forensics utility for scanning suspicious files for potential malware indicators, hidden payloads, and embedded artifacts.

## Features

- Logical vs physical file size checks
- Slack space analysis
- SHA-256 hashing
- Header/signature validation
- Intelligent string extraction and risk scoring
- EOF payload extraction for JPEG/PNG files
- Entropy analysis
- File carving for common embedded signatures (ZIP/PDF/ELF)
- Consolidated confidence report

## Requirements

The script relies on standard Linux command-line tools:

- bash
- coreutils (`stat`, `dd`, `wc`, etc.)
- awk
- grep
- file
- strings
- hexdump
- od
- xxd
- sha256sum

See `requirements.txt` for a package-style dependency list.

## Usage

1. Make the script executable:

```bash
chmod +x TheHidden.sh
```

2. Run the tool:

```bash
./TheHidden.sh
```

3. Enter a target file path when prompted and choose modules from the menu.

## Output Artifacts

Depending on selected modules, the tool can generate:

- Extracted string log (`<target>_extracted_strings.log`)
- EOF payload dumps (`<target>_payload.bin`)
- Carved payload files (`<target>_carved_<offset>.<ext>`)

## Notes

- This tool performs static analysis and heuristics; treat scores as indicators, not definitive verdicts.
- Run in an isolated environment when analyzing untrusted files.
