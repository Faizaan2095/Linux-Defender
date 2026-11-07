# Linux-Defender

A lightweight Linux defense utility designed to detect dangerous archive behavior and large-file misuse before they can cause harm.

## Features

- Large file warning system for oversized files
- Zip bomb detection for suspicious `.zip`, `.jar`, `.apk`, and similar archives
- Directory scanning to inspect files recursively
- Command-line interface for quick local protection checks

## Quick start

```bash
python3 -m linux_defender.cli /path/to/file-or-directory --max-file-size-mb 100
```

## Example checks

Warn and block suspicious files above 250 MB:

```bash
python3 -m linux_defender.cli ~/Downloads --max-file-size-mb 250 --max-zip-ratio 10 --max-total-uncompressed-mb 500
```

## Why this matters

Zip bombs and oversized files can exhaust memory, CPU, disk space, or trigger denial-of-service conditions on Linux systems. This tool gives a fast first layer of protection before extraction or movement.

## Project status

This repository is now initialized with the first feature: archive and large-file defense checks.
