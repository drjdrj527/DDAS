# DDAS
---

# Duplicate File Detection for Partial Downloads

This C program monitors a specified directory for new files and detects duplicate files by calculating their SHA-256 hash. It can identify duplicates before they are fully downloaded, including files with extensions like `.crdownload`, `.part`, `.download`, and `.opdownload`.

## Features

* **SHA-256 Hashing:** Detects duplicate files based on their content.
* **Partial Download Detection:** Identifies files that are still downloading (e.g., `.crdownload`, `.part`).
* **Duplicate Alerts:** Triggers system notifications and plays an alert sound when duplicates are found.
* **Cross-Platform Support:** Works on macOS and Linux with platform-specific notifications and sound alerts.
* **Real-Time Monitoring:** Continuously scans the specified directory for new files.

## How It Works

1. The program scans the specified directory for new files.
2. For each file, it computes the SHA-256 hash.
3. If a file is partially downloaded, it hashes the chunk and checks for duplicates against fully downloaded files.
4. If a duplicate is found, an alert sound is played, and a system notification is displayed.

## Files

* `full_download_files.txt`: Stores hashes of fully downloaded files.
* `partial_download_files.txt`: Stores hashes of partially downloaded files.

## Usage

1. Run the program.
2. Enter the directory path to scan for new downloads.
3. The program will monitor the directory and alert you if duplicates are found.

## System Requirements

* **macOS/Linux**: The program is designed to work on both macOS and Linux systems with platform-specific alert mechanisms.
* **Dependencies**: The program relies on standard C libraries and system commands for sound playback and notifications.
