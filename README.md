# WP-Inspect: Investigate Hacked WordPress Instances

## Introduction

This tool is designed to assist in identifying changes made to WordPress files by comparing it to either the original source code from the internet or a backup of the installation.

![Alt Text](resources/demo.gif)

## Purpose

The primary purpose of this tool is to aid in forensic investigations of WordPress websites by identifying any alterations or additions to the core files or uploaded content. It helps investigators determine if any unauthorized changes have been made, such as malware injections, file modifications, or user uploads that may be of interest.

## Features

- **Comparison with Original Source Code:** Compare the WordPress installation folder with the original source code obtained from the internet to identify any discrepancies.

- **Comparison with Backup:** Compare the WordPress installation folder with a backup to detect any changes made since the backup was created.

## Prerequisites

- Python Version 3.9 or above is required.
- Please note that as of my last update, this tool may not be compatible with Windows operating systems.

## Installation

- Install WP-Inspect using pip:

  ```bash
  pip install git+https://github.com/LucaKuechler/WP-Inspect.git
  ```

## Usage

- Compare WordPress Source Code to Original Source Code and export results to csv:

  ```bash
  wpinspect web ../wordpress_hacked_files/ --csv /tmp/out.csv
  ```

- Compare WordPress Source Code to WordPress Backup Files and export results to csv:

  ```bash
  wpinspect local ../wordpress_backup_files/ ../wordpress_hacked_files/ --csv /tmp/out.csv
  ```

## Acknowledgments

- Special thanks to @ym405nm for inspiring this project with his tool [wp-forensics](https://github.com/ym405nm/wp-forensics).
