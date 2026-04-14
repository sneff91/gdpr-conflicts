# CUCM GDPR Advertised Pattern Conflict Checker

## Table of Contents

* [Overview](#overview)
* [Features](#features)
* [Requirements](#requirements)
* [Installation](#installation)
* [Configuration](#configuration)
* [Configuration Reference](#configuration-reference)
* [Usage](#usage)
* [Output](#output)
* [Security Notes](#security-notes)
* [License](#license)
* [Disclaimer](#disclaimer)

## Overview

This project connects to one or more Cisco Unified Communications Manager (CUCM) clusters via the AXL SOAP API and retrieves Global Dial Plan Replication (GDPR) advertised patterns. It then compares these patterns intra-cluster and inter-cluster to identify conflicts/overlapping patterns. Results can be logged to file and/or sent as a notification via email (unauthenticated email currently only supported).

---

## Features

* Conflict detection with configurable severity levels
* Environment variable support in the configuration file (such as AXL credentials)
* Output formatting, limits, and pattern types via configuration file
* Multi-output result logging
* Built-in configurable log retention policy

---

## Requirements

* Python 3.10+
* Dependencies listed in `pyproject.toml`
* Network access to CUCM AXL interfaces
* CUCM 'Application User' or 'End User' with the 'Standard AXL API Access' role

---

## Installation

### 1. Get the Code

Clone the repository:

```bash
git clone https://github.com/<your-username>/<your-repo-name>.git
cd <your-repo-name>
```

Alternatively, you can download the repository as a ZIP file from GitHub and extract it.

### 2. Install Dependencies

### Option 1: Using uv (recommended)

```bash
uv sync
```

### Option 2: Using pip

```bash
pip install .
```

---

## Configuration

Copy the `config.example.ini` example configuration file to `config.ini`:

```bash
cp config.example.ini config.ini
```

Edit `config.ini` with your environment-specific values. Sensitive values (like passwords) can be referenced using environment variables:

* Linux/macOS:

  ```bash
  AXL_PASS = $CUCM_AXL_PASS
  ```

* Windows:

  ```cmd
  AXL_PASS = %CUCM_AXL_PASS%
  ```

---

## Configuration Reference

### Global Settings

| Setting | Description | Data Type | Default Value |
| - | - | - | - |
| OUTPUT_DESTINATION | `logging`, `email`, or `both`. Determines where results are sent | String | logging |
| PATTERN_TYPES | `enterprise`, `e164`, or `both`. Determines which type(s) of Advertised Pattern(s) to analyze | String | both |
| INCLUDE_ELAPSED_TIME | Include timing metrics | Boolean | true |
| SEVERITY_LEVEL | `informational` or `warning`. `informational` returns intra-cluster pattern overlap and inter-cluster conflicts, `warning` returns only inter-cluster conflicts | String | warning |
| MAX_RESULTS | Maximum expansion size for patterns. E.g. 12XXX expands to 1000 numbers | Integer | 200000 |
| MAX_SAMPLES | Maximum number of sample conflicts to display in results | Integer | 20 |
| CERT_PATH | CA certificate path to use for certificate validation | String | (System CA trust) |
| USE_PRETTY_PRINT | Enable "pretty print" formatted JSON output (applies to logged files and email) | Boolean | false |

---

## Usage

### Option 1: Using uv (recommended)

Run the script directly:

```bash
uv run python gdpr_conflicts.py
```

### Option 2: Using standard Python

Activate your virtual environment (if being used), then run:

```bash
python gdpr_conflicts.py
```

**Note**: *Depending on your system, you may need to use `python3` or `py` instead of `python`.*

---

## Output

Depending on configuration, results will be logged to file and/or sent in an email in JSON format to the address configured in `config.ini`.

---

### Logging Settings

| Setting | Description | Data Type | Default Value |
| - | - | - | - |
| LOG_RETENTION | Determines the number of days to keep logs for | Integer | 30 |
| LOG_FILE_DIR | Directory to use for log files | String | `logging` sub-directory within the script directory. This will get created automatically |

---

### CUCM Cluster Configuration

Each CUCM cluster must have its own section, using the `cucm_` prefix in the section name:

```
[cucm_<unique_name>]
```

Required fields:

| Setting | Description | Data Type | Default Value |
| - | - | - | - |
| LABEL | Human-friendly label/name for this CUCM cluster. This will be specified in the output along with conflicting patterns that exist on that CUCM cluster | String | *None* |
| FQDN | Fully Qualified Domain Name (FQDN) of the CUCM Publisher for the cluster. Do not include http(s):// prefix or resource suffix | String | *None* |
| AXL_USER | Username to use for authenticating to CUCM's AXL API interface | String | *None* |
| AXL_PASS | Password to use for authenticating to CUCM's AXL API interface | String | *None* |

Optional fields:

| Setting | Description | Data Type | Default Value |
| - | - | - | - |
| IGNORE_PATTERNS | Advertised patterns to ignore when assessing conflicts | String | *None* |
| VERIFY_CERT | Whether TLS certificates present by CUCM should be validated | String | true |
| HTTP_SECURE | Whether HTTPS should be used for communicating with the cluster | String | true |

---

## Security Notes

* Do **not** commit `config.ini` to Git

---

## License

MIT License — see LICENSE file for details.

---

## Disclaimer

This tool is not affiliated with or endorsed by Cisco. Use at your own risk.
