# SOC Log Parser

A lightweight Python security utility designed for Security Operations Center (SOC) analysts to parse, analyze, and generate structured incident reports from Linux authentication logs (`auth.log`).

---

## 📁 Directory Structure

```text
├── .gitignore
├── README.md
├── parser.py
├── sample_logs/
│   └── auth.log
└── output/          (created automatically when you run the script)
```

---

## 🚀 Features

- **Brute-Force Detection**: Flags IP addresses exceeding a configurable threshold of failed authentication attempts.
- **Failed Login Tracking**: Analyzes targeted usernames and IP sources.
- **Successful Login Auditing**: Summarizes successful SSH logins (password & publickey authentication).
- **Privilege Escalation Monitoring**: Tracks `sudo` command executions and the users executing them.
- **Automatic Reporting**: Formats security findings into a clean, text-based SOC summary report in `output/report.txt`.

---

## 💻 Usage

### Prerequisites
- Python 3.x installed (no external dependencies required).

### Running the Parser
To execute the parser with default settings:

```bash
python parser.py
```

This will read `sample_logs/auth.log` and automatically create the `output/` folder containing `output/report.txt`.

### Custom Command-Line Options

| Parameter | Description | Default |
| :--- | :--- | :--- |
| `--log` | Path to input log file | `sample_logs/auth.log` |
| `--output` | Path to save output report | `output/report.txt` |
| `--threshold` | Failed login attempt limit for brute-force alerting | `3` |

#### Example Command:
```bash
python parser.py --log sample_logs/auth.log --output output/custom_report.txt --threshold 5
```

---

## 📊 Sample Output Preview

```text
=== SOC Security Log Parser Report ===

Total lines read:      15
Lines matched:         15
Lines skipped:         0

Flagged IPs (3+ failed attempts):
------------------------------------------------------------
IP: 192.168.1.105      | Failed Count: 7    | Usernames tried: admin, administrator, root, test, ubuntu
```
