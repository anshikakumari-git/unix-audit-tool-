# UNIX-Based Password and File Access Security Audit Tool

## 1. Project Overview

The UNIX-Based Password and File Access Security Audit Tool is a Bash scripting-based security application designed to identify potential security vulnerabilities and misconfigurations in a UNIX/Linux system.

The tool automates security auditing by checking user account configurations, file and directory permissions, and authentication logs. It collects the findings, classifies them according to severity, and generates a consolidated security audit report.

The project provides a simple menu-driven interface that allows users to perform a complete security audit or execute individual auditing modules.

## 2. Objectives

- Automate the process of UNIX/Linux security auditing.
- Identify insecure password and user account configurations.
- Detect potentially unsafe file and directory permissions.
- Analyze authentication logs for suspicious activity.
- Classify security findings according to severity.
- Generate and maintain consolidated security audit reports.

## 3. Features

### A. Password and User Account Audit
- Checks for unauthorized accounts with UID 0.
- Detects accounts with empty passwords.
- Identifies non-expiring and potentially outdated passwords.
- Displays password aging information.

### B. File and Directory Permission Audit
- Detects world-writable files and directories.
- Identifies SUID (Set User ID) files.
- Identifies SGID (Set Group ID) files.
- Detects unowned files and directories.
- Checks permissions of important system files such as `/etc/passwd` and `/etc/shadow`.

### C. Authentication Log Analysis
- Analyzes authentication logs.
- Identifies successful login sessions.
- Detects sudo authentication failures.
- Helps administrators review authentication-related activities.

### D. Security Report Generation
- Collects findings from all auditing modules.
- Classifies findings into Critical, High, Medium, and Low severity levels.
- Generates consolidated security audit reports.
- Stores previously generated reports for future reference.

## 4. Technologies Used

| Category | Technology |
|---|---|
| Programming Language | Bash Shell Scripting |
| Operating Environment | Ubuntu Linux |
| Code Editor | Visual Studio Code |
| Version Control | Git and GitHub |
| Execution Environment | Ubuntu Terminal / WSL 2 |

### Linux Utilities Used
- `find`
- `stat`
- `chmod`
- `chage`
- `grep`
- `awk`
- `sudo`

## 5. Project Structure

```text
unix-audit-tool/
│
├── audit.sh
├── controller.sh
├── password_audit.sh
├── file_audit.sh
├── log_analyzer.sh
├── report_generator.sh
├── log_results.txt
├── README.md
│
└── temp/
    ├── password_findings.txt
    ├── file_findings.txt
    ├── log_findings.txt
    ├── normalized_findings.txt
    └── classified_findings.txt
```

**File Descriptions:**

- `audit.sh` – Main entry point of the application.
- `controller.sh` – Manages the execution of auditing modules.
- `password_audit.sh` – Performs password and user account auditing.
- `file_audit.sh` – Checks file and directory permissions.
- `log_analyzer.sh` – Analyzes authentication logs.
- `report_generator.sh` – Generates consolidated security reports.
- `log_results.txt` – Stores authentication log analysis results.
- `temp/` – Stores intermediate and processed audit findings.

## 6. System Requirements

- Linux-based operating system (Ubuntu recommended).
- Bash shell.
- Administrative privileges for system-level auditing.
- Basic Linux utilities such as `find`, `stat`, `grep`, and `awk`.
- Git for cloning the repository.

## 7. Installation and Execution

### Step 1: Clone the Repository

```bash
git clone https://github.com/Aaliya007/unix-audit-tool.git
```

### Step 2: Navigate to the Project Directory

```bash
cd unix-audit-tool
```

### Step 3: Give Execution Permissions

```bash
chmod +x *.sh
```

### Step 4: Run the Application

```bash
sudo bash audit.sh
```

## 8. Application Menu

The application provides the following menu options:

```text
======================================
       UNIX SECURITY AUDIT TOOL
======================================
1. Complete Security Audit
2. Password Audit
3. File Permission Audit
4. Authentication Log Audit
5. View Previous Reports
6. Exit
======================================
```

Users can select an option to execute the complete audit, run individual modules, view previous reports, or exit the application.

## 9. Output and Reports

The application generates security findings based on the results of the auditing modules.

Findings are classified into four severity levels:

- **Critical:** Very serious security issues requiring immediate attention.
- **High:** Significant security concerns requiring investigation.
- **Medium:** Potential security issues that should be reviewed.
- **Low:** Lower-priority findings requiring attention where necessary.

Individual module findings are stored in the `temp/` directory.

Generated security reports are stored at:

```text
/var/log/audit_tool/
```

## 10. Testing and Results

The application was tested in an Ubuntu Linux environment.

The following functionalities were successfully tested:

- Password and user account auditing.
- File and directory permission scanning.
- SUID and SGID detection.
- Unowned file detection.
- Authentication log analysis.
- Complete security audit execution.
- Severity-based report generation.
- Viewing previously generated reports.

During the final integrated audit, all three auditing modules executed successfully.

**Observed Final Audit Results:**

| Severity | Findings |
|---|---:|
| Critical | 0 |
| High | 2 |
| Medium | 22 |
| Low | 1 |
| **Total** | **25** |

These results represent the findings from the tested system and may differ on other Linux systems.

## 11. Limitations

- The tool primarily focuses on selected password, file permission, and authentication security checks.
- Some findings may represent legitimate system configurations and require manual review.
- The accuracy of authentication analysis depends on the availability and accessibility of system logs.
- The tool does not automatically repair detected security issues.
- The current implementation is designed for Linux-based environments.

## 12. Future Scope

- Add automatic security recommendations and remediation options.
- Introduce graphical user interface support.
- Improve authentication log analysis and anomaly detection.
- Add email or notification alerts for critical findings.
- Support scheduled and periodic security audits.
- Expand auditing to additional UNIX/Linux security configurations.

## 13. Team Project

This project was developed collaboratively, with different team members responsible for individual modules, integration, and testing.

## 14. Conclusion

The UNIX-Based Password and File Access Security Audit Tool provides an automated approach to identifying potential security misconfigurations in UNIX/Linux systems.

By combining password auditing, file permission checking, and authentication log analysis, the application simplifies the security auditing process and generates organized reports for further investigation.

The project demonstrates the practical application of Bash scripting, Linux commands, file permissions, authentication mechanisms, and modular programming in system security.
