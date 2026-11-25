#!/bin/bash
# =============================================================
# report_generator.sh
# Member 5 - Risk Classification & Report Generator
#
# Collects findings from the password, file and log audit
# modules, classifies each finding by severity, counts issues
# and writes a timestamped report.
#
# Usage:
#   ./report_generator.sh              Generate a report
#   ./report_generator.sh generate     Generate a report
#   ./report_generator.sh previous     List and view old reports
# =============================================================

BASE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TEMP_DIR="$BASE_DIR/temp"
# Default location required by the project.  REPORT_DIR may be overridden
# only for safe testing in a non-root environment.
REPORT_DIR="${REPORT_DIR:-/var/log/audit_tool}"

# Combined working files (created only inside this script)
NORMALIZED_FILE="$TEMP_DIR/normalized_findings.txt"
CLASSIFIED_FILE="$TEMP_DIR/classified_findings.txt"

# Counters - each finding is counted exactly once
CRITICAL_COUNT=0
HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0
TOTAL_COUNT=0
INVALID_COUNT=0

# Files that were actually used as input (for status messages)
USED_PASSWORD=""
USED_FILE=""
USED_LOG=""

# -------------------------------------------------------------
# Find the first existing file from a list of possible paths.
# Other modules do not all write to temp/, so fallbacks are used.
# -------------------------------------------------------------
first_existing_file() {
    local path
    for path in "$@"; do
        if [ -f "$path" ]; then
            echo "$path"
            return 0
        fi
    done
    return 1
}


classify_severity() {
    local issue="$1"
    local resource="$2"
    local issue_lc resource_lc

    # Convert to lowercase for simple pattern matching
    issue_lc=$(echo "$issue" | tr 'A-Z' 'a-z')
    resource_lc=$(echo "$resource" | tr 'A-Z' 'a-z')

    # --- CRITICAL ---
    # Extra / multiple UID 0 accounts
    case "$issue_lc" in
        *uid\ 0*|*uid0*|*extra*root*|*root\ privileg*)
            echo "CRITICAL"
            return
            ;;
        *empty*password*)
            echo "CRITICAL"
            return
            ;;
    esac

    # Insecure permissions on critical system files
    case "$resource_lc" in
        /etc/shadow*|/etc/passwd|/etc/group|/etc/gshadow*|/etc/sudoers*)
            case "$issue_lc" in
                *unsafe*|*insecure*|*permission*|*world*writ*)
                    echo "CRITICAL"
                    return
                    ;;
            esac
            ;;
    esac

    # --- HIGH ---
    # Repeated failed logins / possible brute force
    case "$issue_lc" in
        *failed*login*|*brute*|*repeated*failed*)
            echo "HIGH"
            return
            ;;
        *sudo*fail*)
            echo "HIGH"
            return
            ;;
        *password*expir*)
            echo "HIGH"
            return
            ;;
        *world*writ*)
            # World-writable files under home or tmp are minor;
            # world-writable system locations are HIGH.
            case "$resource_lc" in
                /home/*|/tmp/*|/var/tmp/*)
                    echo "LOW"
                    return
                    ;;
                *)
                    echo "HIGH"
                    return
                    ;;
            esac
            ;;
        *unauthorized*)
            echo "HIGH"
            return
            ;;
    esac

    # --- MEDIUM ---
    case "$issue_lc" in
        *non-expir*|*non\ expir*)
            echo "MEDIUM"
            return
            ;;
        *not\ changed*|*old*password*|*password-change*|*password\ age*)
            echo "MEDIUM"
            return
            ;;
        *unowned*)
            echo "MEDIUM"
            return
            ;;
        *suid*|*sgid*)
            # SUID/SGID is a finding to investigate, not automatically
            # treated as a confirmed dangerous file.
            echo "MEDIUM"
            return
            ;;
    esac

    # --- LOW (default for remaining configuration issues) ---
    echo "LOW"
}

# -------------------------------------------------------------
# Convert one input line into ISSUE|RESOURCE|RECOMMENDATION.
# Accepts both:
#   ISSUE|RESOURCE|RECOMMENDATION
#   SEVERITY_OR_CODE|ISSUE|RESOURCE|RECOMMENDATION
# -------------------------------------------------------------
normalize_line() {
    local line="$1"
    local field1 field2 field3 field4
    local issue resource recommendation

    # Skip empty lines and comments
    [ -z "$line" ] && return
    case "$line" in
        \#*) return ;;
    esac

    # Split on | into at most 4 pieces
    IFS='|' read -r field1 field2 field3 field4 <<EOF
$line
EOF

    if [ -n "$field4" ]; then
        # 4-field line from password_audit, file_audit or log_analyzer
        # Drop field1 (severity or event code); we classify ourselves.
        issue="$field2"
        resource="$field3"
        recommendation="$field4"
    elif [ -n "$field3" ]; then
        # 3-field internal format
        issue="$field1"
        resource="$field2"
        recommendation="$field3"
    else
        echo "Warning: Skipping invalid finding line: $line" >&2
        INVALID_COUNT=$((INVALID_COUNT + 1))
        return
    fi

    # Skip purely informational log lines (not a security issue)
    case "$issue" in
        *Successful\ login*)
            return
            ;;
    esac

    # All three values must be present
    if [ -z "$issue" ] || [ -z "$resource" ] || [ -z "$recommendation" ]; then
        echo "Warning: Skipping incomplete finding line: $line" >&2
        INVALID_COUNT=$((INVALID_COUNT + 1))
        return
    fi

    echo "$issue|$resource|$recommendation"
}

# -------------------------------------------------------------
# Collect findings from whichever modules have been run.
# Missing files are skipped so individual audits still work.
# -------------------------------------------------------------
collect_findings() {
    mkdir -p "$TEMP_DIR"
    : > "$NORMALIZED_FILE"

    USED_PASSWORD=$(first_existing_file \
        "$TEMP_DIR/password_findings.txt" \
        "$BASE_DIR/password_findings.txt" \
        "./password_findings.txt") || true

    USED_FILE=$(first_existing_file \
        "$TEMP_DIR/file_findings.txt" \
        "/tmp/file_findings.txt" \
        "$BASE_DIR/file_findings.txt") || true

    USED_LOG=$(first_existing_file \
        "$TEMP_DIR/log_findings.txt" \
        "$BASE_DIR/log_results.txt" \
        "./log_results.txt") || true

    echo
    echo "Collecting findings from available modules..."

    if [ -n "$USED_PASSWORD" ]; then
        echo "  Password audit : $USED_PASSWORD"
        if [ ! -s "$USED_PASSWORD" ]; then
            echo "  (file is empty - no password findings)"
        else
            while IFS= read -r line || [ -n "$line" ]; do
                normalize_line "$line" >> "$NORMALIZED_FILE"
            done < "$USED_PASSWORD"
        fi
    else
        echo "  Password audit : no findings file (module may not have been run)"
    fi

    if [ -n "$USED_FILE" ]; then
        echo "  File audit     : $USED_FILE"
        if [ ! -s "$USED_FILE" ]; then
            echo "  (file is empty - no file permission findings)"
        else
            while IFS= read -r line || [ -n "$line" ]; do
                normalize_line "$line" >> "$NORMALIZED_FILE"
            done < "$USED_FILE"
        fi
    else
        echo "  File audit     : no findings file (module may not have been run)"
    fi

    if [ -n "$USED_LOG" ]; then
        echo "  Log audit      : $USED_LOG"
        if [ ! -s "$USED_LOG" ]; then
            echo "  (file is empty - no log findings)"
        else
            while IFS= read -r line || [ -n "$line" ]; do
                normalize_line "$line" >> "$NORMALIZED_FILE"
            done < "$USED_LOG"
        fi
    else
        echo "  Log audit      : no findings file (module may not have been run)"
    fi

    # Remove duplicate lines so each issue is counted once
    if [ -s "$NORMALIZED_FILE" ]; then
        sort -u "$NORMALIZED_FILE" -o "$NORMALIZED_FILE"
    fi
}

# -------------------------------------------------------------
# Classify every normalized finding and update counters.
# Output format: SEVERITY/ISSUE/RESOURCE/RECOMMENDATION
# -------------------------------------------------------------
classify_all_findings() {
    : > "$CLASSIFIED_FILE"
    CRITICAL_COUNT=0
    HIGH_COUNT=0
    MEDIUM_COUNT=0
    LOW_COUNT=0
    TOTAL_COUNT=0

    if [ ! -s "$NORMALIZED_FILE" ]; then
        return
    fi

    while IFS='|' read -r issue resource recommendation || [ -n "$issue" ]; do
        [ -z "$issue" ] && continue

        severity=$(classify_severity "$issue" "$resource")

        echo "$severity/$issue/$resource/$recommendation" >> "$CLASSIFIED_FILE"

        case "$severity" in
            CRITICAL) CRITICAL_COUNT=$((CRITICAL_COUNT + 1)) ;;
            HIGH)     HIGH_COUNT=$((HIGH_COUNT + 1)) ;;
            MEDIUM)   MEDIUM_COUNT=$((MEDIUM_COUNT + 1)) ;;
            LOW)      LOW_COUNT=$((LOW_COUNT + 1)) ;;
        esac
        TOTAL_COUNT=$((TOTAL_COUNT + 1))
    done < "$NORMALIZED_FILE"
}

# -------------------------------------------------------------
# Build the report text (used for both the file and the screen).
# -------------------------------------------------------------
build_report_text() {
    local audit_datetime system_name audit_status

    audit_datetime=$(date '+%d-%m-%Y %H:%M:%S')
    system_name=$(uname -s)

    if [ -z "$USED_PASSWORD" ] && [ -z "$USED_FILE" ] && [ -z "$USED_LOG" ]; then
        audit_status="NO INPUT DATA"
    elif [ -z "$USED_PASSWORD" ] || [ -z "$USED_FILE" ] || [ -z "$USED_LOG" ]; then
        audit_status="COMPLETED (PARTIAL - some modules had no findings file)"
    else
        audit_status="COMPLETED"
    fi

    cat <<EOF
========================================
       UNIX SECURITY AUDIT REPORT
========================================

Audit Date and Time: $audit_datetime
System: $system_name
Audit Status: $audit_status

----------------------------------------
           SECURITY FINDINGS
----------------------------------------

EOF

    if [ -s "$CLASSIFIED_FILE" ]; then
        cat "$CLASSIFIED_FILE"
        echo
    else
        echo "No security findings were collected."
        echo
    fi

    cat <<EOF
----------------------------------------
             AUDIT SUMMARY
----------------------------------------

Critical Issues: $CRITICAL_COUNT
High Issues: $HIGH_COUNT
Medium Issues: $MEDIUM_COUNT
Low Issues: $LOW_COUNT

Total Issues: $TOTAL_COUNT

========================================
EOF
}

# -------------------------------------------------------------
# Save the report under /var/log/audit_tool/ with a timestamp.
# If the directory cannot be used, show an error (do not fail
# silently). The report is still printed on the terminal.
# -------------------------------------------------------------
save_report() {
    local timestamp report_file

    timestamp=$(date '+%Y%m%d_%H%M%S')
    report_file="$REPORT_DIR/audit_report_${timestamp}.txt"

    if ! mkdir -p "$REPORT_DIR" 2>/dev/null; then
        echo
        echo "Error: Cannot create or access report directory: $REPORT_DIR"
        echo "Hint: run this script with sudo so the report can be saved."
        SAVED_REPORT=""
        return 1
    fi

    if ! build_report_text > "$report_file" 2>/dev/null; then
        echo
        echo "Error: Failed to write the report file: $report_file"
        echo "Check directory permissions for $REPORT_DIR."
        SAVED_REPORT=""
        return 1
    fi

    SAVED_REPORT="$report_file"
    return 0
}

# -------------------------------------------------------------
# Print the full report and a short terminal summary.
# -------------------------------------------------------------
display_report() {
    echo
    build_report_text

    echo
    echo "----------------------------------------"
    echo "         TERMINAL SUMMARY"
    echo "----------------------------------------"
    echo "Total issues found : $TOTAL_COUNT"
    echo "Critical issues    : $CRITICAL_COUNT"
    echo "High issues        : $HIGH_COUNT"
    echo "Medium issues      : $MEDIUM_COUNT"
    echo "Low issues         : $LOW_COUNT"

    if [ -n "$SAVED_REPORT" ]; then
        echo "Report saved at    : $SAVED_REPORT"
    else
        echo "Report saved at    : (not saved - see error above)"
    fi
    echo "----------------------------------------"
}

# -------------------------------------------------------------
# List previous reports, let the user pick one, then cat it.
# -------------------------------------------------------------
view_previous_reports() {
    local files=()
    local index=0
    local choice
    local selected

    echo
    echo "========================================"
    echo "     PREVIOUS SECURITY AUDIT REPORTS"
    echo "========================================"

    if [ ! -d "$REPORT_DIR" ]; then
        echo "No previous reports found."
        echo "Report directory does not exist: $REPORT_DIR"
        return 0
    fi

    # Newest reports first. nullglob avoids a fake filename when none exist.
    shopt -s nullglob
    local all_reports=( "$REPORT_DIR"/audit_report_*.txt )
    shopt -u nullglob

    # Sort by modification time using ls, if any reports exist
    if [ ${#all_reports[@]} -gt 0 ]; then
        while IFS= read -r report_path; do
            [ -z "$report_path" ] && continue
            files+=("$report_path")
            index=$((index + 1))
            echo "$index) $(basename "$report_path")"
        done <<EOF
$(ls -1t "${all_reports[@]}" 2>/dev/null)
EOF
    fi

    if [ "$index" -eq 0 ]; then
        echo "No previous reports found."
        return 0
    fi

    echo "0) Cancel"
    echo
    read -rp "Enter the number of the report to view: " choice

    # Must be a whole number
    case "$choice" in
        ''|*[!0-9]*)
            echo "Invalid selection. Please enter a number from the list."
            return 1
            ;;
    esac

    if [ "$choice" -eq 0 ]; then
        echo "Cancelled."
        return 0
    fi

    if [ "$choice" -lt 1 ] || [ "$choice" -gt "$index" ]; then
        echo "Invalid selection. Choose a number between 1 and $index."
        return 1
    fi

    selected="${files[$((choice - 1))]}"

    if [ ! -r "$selected" ]; then
        echo "Error: Cannot read the selected report: $selected"
        return 1
    fi

    echo
    echo "Showing: $(basename "$selected")"
    echo "----------------------------------------"
    cat "$selected"
    echo "----------------------------------------"
    return 0
}

# -------------------------------------------------------------
# Main: generate a classified report from available findings.
# -------------------------------------------------------------
generate_report() {
    collect_findings
    classify_all_findings

    SAVED_REPORT=""
    # Keep displaying the summary if saving fails, but return a failure
    # status so the controller can report the report-generation problem.
    save_report
    local save_status=$?
    display_report
    return "$save_status"
}

# -------------------------------------------------------------
# Entry point
# -------------------------------------------------------------
case "${1:-generate}" in
    generate|"")
        generate_report
        ;;
    previous|reports)
        view_previous_reports
        ;;
    *)
        echo "Usage: $0 [generate|previous]"
        echo "  generate   Collect findings, classify them and write a report"
        echo "  previous   List and display previously saved reports"
        exit 1
        ;;
esac
