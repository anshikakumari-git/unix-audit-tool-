#!/bin/bash

# Find the main project directory
BASE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# Modules live in the project root. If a modules/ folder is added later,
# that location is used instead.
if [[ -d "$BASE_DIR/modules" ]]; then
    MODULE_DIR="$BASE_DIR/modules"
else
    MODULE_DIR="$BASE_DIR"
fi

TEMP_DIR="$BASE_DIR/temp"

# Function to check root privileges
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "Error: Please run the audit using sudo."
        return 1
    fi
    return 0
}

# Function to execute an audit module
# Extra arguments are forwarded (used to set findings output files).
run_module() {
    local module_file="$1"
    shift

    if [[ ! -f "$module_file" ]]; then
        echo "Error: Module not found: $module_file"
        return 1
    fi

    echo
    echo "Running: $(basename "$module_file")"
    echo "--------------------------------------"

    if bash "$module_file" "$@"; then
        echo "Module completed successfully."
        return 0
    else
        echo "Error: Module execution failed."
        return 1
    fi
}

# Copy log analyzer output into the shared temp findings file.
copy_log_findings() {
    mkdir -p "$TEMP_DIR"
    if [[ -f "$BASE_DIR/log_results.txt" ]]; then
        cp "$BASE_DIR/log_results.txt" "$TEMP_DIR/log_findings.txt"
    elif [[ -f "log_results.txt" ]]; then
        cp "log_results.txt" "$TEMP_DIR/log_findings.txt"
    fi
}

# Member 5: classify findings and write the report (does not re-run audits).
run_report_generator() {
    echo
    echo "Generating classified security report..."
    echo "--------------------------------------"
    bash "$BASE_DIR/report_generator.sh" generate
}

# Function to run all audit modules
run_complete_audit() {
    local total=3
    local successful=0
    local failed=0

    echo
    echo "======================================"
    echo "       COMPLETE SECURITY AUDIT"
    echo "======================================"

    mkdir -p "$TEMP_DIR"

    if run_module "$MODULE_DIR/password_audit.sh" "$TEMP_DIR/password_findings.txt"; then
        ((successful++))
    else
        ((failed++))
    fi

    if run_module "$MODULE_DIR/file_audit.sh" "/" "$TEMP_DIR/file_findings.txt"; then
        ((successful++))
    else
        ((failed++))
    fi

    if run_module "$MODULE_DIR/log_analyzer.sh"; then
        copy_log_findings
        ((successful++))
    else
        ((failed++))
    fi

    echo
    echo "======================================"
    echo "          AUDIT SUMMARY"
    echo "======================================"
    echo "Total Modules: $total"
    echo "Successful: $successful"
    echo "Failed: $failed"
    echo "======================================"

    run_report_generator
}

# Handle the operation received from audit.sh
case "$1" in

    all)
        if ! check_root; then
            exit 1
        fi

        run_complete_audit
        ;;

    password)
        if check_root; then
            mkdir -p "$TEMP_DIR"
            run_module "$MODULE_DIR/password_audit.sh" "$TEMP_DIR/password_findings.txt"
            run_report_generator
        else
            exit 1
        fi
        ;;

    files)
        if check_root; then
            mkdir -p "$TEMP_DIR"
            run_module "$MODULE_DIR/file_audit.sh" "/" "$TEMP_DIR/file_findings.txt"
            run_report_generator
        else
            exit 1
        fi
        ;;

    logs)
        if check_root; then
            mkdir -p "$TEMP_DIR"
            run_module "$MODULE_DIR/log_analyzer.sh"
            copy_log_findings
            run_report_generator
        else
            exit 1
        fi
        ;;

    reports)
        bash "$BASE_DIR/report_generator.sh" previous
        ;;

    *)
        echo "Invalid controller operation!"
        exit 1
        ;;

esac
