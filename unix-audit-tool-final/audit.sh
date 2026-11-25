#!/bin/bash

BASE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

while true
do
    clear

    echo "======================================"
    echo "       UNIX SECURITY AUDIT TOOL"
    echo "======================================"
    echo "1. Complete Security Audit"
    echo "2. Password Audit"
    echo "3. File Permission Audit"
    echo "4. Authentication Log Audit"
    echo "5. View Previous Reports"
    echo "6. Exit"
    echo "======================================"

    read -rp "Enter your choice (1-6): " choice

    case "$choice" in
        1) bash "$BASE_DIR/controller.sh" all ;;
        2) bash "$BASE_DIR/controller.sh" password ;;
        3) bash "$BASE_DIR/controller.sh" files ;;
        4) bash "$BASE_DIR/controller.sh" logs ;;
        5) bash "$BASE_DIR/controller.sh" reports ;;
        6)
            echo "Thank you for using Unix Security Audit Tool!"
            exit 0
            ;;
        *)
            echo "Invalid choice! Please enter 1 to 6."
            ;;
    esac

    echo
    read -rp "Press Enter to return to the main menu..."
done