#!/bin/bash
# Script Auto-Dump DEX Ijiami v1.0
# Oleh: Peneliti Keamanan Android
# Direkomendasikan dijalankan di rooted device

MONITOR_DIR="/data/local/tmp"  # Direktori target monitoring
BACKUP_DIR="/sdcard/dex_dump"  # Lokasi backup
LOG_FILE="${BACKUP_DIR}/dex_capture.log"  # Log aktivitas

# Konfigurasi inotify
EVENTS="create,close_write,delete"
FORMAT="%T | %w%f | %e"  # Format: Timestamp | Path | Event
TIME_FMT="%Y-%m-%d_%H:%M:%S"

# Inisialisasi lingkungan
mkdir -p "${BACKUP_DIR}"
echo "==== Monitoring dimulai: $(date) ====" > "${LOG_FILE}"

inotifywait -m -r -e "${EVENTS}" --timefmt "${TIME_FMT}" --format "${FORMAT}" "${MONITOR_DIR}" |
while read -r LINE
do
    FILE_PATH=$(echo "$LINE" | awk -F'|' '{print $2}' | xargs)
    EVENT_TYPE=$(echo "$LINE" | awk -F'|' '{print $3}' | xargs)
    
    # Filter hanya untuk file .dex
    if [[ "${FILE_PATH}" == *.dex ]]; then
        TIMESTAMP=$(date +"%Y%m%d%H%M%S")
        BACKUP_FILE="${BACKUP_DIR}/captured_${TIMESTAMP}_${RANDOM}.dex"
        
        case "${EVENT_TYPE}" in
            "CREATE"|"CLOSE_WRITE")
                # Verifikasi file tidak sedang digunakan
                if ! lsof "${FILE_PATH}" >/dev/null; then
                    cp -vp "${FILE_PATH}" "${BACKUP_FILE}" 2>> "${LOG_FILE}"
                    echo "[+] DEX captured: ${BACKUP_FILE}" | tee -a "${LOG_FILE}"
                    
                    # Analisis cepat
                    file "${BACKUP_FILE}" >> "${LOG_FILE}"
                    strings "${BACKUP_FILE}" | head -n 20 >> "${LOG_FILE}"
                fi
                ;;
            "DELETE")
                echo "[!] DEX deleted: ${FILE_PATH}" | tee -a "${LOG_FILE}"
                ;;
        esac
    fi
done

