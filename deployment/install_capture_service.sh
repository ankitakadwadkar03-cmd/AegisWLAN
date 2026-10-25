#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

SERVICE_NAME="netshield-ml-capture.service"
SCANNER_SERVICE_NAME="netshield-ml-scanner.service"
INTERFACE="${1:-wlan0}"

INSTALL_ROOT="/opt/netshield-ml-capture"
VENV_DIR="${INSTALL_ROOT}/venv"

BACKEND_DIR="${PROJECT_ROOT}/backend"
SOURCE_DIR="${BACKEND_DIR}/packet_capture"
ML_DIR="${BACKEND_DIR}/ml"
DATA_DIR="${BACKEND_DIR}/data"
MODEL_FILE="${ML_DIR}/models/random_forest_awid3_v3_expanded.joblib"
REQUIREMENTS_FILE="${BACKEND_DIR}/requirements.txt"

OUTPUT_DIR="${DATA_DIR}/packet_logs"
OUTPUT_FILE="${OUTPUT_DIR}/wifi_packets.csv"

CURRENT_USER="${SUDO_USER:-$USER}"
SYSTEMCTL="$(command -v systemctl)"

required_files=(
    "${SOURCE_DIR}/packet_sniffer.py"
    "${SOURCE_DIR}/packet_analyzer.py"
    "${SOURCE_DIR}/packet_logger.py"
    "${ML_DIR}/live_inference.py"
    "${ML_DIR}/inference_service.py"
    "${MODEL_FILE}"
    "${DATA_DIR}/incident_store.py"
    "${REQUIREMENTS_FILE}"
)

for file in "${required_files[@]}"; do
    if [[ ! -f "${file}" ]]; then
        echo "Required file missing: ${file}" >&2
        exit 1
    fi
done

echo "Installing NetShield ML packet capture..."
echo "Interface: ${INTERFACE}"
echo "Project:   ${PROJECT_ROOT}"

mkdir -p "${OUTPUT_DIR}"
sudo chown -R "${CURRENT_USER}:${CURRENT_USER}" "${DATA_DIR}"
sudo chmod -R u+rwX,g+rwX "${DATA_DIR}"

sudo install -d -m 0755 "${INSTALL_ROOT}"

# Remove legacy partial app copy if it exists from previous installations
if [[ -d "${INSTALL_ROOT}/app" ]]; then
    sudo rm -rf "${INSTALL_ROOT}/app"
fi

if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
    sudo python3 -m venv "${VENV_DIR}"
fi

sudo "${VENV_DIR}/bin/python" -m pip install --upgrade pip
sudo "${VENV_DIR}/bin/python" -m pip install -r "${REQUIREMENTS_FILE}"

sudo tee "/etc/systemd/system/${SERVICE_NAME}" >/dev/null <<SERVICE
[Unit]
Description=NetShield ML Live WiFi Packet Capture
After=network.target
ConditionPathExists=${SOURCE_DIR}/packet_sniffer.py

[Service]
Type=simple
WorkingDirectory=${BACKEND_DIR}

Environment=PYTHONUNBUFFERED=1
Environment="PYTHONPATH=${BACKEND_DIR}"
Environment="PATH=${VENV_DIR}/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

ExecStartPre=/bin/sh -c '! ${SYSTEMCTL} is-active --quiet ${SCANNER_SERVICE_NAME}'

ExecStart=${VENV_DIR}/bin/python ${SOURCE_DIR}/packet_sniffer.py --interface ${INTERFACE} --output ${OUTPUT_FILE}

KillSignal=SIGTERM
TimeoutStopSec=45
Restart=no

StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SERVICE

sudo tee /etc/sudoers.d/netshield-ml-capture >/dev/null <<SUDOERS
${CURRENT_USER} ALL=(root) NOPASSWD: ${SYSTEMCTL} start ${SERVICE_NAME}, ${SYSTEMCTL} stop ${SERVICE_NAME}
SUDOERS

sudo chmod 440 /etc/sudoers.d/netshield-ml-capture

sudo visudo -cf /etc/sudoers.d/netshield-ml-capture

sudo systemctl daemon-reload

echo
echo "Packet-capture service installed successfully."
echo "Service was NOT started."
