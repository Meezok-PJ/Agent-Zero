#!/usr/bin/env bash
set -euo pipefail

# ----------------------------------------------------
# Kali Sandbox Management Script
#
# This script automates the creation, management, and
# removal of a Kali Linux Docker container for a safe,
# isolated hacking/testing environment.
# ----------------------------------------------------

# --- Config / Defaults ---
# The main project directory where the Dockerfile and docker-compose.yml are stored.
# This variable is dynamically set based on whether the script is run with sudo.
KALI_SANDBOX_DIR=""
# The directory for persistent data, mounted inside the container at /workspace.
SANDBOX_DIR=""

# --- Colors ---
RED="\e[31m"
GREEN="\e[32m"
BLUE="\e[34m"
YELLOW="\e[33m"
RESET="\e[0m"

# --- Global Variables ---
DOCKER_COMPOSE_CMD=""
CONTAINER_NAME="Zero"
# Get the absolute path of the script to avoid issues with `cd`
SCRIPT_PATH=$(readlink -f "$0")

# --- Functions ---

# Displays a simple watermark.
watermark() {
    echo -e "${BLUE}========================================${RESET}"
    echo -e "${GREEN}      Powered by: Meezok's Sandbox Tool${RESET}"
    echo -e "${BLUE}========================================${RESET}"
}

# Detects the correct docker-compose command (plugin vs. legacy).
detect_docker_compose() {
    if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1 2>/dev/null; then
        DOCKER_COMPOSE_CMD="docker compose"
    elif command -v docker-compose >/dev/null 2>&1; then
        DOCKER_COMPOSE_CMD="docker-compose"
    else
        echo -e "${RED}Error:${RESET} No docker-compose found. Install Docker Engine + Compose plugin or docker-compose."
        exit 1
    fi
}

# Checks if Docker is installed and a compatible docker-compose command exists.
check_docker() {
    if ! command -v docker >/dev/null 2>&1; then
        echo -e "${RED}Docker is required. Install Docker and try again.${RESET}"
    fi
    detect_docker_compose
}

# Ensures the script is run with proper privileges.
check_privileges() {
    # Check if the user is in the 'docker' group or is running with sudo.
    if ! groups | grep -q "docker" && [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Error:${RESET} You must be in the 'docker' group or run this script with sudo."
        echo -e "To add yourself to the docker group, run: ${YELLOW}sudo usermod -aG docker \$USER${RESET}"
        echo -e "You will need to log out and log back in for the changes to take effect."
        echo -e "Alternatively, you can run this script with: ${YELLOW}sudo $0 $@${RESET}"
        exit 1
    fi
}

# Prompts the user to set up a custom path.
prompt_for_paths() {
    echo -e "${YELLOW}* Project files not found. Let's set up the directories.${RESET}"
    while true; do
        read -rp "Do you want to use the default path: $HOME/kali_sandbox (y/n)? " choice
        case "$choice" in
            y|Y)
                KALI_SANDBOX_DIR="$HOME/kali_sandbox"
                SANDBOX_DIR="$HOME/workspace"
                break
                ;;
            n|N)
                read -rp "Enter the full path for the Kali Docker project: " custom_dir
                if [ -z "$custom_dir" ]; then
                    echo -e "${RED}Error:${RESET} Path cannot be empty."
                    continue
                fi
                KALI_SANDBOX_DIR="$custom_dir"
                SANDBOX_DIR="${KALI_SANDBOX_DIR}/workspace" # Create a subdir for clarity
                # Basic validation: check if parent directory exists and is writable
                PARENT_DIR=$(dirname "$KALI_SANDBOX_DIR")
                if [ ! -d "$PARENT_DIR" ] || [ ! -w "$PARENT_DIR" ]; then
                    echo -e "${RED}Error:${RESET} The parent directory '$PARENT_DIR' does not exist or is not writable."
                    continue
                fi
                break
                ;;
            *)
                echo "Invalid input. Please enter 'y' or 'n'."
                ;;
        esac
    done
}


# Creates the project files (Dockerfile, docker-compose.yml, README.md).
create_project_files() {
    echo -e "${GREEN}* Creating project files in ${KALI_SANDBOX_DIR}...${RESET}"
    mkdir -p "$SANDBOX_DIR"
    mkdir -p "$KALI_SANDBOX_DIR"
    cd "$KALI_SANDBOX_DIR" || exit 1

    # Get the script's directory (project root)
    SCRIPT_DIR=$(dirname "$SCRIPT_PATH")
    
    # Copy Dockerfile from project root if it exists
    if [ -f "$SCRIPT_DIR/Dockerfile" ]; then
        echo -e "${GREEN}* Copying Dockerfile from project root...${RESET}"
        cp "$SCRIPT_DIR/Dockerfile" .
    else
        echo -e "${YELLOW}* Warning: Dockerfile not found in project root. Creating a basic one...${RESET}"
        cat > Dockerfile <<EOF
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update && apt install -y \\
    net-tools \\
    iproute2 \\
    iputils-ping \\
    curl \\
    nmap \\
    nano \\
    dnsutils \\
    git \\
    python3 \\
    python3-pip \\
    wget \\
    unzip \\
    && apt clean

WORKDIR /workspace
CMD ["/bin/bash"]
EOF
    fi
    
    # Copy Python tool files from project root
    if [ -f "$SCRIPT_DIR/Agent-Zero.py" ]; then
        cp "$SCRIPT_DIR/Agent-Zero.py" .
    fi
    if [ -f "$SCRIPT_DIR/agent-zero2.0.py" ]; then
        cp "$SCRIPT_DIR/agent-zero2.0.py" .
    fi
    if [ -f "$SCRIPT_DIR/requirements.txt" ]; then
        cp "$SCRIPT_DIR/requirements.txt" .
    fi
    if [ -f "$SCRIPT_DIR/env" ]; then
        cp "$SCRIPT_DIR/env" .
    fi

    cat > docker-compose.yml <<EOF
services:
  static:
    build: .
    image: static
    container_name: ${CONTAINER_NAME}
    hostname: sandbox
    network_mode: host
    volumes:
      - "$SANDBOX_DIR:/workspace"
    environment:
      - OLLAMA_URL=http://localhost:11434
    env_file:
      - ./env
    tty: true
    stdin_open: true
    # Uncomment the line below to auto-start the analysis tool
    # command: ["python3", "/workspace/agent-zero2.0.py"]

EOF

    # README with start/stop/uninstall instructions (absolute $HOME paths included)
    cat > README.md <<EOF
# Kali Docker Sandbox — Break Code, Not Your System

## Overview
An isolated Kali Linux environment for safe script testing, debugging, and experimentation without risking your host system's dependencies.

## Project location
- Project dir: ${KALI_SANDBOX_DIR}
- Persistent data: ${SANDBOX_DIR} (mounted to /workspace inside container)

## Quick start (from the project directory)
\`\`\`bash
cd "${KALI_SANDBOX_DIR}"
# start
${DOCKER_COMPOSE_CMD} up -d
# stop
${DOCKER_COMPOSE_CMD} down
# view logs
${DOCKER_COMPOSE_CMD} logs -f
# access container
sudo docker exec -it ${CONTAINER_NAME} bash
\`\`\`

## Use the included management script
A copy of this management script has been placed in your project directory at:
\`\`\`bash
${KALI_SANDBOX_DIR}/manage.sh
\`\`\`
You can use it from anywhere. You will need to either be in the docker group or use \`sudo\`.
\`\`\`bash
# with sudo
sudo bash "${KALI_SANDBOX_DIR}/manage.sh" start
# as a user in the docker group
bash "${KALI_SANDBOX_DIR}/manage.sh" start
\`\`\`

## Why use this tool
- Host-safe: Avoid breaking host dependencies.
- Persistent storage: Files survive container restarts (/workspace).
- Malware analysis tools: Pre-installed CAPA, FLOSS, and theZoo samples.
- Python analysis tools: Agent-Zero static analysis tool ready to use.
- Network access: Connect to host Ollama API and external APIs.
- Quick to set up and remove for iterative malware analysis.

**Author:** Meezok
EOF
}

# Copies this script to the project directory for easy management.
copy_self_to_project_dir() {
    echo -e "${YELLOW}* Copying management script to ${KALI_SANDBOX_DIR}/manage.sh...${RESET}"
    cp "$SCRIPT_PATH" "${KALI_SANDBOX_DIR}/manage.sh"
    chmod +x "${KALI_SANDBOX_DIR}/manage.sh"
}

# Starts the Kali sandbox.
start() {
    # Fix sudo home directory issue
    if [[ "$EUID" -eq 0 ]] && [[ -n "${SUDO_USER}" ]]; then
        export HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    fi

    # Set default paths if they are still empty
    if [ -z "$KALI_SANDBOX_DIR" ]; then
        KALI_SANDBOX_DIR="$HOME/kali_sandbox"
        SANDBOX_DIR="$HOME/workspace"
    fi

    check_docker

    if [ ! -d "$KALI_SANDBOX_DIR" ]; then
        prompt_for_paths
    fi


    if [ ! -f "$KALI_SANDBOX_DIR/docker-compose.yml" ]; then
        echo -e "${YELLOW}* Project files not found. Creating them now...${RESET}"
        create_project_files
        copy_self_to_project_dir
    fi
    
    echo -e "${GREEN}* Starting Kali sandbox...${RESET}"
    cd "$KALI_SANDBOX_DIR" || exit 1
    ${DOCKER_COMPOSE_CMD} up -d --build
    echo -e "${GREEN}* Kali sandbox is now running.${RESET}"
    echo -e "${YELLOW}Use 'bash ${KALI_SANDBOX_DIR}/manage.sh access' to enter the container.${RESET}"
}

# Stops the Kali sandbox.
stop() {
    # Fix sudo home directory issue
    if [[ "$EUID" -eq 0 ]] && [[ -n "${SUDO_USER}" ]]; then
        export HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    fi

    # Set default paths if not set
    if [ -z "$KALI_SANDBOX_DIR" ]; then
        KALI_SANDBOX_DIR="$HOME/kali_sandbox"
        SANDBOX_DIR="$HOME/workspace"
    fi
    
    check_docker

    if [ ! -f "$KALI_SANDBOX_DIR/docker-compose.yml" ]; then
        echo -e "${YELLOW}* Project not found at '${KALI_SANDBOX_DIR}'. Nothing to stop.${RESET}"
        exit 0
    fi
    
    echo -e "${GREEN}* Stopping Kali sandbox...${RESET}"
    cd "$KALI_SANDBOX_DIR" || exit 1
    ${DOCKER_COMPOSE_CMD} down
    echo -e "${GREEN}* Kali sandbox stopped.${RESET}"
}

# Accesses the running container's bash shell.
access() {
    # Fix sudo home directory issue
    if [[ "$EUID" -eq 0 ]] && [[ -n "${SUDO_USER}" ]]; then
        export HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    fi

    # Set default paths if not set
    if [ -z "$KALI_SANDBOX_DIR" ]; then
        KALI_SANDBOX_DIR="$HOME/kali_sandbox"
        SANDBOX_DIR="$HOME/workspace"
    fi

    echo -e "${GREEN}* Accessing Kali container...${RESET}"
    sudo docker exec -it ${CONTAINER_NAME} bash
}

# Uninstalls the sandbox, removing all files and the project directory.
uninstall() {
    # Fix sudo home directory issue
    if [[ "$EUID" -eq 0 ]] && [[ -n "${SUDO_USER}" ]]; then
        export HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    fi

    # Set default paths if not set
    if [ -z "$KALI_SANDBOX_DIR" ]; then
        KALI_SANDBOX_DIR="$HOME/kali_sandbox"
        SANDBOX_DIR="$HOME/workspace"
    fi

    check_docker

    if [ ! -d "$KALI_SANDBOX_DIR" ]; then
        echo -e "${YELLOW}* Project directory not found. Nothing to uninstall.${RESET}"
        exit 0
    fi

    echo -e "${RED}* Stopping and removing Kali sandbox containers and network...${RESET}"
    cd "$KALI_SANDBOX_DIR" || exit 1
    ${DOCKER_COMPOSE_CMD} down -v
    
    echo -e "${RED}* Removing project directory: ${KALI_SANDBOX_DIR}...${RESET}"
    rm -rf "$KALI_SANDBOX_DIR"
    echo -e "${RED}* Removing persistent data directory: ${SANDBOX_DIR}...${RESET}"
    rm -rf "$SANDBOX_DIR"

    echo -e "${GREEN}* Uninstallation complete.${RESET}"
}

# Displays the help message.
help() {
    watermark
    echo -e "${YELLOW}Usage: bash $0 [command]${RESET}"
    echo
    echo -e "${BLUE}Commands:${RESET}"
    echo -e "  ${GREEN}start${RESET}     - Builds and starts the Kali sandbox container."
    echo -e "  ${GREEN}stop${RESET}      - Stops and removes the sandbox container and network."
    echo -e "  ${GREEN}access${RESET}    - Enters the running container's bash shell."
    echo -e "  ${GREEN}uninstall${RESET} - Removes all project files, containers, and persistent data."
    echo -e "  ${GREEN}help${RESET}      - Displays this help message."
    echo
    echo -e "${BLUE}Configuration:${RESET}"
    echo -e "  You can override the default directories by setting these environment variables:"
    echo -e "  ${YELLOW}KALI_SANDBOX_DIR=${RESET}  (default: ${KALI_SANDBOX_DIR})"
    echo -e "  ${YELLOW}KALI_SANDBOX_DATA_DIR=${RESET} (default: ${SANDBOX_DIR})"
    echo
    echo -e "${BLUE}Additional Commands:${RESET}"
    echo -e "  ${YELLOW}* Manual container access: sudo docker exec -it ${CONTAINER_NAME} bash${RESET}"
    echo
}

# --- Main Logic ---
main() {
    watermark
    if [ $# -eq 0 ]; then
        help
        exit 1
    fi

    check_privileges
    
    case "$1" in
        start)
            start
            ;;
        stop)
            stop
            ;;
        access)
            access
            ;;
        uninstall)
            uninstall
            ;;
        help|--help|-h)
            help
            ;;
        *)
            echo -e "${RED}Invalid command: $1${RESET}"
            help
            exit 1
            ;;
    esac
}

main "$@"
