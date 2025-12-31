# Agent-Zero: Comprehensive Malware Analysis Tool

  

[![Docker](https://img.shields.io/badge/Docker-Required-blue)](https://www.docker.com/)

[![Python](https://img.shields.io/badge/Python-3.x-green)](https://www.python.org/)


A comprehensive defensive cybersecurity tool that performs static amalware analysis in an isolated Kali Linux Docker container. Agent-Zero integrates multiple analysis tools including CAPA, FLOSS, VirusTotal, and Hybrid Analysis (Falcon Sandbox) to provide thorough malware investigation capabilities.

  

## ⚠️ Critical Setup & Security Warnings

  

### Security Disclaimer

  

This tool uses Docker for isolation to create a controlled analysis environment. However, it requires network access to communicate with external APIs (VirusTotal, Hybrid Analysis).

  

> **⚠️ DO NOT RUN HIGHLY UNSAFE OR MALICIOUS BINARIES.** This tool is intended for **STATIC analysis only** in a secure setting.

  

The Docker container provides isolation, but always exercise caution when:

- Analyzing live malware samples

- Sharing analysis results

- Handling IOCs (Indicators of Compromise)

- Working with real-world attack samples

  

### Hardware Requirements

  

The tool is resource-heavy due to the local AI model (Gemma 3:12b). It must be run on a machine with real, native hardware access. Emulated environments are not supported unless they provide GPU passthrough.

  

**System Requirements:**

- **Operating System**: Linux (Preferred). Windows users must use WSL2 (Windows Subsystem for Linux) to ensure full hardware and GPU capability.

- **GPU (VRAM)**: Minimum 8 GB VRAM. Critical for the local AI model. Ensure GPU drivers are up to date.

- **CPU**: Intel Core i5 or higher

- **RAM**: 8 GB minimum

- **Disk Space**: At least 20GB free (for Docker images and model storage)

  

## Features

  

- **Static Analysis**: String extraction with FLOSS de-obfuscation, API categorization, and pattern matching

- **CAPA Integration**: MITRE ATT&CK TTP detection and static analysis

- **Dynamic Analysis**: Hybrid Analysis (Falcon Sandbox) integration for behavioral analysis

- **VirusTotal Integration**: Multi-engine malware detection and analysis

- **Pre-installed Tools**: CAPA v9.3.1, FLOSS v3.1.1, and theZoo malware samples repository

- **Interactive Terminal UI**: User-friendly menu-driven interface (agent-zero2.0.py)

- **Isolated Environment**: Safe malware analysis in a containerized Kali Linux sandbox

- **Persistent Storage**: Analysis results and workspace data survive container restarts

  

## Prerequisites

  

Before setting up Agent-Zero, ensure you have the following installed and configured:

  

### Required Software

  

1. **Docker Engine**

   - Installation guide: [Docker Documentation](https://docs.docker.com/get-docker/)

   - Verify installation: `docker --version`

  

2. **Docker Compose**

   - Modern Docker Desktop includes Compose plugin

   - Legacy standalone: [Docker Compose Installation](https://docs.docker.com/compose/install/)

   - Verify installation: `docker compose version` or `docker-compose --version`

  

3. **Sudo/Root Access**

   - Required to build and run Docker containers

   - Alternatively, add your user to the docker group: `sudo usermod -aG docker $USER` (requires logout/login)

  

### Required Software (continued)

  

4. **Ollama** (for local AI model)

   - Installation guide: [Ollama Installation](https://ollama.com/download)

   - Required for LLM-powered analysis

   - Install before running the tool: `curl -fsSL https://ollama.com/install.sh | sh`

   - Or download from: https://ollama.com/download

  

## API Keys Setup

  

Agent-Zero requires API keys from two services for full functionality. Both offer free tier access.

  

### 1. VirusTotal API Key

  

1. Visit [VirusTotal](https://www.virustotal.com/gui/join-us) and create a free account

2. Navigate to your [API Key page](https://www.virustotal.com/gui/user/me/apikey)

3. Copy your API key

4. Add it to the `env` file (see Configuration section below)

  

**Free Tier Limits**: 4 requests per minute, 500 requests per day

  

### 2. Hybrid Analysis API Key

  

1. Visit [Hybrid Analysis](https://www.hybrid-analysis.com/signup) and create a free account

2. Log in and go to your [API Key settings](https://www.hybrid-analysis.com/my-account?tab=%23api-key-tab)

3. Generate and copy your API key

4. Add it to the `env` file (see Configuration section below)

  

**Free Tier**: Limited submissions per day

  

## Installation & Setup

  

### Step 0: Install Ollama and Pull Model

  

**IMPORTANT**: Install Ollama and download the required large language model before running the tool.

  

```bash

# Install Ollama (if not already installed)

curl -fsSL https://ollama.com/install.sh | sh

  

# Pull the recommended model (Gemma 3:12b)

ollama pull gemma3:12b

```

  

**Note**: This model is approximately 7GB and requires 8GB+ VRAM. The download may take several minutes depending on your internet connection.

  

### Step 1: Clone the Repository

  

### Step 1: Clone the Repository

  

```bash

git clone <repository-url>

cd github-zero

```

  

Or download and extract the repository to your desired location.

  

### Step 2: Configure API Keys

  

You must set your API keys in the `env` file to enable external threat intelligence lookups. Hybrid Analysis is preferred for dynamic analysis integration.

  

Edit the `env` file in the project root directory:

  

```bash

nano env

```

  

Replace the placeholder values with your actual API keys:

  

```env

# VirusTotal API Key

# Get your free API key from: https://www.virustotal.com/gui/join-us

VT_API_KEY=your_virustotal_api_key_here

  

# Hybrid Analysis (Falcon Sandbox) API Key

# Get your free API key from: https://www.hybrid-analysis.com/signup

HYBRID_ANALYSIS_API_KEY=your_hybrid_analysis_api_key_here

```

  

**Important**: Do not commit the `env` file with real API keys to version control. It's recommended to add `env` to `.gitignore`.

  

### Step 3: Verify Docker and Ollama Installation

  

Ensure Docker, Docker Compose, and Ollama are installed and running:

  

```bash

# Verify Docker

docker --version

docker compose version

# or for legacy installations:

docker-compose --version

  

# Verify Ollama

ollama --version

  

# Verify model is available

ollama list | grep gemma3

```

  

Start Docker service if needed:

```bash

sudo systemctl start docker  # Linux

# or use Docker Desktop on Windows/macOS

```

  

Start Ollama service if needed:

```bash

ollama serve

```

  

### Step 4: Build and Start the Container

  

Run the setup script with sudo:

  

```bash

sudo bash zero.sh start

```

  

This command will:

- Create the necessary directories (`~/kali_sandbox` by default)

- Build the Docker container with all required tools

- Copy project files into the container

- Start the container in detached mode

  

**Note**: On first run, the build process may take several minutes as it downloads the Kali Linux base image and installs all tools.

  

## Usage

  

### Starting the Container

  

If the container is not running, start it:

  

```bash

sudo bash zero.sh start

```

  

### Accessing the Container

  

To enter the container's bash shell:

  

```bash

sudo bash zero.sh access

```

  

Or manually:

  

```bash

sudo docker exec -it Zero bash

```

  

### Running Malware Analysis

  

Once inside the container, navigate to the workspace:

  

```bash

cd /workspace

```

  

#### Using the Interactive Terminal UI (Recommended)

  

For the interactive UI, run:

  

```bash

python3 agent-zero2.0.py

```

  

This launches an interactive menu-driven interface for easy malware analysis. The model (gemma3:12b) can be configured within the interface.

  

#### Using the Main Analysis Tool (CLI Version)

  

For command-line interface (less user-friendly):

  

```bash

python3 Agent-Zero.py --file /path/to/sample.exe

```

  

**CLI Options Reference**:

  

| Option | Description |

|--------|-------------|

| `--file FILE` | Path to the binary file to analyze (required unless running `--web`) |

| `--model MODEL` | Ollama model to use for analysis (recommended: `gemma3:12b`) |

| `--ollama-url URL` | Custom Ollama API endpoint (default: `http://localhost:11434/api/generate`) |

| `--outdir OUTDIR` | Output directory to save reports (default: `out`) |

| `--web` | Start Flask web server interface |

| `--web-port PORT` | Web server port (default: 5000) |

| `--vt-only` | Quick check: runs VirusTotal lookup and basic pattern check only (skips LLM, CAPA, and FLOSS) |

| `--no-llm` | Skip LLM report generation; use heuristic analysis only |

| `--no-vt` | Skip VirusTotal lookup |

| `--no-dynamic` | Skip dynamic analysis (requires Hybrid Analysis API key) |

| `--no-capa` | Skip CAPA static analysis phase |

| `--capa-verbose` | Enable CAPA verbose mode (-vv) |

| `--no-floss` | Skip FLOSS string de-obfuscation phase |

| `--stage-reports` | Generate individual stage reports (JSON/Text) |

| `--dataset-csv PATH` | Path to CSV of malware API sequences (for specialized analysis) |

| `--retries N` | Number of retry attempts for API calls (default: 3) |

  

**Usage Examples**:

  

```bash

# Full analysis with recommended model

python3 Agent-Zero.py --file /workspace/theZoo/malwares/Binaries/sample.exe --model gemma3:12b

  

# Quick VirusTotal check only

python3 Agent-Zero.py --file sample.exe --vt-only

  

# Analysis without LLM (heuristic only)

python3 Agent-Zero.py --file sample.exe --no-llm

  

# Full analysis with web interface

python3 Agent-Zero.py --file sample.exe --web --web-port 5000

  

# Analysis without dynamic analysis

python3 Agent-Zero.py --file sample.exe --no-dynamic

  

# Generate individual stage reports

python3 Agent-Zero.py --file sample.exe --stage-reports

  

# Show help

python3 Agent-Zero.py --help

```

  

### Stopping the Container

  

To stop the container:

  

```bash

sudo bash zero.sh stop

```

  

### Container Management Commands

  

Agent-Zero is managed via the `./zero.sh` wrapper script, which handles the Kali Linux sandbox Docker container.

  

```bash

sudo bash zero.sh start      # Build and start the container

sudo bash zero.sh stop       # Stop the container

sudo bash zero.sh access     # Enter the container shell

sudo bash zero.sh uninstall  # Remove container and all project files

sudo bash zero.sh help       # Show help message (or -h)

```

  

**Configuration Overrides**:

You can override default directories by setting these environment variables:

- `KALI_SANDBOX_DIR` (default: `~/kali_sandbox`)

- `KALI_SANDBOX_DATA_DIR` (default: `~/workspace`)

  

**Manual Container Access**:

```bash

sudo docker exec -it Zero bash

```

  

## Project Structure

  

```

github-zero/

├── README.md              # This file

├── zero.sh                # Container management script

├── Dockerfile             # Container build configuration

├── Agent-Zero.py          # Main malware analysis tool

├── agent-zero2.0.py       # Interactive terminal UI version

├── requirements.txt       # Python dependencies

├── env                    # API key configuration (configure this!)

└── refrence list.txt      # Reference links and documentation

```

  

### Key Files Description

  

- **`zero.sh`**: Main setup and management script that builds the Docker container and manages its lifecycle

- **`Dockerfile`**: Defines the Kali Linux container with pre-installed analysis tools

- **`Agent-Zero.py`**: Comprehensive static and dynamic malware analysis tool with CLI and web interface

- **`agent-zero2.0.py`**: Interactive menu-driven version of the analysis tool

- **`env`**: Configuration file for API keys (VirusTotal and Hybrid Analysis)

- **`requirements.txt`**: Python package dependencies

  

## Features & Tools Included

  

### Pre-installed Analysis Tools

  

- **CAPA v9.3.1**: Detects capabilities in executables and identifies MITRE ATT&CK techniques

  - GitHub: [mandiant/capa](https://github.com/mandiant/capa)

- **FLOSS v3.1.1**: Automatically extracts obfuscated strings from malware

  - GitHub: [mandiant/flare-floss](https://github.com/mandiant/flare-floss)

- **theZoo**: Collection of live malware samples for testing (in `/workspace/theZoo`)

  - GitHub: [ytisf/theZoo](https://github.com/ytisf/theZoo)

  

### Analysis Capabilities

  

- Multi-stage analysis pipeline with LLM validation

- String extraction and de-obfuscation

- API categorization and pattern matching

- MITRE ATT&CK TTP detection

- Behavioral analysis via Hybrid Analysis

- Multi-engine detection via VirusTotal

- Hard-coded behavioral pattern detection

- CSV dataset matching for known malware signatures

- Comprehensive reporting (JSON and formatted text)

  

### API Integrations

  

- **VirusTotal**: Multi-engine malware detection

- **Hybrid Analysis (Falcon Sandbox)**: Dynamic behavioral analysis

- **Ollama** (optional): Local LLM integration for analysis validation

  

## Troubleshooting

  

### Docker Permission Denied

  

**Error**: `permission denied while trying to connect to the Docker daemon socket`

  

**Solution**:

```bash

# Add your user to the docker group

sudo usermod -aG docker $USER

  

# Log out and log back in for changes to take effect

# Or use sudo with the script

sudo bash zero.sh start

```

  

### Docker Compose Not Found

  

**Error**: `No docker-compose found`

  

**Solution**:

- For Docker Desktop: Use `docker compose` (plugin version)

- For older installations: Install docker-compose separately

  ```bash

  sudo apt-get install docker-compose  # Debian/Ubuntu

  ```

  

### API Key Errors

  

**Error**: `Invalid API key` or `Authentication failed`

  

**Solution**:

1. Verify your API keys are correct in the `env` file

2. Ensure no extra spaces or quotes around the keys

3. Check that you've activated your API keys in the respective service dashboards

4. Verify you haven't exceeded free tier limits

  

### Container Build Fails

  

**Error**: Build process fails or times out

  

**Solution**:

- Ensure you have stable internet connection

- Check available disk space: `df -h`

- Try cleaning Docker cache: `sudo docker system prune -a`

- Rebuild: `sudo bash zero.sh start`

  

### Container Not Starting

  

**Error**: Container exits immediately after start

  

**Solution**:

- Check container logs: `sudo docker logs Zero`

- Verify Docker is running: `sudo systemctl status docker`

- Ensure no port conflicts (container uses host networking)

  

### Cannot Access Container

  

**Error**: `Error: No such container: Zero`

  

**Solution**:

- Ensure container is running: `sudo docker ps -a`

- Start the container: `sudo bash zero.sh start`

- Check container name: Should be "Zero" (case-sensitive)

  

### Workspace Files Missing

  

**Issue**: Tools or Python scripts not found in `/workspace`

  

**Solution**:

- The entrypoint script copies files on first startup

- Check container logs for initialization messages

- Restart the container: `sudo bash zero.sh stop && sudo bash zero.sh start`

  

## References & Documentation

  

### Tool Documentation

  

- **CAPA**: [GitHub Repository](https://github.com/mandiant/capa) | [Documentation](https://github.com/mandiant/capa)

- **FLOSS**: [GitHub Repository](https://github.com/mandiant/flare-floss) | [Documentation](https://github.com/mandiant/flare-floss)

- **theZoo**: [GitHub Repository](https://github.com/ytisf/theZoo)

  

### API Documentation

  

- **VirusTotal API**: [Documentation](https://docs.virustotal.com/reference)

- **Hybrid Analysis API**: [Documentation](https://www.hybrid-analysis.com/docs/api/v2)

- **Ollama API**: [Documentation](https://docs.ollama.com/api/introduction)

  

### Related Projects

  

- **Automated Kali Docker**: [GitHub Repository](https://github.com/Meezok-PJ/Automated-Kali-Docker)

  
  

## License

  

[Specify your license here - MIT, GPL, etc.]

  

## Author

  

**Meezok**

  

---

  

## Quick Start Checklist

  

- [ ] **Hardware verified**: 8GB+ VRAM GPU, 8GB RAM, adequate disk space

- [ ] **Ollama installed** and `gemma3:12b` model pulled

- [ ] **Docker and Docker Compose** installed and running

- [ ] **VirusTotal API key** obtained and added to `env`

- [ ] **Hybrid Analysis API key** obtained and added to `env`

- [ ] Run `sudo bash zero.sh start` to build container

- [ ] Access container with `sudo bash zero.sh access`

- [ ] Navigate to `/workspace` and run analysis tool

  

For detailed usage examples and advanced configuration, refer to the inline documentation in the Python scripts or use the `--help` flag with the analysis tools.
