# Agent-Zero: Comprehensive Staged Malware Analysis Tool

**Agent-Zero** is a staged static malware analysis framework that integrates traditional security tools with local Large Language Model (LLM) capabilities to provide comprehensive threat assessments. Operating within an isolated Kali Linux Docker container, it bridges the gap between raw data collection and human-level reasoning.

---

## 🚀 Core Analysis Methodology

Agent-Zero employs a systematic, four-stage pipeline designed to mimic professional analysis workflows.

| Stage | Focus | Process |
| --- | --- | --- |
| **Stage 1** | **Extraction** | Extracts strings via multiple methods and uses **FLOSS** to recover hidden/obfuscated data.

 |
| **Stage 2** | **Categorization** | Groups API calls and executes **CAPA** to map capabilities to the **MITRE ATT&CK** framework.

 |
| **Stage 3** | **Enrichment** | Correlates findings with **VirusTotal** reputation and **Hybrid Analysis** behavioral context.

 |
| **Stage 4** | **Synthesis** | The LLM produces a final verdict (Benign/Suspicious/Malicious) with a confidence score and risk assessment.

 |

---

## ⚠️ Critical Security & Hardware Requirements

### Security Disclaimer

> 
> **⚠️ WARNING:** This tool is intended for **STATIC analysis only**. While it uses Docker for isolation, it requires network access for external API validation (VirusTotal/Hybrid Analysis). Always exercise extreme caution when handling live malware samples.
> 
> 

### Hardware Requirements

The intelligence core is powered by **Gemma 3:12b** running locally.

* 
**GPU (VRAM):** Minimum **8 GB VRAM** (Optimized for NVIDIA RTX 2080 level hardware).


* **Operating System:** Linux (Preferred) or Windows with **WSL2** for GPU passthrough.
* **Storage:** 20GB+ free (for Docker images and the ~7GB LLM model).

---

## 🛠️ Installation & Setup

### 1. Install Ollama and Pull Model

Install the [Ollama framework](https://ollama.com/) to serve as the local inference engine.

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# [cite_start]Pull the primary model (Gemma 3:12b was selected for its JSON reliability and logic) [cite: 79, 84]
ollama pull gemma3:12b

```

### 2. Configure API Keys

Edit the `env` file in the project root to enable external threat intelligence.

```bash
VT_API_KEY=your_virustotal_key
HYBRID_ANALYSIS_API_KEY=your_hybrid_analysis_key

```

### 3. Build and Start the Sandbox

Agent-Zero uses a custom Docker image built on a **Kali Linux** base for a standardized, isolated environment.

```bash
sudo bash zero.sh start   # Builds and starts the detached container
sudo bash zero.sh access  # Enters the container shell

```

---

## 💻 Usage

Once inside the container (`/workspace`), you can run the analysis via the CLI or the interactive UI.

### Interactive Terminal UI (Recommended)

Launch the menu-driven interface:

```bash
python3 agent-zero2.0.py

```

### Command Line Interface

```bash
# Full staged analysis
python3 Agent-Zero.py --file /path/to/sample.exe --model gemma3:12b

# Quick VirusTotal check only (skips LLM and static tools)
python3 Agent-Zero.py --file sample.exe --vt-only

```

---

## 📊 Key Features & Integrated Tools

* 
**CAPA (v9.3.1):** Identifies over 400 capabilities and maps them to MITRE ATT&CK.


* 
**FLOSS (v3.1.1):** Uses advanced emulation to de-obfuscate hidden C2 URLs and configurations.


* 
**Local AI (Gemma 3):** Synthesizes raw data into coherent, context-based threat intelligence.


* 
**theZoo:** Includes a built-in repository of live malware samples for testing and research.



---

## 📝 Project Details

* 
**Topic:** Static Malware Detection (Binary Classification).


* 
**Academic Year:** 2025/2026.


* 
**Author:** Meezok.



**Future Work:** Planned updates include integration of **Dynamic Analysis**, memory forensics via Volatility, and fine-tuning models on specific malware datasets.

Would you like me to help you generate a sample analysis report using the Stage 1-4 format described in your documentation?
