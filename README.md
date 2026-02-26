# ai-packet-analyzer 🔐

> AI-powered network packet analyzer that detects C2 communication, data exfiltration, and lateral movement from pcap or tcpdump output.

![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=flat-square&logo=python&logoColor=white)
![OpenAI](https://img.shields.io/badge/OpenAI-GPT--4.1-412991?style=flat-square&logo=openai&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Security](https://img.shields.io/badge/Category-network-security-red?style=flat-square)

## Overview

AI-powered network packet analyzer that detects C2 communication, data exfiltration, and lateral movement from pcap or tcpdump output. This tool is designed for security professionals who want to augment their workflows with AI-driven intelligence, reducing manual analysis time and surfacing actionable insights faster.

## Features

- **AI-Driven Analysis** — Leverages GPT-4.1 for deep contextual reasoning beyond simple pattern matching.
- **Rich Terminal Output** — Color-coded, structured output with tables and formatted Markdown.
- **Flexible Input** — Accepts files, stdin pipes, and direct arguments for seamless workflow integration.
- **MITRE ATT&CK Integration** — Maps findings to the ATT&CK framework where applicable.
- **Actionable Output** — Every analysis includes concrete remediation and response recommendations.

## Installation

```bash
git clone https://github.com/rawqubit/ai-packet-analyzer.git
cd ai-packet-analyzer
pip install -r requirements.txt
export OPENAI_API_KEY="your-api-key-here"
```

## Usage

```bash
python main.py analyze-pcap capture.pcap --focus "C2 detection"
tcpdump -r capture.pcap -n | python main.py analyze-text -
python main.py analyze-text tshark_output.txt
```

Run `python main.py --help` for full usage information.

## Requirements

- Python 3.9+
- OpenAI API key (set as `OPENAI_API_KEY` environment variable)

## License

MIT License — see [LICENSE](LICENSE) for details.
