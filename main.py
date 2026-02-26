#!/usr/bin/env python3
"""
ai-packet-analyzer: AI-powered network packet analyzer.
Parses pcap files or accepts tcpdump/tshark text output and uses AI to
identify suspicious traffic patterns, C2 communication, data exfiltration,
lateral movement, and other network-based threats.
"""

import sys
import subprocess
import click
from openai import OpenAI
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

client = OpenAI()
console = Console()


def parse_pcap(pcap_file: str, max_packets: int = 500) -> str:
    """Use tshark to extract a text summary from a pcap file."""
    try:
        result = subprocess.run(
            ["tshark", "-r", pcap_file, "-T", "fields",
             "-e", "frame.number", "-e", "frame.time_relative",
             "-e", "ip.src", "-e", "ip.dst",
             "-e", "tcp.srcport", "-e", "tcp.dstport",
             "-e", "udp.srcport", "-e", "udp.dstport",
             "-e", "_ws.col.Protocol", "-e", "_ws.col.Info",
             "-E", "header=y", "-E", "separator=|",
             "-c", str(max_packets)],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            # Fallback: basic tshark summary
            result = subprocess.run(
                ["tshark", "-r", pcap_file, "-c", str(max_packets)],
                capture_output=True, text=True, timeout=30
            )
        return result.stdout or result.stderr
    except FileNotFoundError:
        return "tshark not found. Please install Wireshark/tshark to parse pcap files."
    except subprocess.TimeoutExpired:
        return "tshark timed out parsing the pcap file."


@click.group()
def cli():
    """AI-powered network packet analysis toolkit."""
    pass


@cli.command()
@click.argument("pcap_file", type=click.Path(exists=True))
@click.option("--focus", default=None,
              help="Analysis focus (e.g., 'C2 detection', 'data exfiltration', 'lateral movement').")
def analyze_pcap(pcap_file: str, focus: str):
    """Analyze a pcap file for suspicious network activity."""
    console.print(Panel(f"[bold cyan]Parsing {pcap_file}...[/bold cyan]", expand=False))
    packet_data = parse_pcap(pcap_file)

    if not packet_data.strip():
        console.print("[bold red]Could not extract packet data.[/bold red]")
        sys.exit(1)

    _run_ai_analysis(packet_data, focus)


@cli.command()
@click.argument("source", default="-", metavar="FILE_OR_STDIN")
@click.option("--focus", default=None,
              help="Analysis focus (e.g., 'C2 detection', 'data exfiltration').")
def analyze_text(source: str, focus: str):
    """Analyze tcpdump or tshark text output for suspicious activity.

    Pass '-' as SOURCE to read from stdin.

    Example:
        tcpdump -r capture.pcap -n | python main.py analyze-text -
        python main.py analyze-text tshark_output.txt --focus "C2 detection"
    """
    if source == "-":
        packet_data = sys.stdin.read()
    else:
        try:
            with open(source, "r", errors="ignore") as f:
                packet_data = f.read()
        except FileNotFoundError:
            console.print(f"[bold red]File not found:[/bold red] {source}")
            sys.exit(1)

    if not packet_data.strip():
        console.print("[bold red]No packet data provided.[/bold red]")
        sys.exit(1)

    console.print(Panel("[bold cyan]Analyzing network traffic...[/bold cyan]", expand=False))
    _run_ai_analysis(packet_data, focus)


def _run_ai_analysis(packet_data: str, focus: str):
    """Run AI analysis on packet data."""
    focus_ctx = f"\nAnalysis Focus: {focus}" if focus else ""

    prompt = f"""You are a senior network security analyst and threat hunter. Analyze the following network traffic data for security threats.
{focus_ctx}

Provide:
1. **Traffic Overview** – Summary of protocols, top talkers, and traffic patterns.
2. **Suspicious Activity** – Identify anomalous or malicious traffic with specific evidence.
3. **Threat Classification** – Categorize threats (C2, exfiltration, scanning, lateral movement, etc.).
4. **IOCs Extracted** – IPs, domains, ports, user-agents, or signatures of interest.
5. **Attack Timeline** – If applicable, reconstruct the sequence of events.
6. **MITRE ATT&CK Mapping** – Map observed behaviors to ATT&CK techniques.
7. **Recommended Actions** – Immediate containment and investigation steps.
8. **Detection Rules** – Suggest Snort/Suricata or Zeek signatures for the observed threats.

Network Traffic Data:
---
{packet_data[:8000]}
---

Format your response in Markdown."""

    try:
        response = client.chat.completions.create(
            model="gpt-4.1-mini",
            messages=[
                {"role": "system", "content": "You are an expert network security analyst with deep knowledge of network protocols, intrusion detection, and threat hunting."},
                {"role": "user", "content": prompt}
            ]
        )
        console.print(Markdown(response.choices[0].message.content))
    except Exception as e:
        console.print(f"[bold red]AI analysis error:[/bold red] {e}")


if __name__ == "__main__":
    cli()
