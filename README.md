# Application Threat Checker (SOC Quarantine Intelligence)

A desktop GUI (Python + customtkinter) that helps SOC analysts triage **quarantined email reports**. Paste quarantine entries, and it extracts sender domains, IPs and URLs, checks their reputation on VirusTotal, and classifies each as **Safe / Suspicious / Malicious / Unknown** with exportable results.

## Features

- Modern light/dark GUI
- Parses pasted quarantine reports (recipient, sender, sender IP, subject, reason, detection technologies)
- VirusTotal reputation lookups for domains and IPs
- Optional AI-assisted analysis (Gemini, xAI, NVIDIA) when keys are provided
- CSV export
- API keys stored in the OS credential store (`keyring`) — never in plain-text files

## Triage rules

- 0 malicious + exactly 1 suspicious → **Suspicious**
- Any malicious, or more than 1 suspicious → **Malicious**
- 0 detections → **Safe** (never a guarantee)
- Any lookup/API error → **Unknown**, never "Safe"

## Run from source

Requires Python 3.10+.

```bash
pip install -r requirements.txt
python "EXE SOC/Reputation_Checker.py"
```

Add API keys in **Settings**, or set environment variables: `VIRUSTOTAL_API_KEY`, `GEMINI_API_KEY`, `XAI_API_KEY`, `NVIDIA_API_KEY`.

## Windows executable

A prebuilt `ReputationChecker.exe` is available on the repository's **Releases** page. To build it yourself:

```bash
pip install pyinstaller
pyinstaller "EXE SOC/ReputationChecker.spec"
```

Preferences are stored in `~/.soc_quarantine_analyzer/settings.json` (override with `SOC_ANALYZER_HOME`).

## Disclaimer

Reputation results are one signal among many. Always validate before taking action.
