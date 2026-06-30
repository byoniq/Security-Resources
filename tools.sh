#!/bin/bash

# This script installs various pentesting tools on a Kali Linux system.

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run this script as root"
  exit 1
fi

# Log file
LOGFILE="/var/log/pentest_setup.log"
exec > >(tee -i $LOGFILE) 2>&1

echo "Starting installation process..."

# Function to install packages with automatic "yes"
install_package() {
    if ! dpkg -s "$1" &> /dev/null; then
        echo "Installing $1..."
        apt-get install -y "$1"
    else
        echo "$1 is already installed."
    fi
}

# Update and upgrade system packages
echo "Updating system..."
apt-get update -y && apt-get upgrade -y

# Install commonly used tools
PACKAGES=(
  nuclei seclists gedit tor rlwrap eyewitness bloodhound trufflehog
  dirsearch keepass2 knockd subfinder docker.io chisel dnsrecon feroxbuster
  gobuster nbtscan onesixtyone oscanner redis-tools svwar tnscmd10g
  whatweb wkhtmltopdf zaproxy hexedit skipfish code commix libreoffice
  spray ntpdate golang-go code-oss osrframework sublist3r guake
)

for package in "${PACKAGES[@]}"; do
  install_package "$package"
done

# Install Rustscan
if [ ! -f /home/kali/tools/rustscan_2.0.1_amd64.deb ]; then
  echo "Installing Rustscan..."
  wget -q --show-progress -P /home/kali/tools https://github.com/RustScan/RustScan/releases/download/2.0.1/rustscan_2.0.1_amd64.deb
  dpkg -i /home/kali/tools/rustscan_2.0.1_amd64.deb
else
  echo "Rustscan already downloaded."
fi

# Update Searchsploit
echo "Updating Searchsploit..."
searchsploit -u

# Install pip for Python 2 and 3
echo "Installing Python dependencies..."
wget -q --show-progress https://bootstrap.pypa.io/pip/2.7/get-pip.py
python2 get-pip.py && rm get-pip.py
pip2 install xlrd==1.2.0
pip3 install pycryptodome wapiti3 certipy-ad arjun mitmproxy2swagger

# Install Arsenal for cheatsheet generation
pip3 install arsenal-cli
sysctl -w dev.tty.legacy_tiocsti=1  # Fix issue with arsenal

# Create directory structure
echo "Creating directory structure..."
mkdir -p /home/kali/{tools,scripts,server,loot,custom_scripts,vpn,compile,crack}

# Clone and setup repositories
REPOS=(
  "https://github.com/Tib3rius/AutoRecon /home/kali/tools/AutoRecon"
  "https://github.com/cddmp/enum4linux-ng /home/kali/tools/enum4linux-ng"
  "https://github.com/blacklanternsecurity/MANSPIDER /home/kali/tools/MANSPIDER"
  "https://github.com/redhuntlabs/Octopii /home/kali/tools/Octopii"
  "https://github.com/AggressiveUser/AllForOne /home/kali/tools/AllForOne"
  "https://github.com/xm1k3/cent /home/kali/tools/cent"
  "https://github.com/xnl-h4ck3r/GAP-Burp-Extension /home/kali/tools/GAP-Burp-Extension"
  "https://github.com/LewisArdern/metasecjs /home/kali/tools/metasecjs"
  "https://github.com/BishopFox/jsluice /home/kali/tools/jsluice"
  "https://github.com/glowbase/macro_reverse_shell /home/kali/tools/macro_reverse_shell"
  "https://github.com/s0md3v/XSStrike /home/kali/tools/XSStrike"
  "https://github.com/dafthack/MSOLSpray /home/kali/tools/MSOLSpray"
  "https://github.com/wireghoul/dotdotpwn /home/kali/tools/dotdotpwn"
  "https://github.com/r0oth3x49/ghauri /home/kali/tools/ghauri"
  "https://github.com/fin3ss3g0d/evilgophish /home/kali/tools/evilgophish"
  "https://github.com/kgretzky/evilginx2 /home/kali/tools/evilginx2"
  "https://github.com/Pennyw0rth/NetExec /home/kali/tools/netexec"
  "https://github.com/lanmaster53/recon-ng.git /home/kali/tools/recon-ng"
  "https://github.com/r3curs1v3-pr0xy/sub404.git /home/kali/tools/sub404"
  "https://github.com/aws/aws-cli.git /home/kali/tools/aws-cli"
  "https://github.com/yassineaboukir/Asnlookup.git /home/kali/tools/asnlookup"
  "https://github.com/j3ssie/metabigor.git /home/kali/tools/meabigor"
  "https://github.com/initstring/cloud_enum.git /home/kali/tools/cloud-enum"
  "https://github.com/hahwul/dalfox.git /home/kali/tools/dalfox"
  "https://github.com/RhinoSecurityLabs/pacu.git /home/kali/tools/pacu"
  "https://github.com/robertdavidgraham/masscan.git /home/kali/tools/masscan"
  )

for repo in "${REPOS[@]}"; do
  repo_url=$(echo "$repo" | awk '{print $1}')
  repo_path=$(echo "$repo" | awk '{print $2}')
  
  if [ ! -d "$repo_path" ]; then
    echo "Cloning $repo_url..."
    git clone "$repo_url" "$repo_path"
  else
    echo "$repo_path already exists."
  fi
done

# Download tools and scripts
echo "Downloading additional tools and scripts..."
wget -q --show-progress -P /home/kali/server https://github.com/BloodHoundAD/SharpHound/releases/download/v1.1.1/SharpHound-v1.1.1.zip
wget -q --show-progress -P /home/kali/server https://github.com/BloodHoundAD/SharpHound/releases/download/v2.3.0/SharpHound-v2.3.0.zip
wget -q --show-progress -P /home/kali/server https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1
wget -q --show-progress -P /home/kali/server https://github.com/tevora-threat/SharpView/raw/master/Compiled/SharpView.exe
wget -q --show-progress -P /home/kali/tools https://github.com/projectdiscovery/katana/releases/download/v1.0.4/katana_1.0.4_linux_amd64.zip

# =====================================================================
# AI-ENABLED SECURITY TOOLING (added 2026-06-30)
# Modern AI/LLM-assisted offensive tooling + GenAI red-team frameworks.
# Installed with pipx/venv to stay PEP-668-safe on current Kali.
# =====================================================================
echo "Installing AI-enabled security tooling..."

# --- Prerequisites -----------------------------------------------------
# Node.js + npm (Shannon, promptfoo) and pipx (isolated Python CLI tools)
install_package nodejs
install_package npm
install_package pipx
pipx ensurepath || true
export PATH="$PATH:/root/.local/bin:/usr/local/bin"

# --- ProjectDiscovery AI suite (nuclei -ai, subfinder, httpx, katana...) -
# pdtm = ProjectDiscovery Tool Manager; -ia installs/updates the full suite.
# Needs Go 1.21+ (golang-go above). Nuclei AI template generation requires a
# PDCP key: `export PDCP_API_KEY=...` then `nuclei -auth`
# (free key: https://cloud.projectdiscovery.io).
echo "Installing ProjectDiscovery tool manager + suite..."
GOBIN=/usr/local/bin go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest
pdtm -ia || echo "pdtm install-all failed — check Go version (needs 1.21+)."

# --- AI pentest orchestration / agent frameworks -----------------------
# HexStrike AI — MCP server exposing 150+ security tools to AI agents.
if [ ! -d /home/kali/tools/hexstrike-ai ]; then
  echo "Installing HexStrike AI..."
  git clone https://github.com/0x4m4/hexstrike-ai /home/kali/tools/hexstrike-ai
  python3 -m venv /home/kali/tools/hexstrike-ai/hexstrike-env
  /home/kali/tools/hexstrike-ai/hexstrike-env/bin/pip install -r /home/kali/tools/hexstrike-ai/requirements.txt
else
  echo "HexStrike AI already exists."
fi

# CAI (Cybersecurity AI) — AI agent framework for offensive/defensive testing.
pipx install cai-framework

# Shannon — AI-driven web/app pentest framework (run: npx @keygraph/shannon).
npm install -g @keygraph/shannon

# --- GenAI / LLM red-team & vulnerability tooling ----------------------
# garak — NVIDIA LLM vuln scanner (prompt injection, jailbreak, data leak).
pipx install garak
# PyRIT — Microsoft Python Risk Identification Tool for generative AI.
pipx install pyrit
# Vulnhuntr — LLM-driven remotely-exploitable vuln discovery (requires py3.10).
pipx install git+https://github.com/protectai/vulnhuntr.git --python python3.10 \
  || echo "Vulnhuntr needs python3.10 on PATH — install it then re-run."
# promptfoo — LLM eval & red-teaming harness (npm).
npm install -g promptfoo

# --- Personal AI security tooling (byoniq — private, needs gh auth) ----
# Uncomment after `gh auth switch --user byoniq`:
# git clone https://github.com/byoniq/exhume.git /home/kali/tools/exhume   # passive CVE/exploit discovery
# git clone https://github.com/byoniq/ceasar.git /home/kali/tools/ceasar   # GHDB foothold scanner

# Update the database
echo "Updating the file database..."
updatedb

echo "Installation complete. Check $LOGFILE for details."
