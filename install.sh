#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}
▄▄▄█████▓▓█████  ▄████▄   ██░ ██  ▄▄▄       ▄████▄   ██ ▄█▀▒███████▒
▓  ██▒ ▓▒▓█   ▀ ▒██▀ ▀█  ▓██░ ██▒▒████▄    ▒██▀ ▀█   ██▄█▒ ▒ ▒ ▒ ▄▀░
▒ ▓██░ ▒░▒███   ▒▓█    ▄ ▒██▀▀██░▒██  ▀█▄  ▒▓█    ▄ ▓███▄░ ░ ▒ ▄▀▒░ 
░ ▓██▓ ░ ▒▓█  ▄ ▒▓▓▄ ▄██▒░▓█ ░██ ░██▄▄▄▄██ ▒▓▓▄ ▄██▒▓██ █▄   ▄▀▒   ░
  ▒██▒ ░ ░▒████▒▒ ▓███▀ ░░▓█▒░██▓ ▓█   ▓██▒▒ ▓███▀ ░▒██▒ █▄▒███████▒
${NC}"

echo -e "${YELLOW}Starting TechackZ installation...${NC}\n"

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Python 3 is not installed. Please install Python 3 first.${NC}"
    exit 1
fi

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    echo -e "${RED}pip3 is not installed. Please install pip3 first.${NC}"
    exit 1
fi

# Check if Go is installed (required for Nuclei)
if ! command -v go &> /dev/null; then
    echo -e "${RED}Go is not installed. Please install Go first.${NC}"
    exit 1
fi

# Create virtual environment
echo -e "${YELLOW}Creating virtual environment...${NC}"
python3 -m venv venv

# Activate virtual environment
echo -e "${YELLOW}Activating virtual environment...${NC}"
source venv/bin/activate

# Install Python dependencies
echo -e "${YELLOW}Installing Python dependencies...${NC}"
pip3 install -r requirements.txt

# Install Nuclei
echo -e "${YELLOW}Installing Nuclei...${NC}"
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Update Nuclei templates
echo -e "${YELLOW}Updating Nuclei templates...${NC}"
nuclei -update-templates

# Create necessary directories
echo -e "${YELLOW}Creating necessary directories...${NC}"
mkdir -p output
mkdir -p logs

# Set permissions
echo -e "${YELLOW}Setting permissions...${NC}"
chmod +x pentest_tech.py

echo -e "${GREEN}Installation completed successfully!${NC}"
echo -e "${YELLOW}To start using TechackZ:${NC}"
echo -e "1. Activate the virtual environment: ${GREEN}source venv/bin/activate${NC}"
echo -e "2. Run the tool: ${GREEN}python3 techackz.py -u <target_url>${NC}"
