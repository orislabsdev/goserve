#!/bin/bash

# Colors for better visibility
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}Starting Go Serve Services...${NC}"

# Function to handle cleanup on exit
cleanup() {
    echo -e "\n${BLUE}Stopping Go Serve services...${NC}"
    # Kill all background jobs
    kill $(jobs -p) 2>/dev/null
    exit
}

# Trap Ctrl+C (SIGINT) and SIGTERM
trap cleanup SIGINT SIGTERM

# Start Backend
echo -e "${GREEN}Starting Go Serve...${NC}"
cd .. && ./build/goserve --config ./config/server.env &
