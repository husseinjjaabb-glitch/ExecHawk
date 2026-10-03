#!/bin/bash
set -e
TARGET=${1:-"http://localhost:8080"}

echo "🦅 Exec Hawk — Quick Start"
echo "══════════════════════════════════"

# Build
echo "[1/3] Building..."
mkdir -p build && cd build
cmake .. > /dev/null 2>&1
make -j$(nproc) > /dev/null 2>&1
echo "    ✓ Engine built"
cd ..

# Engine
echo "[2/3] Starting engine..."
./build/exec_hawk "$TARGET" &
echo "    ✓ Running against $TARGET"

# API
echo "[3/3] Starting API..."
cd ui && python3 dashboard.py &
echo "    ✓ API on :8443"

echo ""
echo "🦅 Exec Hawk LIVE"
echo "   API: http://localhost:8443"
echo "══════════════════════════════════"
wait