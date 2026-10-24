#!/bin/bash
# Double-click launcher for the Mac: update from GitHub, then start the dashboard.
# The Desktop netScan.command just runs this file, so improvements to it arrive with every update too.
# Set NETSCAN_BRANCH to follow a different branch (default: main).
cd "$(dirname "$0")/.." || exit 1
BRANCH="${NETSCAN_BRANCH:-main}"

if [ ! -x .venv/bin/netscan ]; then
  echo "No virtualenv found in $(pwd). Run:  python3 -m venv .venv && .venv/bin/pip install ."
  read -r -p "Press Enter to close."
  exit 1
fi

echo "Checking GitHub for a newer netScan..."
if git fetch --quiet origin 2>/dev/null; then
  current="$(git rev-parse --abbrev-ref HEAD)"
  if [ "$current" != "$BRANCH" ]; then
    if [ -z "$(git status --porcelain --untracked-files=no)" ]; then
      echo "Switching from $current to $BRANCH"
      git checkout --quiet "$BRANCH" || echo "Could not switch to $BRANCH; staying on $current."
    else
      echo "You have uncommitted changes on $current, so staying on it."
    fi
  fi
  .venv/bin/netscan update || echo "Update skipped; starting the version you have."
else
  echo "Cannot reach GitHub; starting the version you have."
fi

echo
echo "Starting the netScan dashboard. Enter your Mac password for network access."
sudo -E .venv/bin/netscan web --open
status=$?
echo
read -r -p "netScan stopped (exit $status). Press Enter to close."
