#!/usr/bin/env bash
# Download the OSV vulnerability database for offline scanning.
#
# This is the ONLY moment the platform touches the OSV endpoint, and it runs on
# whatever connected host the operator chooses — never inside a request, never
# from the worker. Copy the resulting directory to the deployment
# (`$DIOPTRA_DATA_DIR/osv`, which the worker sees as DIOPTRA_OSV_DB_DIR) and
# every analysis reads it locally.
# Re-run to refresh; the report shows the tool as a coverage gap when the
# directory is absent. Contingency "no internet" in docs/development-phases.md:
# copy the directory from a machine that has it.
#
#   scripts/osv_db_download.sh /var/lib/dioptra/osv [Ecosystem ...]
#
# Layout produced is the one osv-scanner 2.x reads through
# OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=<dir>, mounted read-only:
#   <dir>/osv-scanner/<Ecosystem>/all.zip

set -euo pipefail

DIR="${1:?usage: $0 <target-dir> [Ecosystem ...]}"
shift || true
ECOSYSTEMS=("$@")
if [ "${#ECOSYSTEMS[@]}" -eq 0 ]; then
  # Wave 1 + wave 2 languages of the plan.
  ECOSYSTEMS=(npm PyPI Packagist Maven Go)
fi

BASE="https://osv-vulnerabilities.storage.googleapis.com"
mkdir -p "$DIR"
for eco in "${ECOSYSTEMS[@]}"; do
  mkdir -p "$DIR/osv-scanner/$eco"
  echo "downloading $eco ..."
  curl -fsSL --proto '=https' --tlsv1.2 -o "$DIR/osv-scanner/$eco/all.zip.part" "$BASE/$eco/all.zip"
  mv "$DIR/osv-scanner/$eco/all.zip.part" "$DIR/osv-scanner/$eco/all.zip"
done
date -u +%Y-%m-%dT%H:%M:%SZ > "$DIR/LAST_SYNC"
echo "done: $(cat "$DIR/LAST_SYNC") — $(du -sh "$DIR" | cut -f1) in $DIR"
