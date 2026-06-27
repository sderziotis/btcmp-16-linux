#!/usr/bin/env bash
# ===========================================================================
#  DF-14 — generate timeline.plaso from the host artifact tree
#
#  Run this ONCE during instructor prep, on a box with Docker (e.g. uavm).
#  It uses the official log2timeline/plaso image so the resulting .plaso is
#  version-compatible with the Plaso bundled in the Timesketch worker — which
#  is what actually re-runs psort on upload. Building the .plaso with a random
#  locally-installed Plaso version is the usual cause of "Format not supported"
#  import failures, so prefer this.
#
#  Usage:
#     ./build_df14_artifacts.sh ./root_fs      # 1) lay down the tree
#     ./generate_plaso.sh                       # 2) -> ./timeline.plaso
#
#  Then stage ./timeline.plaso + ./external-events.jsonl into
#  files/df14/ in your Ansible repo (the playbook copies them to
#  /home/user/df14/ on uavm).
# ===========================================================================
set -euo pipefail
TREE="${1:-./root_fs}"
OUT="${2:-./timeline.plaso}"
IMAGE="log2timeline/plaso:latest"

if [ ! -d "$TREE" ]; then
  echo "ERROR: artifact tree '$TREE' not found. Run build_df14_artifacts.sh first." >&2
  exit 1
fi
rm -f "$OUT"

# IMPORTANT: do NOT pass --timezone. The host logs are EST wall-clock stored
# as UTC on purpose; default UTC parsing keeps them in the 02:xx band so the
# +5h gap against the UTC VPN feed remains the trainee's normalization task.
# (Year for syslog lines is inferred from auth.log's mtime, set to 2025 by the
#  builder.)
docker run --rm -v "$(pwd)":/data "$IMAGE" \
  log2timeline \
    --status_view none \
    --partitions all \
    --storage-file "/data/$(basename "$OUT")" \
    "/data/$TREE"

echo
echo "Created: $OUT"
echo "Quick check:"
docker run --rm -v "$(pwd)":/data "$IMAGE" \
  pinfo --output-format text "/data/$(basename "$OUT")" 2>/dev/null | sed -n '1,25p' || true
echo
echo "Next: copy $OUT and external-events.jsonl into files/df14/ of your repo."
