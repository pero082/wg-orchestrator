#!/bin/bash
# docs/STRESS_TEST.md companion script
# tests/stress/api_load.sh

echo "Starting Stress Test against API..."
# Requires 'vegeta' or similar. Using curl loop for basic stress if not present.

URL="http://127.0.0.1:8080/health/live"

start_time=$(date +%s)
requests=0
errors=0

for i in {1..1000}; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "$URL")
    if [[ "$code" != "200" ]]; then
        errors=$((errors+1))
        echo -n "X"
    else
        requests=$((requests+1))
    fi
done

end_time=$(date +%s)
duration=$((end_time - start_time))

echo ""
echo "--------------------------------"
echo "Results:"
echo "Duration: ${duration}s"
echo "Requests: $requests"
echo "Errors:   $errors"
echo "RPS:      $((requests / duration))"
echo "--------------------------------"
