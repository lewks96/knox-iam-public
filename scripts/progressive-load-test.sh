#!/bin/bash
# Run a progressive load test to find sustainable capacity

set -e

echo "==========================================="
echo "Knox IAM Progressive Load Test"
echo "==========================================="
echo ""

# Check if k6 is already running
if pgrep -f "k6" > /dev/null; then
    echo "❌ ERROR: k6 is already running!"
    echo "   Stop it first: pkill k6"
    exit 1
fi

# Check if pods are healthy
readyPods=$(kubectl get pods -n knox -l app=knox-server -o jsonpath='{.items[*].status.conditions[?(@.type=="Ready")].status}' | grep -c "True" || echo "0")
totalPods=$(kubectl get pods -n knox -l app=knox-server --no-headers | wc -l | tr -d ' ')

if [ "$readyPods" -lte 2 ]; then
    echo "❌ ERROR: Not enough ready pods ($readyPods/$totalPods)"
    echo "   Wait for pods to be healthy first"
    kubectl get pods -n knox -l app=knox-server
    exit 1
fi

echo "✅ $readyPods/$totalPods pods ready"
echo ""

# Function to run a load test stage
run_test() {
    local vus=$1
    local duration=$2
    local description=$3

    echo "=========================================="
    echo "Test: $description"
    echo "VUs: $vus, Duration: $duration"
    echo "=========================================="
    echo ""

    # Run k6 with the specified load
    k6 run \
        -e SLEEP_BETWEEN_STEPS=0 \
        --stage "30s:$vus,${duration}:$vus,30s:0" \
        k6/load_test.js

    local exit_code=$?

    if [ $exit_code -ne 0 ]; then
        echo ""
        echo "❌ Test failed with exit code $exit_code"
        echo ""
        echo "Checking for pod issues..."
        kubectl get pods -n knox -l app=knox-server
        echo ""
        return 1
    fi

    echo ""
    echo "✅ Test passed!"
    echo ""

    # Cool down period
    echo "Cooling down for 10 seconds..."
    sleep 10

    # Check for any pod issues
    crashingPods=$(kubectl get pods -n knox -l app=knox-server -o jsonpath='{.items[?(@.status.containerStatuses[0].restartCount>0)].metadata.name}' | wc -w | tr -d ' ')
    if [ "$crashingPods" -gt 0 ]; then
        echo "⚠️  WARNING: $crashingPods pod(s) have restarted"
        kubectl get pods -n knox -l app=knox-server
        return 1
    fi

    return 0
}

# Progressive test stages
echo "Starting progressive load tests..."
echo ""
echo "This will run multiple tests with increasing load"
echo "to find the sustainable capacity of the system."
echo ""

# Stage 1: Light load
if ! run_test 5 "2m" "Stage 1: Light Load (5 VUs)"; then
    echo "Failed at Stage 1 - system cannot handle even light load"
    exit 1
fi

# Stage 2: Moderate load
if ! run_test 10 "2m" "Stage 2: Moderate Load (10 VUs)"; then
    echo "Failed at Stage 2 - sustainable capacity is < 10 VUs"
    exit 1
fi

# Stage 3: Medium load
if ! run_test 20 "2m" "Stage 3: Medium Load (20 VUs)"; then
    echo "Failed at Stage 3 - sustainable capacity is between 10-20 VUs"
    exit 1
fi

# Stage 4: Heavy load
if ! run_test 30 "2m" "Stage 4: Heavy Load (30 VUs)"; then
    echo "Failed at Stage 4 - sustainable capacity is between 20-30 VUs"
    exit 1
fi

# Stage 5: Very heavy load
if ! run_test 50 "2m" "Stage 5: Very Heavy Load (50 VUs)"; then
    echo "Failed at Stage 5 - sustainable capacity is between 30-50 VUs"
    exit 1
fi

echo ""
echo "==========================================="
echo "✅ ALL TESTS PASSED!"
echo "==========================================="
echo ""
echo "The system can handle at least 50 concurrent VUs"
echo "sustainably without pod failures."
echo ""
echo "Consider this the baseline capacity."
echo "To test higher loads, increase gradually:"
echo "  - 75 VUs"
echo "  - 100 VUs"
echo "  - etc."
echo ""

