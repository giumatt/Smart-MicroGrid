#!/bin/bash
# Unban a device banned by the Trust Engine.
# Can be run on the host or inside the Docker container.

echo "============================================================"
echo "   Smart MicroGrid - Device Recovery Tool"
echo "============================================================"
echo ""

# Detect whether we are inside a container or on the host
if [ -f /.dockerenv ] || [ -n "$DOCKER_CONTAINER" ]; then
    echo "Running inside Docker"
    python3 /app/src/scripts/unban_device.py
else
    # On the host: run the script through docker exec
    echo "💻 Running on the local host"
    echo ""
    
    # Find the trust engine (or provisioner) container
    CONTAINER=$(docker ps --filter "name=trust" --format "{{.Names}}" | head -n1)
    
    if [ -z "$CONTAINER" ]; then
        CONTAINER=$(docker ps --filter "name=provision" --format "{{.Names}}" | head -n1)
    fi
    
    if [ -z "$CONTAINER" ]; then
        echo "No running trust_engine or provisioner container found"
        echo "   Start the containers with: cd gateway && docker-compose up -d"
        exit 1
    fi
    
    echo "Using container: $CONTAINER"
    echo ""
    
    # Check that the script exists in the container
    docker exec "$CONTAINER" test -f /app/src/scripts/unban_device.py
    if [ $? -ne 0 ]; then
        echo "Script not found in the container"
        echo "   Make sure the src/scripts/ directory is mounted"
        exit 1
    fi
    
    # Run the script in the container
    docker exec -it "$CONTAINER" python3 /app/src/scripts/unban_device.py
fi