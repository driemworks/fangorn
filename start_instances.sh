#!/bin/bash

# Cleanup function to be called on exit
cleanup() {
    echo ""
    echo "Ctrl+C received, cleaning up..."
    if [ -f "ticket.txt" ]; then
        rm "ticket.txt"
        echo "ticket.txt deleted"
    fi
    if [ -f "pubkey.txt" ]; then
        rm "pubkey.txt"
        echo "pubkey.txt deleted"
    fi
    exit 0
}

# Set trap to catch Ctrl+C (SIGINT) and call cleanup
trap cleanup SIGINT

# Check if ticket.txt exists and delete it
if [ -f "ticket.txt" ]; then
    echo "Found existing ticket.txt, deleting..."
    rm "ticket.txt"
fi
# Check if pubkey.txt exists and delete it
if [ -f "pubkey.txt" ]; then
    echo "Found existing pubkey.txt, deleting..."
    rm "pubkey.txt"
fi

# Start the first instance
echo "Starting first instance: ./target/debug/fangorn run --bind-port 9944 --rpc-port 30333 --is-bootstrap --index 0"
./target/debug/fangorn run --bind-port 9944 --rpc-port 30333 --is-bootstrap --index 0 &
FIRST_PID=$!
echo "PID of instance: $FIRST_PID"
# Wait for ticket.txt to appear
# Note: there is no need to sleep for 2 seconds. It works (quicker) with sleep 0.5 as well.
echo "Waiting for ticket.txt..."
while [ ! -f "ticket.txt" ]; do
    sleep 2
done

echo "Waiting for pubkey.txt..."
while [ ! -f "pubkey.txt" ]; do
    sleep 2
done

TICKET_CONTENT=$(cat ticket.txt)
PUBKEY=$(cat pubkey.txt)
echo "ticket.txt and pubukey.txt found!"

echo "Starting second instance: /target/debug/fangorn run --bind-port 9945 --rpc-port 30334 --bootstrap-pubkey $PUBKEY --bootstrap-ip 172.31.149.62:9944 --ticket $TICKET_CONTENT --index 1"
# Start the second instance
./target/debug/fangorn run --bind-port 9945 --rpc-port 30334 --bootstrap-pubkey $PUBKEY --bootstrap-ip 172.31.149.62:9944 --ticket $TICKET_CONTENT --index 1 &
SECOND_PID=$!
echo "PID of second instance: $SECOND_PID"

echo "Both instances running. Press Ctrl+C to stop."

# Wait indefinitely (servers run in background)
wait