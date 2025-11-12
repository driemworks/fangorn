#!/bin/bash

# Create a unique signal file
SIGNAL_FILE="/tmp/fangorn_signal_$$"

# the ink! smart contract address
CONTRACT_ADDR="5Ccuf8QBBoqZtUPFTxwixMd9mfHLUmXhRvNfBdEU7uL1ApR7"

# Cleanup function to be called on exit
cleanup() {
    echo ""
    echo "Ctrl+C received, cleaning up..."
    
    # Kill first instance if it's running
    if [ ! -z "$FIRST_PID" ] && kill -0 "$FIRST_PID" 2>/dev/null; then
        echo "Stopping first server (PID: $FIRST_PID)..."
        kill "$FIRST_PID"
    fi
    
    # Signal second terminal to close (it will kill its own process and exit)
    if [ -f "$SIGNAL_FILE.second_pid" ]; then
        SECOND_PID=$(cat "$SIGNAL_FILE.second_pid")
        if [ ! -z "$SECOND_PID" ] && kill -0 "$SECOND_PID" 2>/dev/null; then
            echo "Stopping second server and closing second terminal..."
            kill "$SECOND_PID"
        fi
    fi
    
    if [ -f "ticket.txt" ]; then
        rm "ticket.txt"
        echo "ticket.txt deleted"
    fi
    if [ -f "pubkey.txt" ]; then
        rm "pubkey.txt"
        echo "pubkey.txt deleted"
    fi
    if [ -f "$SIGNAL_FILE" ]; then
        rm "$SIGNAL_FILE"
    fi
    if [ -f "$SIGNAL_FILE.second_pid" ]; then
        rm "$SIGNAL_FILE.second_pid"
    fi
    echo "Removing files from docs store"
    find ./tmp/docs -mindepth 1 -delete 2>/dev/null
    echo "Removing files from intents store"
    find ./tmp/intents -mindepth 1 -delete 2>/dev/null
    echo "Removing files from plaintext store"
    find ./tmp/plaintexts -mindepth 1 -delete 2>/dev/null
    echo "Killing substrate contracts node"
    kill "$SCN_PID"
    
    # Don't exit - just return to shell
    echo "Cleanup complete."
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

# Clean up old signal files if they exist
if [ -f "$SIGNAL_FILE" ]; then
    rm "$SIGNAL_FILE"
fi
if [ -f "$SIGNAL_FILE.second_pid" ]; then
    rm "$SIGNAL_FILE.second_pid"
fi

# Start substrate-contracts node
echo "Starting substrate-contracts-node"
substrate-contracts-node --tmp --dev &
SCN_PID=$!
echo "PID of contracts node $SCN_PID"

# wait for the node to be ready
# --- Wait for the Node to be Ready (Health Check) ---
echo "Waiting for the contracts node to be ready on 9944."

# wait until the rpc port is reachable
wait_for_rpc() {
    local max_time=30
    local interval=3
    local elapsed=0
    local host="localhost"
    local port="9944"
    local pid_to_check=$SCN_PID

    # Use netcat to poll the endpoint
    while ! nc -z -w 1 "$host" "$port" 2>/dev/null; do
        # 1. Check for PID death
        if ! kill -0 "$pid_to_check" 2>/dev/null; then
             echo ""
             echo "❌ ERROR: substrate-contracts-node (PID $pid_to_check) died unexpectedly."
             return 1
        fi
        
        # 2. Check for timeout
        if [ "$elapsed" -ge "$max_time" ]; then
            echo ""
            echo "ERROR: Timed out waiting for RPC endpoint to be ready."
            # Kill the background process if it timed out but is still running
            kill "$pid_to_check" 2>/dev/null
            return 1
        fi
        
        printf "."
        sleep "$interval"
        elapsed=$((elapsed + interval))
    done
    echo ""
    echo "Contracts node is ready."
    return 0
}

if ! wait_for_rpc; then
    echo "Aborting script due to node failure."
    exit 1
fi

# deploy the contract
# NOTE: If we modify the contract, then we need to manually update the contract address
# but normally, it will produce a deterministic contract address 
cargo contract instantiate ./target/ink/iris/iris.contract --suri //Alice -x -y

# Start the first instance in the background of current terminal
echo "Starting first instance: ./target/debug/fangorn run --bind-port 9933 --rpc-port 30332 --is-bootstrap --index 0 --contract-addr "$CONTRACT_ADDR""
./target/debug/fangorn run --bind-port 9933 --rpc-port 30332 --is-bootstrap --index 0 --contract-addr "$CONTRACT_ADDR" &
FIRST_PID=$!
echo "PID of first instance: $FIRST_PID"

# Wait for ticket.txt to appear
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
echo "ticket.txt and pubkey.txt found!"
echo "Starting second instance in new terminal..."

# Pass the main script's PID and signal file to the second terminal
MAIN_PID=$$
gnome-terminal -- bash -c "
SECOND_SERVER_PID=\"\"

cleanup_second() {
    echo \"\"
    echo \"Second terminal: Ctrl+C received, cleaning up...\"
    if [ ! -z \"\$SECOND_SERVER_PID\" ] && kill -0 \"\$SECOND_SERVER_PID\" 2>/dev/null; then
        echo \"Stopping second server...\"
        kill \"\$SECOND_SERVER_PID\"
    fi
    echo \"Signaling main script...\"
    echo \"stop\" > \"$SIGNAL_FILE\"
    echo \"Closing terminal...\"
    exit 0
}

trap cleanup_second SIGINT

echo 'Starting second instance: ./target/debug/fangorn run --bind-port 9945 --rpc-port 30334 --bootstrap-pubkey $PUBKEY --bootstrap-ip 172.31.149.62:9933 --ticket $TICKET_CONTENT --index 1 --contract-addr "$CONTRACT_ADDR"'
./target/debug/fangorn run --bind-port 9945 --rpc-port 30334 --bootstrap-pubkey $PUBKEY --bootstrap-ip 172.31.149.62:9933 --ticket $TICKET_CONTENT --index 1 --contract-addr "$CONTRACT_ADDR" &
SECOND_SERVER_PID=\$!
echo \"PID: \$SECOND_SERVER_PID\"
echo \"\$SECOND_SERVER_PID\" > \"$SIGNAL_FILE.second_pid\"
echo 'Press Ctrl+C here to stop both instances'

wait \$SECOND_SERVER_PID
" &

# Monitor for signal file in the background
(
    while true; do
        if [ -f "$SIGNAL_FILE" ]; then
            echo "Received stop signal from second terminal"
            # Call cleanup but don't exit the main shell
            cleanup
            break
        fi
        sleep 0.5
    done
) &
MONITOR_PID=$!

echo "Both instances running. Press Ctrl+C in either window to stop both."

# Wait for the first process
wait $FIRST_PID

echo "First instance stopped. Cleaning up remaining processes..."
cleanup