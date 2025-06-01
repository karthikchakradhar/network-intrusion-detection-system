from core.packet_sniffer import IDSSniffer
import argparse
import signal
import sys

def signal_handler(sig, frame):
    print("\nIDS shutdown requested")
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(
        description="Advanced Network Intrusion Detection System",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('-i', '--interface', required=True,
                      help="Network interface to monitor")
    parser.add_argument('-v', '--verbose', action='store_true',
                      help="Enable verbose output")
    
    args = parser.parse_args()
    
    # Handle Ctrl+C gracefully
    signal.signal(signal.SIGINT, signal_handler)
    
    print(f"[*] Starting IDS on interface {args.interface}")
    print("[*] Press Ctrl+C to stop monitoring\n")
    
    try:
        ids = IDSSniffer(args.interface)
        ids.start_sniffing()
    except Exception as e:
        print(f"[!] Fatal error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()