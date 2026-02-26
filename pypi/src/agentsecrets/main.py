import os
import sys
import subprocess
from .binary import ensure_binary

def main():
    """
    Main entry point for the agentsecrets CLI wrapper.
    Ensures the Go binary is present and invokes it with all arguments.
    """
    try:
        binary_path = ensure_binary()
        
        # Invoke the binary with the same arguments as the python script
        result = subprocess.run([binary_path] + sys.argv[1:])
        
        # Exit with the same return code as the binary
        sys.exit(result.returncode)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
