"""
SolarShield — launch the API + dashboard.

Usage:
    python run.py            # production (single worker)
    python run.py --reload   # development with auto-reload
    python run.py --port 8080
"""

import argparse
import sys

import uvicorn


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the SolarShield API server")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Bind port (default: 8000)")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload for development")
    args = parser.parse_args()

    print(f"Starting SolarShield at http://{args.host}:{args.port}")
    uvicorn.run(
        "src.api.server:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
    )


if __name__ == "__main__":
    main()
