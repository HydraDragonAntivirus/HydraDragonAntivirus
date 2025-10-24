#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Entry point for HydraDragon Antivirus.
This wrapper handles running the async main function.
"""

import sys
import asyncio
import traceback


def main():
    """Synchronous entry point wrapper that runs the async main."""
    try:
        from hydradragon.engine import main as async_main
        
        # Run the async main function
        exit_code = asyncio.run(async_main())
        return exit_code if exit_code is not None else 0

    except Exception:
        print("Fatal error:", file=sys.stderr)
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
