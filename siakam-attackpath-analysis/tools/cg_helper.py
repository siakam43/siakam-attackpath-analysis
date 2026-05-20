#!/usr/bin/env python3
"""cg_helper.py - Query callgraph.json for caller/callee relationships.

Usage:
    python3 cg_helper.py <FUNC> caller --callgraph-path <path>
    python3 cg_helper.py <FUNC> callee --callgraph-path <path>

Outputs JSON array of matching edges to stdout.
"""

import argparse
import json
import sys
from pathlib import Path


def load_callgraph(path):
    if not path.exists():
        print(json.dumps({"error": f"callgraph.json not found at {path}"}), file=sys.stderr)
        sys.exit(1)
    with open(path, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError as e:
            print(json.dumps({"error": f"Malformed callgraph.json: {e}"}), file=sys.stderr)
            sys.exit(1)


def query_caller(cg, func_name):
    results = []
    for edge in cg.get("edges", []):
        if edge.get("callee") == func_name:
            results.append(edge)
    return results


def query_callee(cg, func_name):
    results = []
    for edge in cg.get("edges", []):
        if edge.get("caller") == func_name:
            results.append(edge)
    return results


def main():
    parser = argparse.ArgumentParser(
        description="Query callgraph.json for caller/callee relationships."
    )
    parser.add_argument("func", help="Function name to query")
    parser.add_argument("mode", choices=("caller", "callee"),
                        help="Query mode: caller (who calls FUNC) or callee (who FUNC calls)")
    parser.add_argument("--callgraph-path", required=True, type=Path,
                        help="Path to callgraph.json (required)")
    args = parser.parse_args()

    cg = load_callgraph(args.callgraph_path)

    if args.mode == "caller":
        results = query_caller(cg, args.func)
    else:
        results = query_callee(cg, args.func)

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
