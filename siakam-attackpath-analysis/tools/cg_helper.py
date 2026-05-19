#!/usr/bin/env python3
"""cg_helper.py - Query callgraph.json for caller/callee relationships.

Usage:
    python3 cg_helper.py <FUNC> caller   # List all functions that call FUNC
    python3 cg_helper.py <FUNC> callee   # List all functions called by FUNC

Reads callgraph.json from the current working directory.
Outputs JSON array of matching edges to stdout.
"""

import json
import sys
import os


def load_callgraph(path="callgraph.json"):
    if not os.path.exists(path):
        print(json.dumps({"error": f"callgraph.json not found at {path}"}))
        sys.exit(1)
    with open(path, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError as e:
            print(json.dumps({"error": f"Malformed callgraph.json: {e}"}))
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
    if len(sys.argv) != 3:
        print(json.dumps({"error": "Usage: cg_helper.py <FUNC> caller|callee"}))
        sys.exit(1)

    func_name = sys.argv[1]
    mode = sys.argv[2]

    if mode not in ("caller", "callee"):
        print(json.dumps({"error": f"Invalid mode '{mode}'. Use 'caller' or 'callee'."}))
        sys.exit(1)

    cg = load_callgraph()

    if mode == "caller":
        results = query_caller(cg, func_name)
    else:
        results = query_callee(cg, func_name)

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
