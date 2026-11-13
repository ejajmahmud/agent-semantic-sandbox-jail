"""CLI for agent-semantic-sandbox-jail."""
import sys
import argparse
from .jail import SemanticSandboxJail

def main():
    parser = argparse.ArgumentParser(description="Agent Semantic Sandbox Jail CLI")
    parser.add_argument("--demo", action="store_true", help="Run AST sandbox safety evaluation demo")
    args = parser.parse_args()

    if args.demo:
        jail = SemanticSandboxJail()
        res1 = jail.execute("result = sum([x * 2 for x in range(10)])")
        print(f"[+] Safe calculation output: {res1.output}")
        res2 = jail.execute("import os; os.system('ls')")
        print(f"[!] Malicious import rejected: {res2.error}")
    else:
        parser.print_help()
    sys.exit(0)

if __name__ == "__main__":
    main()
