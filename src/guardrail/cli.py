import argparse


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="guardrail",
        description="Detect drift and policy violations in AWS infrastructure.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser(
        "scan",
        help="Scan infrastructure for drift and policy violations.",
    )

    args = parser.parse_args()

    if args.command == "scan":
        print("GuardRail scan: not implemented yet.")


if __name__ == "__main__":
    main()
