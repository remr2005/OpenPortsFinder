"""Main file"""

from asyncio import run

from scans import null


def main():
    """Main function"""
    print(run(null("192.168.0.106", "135")))


if __name__ == "__main__":
    main()
