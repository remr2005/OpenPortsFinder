"""Main file"""

from asyncio import run

from scans import fin


def main():
    """Main function"""
    print(run(fin("192.168.0.106", "135")))


if __name__ == "__main__":
    main()
