import os
import sys


def create_repo():
    """
    Create an empty .git directory, and the bare minimum subdirectories required for git to function.
    """
    os.mkdir(".git")
    os.mkdir(".git/objects")
    os.mkdir(".git/refs")
    with open(".git/HEAD", "w") as f:
        f.write("ref: refs/heads/master\n")
    print(f"Initialized empty Git repository.")


def main():
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    # print("Logs from your program will appear here!")
    command = sys.argv[1]
    match command:
        case "init":
            create_repo()
        case _:
            raise RuntimeError(f"Unknown command #{command}")


if __name__ == "__main__":
    main()
