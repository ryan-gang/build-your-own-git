import os
import sys
import zlib


def create_repo():
    """
    Creates an empty .git directory, and the bare minimum subdirectories
    required for git to function.
    """
    os.mkdir(".git")
    os.mkdir(".git/objects")
    os.mkdir(".git/refs")
    with open(".git/HEAD", "w") as f:
        f.write("ref: refs/heads/master\n")
    print(f"Initialized empty Git repository.")


def read_blob(blob_sha: str) -> str:
    """
    Retrieves the contents of a git blob object given its SHA-1 hash.
    Decompresses it, decodes it and returns an utf-8 encoded string.
    """
    dir, file = blob_sha[:2], blob_sha[2:]
    full_path = f".git/objects/{dir}/{file}"
    with open(full_path, "rb") as blob:
        data = zlib.decompress(blob.read())
        text = data.decode(encoding="utf-8")
        return text


def cat_file(option: str, sha: str):
    """
    Examines the contents of any given git object, based on its SHA-1 hash, and
    the options passed through CLI. 
    """
    if option == "-p":
        meta_info, content = read_blob(sha).split("\x00")
        print(content, end="")


def main():
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    # print("Logs from your program will appear here!")
    command = sys.argv[1]
    match command:
        case "init":
            create_repo()
        case "cat-file":
            assert len(sys.argv) == 4, "fatal: wrong number of arguments, should be 4"
            cat_file(option=sys.argv[2], sha=sys.argv[3])
        case _:
            raise RuntimeError(f"Unknown command #{command}")


if __name__ == "__main__":
    main()
