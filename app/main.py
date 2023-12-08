import hashlib
import os
import sys
import zlib


def object_path(sha: str, mkdir: bool = False):
    """
    Given the SHA-1 hash of an object, returns the corresponding path in .git/objects/
    If mkdir is true, all the parent directories are created.
    """
    file_path = f".git/objects/{sha[:2]}/{sha[2:]}"
    parent_path = f".git/objects/{sha[:2]}"

    if mkdir and not os.path.exists(parent_path):
        os.makedirs(parent_path)
    elif not os.path.exists(file_path):
        sys.exit(f"fatal: Not a valid object name {sha}")

    return file_path


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
    full_path = object_path(blob_sha)
    with open(full_path, "rb") as blob:
        data = zlib.decompress(blob.read())
        text = data.decode(encoding="utf-8")
        return text


def create_blob(content: bytes) -> str:
    """
    Creates a blob object from the given bytes content, writes it to the object
    path based on SHA-1 hash and returns the SHA-1 hash.
    """
    object_type = "blob"
    headers = object_type.encode() + b" " + str(len(content)).encode() + b"\x00"
    data = headers + content
    sha = hashlib.sha1(data).hexdigest()

    full_path = object_path(sha, mkdir=True)
    with open(full_path, "wb") as fhand:
        fhand.write(zlib.compress(data))

    return sha


def cat_file(option: str, sha: str):
    """
    Examines the contents of any given git object, based on its SHA-1 hash, and
    the options passed through CLI.
    """
    if option == "-p":
        _, content = read_blob(sha).split("\x00")
        print(content, end="")


def hash_object(option: str, path: str):
    """
    Creates a binary blob from the given data, writes it out to disk, and
    prints the SHA-1 hash.
    """
    if option == "-w":
        with open(path, "rb") as f:
            content = f.read()
            print(content)
            sha = create_blob(content)
            print(sha)


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
        case "hash-object":
            assert len(sys.argv) >= 3, "fatal: wrong number of arguments, should be > 3"
            hash_object(option=sys.argv[2], path=sys.argv[3])
        case _:
            raise RuntimeError(f"Unknown command #{command}")


if __name__ == "__main__":
    main()
