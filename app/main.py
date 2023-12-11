import binascii
import datetime
import hashlib
import os
import sys
import zlib

AUTHOR_NAME = "ryan"
AUTHOR_EMAIL = "ryan-gg@outlook.com"
COMMITER_NAME = AUTHOR_NAME
COMMITER_EMAIL = AUTHOR_EMAIL


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


def read_object(blob_sha: str) -> bytes:
    """
    Retrieves the contents of a git blob object given its SHA-1 hash.
    Decompresses it, decodes it and returns an utf-8 encoded string.
    """
    full_path = object_path(blob_sha)
    with open(full_path, "rb") as blob:
        data = zlib.decompress(blob.read())

    return data


def hash_content(content: bytes, write: bool = False, object_type: str = "blob") -> str:
    """
    Creates a object from the given bytes content, writes it to the object
    path based on SHA-1 hash and returns the SHA-1 hash.
    """
    assert content, "No content received for hashing."
    headers = object_type.encode() + b" " + str(len(content)).encode() + b"\x00"
    data = headers + content
    sha = hashlib.sha1(data).hexdigest()

    if write:
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
        data = read_object(sha)
        text = data.decode(encoding="utf-8")
        _, content = text.split("\x00")
        # metadata and contents are seperated by the null byte.
        print(content, end="")


def hash_object(option: str, path: str) -> str:
    """
    Creates a binary blob from the given data, writes it out to disk, and
    returns the SHA-1 hash.
    """
    write_flag = False
    if option == "-w":
        write_flag = True
    with open(path, "rb") as f:
        content = f.read()
        sha = hash_content(content, write=write_flag)
    return sha


def ls_tree(option: str, sha: str) -> str:
    """
    Reads tree object with given SHA-1, and returns list of (mode, path, sha1) tuples.
    Or a list of paths if --name-only option is passed.
    """
    data, start = read_object(sha), 0
    metadata, _, content = data.partition(b"\x00")
    object_type, length = metadata.decode().split()
    assert object_type == "tree", "Object is not of tree type"
    assert int(length) == len(
        content
    ), "Expected length doesn't match with actual length"
    entries: list[list[str]] = []
    for _ in range(
        (int(length) // 20) + 1
    ):  # Only taking into consideration sha digest length
        end = content.find(b"\x00", start)
        if end == -1:
            break
        mode, path = content[start:end].decode().split()
        sha_digest = content[end + 1 : end + 21]
        entry = [mode, path, sha_digest.hex()]  # Actual ls-tree output
        if option == "--name-only":
            entry = [path]  # --name-only output
        entries.append(entry)
        start = end + 1 + 20

    return "\n".join(map("\n".join, sorted(entries)))


def write_tree(cwd: str = ".") -> str:
    """
    Writes tree object consisting of entire current directory.
    """
    files = os.listdir(cwd)
    if ".git" in files:
        files.remove(".git")
    content = b""
    for file in sorted(files):
        path = os.path.join(cwd, file)
        if os.path.isdir(path):  # isdirectory
            mode = b"40000"
            sha = write_tree(path)
        else:  # isfile
            mode = oct(os.stat(path).st_mode)[-6:].encode()
            sha = hash_object("", path)

        bin_sha = binascii.unhexlify(sha)
        content += mode + b" " + file.encode() + b"\x00" + bin_sha

    return hash_content(content, write=True, object_type="tree")


def commit_tree(tree_sha: str, parent_sha: str, message: str) -> str:
    timestamp = str(datetime.datetime.now().isoformat())

    lines: list[str] = []
    lines.append(f"tree {tree_sha}")
    lines.append(f"parent {parent_sha}")
    lines.append(f"author {AUTHOR_NAME} <{AUTHOR_EMAIL}> {timestamp}")
    lines.append(f"commiter {COMMITER_NAME} <{COMMITER_EMAIL}> {timestamp}")
    lines.append("")
    lines.append(message)
    lines.append("")

    data = "\n".join(lines).encode()

    return hash_content(data, write=True, object_type="commit")


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
            print(hash_object(option=sys.argv[2], path=sys.argv[3]))
        case "ls-tree":
            assert len(sys.argv) == 4, "fatal: wrong number of arguments, should be 4"
            print(ls_tree(option=sys.argv[2], sha=sys.argv[3]))
        case "write-tree":
            print(write_tree())
        case "commit-tree":
            assert len(sys.argv) == 7, "fatal: wrong number of arguments, should be 7"
            print(
                commit_tree(
                    tree_sha=sys.argv[2], parent_sha=sys.argv[4], message=sys.argv[6]
                )
            )
        case _:
            raise RuntimeError(f"Unknown command received: {command}")


if __name__ == "__main__":
    main()
