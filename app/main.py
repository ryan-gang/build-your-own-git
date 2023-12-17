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


def object_path(sha: str, mkdir: bool = False, repo_path: str = ""):
    """
    Given the SHA-1 hash of an object, returns the corresponding path in
    <LOCAL_REPO>/.git/objects/, If `mkdir` flag is true, all the parent
    directories are created.
    """
    file_path = os.path.join(repo_path, ".git", "objects", sha[:2], sha[2:])
    dir_path = os.path.dirname(file_path)
    if mkdir and not os.path.exists(dir_path):
        os.makedirs(dir_path)
    return file_path


def create_repo(repo_path: str = ""):
    """
    Creates an empty .git directory in `repo_path`, and the bare minimum
    subdirectories required for git to function.
    """
    os.mkdir(os.path.join(repo_path, ".git"))
    os.mkdir(os.path.join(repo_path, ".git/objects"))
    os.mkdir(os.path.join(repo_path, ".git/refs"))

    with open(os.path.join(repo_path, ".git/HEAD"), "w") as f:
        f.write("ref: refs/heads/master\n")
    print(f"Initialized empty Git repository.")


def read_object(blob_sha: str, repo_path: str = "") -> tuple[str, str, bytes]:
    """
    Retrieves the contents of a git object given its SHA-1 hash. Decompresses
    it, decodes it and returns a tuple consisting of the object_type,
    object_length and its contents.
    """
    full_path = object_path(blob_sha, mkdir=False, repo_path=repo_path)
    with open(full_path, "rb") as blob:
        data = zlib.decompress(blob.read())

    metadata, _, content = data.partition(b"\x00")
    # metadata and contents are separated by the null byte.
    obj_type, obj_length = metadata.decode().split()
    return obj_type, obj_length, content


def hash_object(path: str, object_type: str = "blob", repo_path: str = "") -> str:
    """
    Reads the file contents from `path` and then hashes and writes out the
    content as a git object, returning a SHA-1 hash in the process.
    """
    with open(path, "rb") as f:
        content = f.read()
    return hash_content(content, object_type, repo_path)


def hash_content(content: bytes, object_type: str = "blob", repo_path: str = "") -> str:
    """
    Creates a git object from the given bytes content and object_type, writes it
    to the object path based on SHA-1 hash and returns the SHA-1 hash.
    """
    sha, data = create_object(content, object_type)
    write_object(sha, data, repo_path)

    return sha


def create_object(content: bytes, object_type: str = "blob") -> tuple[str, bytes]:
    """
    Creates a git object based on the bytes content and object type, returns the
    resulting data as bytes, and a SHA-1 digest of it.
    """
    headers = object_type.encode() + b" " + str(len(content)).encode() + b"\x00"
    data = headers + content
    sha = hashlib.sha1(data).hexdigest()
    return sha, data


def write_object(sha: str, content: bytes, repo_path: str):
    """
    Compresses and writes out the given git object, in the object_path of the
    SHA-1 digest.
    """
    full_path = object_path(sha, mkdir=True, repo_path=repo_path)
    with open(full_path, "wb") as fhand:
        # print(f"Writing data to : {full_path}")
        fhand.write(zlib.compress(content))


def cat_file(sha: str, repo_path: str = ""):
    """
    Returns a decompressed and decoded version of the git object referred to by
    the passed SHA-1 hash.
    """
    _, _, data = read_object(sha, repo_path)
    text = data.decode(encoding="utf-8")
    return text


def ls_tree(sha: str, repo_path: str = "") -> list[tuple[str, str, str]]:
    """
    Reads the given tree object, and returns a list of (mode, path, sha1)
    tuples, referred to in the tree.
    """
    object_type, length, content = read_object(sha, repo_path)
    start = 0

    assert object_type == "tree", "Object is not of tree type"
    assert int(length) == len(
        content
    ), "Expected length doesn't match with actual length"

    entries: list[tuple[str, str, str]] = []
    for _ in range(
        (int(length) // 20) + 1
    ):  # Only taking into consideration sha digest length
        end = content.find(b"\x00", start)
        if end == -1:
            break
        mode, path = content[start:end].decode().split()
        sha_digest = content[end + 1 : end + 21]
        entry = (mode, path, sha_digest.hex())  # Actual ls-tree output
        entries.append(entry)
        start = end + 1 + 20

    return sorted(entries, key=lambda item: item[1])


def write_tree(path: str = ".", repo_path: str = "") -> str:
    """
    Creates, hashes and writes out a tree object from the given directory,
    returning SHA-1 hash of the object.
    """
    files = os.listdir(path)
    IGNORED = ["__pycache__", ".git", ".history"]
    content = b""
    for file in sorted(files):
        if file in IGNORED:
            continue
        obj_path = os.path.join(path, file)
        if os.path.isdir(obj_path):  # is_directory
            mode = b"40000"
            sha = write_tree(obj_path, repo_path)
        else:  # is_file
            mode = oct(os.stat(obj_path).st_mode)[-6:].encode()
            sha = hash_object(obj_path, "blob", repo_path)

        bin_sha = binascii.unhexlify(sha)
        content += mode + b" " + file.encode() + b"\x00" + bin_sha

    return hash_content(content, "tree", repo_path)


def commit_tree(
    tree_sha: str, parent_sha: str, message: str, repo_path: str = ""
) -> str:
    """
    Creates and writes given commit data to repo, returning SHA-1 hash of the
    contents.
    """
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

    return hash_content(data, "commit", repo_path)


def main():
    command = sys.argv[1]

    match command:
        case "init":
            create_repo()

        case "cat-file":
            assert len(sys.argv) == 4, "fatal: wrong number of arguments, should be 4"
            option = sys.argv[2]
            if option != "-p":
                raise RuntimeError(f"Unknown parameter {option} received for cat-file.")
            sha = sys.argv[3]
            print(cat_file(sha), end="")

        case "hash-object":
            assert len(sys.argv) >= 3, "fatal: wrong number of arguments, should be > 3"
            option = sys.argv[2]
            if option != "-w":
                raise RuntimeError(
                    f"Unknown parameter {option} received for hash-object."
                )
            file_path = sys.argv[3]
            print(hash_object(file_path))

        case "ls-tree":
            assert len(sys.argv) == 4, "fatal: wrong number of arguments, should be 4"
            option = sys.argv[2]
            sha = sys.argv[3]
            output = ls_tree(sha)
            if option == "--name-only":
                for entry in output:
                    _, path, _ = entry
                    print(path)
            else:
                raise RuntimeError(f"Unknown parameter {option} received for ls-tree.")

        case "write-tree":
            print(write_tree())

        case "commit-tree":
            assert len(sys.argv) == 7, "fatal: wrong number of arguments, should be 7"
            parent_sha_index = sys.argv.index("-p") + 1
            commit_message_index = sys.argv.index("-m") + 1
            assert (
                parent_sha_index > 2 and commit_message_index > 2
            ), "Wrong argument order for commit-tree"
            try:
                tree_sha = sys.argv[2]
                parent_sha, commit_message = (
                    sys.argv[parent_sha_index],
                    sys.argv[commit_message_index],
                )
            except IndexError:
                raise RuntimeError("Wrong or no argument passed for commit-tree")
            print(commit_tree(tree_sha, parent_sha, commit_message))

        case _:
            raise RuntimeError(f"Unknown command received: {command}")


if __name__ == "__main__":
    main()
