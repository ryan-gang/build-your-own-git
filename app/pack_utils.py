import hashlib
import os
import re
import urllib.request
import zlib
from typing import Optional

from app.git_utils import (cat_file, create_repo, hash_content, ls_tree,
                           read_object)


def clone(repo_url: str, repo_path: str):
    """
    Clones a repository from the given URL to the specified path.

    1. Downloads the Git references (refs) from the remote repository. These
       refs contain information about the repository's branches, tags, and other
       objects.
    2. Parses the downloaded refs to identify the objects (commits, trees,
       blobs) needed for the chosen branch or tag.
    3. Negotiates with the remote repository to download the required objects
       efficiently.
    4. Validates the downloaded objects to ensure they are complete and
       unaltered.
    5. Writes the downloaded objects to the local repository directory at the
       specified path.
    This function essentially creates a complete replica of the remote
    repository at the specified local location.
    """
    os.makedirs(repo_path)
    create_repo(repo_path)

    refs_byte_data = download_refs(repo_url)
    packets = parse_pkt_lines(refs_byte_data)
    refs_to_write = extract_ref_shas_and_paths(packets[1:])
    write_refs(refs_to_write, repo_path)
    shas_needed = extract_ref_shas(packets[1:])
    # print(shas_needed)
    objects_needed = get_objects_needed(shas_needed)
    # print(objects_needed)
    pack_file_response = send_packfile_negotiation(repo_url, body=objects_needed)
    pack_file = validate_pack_file(pack_file_response)
    assert pack_file != b""
    objects = parse_pack_file(pack_file)

    written_objects: set[str] = set()
    for object in objects:
        type, content = process_object(object, written_objects, repo_path)
        sha = hash_content(content=content, object_type=type, repo_path=repo_path)
        written_objects.add(sha)

    print(f"Remote repository {repo_url} cloned in {repo_path}.")


def process_object(
    object: tuple[str, bytes, Optional[bytes]],
    written_objects: set[str],
    repo_path: str = "",
):
    """
    Processes a Git object, handling different types of objects (commit, tree,
    blob, tag, obj_ref_delta), returns the type and content for hashing and
    writing.
    """
    type, content, ref = object

    if type in ["commit", "tree", "blob", "tag"]:
        return type, content

    elif type in ["obj_ref_delta"]:
        assert ref is not None
        delta, ref = content, ref
        ref_sha = ref.hex()
        ref_type, _, ref_content = read_object(ref_sha, repo_path)
        assert ref_sha in written_objects, "Cant find delta from unknown base object"
        content = decode_delta(delta, ref_content)
        return ref_type, content
    else:
        raise RuntimeError(f"Pack obj_type : {type} not implemented.")


def download_refs(repo_url: str) -> bytes:
    """
    This function downloads the repository's references from the remote
    URL. It communicates with the server using Git protocol packets and returns
    the raw bytes data containing the refs information.
    """
    discovery_url = f"{repo_url}/info/refs?service=git-upload-pack"
    with urllib.request.urlopen(discovery_url) as response:
        assert response.code in [200, 304]
        content = response.read()

        assert re.match("^[0-9a-f]{4}#", (content[:5]).decode())
        assert content[-4:].decode() == "0000"
        assert (
            response.getheader("Content-Type")
            == "application/x-git-upload-pack-advertisement"
        )
        return content


def parse_pkt_lines(data: bytes) -> list[bytes]:
    """
    This function parses the given raw bytes data representing Git packet lines.
    It parses the data and returns a list of individual packet lines.
    """
    pkts: list[bytes] = []
    idx = 0
    while idx < len(data):
        pkt = parse_pkt_line(data, idx)
        idx += len(pkt) + 4
        if pkt:
            pkts.append(pkt)

    assert pkts[0].decode().strip() == "# service=git-upload-pack"
    return pkts


def parse_pkt_line(data: bytes, i: int) -> bytes:
    """
    This function parses a single Git packet line starting at a specific index
    within the given data. It extracts the line content and size information,
    before returning the parsed line.
    """
    length = int.from_bytes(bytes.fromhex(data[i : i + 4].decode()), "big") - 4
    i += 4
    pkt = data[i : i + length]
    return pkt


def extract_ref_shas_and_paths(packets: list[bytes]) -> list[tuple[str, str]]:
    """
    This function processes a list of Git packet lines (packets) containing refs information. It parses each packet line to extract the reference SHA-1 hash and the corresponding path, returning a list of tuples containing these pairs.
    """
    refs: list[tuple[str, str]] = []

    for packet in packets:
        if b"\x00" in packet:
            packet = packet.split(b"\x00")[0]
        ref = packet.decode().strip("\n")
        if " " in ref:
            sha, path = ref.split(" ", maxsplit=1)
            refs.append((sha, path))
    return refs


def write_refs(refs: list[tuple[str, str]], local_repo_path: str):
    """
    This function writes the given list of refs to the local repository at the
    specified path. Each ref tuple contains the SHA-1 hash and the corresponding
    path.
    """
    for sha, path in refs:
        write_ref(local_repo_path, path, sha)


def write_ref(local_repo_path: str, path: str, sha: str):
    """
    This function writes a single Git reference to the local repository at the
    specified path. It creates a file with the reference path containing the
    object's SHA-1 hash.
    """
    file_path = os.path.join(local_repo_path, ".git", path)
    if not os.path.exists(os.path.dirname(file_path)):
        os.makedirs(os.path.dirname(file_path))
    with open(file_path, "w") as ref_file:
        ref_file.write(sha)


def extract_ref_shas(packets: list[bytes]) -> list[str]:
    """
    This function extracts the SHA-1 hashes of objects referenced in the given
    list of Git packet lines. It parses each packet line, returning a list of
    extracted SHA-1 hashes.
    """
    shas_needed: set[str] = set()

    sha, _ = packets[0].split(b"\x00")[0].decode().split(" ", maxsplit=1)
    shas_needed.add(sha)

    for packet in packets:
        sha, _ = packet.decode().split(" ", maxsplit=1)
        shas_needed.add(sha)

    return list(shas_needed)


def send_packfile_negotiation(repo_url: str, body: bytes) -> bytes:
    """
    This function initiates the packfile negotiation process with the remote
    repository at repo_url. It sends a specific request body containing
    information about the desired objects and capabilities. The function returns
    the server's response data.
    """
    headers = {"Content-Type": "application/x-git-upload-pack-request"}
    url = f"{repo_url}/git-upload-pack"

    req = urllib.request.Request(url, data=body, headers=headers)
    with urllib.request.urlopen(req) as response:
        assert response.code == 200
        assert (
            response.getheader("Content-Type") == "application/x-git-upload-pack-result"
        )
        # print(response.getheaders())
        return response.read()


def get_objects_needed(refs: list[str]) -> bytes:
    """
    This function builds a request body (bytes) to ask the remote repository for
    the specific objects required based on the given list of refs. It identifies
    missing objects and constructs the appropriate request format for requesting
    their SHA-1 hashes and other data.
    """
    lines: list[bytes] = []

    for ref in refs:
        lines.append(packet_line("want " + ref + "\n"))

    lines.append(packet_line(""))
    lines.append(packet_line("done"))
    return b"".join(lines)


def packet_line(body: str) -> bytes:
    """
    This function constructs a Git protocol packet line according to the
    specifications. It takes a string representing the content of the line and
    converts it to the required byte format with header information like length
    and type. The function then returns the complete packet line as bytes.
    """
    packet = body.encode()
    if len(packet) == 0:
        return b"0000"
    packet_length = len(packet) + 4
    length = f"{hex(packet_length)[2:]}".zfill(4).encode()

    return length + packet


def validate_pack_file(pack_file: bytes) -> bytes:
    """
    This function performs preliminary checks on the given pack file to ensure
    its validity. It verifies the "NAK" acknowledgment from the server. If it is
    valid, it returns the rest of the pack file data.
    """
    packet = parse_pkt_line(pack_file, i=0)
    if packet.decode().strip("\n") == "NAK":
        return pack_file[len(packet) + 4 :]
    return b""


def parse_pack_file(pack_file: bytes) -> list[tuple[str, bytes, Optional[bytes]]]:
    """
    This function parses the entire pack file data (bytes) into a list of
    individual Git objects. It iterates through the file, identifying and
    extracting the object data. The function returns a list of tuples where each
    tuple represents an object: (object_type, object_content, base_object_sha).
    For a non-deltified object the last sha is omitted.
    """
    signature = pack_file[0:4].decode()
    assert signature == "PACK"
    version = int.from_bytes(pack_file[4:8], "big")
    assert version == 2
    object_count = int.from_bytes(pack_file[8:12], "big")

    parsed = 12
    objects: list[tuple[str, bytes, Optional[bytes]]] = []

    for _ in range(object_count):
        parsed_bytes, obj = parse_pack_object(pack_file, parsed)
        parsed += parsed_bytes
        objects.append(obj)

    checksum = pack_file[parsed : parsed + 20]
    parsed += 20
    assert hashlib.sha1(pack_file[:-20]).digest() == checksum
    assert len(pack_file) == parsed

    return objects


def parse_pack_object(
    pack_file: bytes, i: int
) -> tuple[int, tuple[str, bytes, Optional[bytes]]]:
    """
    This function parses a single Git object from the pack file (bytes) starting
    at the specified index. It reads the header bytes to determine the object
    type, size, and SHA-1 hash. For delta objects, it also extracts the base
    object SHA-1. The function returns a tuple containing the parsing offset,
    and the parsed object tuple mentioned above.
    """
    TYPES = {
        1: "commit",
        2: "tree",
        3: "blob",
        4: "tag",
        7: "obj_ref_delta",
    }
    obj_type = parse_obj_type(pack_file, i)
    parsed_bytes, obj_size = parse_obj_size(pack_file, i)
    i += parsed_bytes

    if obj_type in [1, 2, 3, 4]:
        decompressor = zlib.decompressobj()
        obj = decompressor.decompress(pack_file[i:], max_length=obj_size)
        parsed_bytes += len(pack_file) - i - len(decompressor.unused_data)
        return parsed_bytes, (TYPES[obj_type], obj, None)

    elif obj_type == 7:
        ref = pack_file[i : i + 20]
        parsed_bytes += 20
        i += 20
        decompressor = zlib.decompressobj()
        delta = decompressor.decompress(pack_file[i:])
        parsed_bytes += len(pack_file) - i - len(decompressor.unused_data)
        return parsed_bytes, (TYPES[obj_type], delta, ref)

    else:
        raise NotImplementedError(
            f"Pack object type {TYPES[obj_type]} not implemented."
        )


def parse_obj_type(pack_file: bytes, idx: int) -> int:
    """
    This function extracts the object type (commit, tree, blob, etc.) from the
    pack file header at the given index. It reads specific bytes based on the
    header format and translates them into an integer representing the object
    type.
    """
    return (pack_file[idx] & 0b1110000) >> 4


def parse_obj_size_single_byte(pack_file: bytes, curr: int, mask: int) -> str:
    """
    This function parses a single byte from the pack_file for the size
    information. As the size information is spread across consecutive bytes, the
    function returns the extracted size as a binary string, which is then
    concatenated and converted into an int later.
    """
    length = len(bin(mask)) - 2
    val = pack_file[curr] & mask
    val_str = bin(val)[2:].zfill(length)
    return val_str


def parse_obj_size(pack_file: bytes, idx: int) -> tuple[int, int]:
    """
    This function parses the size information for a regular object (not a delta)
    from the pack file header at the given index. It reads specific bytes based
    on the header format and interprets them as a big-endian integer
    representing the object size in bytes. The function returns the extracted
    size as a str.
    """
    curr = start = idx
    object_size: list[str] = []

    b = parse_obj_size_single_byte(pack_file, curr, mask=0b1111)
    object_size.append(b)

    while pack_file[curr] & 0b10000000:
        curr += 1
        b = parse_obj_size_single_byte(pack_file, curr, mask=0b1111111)
        object_size.append(b)

    size = int("".join(object_size[::-1]), 2)
    return curr - start + 1, size


def parse_obj_size_delta(pack_file: bytes, idx: int) -> tuple[int, int]:
    """
    This function parses the size information for a delta object from the pack
    file header at the given index. Delta objects reference a base object and
    represent the difference. The function reads specific bytes and interprets
    them as a big-endian integer representing the size of the delta data. The
    function returns a tuple containing the parsing offset and the
    extracted size.
    """
    curr = start = idx
    object_size: list[str] = []

    b = parse_obj_size_single_byte(pack_file, curr, mask=0b1111111)
    object_size.append(b)

    while pack_file[curr] & 0b10000000:
        curr += 1
        b = parse_obj_size_single_byte(pack_file, curr, mask=0b1111111)
        object_size.append(b)

    size = int("".join(object_size[::-1]), 2)
    return curr - start + 1, size


def parse_copy_offset(determinant: int, stream: bytes, i: int) -> tuple[int, int]:
    """
    This function parses the offset value from a copy instruction within a delta
    object stream at the given index. The determinant provides context for
    decoding the offset bytes. The function reads specific bytes and interprets
    them as a big-endian integer representing the offset within the reference
    object where the copied data starts. The function returns a tuple containing
    the parsing offset and the extracted offset.
    """
    parsed_bytes = 0
    offset_parts: list[int] = []
    determinant_bits = bin(determinant)[-4:][::-1]
    for val in determinant_bits:
        if val == "1":
            offset_parts.append(stream[i])
            i += 1
            parsed_bytes += 1
        else:
            offset_parts.append(0)
    offset = 0
    for idx, part in enumerate(offset_parts):
        offset += part << (idx * 8)
    return parsed_bytes, offset


def parse_copy_size(determinant: int, stream: bytes, i: int) -> tuple[int, int]:
    """
    Similar to parse_copy_offset, this function parses the size value from a
    copy instruction within a delta object stream at the given index. The
    determinant provides context for decoding the size bytes. The function reads
    specific bytes and interprets them as a big-endian integer representing the
    number of bytes to copy from the reference object. The function returns a
    tuple containing the parsing offset and the extracted size.
    """
    parsed_bytes = 0
    size_parts: list[int] = []
    determinant_bits = bin(determinant)[-7:-4][::-1]
    for val in determinant_bits:
        if val == "1":
            size_parts.append(stream[i])
            i += 1
            parsed_bytes += 1
        else:
            size_parts.append(0)
    size = 0
    for idx, part in enumerate(size_parts):
        size += part << (idx * 8)
    return parsed_bytes, size


def parse_copy(stream: bytes, start: int) -> tuple[int, int, int]:
    """
    This function parses a complete copy instruction from the delta object
    stream starting at the given index. It reads the determinant, offset, and
    size bytes and interprets them according to the Git packfile format. The
    function returns a tuple containing the parsing offset, the extracted offset
    within the reference object, and the extracted size to copy.
    """
    cur, parsed_bytes = start, 1
    determinant = stream[cur]
    cur += parsed_bytes
    parsed_bytes, offset = parse_copy_offset(determinant, stream, cur)
    cur += parsed_bytes

    parsed_bytes, size = parse_copy_size(determinant, stream, cur)
    cur += parsed_bytes

    return cur - start, offset, size


def parse_insert(stream: bytes, i: int) -> tuple[int, bytes]:
    """
    This function parses a Git delta object's "insert" instruction from the
    given data stream starting at the provided index. An insert instruction
    represents raw data that wasn't present in the base object and needs to be
    directly included in the reconstructed object. The function returns a tuple
    containing the updated parsing offset and the decoded insert data.
    """
    size, parsed_bytes = stream[i], 1
    i += parsed_bytes
    insert_stream = stream[i : i + size]
    parsed_bytes += size
    return parsed_bytes, insert_stream


def decode_delta(delta: bytes, ref_content: bytes) -> bytes:
    """
    This function applies the "delta" transformation to reconstruct the final
    object content. It takes the delta data containing instructions and
    references. The base object content used as the starting point for applying
    the delta instructions. The function iterates through the delta
    instructions, which can be inserts and copies from the base object. It
    interprets each instruction type and applies it to the current reconstructed
    content. For copy instructions, it extracts the specified data from the base
    object and integrates it. For insert instructions, it incorporates the raw
    data provided in the delta. Finally, the function returns the complete
    reconstructed object content.
    """
    content, i = b"", 0

    parsed_bytes, ref_obj_size = parse_obj_size_delta(delta, i)
    i += parsed_bytes
    assert ref_obj_size == len(ref_content)
    parsed_bytes, obj_size = parse_obj_size_delta(delta, i)
    i += parsed_bytes

    while i < len(delta):
        if delta[i] & 0b10000000:  # copy
            parsed_bytes, offset, size = parse_copy(delta, i)
            content += ref_content[offset : offset + size]
        else:  # insert
            parsed_bytes, to_insert = parse_insert(delta, i)
            content += to_insert
        i += parsed_bytes

    assert obj_size == len(content)
    return content


def get_commit_from_head(repo_path: str) -> str:
    """
    This function retrieves the SHA-1 hash of the current commit pointed to by
    the HEAD reference in the Git repository at the specified path (repo_path).
    """
    head_file_path = os.path.join(repo_path, ".git", "HEAD")
    with open(head_file_path, "r") as fhand:
        head_contents = fhand.read()

    if head_contents.startswith("ref: "):
        obj_path = os.path.join(repo_path, ".git", head_contents.split(" ")[1])
        with open(obj_path, "r") as fhand:
            commit = fhand.read()
    else:
        commit = head_contents

    return commit


def checkout(commit: str, directory: str, repo_path: str = ""):
    """
    This function performs a checkout operation of a specific commit in a Git
    repository. It reads the object tree of the specified commit. Recursively
    iterates through the tree entries, which represent files and subdirectories.
    For each entry, it determines the object type (blob or tree) and its SHA-1
    hash. Based on the object type, it writes the corresponding content to the
    appropriate location within the target directory. Handles subdirectories by
    creating them and recursively checking out their contents.
    """
    if commit == "HEAD":
        commit = get_commit_from_head(repo_path)

    obj_content = read_object(commit, repo_path)[2]
    obj_type, obj_sha = obj_content.split(b"\n", 1)[0].split(b" ", 1)
    assert obj_type == b"tree", "Expecting tree object in commit."

    tree_entries = ls_tree(obj_sha.decode(), repo_path)
    for _, obj_name, obj_sha in tree_entries:
        write_object(directory, obj_name, obj_sha, repo_path)


def write_object(path: str, object_name: str, object_sha: str, repo_path: str = ""):
    """
    This function writes a Git object (blob or tree) to the specified path within the repository. The function Opens the repository object store at the specified path. Writes the object content (determined by the SHA-1 hash) to the appropriate location within the store.
    """
    try:
        object_type = read_object(object_sha, repo_path)[0]
    except FileNotFoundError:
        print(f"File {object_name} has no corresponding object {object_sha}")
        return

    if object_type == "tree":
        tree_entries = ls_tree(object_sha, repo_path)
        for _, obj_name, obj_sha in tree_entries:
            write_object(os.path.join(path, object_name), obj_name, obj_sha, repo_path)

    elif object_type == "blob":
        os.makedirs(path, exist_ok=True)
        with open(os.path.join(path, object_name), "wb") as blob:
            contents = cat_file(object_sha, repo_path)
            blob.write(contents.encode())

    else:
        raise RuntimeError(f"Checkout of {object_type} not implemented.")
