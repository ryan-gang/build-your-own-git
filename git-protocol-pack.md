# Git Pack Protocol

This document outlines the core protocol used by Git for efficient data transfer between client and server. The goal is to identify the **smallest data set** needed to update either one, minimizing unnecessary download/upload.

## Reference Discovery
---
**Initiation** : The client kicks off the exchange (to discover the references available on the remote) by requesting the `info/refs` file of the remote repo. This "smart protocol" flavor includes the `?service=git-upload-pack` query parameter.

```
GET https://<HOST>/<REPO>/info/refs?service=git-upload-pack
``` 

**Response** :
The response body follows a specific format using `pkt-lines`.
Key elements include:
    - **Reference list** : Each reference (branch, tag) with its corresponding object SHA-1 hash.
    - **HEAD** : If valid, points to the first reference. Otherwise, absent.
    - **Capabilities** : Server-supported features like thin-pack and side-band fetching.

```
200 OK
Content-Type: application/x-git-upload-pack-advertisement

001e : # service=git-upload-pack\n
0000
0155 : 8a0d71c87ec9750fb0e2421223e01580e1b650a6 HEAD\x00
multi_ack thin-pack side-band side-band-64k ofs-delta shallow deepen-since deepen-not deepen-relative no-progress include-tag multi_ack_detailed allow-tip-sha1-in-want allow-reachable-sha1-in-want no-done symref=HEAD:refs/heads/master filter object-format=sha1 agent=git/github-0ecc5b5f94fa\n
003f : 8a0d71c87ec9750fb0e2421223e01580e1b650a6 refs/heads/master\n
0000
```

The server will respond by listing all of the references it has (all branches and tags) along with the object name that each reference currently points to.
The returned response is a pkt-line stream describing each ref and its known value.
If HEAD is a valid ref, HEAD MUST appear as the first advertised ref.  If HEAD is not a valid ref, HEAD MUST NOT appear in the advertisement list at all, but other refs may still appear. The stream MUST include capability declarations behind a NUL on the first ref. 

**Client Processing** :
- Parse the `pkt-line` stream and extract the list of references and capabilities.
- For a **clone** operation : Add all references to the "required" list.
- For other scenarios (e.g., pull/push): Analyze the local state and server offerings to determine the minimal set of references needed for update.

## Packfile Negotiation
---
**Client Initiates Negotiation** :
1. **No pack-data required** : If no data transfer is needed, the client sends a `flush-pkt` to terminate the connection. Otherwise, it enters the negotiation phase.
2. **Negotiation Phase** : The client sends `want` lines specifying desired object SHAs, potentially including:
    - Shallow objects: References to recent ancestor commits to limit fetched history.
    - Commit depth: Maximum depth of commit history to fetch (optional).
    - Desired server capabilities from the initial response.
3. **Flush-pkt** : After sending all requests, the client sends a `flush-pkt` to signal completion.

After parsing the above response, our packfile negotiation request looks like
```
0032want 8a0d71c87ec9750fb0e2421223e01580e1b650a6\n
0000
0008done
```
This request shows:
- Wanting a single object SHA.
- No local references (no "have" lines).
- Sending all data as `pkt-lines`, followed by a `flush-pkt`.
We send a request to the server with our request to start and end negotiation (As we require all refs)

```
POST https://<HOST>/<REPO>/git-upload-pack
"Content-Type": "application/x-git-upload-pack-request"

0008NAK\n
PACK\x00\x00\x00\x02
...
\x82\xa0\x9c\xe4\x97
```

As we have sent all wants and no haves, there wont be any common object with the remote, so no ACKs will be sent, and a single NAK on a flush-pkt would be present in the response. 
Along with the packfile containing the requested objects.

## `pkt-line` Format
---
- A variable-length binary string with the total length (including itself) encoded in the first four bytes as hex.
- May contain binary data.
- Non-binary lines should end with an LF character, included in the length.
- Flush-pkt (length 0) acts as a special signal, distinct from an empty line.

## `Packfile` Format
---
Packfiles accommodate objects in two forms: full and deltified. Full objects simply store the raw content, whereas deltified objects represent the difference between themselves and another "base" object. This delta approach significantly reduces redundancy and file size when objects share similarities.

### Packfile Structure
---
1. Header:
	- 4-byte signature: {'P', 'A', 'C', 'K'}.
	- 4-byte version number (network byte order): 2.
	- 4-byte number of objects contained in the pack (network byte order)
	
2. Object entries:
	1. Un-deltified representation
		n-byte type and length `(3-bit type, (n-1)*7+4-bit length)`
		compressed data
	2. Deltified representation
		n-byte type and length `(3-bit type, (n-1)*7+4-bit length)`
		base object name (`OBJ_REF_DELTA`)
		compressed delta data
	The length of each object is encoded in a variable length format and is not constrained to 32-bit or anything.

3. The trailer records a pack checksum of all of the above.

### Packfile entry
---
How a single entry in the pack file looks like.

```
Packed object header
	1-byte size extension bit (MSB)
	type (next 3 bit)
	size0 (lower 4-bit)
	n-byte sizeN (as long as MSB is set, each 7-bit)
	size0..sizeN form 4+7+7+..+7 bit integer, size0
	is the least significant part, and sizeN is the
	most significant part.
Packed object data
	If it is not DELTA, then deflated bytes (the size above
	is the size before compression).
	If it is REF_DELTA, then
	base object name (the size above is the
	size of the delta data that follows).
	delta data, deflated.
```

### Object types
---
Standard Git object types :
- `OBJ_COMMIT` : 1
- `OBJ_TREE` : 2
- `OBJ_BLOB` : 3
- `OBJ_TAG` : 4

Special types for deltified objects :
- `OBJ_OFS_DELTA` : 6
- `OBJ_REF_DELTA` : 7

Type 5 is reserved for future expansion. Type 0 is invalid.

### Size encoding scheme
---
Packfiles employ a custom size encoding scheme for representing object sizes (non negative integers of any size) efficiently.
From each byte, the seven least significant bits are used to form the resulting integer. As long as the most significant bit is 1, this process continues; the byte with MSB 0 provides the last seven bits.  The seven-bit chunks are concatenated. Later values are more significant.

```
while pack_file[curr] & 0b10000000:
	curr += 1
	b = parse_obj_size_single_byte(pack_file, curr, mask=0b1111111)
	object_size.append(b)

size = int("".join(object_size[::-1]), 2)
```

### Deltified representation
---
Conceptually there are only four object types: `commit`, `tree`, `tag` and `blob`. However to save space, an object could be stored as a **delta** of another **base** object. These representations are assigned new types `ofs-delta` and `ref-delta`, which is only valid in a pack file.

Both `ofs-delta` and `ref-delta` store the **delta** to be applied to another object (called **base object**) to reconstruct the object. The difference between them is, `ref-delta` directly encodes base object name. If the base object is in the same pack, `ofs-delta` encodes the offset of the base object in the pack instead.

The base object could also be deltified if it's in the same pack.
Ref-delta can also refer to an object outside the pack. When stored on disk however, the pack should be self contained to avoid cyclic dependency.

The delta data starts with the size of the base object and the size of the object to be reconstructed. These sizes are
encoded using the size encoding from above.  The remainder of the delta data is a sequence of instructions to reconstruct the object from the base object. If the base object is deltified, it must be converted to canonical form first. Each instruction appends more and more data to the target object until it's complete. There are two supported instructions so far: one for copying a byte range from the source object and one for inserting new data embedded in the instruction itself. Each instruction has variable length. Instruction type is determined by the seventh bit of the first octet. 

#### Copy instruction
---
```
  +----------+---------+---------+---------+---------+-------+-------+-------+
  | 1xxxxxxx | offset1 | offset2 | offset3 | offset4 | size1 | size2 | size3 |
  +----------+---------+---------+---------+---------+-------+-------+-------+
```

This is the instruction format to copy a byte range from the source
object. It encodes the offset to copy from and the number of bytes to
copy. Offset and size are in little-endian order.

All offset and size bytes are optional. This is to reduce the
instruction size when encoding small offsets or sizes. The first seven
bits in the first octet determine which of the next seven octets is
present. If bit zero is set, offset1 is present. If bit one is set
offset2 is present and so on.

Note that a more compact instruction does not change offset and size
encoding. For example, if only offset2 is omitted like below, offset3
still contains bits 16-23. It does not become offset2 and contains
bits 8-15 even if it's right next to offset1.

#### Insert instruction
---
```
  +----------+------------+
  | 0xxxxxxx |    data    |
  +----------+------------+
```
This is the instruction to construct the target object without the base
object. The following data is appended to the target object. The first
seven bits of the first octet determine the size of data in
bytes. The size must be non-zero.

---

Ref :
1. https://www.git-scm.com/docs/http-protocol
2. https://git-scm.com/docs/pack-protocol
3. https://github.com/git/git/blob/master/Documentation/gitprotocol-common.txt
4. https://github.com/git/git/blob/master/Documentation/gitprotocol-pack.txt
5. https://github.com/git/git/blob/master/Documentation/gitformat-pack.txt
6. https://github.com/git/git/blob/master/Documentation/gitprotocol-v2.txt
7. https://github.com/git/git/blob/master/Documentation/gitprotocol-capabilities.txt
8. https://codewords.recurse.com/issues/three/unpacking-git-packfiles
9. https://stackoverflow.com/questions/68062812/
