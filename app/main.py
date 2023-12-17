import sys

from app.git_utils import (cat_file, commit_tree, create_repo, hash_object,
                           ls_tree, write_tree)
from app.pack_utils import checkout, clone


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

        case "clone":
            assert len(sys.argv) == 4, "fatal: wrong number of arguments, should be 4"
            repo_url, repo_path = sys.argv[2], sys.argv[3]
            clone(repo_url, repo_path)
            checkout("HEAD", repo_path, repo_path)

        case _:
            raise RuntimeError(f"Unknown command received: {command}")


if __name__ == "__main__":
    main()
