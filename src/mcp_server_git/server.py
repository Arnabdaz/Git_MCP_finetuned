import logging
import os
import re
from pathlib import Path
from typing import Sequence, Optional
from mcp.server import Server
from mcp.server.session import ServerSession
from mcp.server.stdio import stdio_server
from mcp.types import (
    ClientCapabilities,
    TextContent,
    Tool,
    ListRootsResult,
    RootsCapability,
)
from enum import Enum
import git
from git import GitCommandError
from pydantic import BaseModel, Field, validator

# Default number of context lines to show in diff output
DEFAULT_CONTEXT_LINES = 3

# Security validation constants
MAX_PATH_LENGTH = 4096
MAX_BRANCH_NAME_LENGTH = 255
MAX_COMMIT_MESSAGE_LENGTH = 8192
MAX_FILE_LIST_SIZE = 100
BRANCH_NAME_PATTERN = re.compile(
    r"^[a-zA-Z0-9][a-zA-Z0-9._/-]*[a-zA-Z0-9]$|^[a-zA-Z0-9]$"
)
COMMIT_HASH_PATTERN = re.compile(r"^[a-fA-F0-9]{6,40}$")


class SecurityError(Exception):
    """Custom exception for security-related errors."""

    pass


def validate_repo_path(repo_path: str, allowed_paths: Optional[list] = None) -> Path:
    """
    Validate and sanitize repository path to prevent directory traversal attacks.

    Args:
        repo_path: The repository path to validate
        allowed_paths: Optional list of allowed base paths

    Returns:
        Validated and resolved Path object

    Raises:
        SecurityError: If path is invalid or potentially dangerous
    """
    if not repo_path or len(repo_path) > MAX_PATH_LENGTH:
        raise SecurityError("Invalid repository path length")

    try:
        # Resolve the path to get absolute canonical path
        path = Path(repo_path).resolve()
    except (OSError, ValueError) as e:
        raise SecurityError(f"Invalid repository path: {e}")

    # Check for suspicious path components and traversal attempts in original input
    if ".." in repo_path:
        raise SecurityError("Path contains suspicious components")

    # Block access to sensitive system directories (be specific to avoid blocking temp dirs)
    sensitive_dirs = {
        "/etc",
        "/usr/bin",
        "/usr/sbin",
        "/bin",
        "/sbin",
        "/boot",
        "/dev",
        "/proc",
        "/sys",
        "/private/etc",
    }
    path_str = str(path)
    if any(
        path_str.startswith(sys_dir) or path_str == sys_dir
        for sys_dir in sensitive_dirs
    ):
        raise SecurityError("Path contains suspicious components")

    parts = path.parts
    if any(part in ("..", ".", "") or part.startswith(".") for part in parts):
        raise SecurityError("Path contains suspicious components")

    # If allowed_paths is specified, ensure the path is under one of them
    if allowed_paths:
        allowed = False
        for allowed_path in allowed_paths:
            try:
                allowed_path_resolved = Path(allowed_path).resolve()
                if (
                    path == allowed_path_resolved
                    or allowed_path_resolved in path.parents
                ):
                    allowed = True
                    break
            except (OSError, ValueError):
                continue

        if not allowed:
            raise SecurityError("Repository path not in allowed directories")

    return path


def validate_branch_name(branch_name: str) -> str:
    """
    Validate git branch name format.

    Args:
        branch_name: Branch name to validate

    Returns:
        Validated branch name

    Raises:
        SecurityError: If branch name is invalid
    """
    if not branch_name or len(branch_name) > MAX_BRANCH_NAME_LENGTH:
        raise SecurityError("Invalid branch name length")

    # Check for various invalid characters and patterns
    if (
        " " in branch_name
        or "@{" in branch_name
        or branch_name.startswith(".")
        or branch_name.endswith(".")
        or branch_name.startswith("-")
        or branch_name.endswith("-")
        or ".." in branch_name
        or branch_name.endswith("/")
        or branch_name.startswith("/")
    ):
        raise SecurityError("Invalid branch name format")

    if not BRANCH_NAME_PATTERN.match(branch_name):
        raise SecurityError("Invalid branch name format")

    # Check for git reserved names
    reserved_names = {".", "..", "HEAD", "ORIG_HEAD", "FETCH_HEAD", "MERGE_HEAD"}
    if branch_name.upper() in reserved_names:
        raise SecurityError("Branch name conflicts with git reserved names")

    return branch_name


def validate_commit_message(message: str) -> str:
    """
    Validate git commit message.

    Args:
        message: Commit message to validate

    Returns:
        Validated commit message

    Raises:
        SecurityError: If commit message is invalid
    """
    if not message or len(message) > MAX_COMMIT_MESSAGE_LENGTH:
        raise SecurityError("Invalid commit message length")

    # Check for null bytes and other control characters that could be problematic
    if "\x00" in message or any(ord(c) < 32 and c not in "\t\n\r" for c in message):
        raise SecurityError("Commit message contains invalid characters")

    return message.strip()


def validate_file_list(files: list) -> list:
    """
    Validate list of files for git operations.

    Args:
        files: List of file paths

    Returns:
        Validated list of files

    Raises:
        SecurityError: If file list is invalid
    """
    if not files or len(files) > MAX_FILE_LIST_SIZE:
        raise SecurityError("Invalid file list size")

    validated_files = []
    for file_path in files:
        if not isinstance(file_path, str) or len(file_path) > MAX_PATH_LENGTH:
            raise SecurityError(f"Invalid file path: {file_path}")

        # Check for directory traversal attempts
        if "../" in file_path or file_path.startswith("/") or "\\" in file_path:
            raise SecurityError(f"File path contains dangerous components: {file_path}")

        validated_files.append(file_path.strip())

    return validated_files


def validate_commit_hash(commit_hash: str) -> str:
    """
    Validate git commit hash format.

    Args:
        commit_hash: Commit hash to validate

    Returns:
        Validated commit hash

    Raises:
        SecurityError: If commit hash is invalid
    """
    if not commit_hash:
        raise SecurityError("Empty commit hash")

    if not COMMIT_HASH_PATTERN.match(commit_hash):
        raise SecurityError("Invalid commit hash format")

    return commit_hash


def sanitize_error_message(error: Exception) -> str:
    """
    Sanitize error messages to prevent information disclosure.

    Args:
        error: Exception object

    Returns:
        Sanitized error message
    """
    error_msg = str(error)

    # Remove potentially sensitive path information
    error_msg = re.sub(r"/[^\s]*/", "/[PATH]/", error_msg)
    # Replace Windows paths (C:\path\to\file)
    error_msg = re.sub(r"[C-Z]:\\[^\s]*", r"[PATH]", error_msg)

    # Remove user names and system information
    error_msg = re.sub(
        r"user[\s]*[:\s]+\s*\w+", "user: [USER]", error_msg, flags=re.IGNORECASE
    )

    # Limit error message length
    if len(error_msg) > 500:
        error_msg = error_msg[:497] + "..."

    return error_msg


class GitStatus(BaseModel):
    repo_path: str


class GitDiffUnstaged(BaseModel):
    repo_path: str
    context_lines: int = DEFAULT_CONTEXT_LINES


class GitDiffStaged(BaseModel):
    repo_path: str
    context_lines: int = DEFAULT_CONTEXT_LINES


class GitDiff(BaseModel):
    repo_path: str
    target: str
    context_lines: int = DEFAULT_CONTEXT_LINES


class GitCommit(BaseModel):
    repo_path: str
    message: str


class GitAdd(BaseModel):
    repo_path: str
    files: list[str]


class GitReset(BaseModel):
    repo_path: str


class GitLog(BaseModel):
    repo_path: str
    max_count: int = 10


class GitCreateBranch(BaseModel):
    repo_path: str
    branch_name: str
    base_branch: str | None = None


class GitCheckout(BaseModel):
    repo_path: str
    branch_name: str


class GitShow(BaseModel):
    repo_path: str
    revision: str


class GitInit(BaseModel):
    repo_path: str


class GitBranch(BaseModel):
    repo_path: str = Field(
        ...,
        description="The path to the Git repository.",
    )
    branch_type: str = Field(
        ...,
        description="Whether to list local branches ('local'), remote branches ('remote') or all branches('all').",
    )
    contains: Optional[str] = Field(
        None,
        description="The commit sha that branch should contain. Do not pass anything to this param if no commit sha is specified",
    )
    not_contains: Optional[str] = Field(
        None,
        description="The commit sha that branch should NOT contain. Do not pass anything to this param if no commit sha is specified",
    )


class GitCherryPick(BaseModel):
    repo_path: str
    commit_sha: str
    no_commit: bool = False


class GitListRemotes(BaseModel):
    repo_path: str
    verbose: bool = False


class GitPull(BaseModel):
    repo_path: str
    remote: str
    branch: str


class GitPush(BaseModel):
    repo_path: str
    remote: str
    branch: str
    force: bool = False


class GitFetch(BaseModel):
    repo_path: str
    remote: str
    branch: Optional[str] = None
    all_remotes: bool = False


class GitSwitchCreate(BaseModel):
    repo_path: str
    branch_name: str
    base_branch: Optional[str] = None


class GitTools(str, Enum):
    STATUS = "git_status"
    DIFF_UNSTAGED = "git_diff_unstaged"
    DIFF_STAGED = "git_diff_staged"
    DIFF = "git_diff"
    COMMIT = "git_commit"
    ADD = "git_add"
    RESET = "git_reset"
    LOG = "git_log"
    CREATE_BRANCH = "git_create_branch"
    CHECKOUT = "git_checkout"
    SHOW = "git_show"
    INIT = "git_init"
    BRANCH = "git_branch"
    CHERRY_PICK = "git_cherry_pick"
    LIST_REMOTES = "git_list_remotes"
    PULL = "git_pull"
    PUSH = "git_push"
    FETCH = "git_fetch"
    SWITCH_CREATE = "git_switch_create"


def git_status(repo: git.Repo) -> str:
    return repo.git.status()


def git_diff_unstaged(
    repo: git.Repo, context_lines: int = DEFAULT_CONTEXT_LINES
) -> str:
    # Validate context_lines parameter
    if context_lines < 0 or context_lines > 100:
        raise SecurityError("Invalid context lines value")
    return repo.git.diff(f"--unified={context_lines}")


def git_diff_staged(repo: git.Repo, context_lines: int = DEFAULT_CONTEXT_LINES) -> str:
    # Validate context_lines parameter
    if context_lines < 0 or context_lines > 100:
        raise SecurityError("Invalid context lines value")
    return repo.git.diff(f"--unified={context_lines}", "--cached")


def git_diff(
    repo: git.Repo, target: str, context_lines: int = DEFAULT_CONTEXT_LINES
) -> str:
    try:
        # Validate context_lines parameter
        if context_lines < 0 or context_lines > 100:
            raise SecurityError("Invalid context lines value")
        # Validate target (could be branch name or commit hash)
        if len(target) > 255:
            raise SecurityError("Target reference too long")
        return repo.git.diff(f"--unified={context_lines}", target)
    except GitCommandError as e:
        raise SecurityError(sanitize_error_message(e))


def git_commit(repo: git.Repo, message: str) -> str:
    try:
        # Validate commit message
        validated_message = validate_commit_message(message)
        commit = repo.index.commit(validated_message)
        return f"Changes committed successfully with hash {commit.hexsha}"
    except GitCommandError as e:
        raise SecurityError(sanitize_error_message(e))


def git_add(repo: git.Repo, files: list[str]) -> str:
    try:
        # Validate file list
        validated_files = validate_file_list(files)
        repo.index.add(validated_files)
        return "Files staged successfully"
    except GitCommandError as e:
        raise SecurityError(sanitize_error_message(e))


def git_reset(repo: git.Repo) -> str:
    try:
        repo.index.reset()
        return "All staged changes reset"
    except GitCommandError as e:
        raise SecurityError(sanitize_error_message(e))


def git_log(repo: git.Repo, max_count: int = 10) -> list[str]:
    try:
        # Validate max_count parameter
        if max_count < 1 or max_count > 1000:
            raise SecurityError("Invalid max_count value")

        commits = list(repo.iter_commits(max_count=max_count))
        log = []
        for commit in commits:
            log.append(
                f"Commit: {commit.hexsha!r}\n"
                f"Author: {commit.author!r}\n"
                f"Date: {commit.authored_datetime}\n"
                f"Message: {commit.message!r}\n"
            )
        return log
    except GitCommandError as e:
        raise SecurityError(sanitize_error_message(e))


def git_create_branch(
    repo: git.Repo, branch_name: str, base_branch: str | None = None
) -> str:
    try:
        # Validate branch name
        validated_branch_name = validate_branch_name(branch_name)

        if base_branch:
            validated_base_branch = validate_branch_name(base_branch)
            base = repo.references[validated_base_branch]
        else:
            base = repo.active_branch

        repo.create_head(validated_branch_name, base)
        return f"Created branch '{validated_branch_name}' from '{base.name}'"
    except GitCommandError as e:
        raise SecurityError(sanitize_error_message(e))


def git_checkout(repo: git.Repo, branch_name: str) -> str:
    # Validate branch name
    validated_branch_name = validate_branch_name(branch_name)
    try:
        repo.git.checkout(validated_branch_name)
        return f"Switched to branch '{validated_branch_name}'"
    except GitCommandError as e:
        # Re-raise GitCommandError as-is for normal git failures
        raise


def git_init(repo_path: str) -> str:
    try:
        # Validate repository path
        validated_path = validate_repo_path(repo_path)
        repo = git.Repo.init(path=str(validated_path), mkdir=True)
        return f"Initialized empty Git repository in {repo.git_dir}"
    except SecurityError:
        raise
    except Exception as e:
        raise SecurityError(
            f"Error initializing repository: {sanitize_error_message(e)}"
        )


def git_show(repo: git.Repo, revision: str) -> str:
    try:
        # Validate revision parameter - could be commit hash or branch name
        if len(revision) > 255:
            raise SecurityError("Revision reference too long")

        commit = repo.commit(revision)
        output = [
            f"Commit: {commit.hexsha!r}\n"
            f"Author: {commit.author!r}\n"
            f"Date: {commit.authored_datetime!r}\n"
            f"Message: {commit.message!r}\n"
        ]
        if commit.parents:
            parent = commit.parents[0]
            diff = parent.diff(commit, create_patch=True)
        else:
            diff = commit.diff(git.NULL_TREE, create_patch=True)
        for d in diff:
            output.append(f"\n--- {d.a_path}\n+++ {d.b_path}\n")
            output.append(d.diff.decode("utf-8"))
        return "".join(output)
    except GitCommandError as e:
        raise SecurityError(sanitize_error_message(e))


def git_branch(
    repo: git.Repo,
    branch_type: str,
    contains: str | None = None,
    not_contains: str | None = None,
) -> str:
    try:
        # Validate branch_type
        if branch_type not in {"local", "remote", "all"}:
            raise SecurityError(f"Invalid branch type: {branch_type}")

        # Validate contains and not_contains if provided
        if contains and not COMMIT_HASH_PATTERN.match(contains):
            raise SecurityError("Invalid commit hash format for contains parameter")

        if not_contains and not COMMIT_HASH_PATTERN.match(not_contains):
            raise SecurityError("Invalid commit hash format for not_contains parameter")

        match contains:
            case None:
                contains_sha = (None,)
            case _:
                contains_sha = ("--contains", contains)

        match not_contains:
            case None:
                not_contains_sha = (None,)
            case _:
                not_contains_sha = ("--no-contains", not_contains)

        match branch_type:
            case "local":
                b_type = None
            case "remote":
                b_type = "-r"
            case "all":
                b_type = "-a"

        # None value will be auto deleted by GitPython
        branch_info = repo.git.branch(b_type, *contains_sha, *not_contains_sha)

        return branch_info
    except GitCommandError as e:
        raise SecurityError(sanitize_error_message(e))


def git_cherry_pick(repo: git.Repo, commit_sha: str, no_commit: bool = False) -> str:
    try:
        # Validate commit SHA
        validated_commit_sha = validate_commit_hash(commit_sha)

        if no_commit:
            repo.git.cherry_pick(validated_commit_sha, "--no-commit")
            return f"Cherry-picked commit {validated_commit_sha} without committing"
        else:
            repo.git.cherry_pick(validated_commit_sha)
            return f"Cherry-picked commit {validated_commit_sha}"
    except GitCommandError as e:
        raise SecurityError(sanitize_error_message(e))


def git_list_remotes(repo: git.Repo, verbose: bool = False) -> str:
    try:
        if verbose:
            remotes_info = repo.git.remote("-v")
        else:
            remotes_info = repo.git.remote()

        if not remotes_info:
            return "No remotes configured"

        return remotes_info
    except GitCommandError as e:
        raise SecurityError(sanitize_error_message(e))


def git_pull(repo: git.Repo, remote: str, branch: str) -> str:
    try:
        # Validate remote and branch names
        validated_remote = validate_branch_name(remote)
        validated_branch = validate_branch_name(branch)

        repo.git.pull(validated_remote, validated_branch)
        return f"Pulled from {validated_remote}/{validated_branch}"
    except GitCommandError as e:
        raise SecurityError(sanitize_error_message(e))


def git_push(
    repo: git.Repo,
    remote: str,
    branch: str,
    force: bool = False,
) -> str:
    try:
        # Validate remote and branch names
        validated_remote = validate_branch_name(remote)
        validated_branch = validate_branch_name(branch)

        if force:
            repo.git.push(validated_remote, validated_branch, "--force")
            return f"Force pushed {validated_branch} to {validated_remote}"
        else:
            repo.git.push(validated_remote, validated_branch)
            return f"Pushed {validated_branch} to {validated_remote}"
    except GitCommandError as e:
        raise SecurityError(sanitize_error_message(e))


def git_fetch(
    repo: git.Repo,
    remote: str,
    branch: str | None = None,
    all_remotes: bool = False,
) -> str:
    try:
        if all_remotes:
            repo.git.fetch("--all")
            return "Fetched from all remotes"
        elif branch is None:
            # Validate remote name
            validated_remote = validate_branch_name(remote)
            # Fetch all branches from the specified remote
            repo.git.fetch(validated_remote)
            return f"Fetched from {validated_remote}"
        else:
            # Validate remote and branch names
            validated_remote = validate_branch_name(remote)
            validated_branch = validate_branch_name(branch)
            repo.git.fetch(validated_remote, validated_branch)
            return f"Fetched {validated_branch} from {validated_remote}"
    except GitCommandError as e:
        raise SecurityError(sanitize_error_message(e))


def git_switch_create(
    repo: git.Repo, branch_name: str, base_branch: str | None = None
) -> str:
    try:
        # Validate branch name
        validated_branch_name = validate_branch_name(branch_name)

        if base_branch:
            validated_base_branch = validate_branch_name(base_branch)
            repo.git.switch("-c", validated_branch_name, validated_base_branch)
            return f"Created and switched to branch '{validated_branch_name}' from '{validated_base_branch}'"
        else:
            repo.git.switch("-c", validated_branch_name)
            return f"Created and switched to branch '{validated_branch_name}'"
    except GitCommandError as e:
        raise SecurityError(sanitize_error_message(e))


async def serve(repository: Path | None) -> None:
    logger = logging.getLogger(__name__)

    if repository is not None:
        try:
            git.Repo(repository)
            logger.info(f"Using repository at {repository}")
        except git.InvalidGitRepositoryError:
            logger.error(f"{repository} is not a valid Git repository")
            return

    server = Server("mcp-server-git")

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool(
                name=GitTools.STATUS,
                description="Shows the working tree status",
                inputSchema=GitStatus.model_json_schema(),
            ),
            Tool(
                name=GitTools.DIFF_UNSTAGED,
                description="Shows changes in the working directory that are not yet staged",
                inputSchema=GitDiffUnstaged.model_json_schema(),
            ),
            Tool(
                name=GitTools.DIFF_STAGED,
                description="Shows changes that are staged for commit",
                inputSchema=GitDiffStaged.model_json_schema(),
            ),
            Tool(
                name=GitTools.DIFF,
                description="Shows differences between branches or commits",
                inputSchema=GitDiff.model_json_schema(),
            ),
            Tool(
                name=GitTools.COMMIT,
                description="Records changes to the repository",
                inputSchema=GitCommit.model_json_schema(),
            ),
            Tool(
                name=GitTools.ADD,
                description="Adds file contents to the staging area",
                inputSchema=GitAdd.model_json_schema(),
            ),
            Tool(
                name=GitTools.RESET,
                description="Unstages all staged changes",
                inputSchema=GitReset.model_json_schema(),
            ),
            Tool(
                name=GitTools.LOG,
                description="Shows the commit logs",
                inputSchema=GitLog.model_json_schema(),
            ),
            Tool(
                name=GitTools.CREATE_BRANCH,
                description="Creates a new branch from an optional base branch",
                inputSchema=GitCreateBranch.model_json_schema(),
            ),
            Tool(
                name=GitTools.CHECKOUT,
                description="Switches branches",
                inputSchema=GitCheckout.model_json_schema(),
            ),
            Tool(
                name=GitTools.SHOW,
                description="Shows the contents of a commit",
                inputSchema=GitShow.model_json_schema(),
            ),
            Tool(
                name=GitTools.INIT,
                description="Initialize a new Git repository",
                inputSchema=GitInit.model_json_schema(),
            ),
            Tool(
                name=GitTools.BRANCH,
                description="List Git branches",
                inputSchema=GitBranch.model_json_schema(),
            ),
            Tool(
                name=GitTools.CHERRY_PICK,
                description="Cherry-pick a commit to the current branch",
                inputSchema=GitCherryPick.model_json_schema(),
            ),
            Tool(
                name=GitTools.LIST_REMOTES,
                description="List configured remotes",
                inputSchema=GitListRemotes.model_json_schema(),
            ),
            Tool(
                name=GitTools.PULL,
                description="Pull changes from remote repository",
                inputSchema=GitPull.model_json_schema(),
            ),
            Tool(
                name=GitTools.PUSH,
                description="Push changes to remote repository",
                inputSchema=GitPush.model_json_schema(),
            ),
            Tool(
                name=GitTools.FETCH,
                description="Fetch changes from remote repository",
                inputSchema=GitFetch.model_json_schema(),
            ),
            Tool(
                name=GitTools.SWITCH_CREATE,
                description="Switches to a new branch or creates it from an optional base branch",
                inputSchema=GitSwitchCreate.model_json_schema(),
            ),
        ]

    async def list_repos() -> Sequence[str]:
        async def by_roots() -> Sequence[str]:
            if not isinstance(server.request_context.session, ServerSession):
                raise TypeError(
                    "server.request_context.session must be a ServerSession"
                )

            if not server.request_context.session.check_client_capability(
                ClientCapabilities(roots=RootsCapability())
            ):
                return []

            roots_result: ListRootsResult = (
                await server.request_context.session.list_roots()
            )
            logger.debug(f"Roots result: {roots_result}")
            repo_paths = []
            for root in roots_result.roots:
                path = root.uri.path
                try:
                    git.Repo(path)
                    repo_paths.append(str(path))
                except git.InvalidGitRepositoryError:
                    pass
            return repo_paths

        def by_commandline() -> Sequence[str]:
            return [str(repository)] if repository is not None else []

        cmd_repos = by_commandline()
        root_repos = await by_roots()
        return [*root_repos, *cmd_repos]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> list[TextContent]:
        try:
            # Validate and sanitize repo_path
            repo_path_str = arguments["repo_path"]
            validated_repo_path = validate_repo_path(repo_path_str)

            # Handle git init separately since it doesn't require an existing repo
            if name == GitTools.INIT:
                result = git_init(str(validated_repo_path))
                return [TextContent(type="text", text=result)]

            # For all other commands, we need an existing repo
            repo = git.Repo(validated_repo_path)

        except SecurityError as e:
            return [TextContent(type="text", text=f"Security error: {str(e)}")]
        except Exception as e:
            return [
                TextContent(type="text", text=f"Error: {sanitize_error_message(e)}")
            ]

        try:
            match name:
                case GitTools.STATUS:
                    status = git_status(repo)
                    return [
                        TextContent(type="text", text=f"Repository status:\n{status}")
                    ]

                case GitTools.DIFF_UNSTAGED:
                    diff = git_diff_unstaged(
                        repo, arguments.get("context_lines", DEFAULT_CONTEXT_LINES)
                    )
                    return [TextContent(type="text", text=f"Unstaged changes:\n{diff}")]

                case GitTools.DIFF_STAGED:
                    diff = git_diff_staged(
                        repo, arguments.get("context_lines", DEFAULT_CONTEXT_LINES)
                    )
                    return [TextContent(type="text", text=f"Staged changes:\n{diff}")]

                case GitTools.DIFF:
                    diff = git_diff(
                        repo,
                        arguments["target"],
                        arguments.get("context_lines", DEFAULT_CONTEXT_LINES),
                    )
                    return [
                        TextContent(
                            type="text",
                            text=f"Diff with {arguments['target']}:\n{diff}",
                        )
                    ]

                case GitTools.COMMIT:
                    result = git_commit(repo, arguments["message"])
                    return [TextContent(type="text", text=result)]

                case GitTools.ADD:
                    result = git_add(repo, arguments["files"])
                    return [TextContent(type="text", text=result)]

                case GitTools.RESET:
                    result = git_reset(repo)
                    return [TextContent(type="text", text=result)]

                case GitTools.LOG:
                    log = git_log(repo, arguments.get("max_count", 10))
                    return [
                        TextContent(
                            type="text", text="Commit history:\n" + "\n".join(log)
                        )
                    ]

                case GitTools.CREATE_BRANCH:
                    result = git_create_branch(
                        repo, arguments["branch_name"], arguments.get("base_branch")
                    )
                    return [TextContent(type="text", text=result)]

                case GitTools.CHECKOUT:
                    result = git_checkout(repo, arguments["branch_name"])
                    return [TextContent(type="text", text=result)]

                case GitTools.SHOW:
                    result = git_show(repo, arguments["revision"])
                    return [TextContent(type="text", text=result)]

                case GitTools.BRANCH:
                    result = git_branch(
                        repo,
                        arguments.get("branch_type", "local"),
                        arguments.get("contains", None),
                        arguments.get("not_contains", None),
                    )
                    return [TextContent(type="text", text=result)]

                case GitTools.CHERRY_PICK:
                    result = git_cherry_pick(
                        repo, arguments["commit_sha"], arguments.get("no_commit", False)
                    )
                    return [TextContent(type="text", text=result)]

                case GitTools.LIST_REMOTES:
                    result = git_list_remotes(repo, arguments.get("verbose", False))
                    return [TextContent(type="text", text=result)]

                case GitTools.PULL:
                    result = git_pull(
                        repo,
                        arguments["remote"],
                        arguments["branch"],
                    )
                    return [TextContent(type="text", text=result)]

                case GitTools.PUSH:
                    result = git_push(
                        repo,
                        arguments["remote"],
                        arguments["branch"],
                        arguments.get("force", False),
                    )
                    return [TextContent(type="text", text=result)]

                case GitTools.FETCH:
                    result = git_fetch(
                        repo,
                        arguments["remote"],
                        arguments.get("branch", None),
                        arguments.get("all_remotes", False),
                    )
                    return [TextContent(type="text", text=result)]

                case GitTools.SWITCH_CREATE:
                    result = git_switch_create(
                        repo,
                        arguments["branch_name"],
                        arguments.get("base_branch"),
                    )
                    return [TextContent(type="text", text=result)]

                case _:
                    raise ValueError(f"Unknown tool: {name}")

        except SecurityError as e:
            return [TextContent(type="text", text=f"Security error: {str(e)}")]
        except Exception as e:
            return [
                TextContent(type="text", text=f"Error: {sanitize_error_message(e)}")
            ]

    options = server.create_initialization_options()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, options, raise_exceptions=True)
