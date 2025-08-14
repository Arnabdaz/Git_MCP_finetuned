"""
Security tests for MCP Git Server.

These tests verify that our security validations work correctly and prevent
various attack scenarios.
"""

import pytest
from pathlib import Path
import tempfile
import git
from mcp_server_git.server import (
    SecurityError,
    validate_repo_path,
    validate_branch_name,
    validate_commit_message,
    validate_file_list,
    validate_commit_hash,
    sanitize_error_message,
    git_init,
    git_add,
    git_commit,
    git_checkout,
    git_create_branch,
    git_cherry_pick,
    git_pull,
    git_push,
    git_branch,
)


class TestPathValidation:
    """Test path validation security."""

    def test_valid_path(self):
        """Test that valid paths are accepted."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            result = validate_repo_path(tmp_dir)
            assert isinstance(result, Path)

    def test_path_traversal_attempts(self):
        """Test that path traversal attempts are blocked."""
        dangerous_paths = [
            "../../../etc/passwd",
            "repo/../../../etc/passwd",
            "/etc/passwd",
            "repo/../../sensitive_file",
            "repo/../.ssh/id_rsa",
        ]

        for path in dangerous_paths:
            with pytest.raises(
                SecurityError,
                match="Path contains suspicious components|Invalid repository path",
            ):
                validate_repo_path(path)

    def test_path_length_limit(self):
        """Test that excessively long paths are rejected."""
        long_path = "a" * 5000  # Exceeds MAX_PATH_LENGTH
        with pytest.raises(SecurityError, match="Invalid repository path length"):
            validate_repo_path(long_path)

    def test_empty_path(self):
        """Test that empty paths are rejected."""
        with pytest.raises(SecurityError, match="Invalid repository path length"):
            validate_repo_path("")

    def test_allowed_paths_restriction(self):
        """Test that allowed paths restriction works."""
        with tempfile.TemporaryDirectory() as allowed_dir:
            with tempfile.TemporaryDirectory() as forbidden_dir:
                # This should work
                validate_repo_path(allowed_dir, [allowed_dir])

                # This should fail
                with pytest.raises(
                    SecurityError, match="Repository path not in allowed directories"
                ):
                    validate_repo_path(forbidden_dir, [allowed_dir])


class TestBranchNameValidation:
    """Test branch name validation security."""

    def test_valid_branch_names(self):
        """Test that valid branch names are accepted."""
        valid_names = [
            "main",
            "feature/new-feature",
            "bugfix-123",
            "release-1.0.0",
            "user/feature-branch",
            "v1.2.3",
        ]

        for name in valid_names:
            result = validate_branch_name(name)
            assert result == name

    def test_invalid_branch_names(self):
        """Test that invalid branch names are rejected."""
        invalid_names = [
            "",  # Empty
            "a" * 300,  # Too long
            "branch with spaces",  # Spaces
            "branch@{upstream}",  # Special git syntax
            ".branch",  # Starts with dot
            "branch.",  # Ends with dot
            "-branch",  # Starts with dash
            "branch-",  # Ends with dash
            "branch..other",  # Double dots
            "branch/",  # Ends with slash
            "/branch",  # Starts with slash
        ]

        for name in invalid_names:
            with pytest.raises(SecurityError, match="Invalid branch name"):
                validate_branch_name(name)

    def test_reserved_names(self):
        """Test that git reserved names are rejected."""
        reserved_names = ["HEAD", "ORIG_HEAD", "FETCH_HEAD", "MERGE_HEAD"]

        for name in reserved_names:
            with pytest.raises(
                SecurityError, match="Branch name conflicts with git reserved names"
            ):
                validate_branch_name(name)


class TestCommitMessageValidation:
    """Test commit message validation security."""

    def test_valid_commit_messages(self):
        """Test that valid commit messages are accepted."""
        valid_messages = [
            "Fix bug in authentication",
            "Add new feature\n\nThis is a longer description\nwith multiple lines.",
            "Update dependencies",
            "feat: add new functionality",
        ]

        for message in valid_messages:
            result = validate_commit_message(message)
            assert result == message.strip()

    def test_invalid_commit_messages(self):
        """Test that invalid commit messages are rejected."""
        # Empty message
        with pytest.raises(SecurityError, match="Invalid commit message length"):
            validate_commit_message("")

        # Too long message
        long_message = "a" * 10000
        with pytest.raises(SecurityError, match="Invalid commit message length"):
            validate_commit_message(long_message)

        # Message with null byte
        with pytest.raises(
            SecurityError, match="Commit message contains invalid characters"
        ):
            validate_commit_message("Normal message\x00with null")

        # Message with control characters
        with pytest.raises(
            SecurityError, match="Commit message contains invalid characters"
        ):
            validate_commit_message("Normal message\x01with control char")


class TestFileListValidation:
    """Test file list validation security."""

    def test_valid_file_lists(self):
        """Test that valid file lists are accepted."""
        valid_lists = [
            ["file1.txt", "file2.py"],
            ["src/main.py", "tests/test_main.py"],
            ["README.md"],
        ]

        for file_list in valid_lists:
            result = validate_file_list(file_list)
            assert result == file_list

    def test_invalid_file_lists(self):
        """Test that invalid file lists are rejected."""
        # Empty list
        with pytest.raises(SecurityError, match="Invalid file list size"):
            validate_file_list([])

        # Too many files
        large_list = [f"file{i}.txt" for i in range(200)]
        with pytest.raises(SecurityError, match="Invalid file list size"):
            validate_file_list(large_list)

        # File with path traversal
        with pytest.raises(
            SecurityError, match="File path contains dangerous components"
        ):
            validate_file_list(["../etc/passwd"])

        # Absolute path
        with pytest.raises(
            SecurityError, match="File path contains dangerous components"
        ):
            validate_file_list(["/etc/passwd"])

        # Windows path
        with pytest.raises(
            SecurityError, match="File path contains dangerous components"
        ):
            validate_file_list(["C:\\Windows\\system32\\config\\sam"])


class TestCommitHashValidation:
    """Test commit hash validation security."""

    def test_valid_commit_hashes(self):
        """Test that valid commit hashes are accepted."""
        valid_hashes = [
            "abc123",  # Short hash
            "a1b2c3d4e5f6",  # Medium hash
            "1234567890abcdef1234567890abcdef12345678",  # Full SHA-1
        ]

        for hash_val in valid_hashes:
            result = validate_commit_hash(hash_val)
            assert result == hash_val

    def test_invalid_commit_hashes(self):
        """Test that invalid commit hashes are rejected."""
        invalid_hashes = [
            "",  # Empty
            "xyz123",  # Invalid characters
            "12345",  # Too short
            "a" * 50,  # Too long
            "123-456",  # Invalid characters
        ]

        for hash_val in invalid_hashes:
            with pytest.raises(SecurityError):
                validate_commit_hash(hash_val)


class TestErrorMessageSanitization:
    """Test error message sanitization."""

    def test_path_sanitization(self):
        """Test that file paths are sanitized in error messages."""
        error = Exception("Error accessing /home/user/sensitive/file.txt")
        sanitized = sanitize_error_message(error)
        assert "/home/user/sensitive/file.txt" not in sanitized
        assert "/[PATH]/" in sanitized

    def test_user_info_sanitization(self):
        """Test that user information is sanitized."""
        error = Exception("Authentication failed for user: john_doe")
        sanitized = sanitize_error_message(error)
        assert "john_doe" not in sanitized
        assert "user: [USER]" in sanitized

    def test_message_length_limit(self):
        """Test that error messages are truncated if too long."""
        long_message = "Error: " + "a" * 1000
        error = Exception(long_message)
        sanitized = sanitize_error_message(error)
        assert len(sanitized) <= 500
        assert sanitized.endswith("...")


class TestGitFunctionSecurity:
    """Test that git functions properly validate inputs."""

    @pytest.fixture
    def test_repo(self, tmp_path):
        """Create a test git repository."""
        repo_path = tmp_path / "test_repo"
        repo = git.Repo.init(repo_path)

        # Create initial commit
        test_file = repo_path / "test.txt"
        test_file.write_text("test content")
        repo.index.add(["test.txt"])
        repo.index.commit("Initial commit")

        return repo

    def test_git_add_validates_files(self, test_repo):
        """Test that git_add validates file list."""
        # Valid files should work
        git_add(test_repo, ["test.txt"])

        # Invalid files should fail
        with pytest.raises(SecurityError):
            git_add(test_repo, ["../etc/passwd"])

    def test_git_commit_validates_message(self, test_repo):
        """Test that git_commit validates commit message."""
        # Stage a file first
        test_file = Path(test_repo.working_dir) / "new_file.txt"
        test_file.write_text("new content")
        test_repo.index.add(["new_file.txt"])

        # Valid commit should work
        git_commit(test_repo, "Valid commit message")

        # Invalid commit message should fail
        with pytest.raises(SecurityError):
            git_commit(test_repo, "Message with null\x00byte")

    def test_git_checkout_validates_branch_name(self, test_repo):
        """Test that git_checkout validates branch names."""
        # Create a valid branch first
        test_repo.create_head("valid-branch")

        # Valid branch should work
        git_checkout(test_repo, "valid-branch")

        # Invalid branch name should fail
        with pytest.raises(SecurityError):
            git_checkout(test_repo, "invalid branch name")

    def test_git_create_branch_validates_names(self, test_repo):
        """Test that git_create_branch validates branch names."""
        # Valid branch creation should work
        git_create_branch(test_repo, "new-feature")

        # Invalid branch name should fail
        with pytest.raises(SecurityError):
            git_create_branch(test_repo, "")  # Empty name

    def test_git_init_validates_path(self):
        """Test that git_init validates repository path."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            # Valid path should work
            git_init(tmp_dir)

        # Invalid path should fail
        with pytest.raises(SecurityError):
            git_init("../../../etc")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
