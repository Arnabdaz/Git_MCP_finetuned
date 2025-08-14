import pytest
from pathlib import Path
import git
from mcp_server_git.server import (
    git_checkout, 
    git_branch, 
    git_status,
    git_add,
    git_commit,
    git_create_branch,
    git_init,
    git_log,
    git_show
)
import shutil
import os

@pytest.fixture
def test_repository(tmp_path: Path):
    repo_path = tmp_path / "temp_test_repo"
    test_repo = git.Repo.init(repo_path)

    Path(repo_path / "test.txt").write_text("test")
    test_repo.index.add(["test.txt"])
    test_repo.index.commit("initial commit")

    yield test_repo

    shutil.rmtree(repo_path)

def test_git_checkout_existing_branch(test_repository):
    test_repository.git.branch("test-branch")
    result = git_checkout(test_repository, "test-branch")

    assert "Switched to branch 'test-branch'" in result
    assert test_repository.active_branch.name == "test-branch"

def test_git_checkout_nonexistent_branch(test_repository):

    with pytest.raises(git.GitCommandError):
        git_checkout(test_repository, "nonexistent-branch")

def test_git_branch_local(test_repository):
    test_repository.git.branch("new-branch-local")
    result = git_branch(test_repository, "local")
    assert "new-branch-local" in result

def test_git_branch_remote(test_repository):
    # GitPython does not easily support creating remote branches without a remote.
    # This test will check the behavior when 'remote' is specified without actual remotes.
    result = git_branch(test_repository, "remote")
    assert "" == result.strip()  # Should be empty if no remote branches

def test_git_branch_all(test_repository):
    test_repository.git.branch("new-branch-all")
    result = git_branch(test_repository, "all")
    assert "new-branch-all" in result

def test_git_branch_contains(test_repository):
    # Get the current branch name before creating new branch
    original_branch = test_repository.active_branch.name
    
    # Create a new branch and commit to it
    test_repository.git.checkout("-b", "feature-branch")
    Path(test_repository.working_dir / Path("feature.txt")).write_text("feature content")
    test_repository.index.add(["feature.txt"])
    commit = test_repository.index.commit("feature commit")
    test_repository.git.checkout(original_branch)

    result = git_branch(test_repository, "local", contains=commit.hexsha)
    assert "feature-branch" in result
    assert original_branch not in result

def test_git_branch_not_contains(test_repository):
    # Get the current branch name before creating new branch
    original_branch = test_repository.active_branch.name
    
    # Create a new branch and commit to it
    test_repository.git.checkout("-b", "another-feature-branch")
    Path(test_repository.working_dir / Path("another_feature.txt")).write_text("another feature content")
    test_repository.index.add(["another_feature.txt"])
    commit = test_repository.index.commit("another feature commit")
    test_repository.git.checkout(original_branch)

    result = git_branch(test_repository, "local", not_contains=commit.hexsha)
    assert "another-feature-branch" not in result
    assert original_branch in result


def test_git_status(test_repository):
    # Create a new file
    test_file = Path(test_repository.working_dir) / "new_file.txt"
    test_file.write_text("new content")
    
    result = git_status(test_repository)
    assert "new_file.txt" in result
    assert "Untracked files" in result or "untracked" in result.lower()


def test_git_add(test_repository):
    # Create a new file
    test_file = Path(test_repository.working_dir) / "add_test.txt"
    test_file.write_text("content to add")
    
    result = git_add(test_repository, ["add_test.txt"])
    assert "staged successfully" in result.lower()


def test_git_commit(test_repository):
    # Create and stage a file
    test_file = Path(test_repository.working_dir) / "commit_test.txt"
    test_file.write_text("content to commit")
    test_repository.index.add(["commit_test.txt"])
    
    result = git_commit(test_repository, "Test commit message")
    assert "committed successfully" in result.lower()
    assert "hash" in result.lower()


def test_git_create_branch(test_repository):
    result = git_create_branch(test_repository, "new-test-branch")
    assert "Created branch 'new-test-branch'" in result
    
    # Verify branch exists
    branches = [branch.name for branch in test_repository.branches]
    assert "new-test-branch" in branches


def test_git_log(test_repository):
    result = git_log(test_repository, max_count=5)
    assert isinstance(result, list)
    assert len(result) >= 1  # Should have at least the initial commit
    assert "initial commit" in result[0]


def test_git_show(test_repository):
    # Get the latest commit hash
    latest_commit = test_repository.head.commit
    
    result = git_show(test_repository, latest_commit.hexsha)
    assert latest_commit.hexsha in result
    assert "initial commit" in result


def test_git_init():
    # Test git init in a temporary directory
    temp_dir = Path("test_init_repo")
    try:
        result = git_init(str(temp_dir))
        assert "Initialized empty Git repository" in result
        assert temp_dir.exists()
        
        # Verify it's actually a git repo
        repo = git.Repo(temp_dir)
        assert repo.git_dir is not None
        
    finally:
        # Clean up
        if temp_dir.exists():
            shutil.rmtree(temp_dir)
