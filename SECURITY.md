# Security Guide

## Overview

This document outlines the security measures implemented in mcp-server-git and provides guidance for secure deployment and usage.

## Security Features

### 1. Input Validation

All user inputs are thoroughly validated to prevent various attack vectors:

- **Path Validation**: Repository paths are validated to prevent directory traversal attacks
- **Branch Name Validation**: Branch names must follow git naming conventions
- **Commit Message Validation**: Commit messages are checked for length and dangerous characters
- **File Path Validation**: File paths in operations are validated against path traversal attempts
- **Commit Hash Validation**: Commit hashes must follow proper hexadecimal format

### 2. Error Message Sanitization

Error messages are sanitized to prevent information disclosure:

- File paths are replaced with generic `[PATH]` placeholders
- User information is replaced with `[USER]` placeholders
- Error message length is limited to prevent resource exhaustion
- System information is stripped from error responses

### 3. Docker Security

The Docker image implements security best practices:

- **Non-root User**: Runs as a dedicated `mcpuser` (UID 1000) instead of root
- **Read-only Filesystem**: Container filesystem is read-only where possible
- **Minimal Attack Surface**: Uses slim base images with minimal packages
- **Security Labels**: Includes security scanning and non-root labels
- **Proper File Permissions**: Application files have appropriate ownership

### 4. Resource Limits

Various limits are imposed to prevent resource exhaustion:

- Maximum path length: 4096 characters
- Maximum branch name length: 255 characters
- Maximum commit message length: 8192 characters
- Maximum file list size: 100 files
- Maximum git log entries: 1000 commits
- Maximum context lines in diff: 100 lines

## Secure Deployment

### Docker Security Configuration

When running the Docker container, use these security options:

```bash
docker run \
  --rm \
  -i \
  --security-opt=no-new-privileges:true \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=100m \
  --mount type=bind,src=/path/to/your/repos,dst=/workspace \
  --user 1000:1000 \
  mcp/git \
  --repository /workspace/your-repo
```

### Environment Configuration

For production deployments:

1. **Limit Repository Access**: Only mount specific repository directories, not entire user directories
2. **Use Read-only Mounts**: When possible, mount repositories as read-only
3. **Network Security**: Run containers in isolated networks if network access is not needed
4. **Regular Updates**: Keep the base image and dependencies updated
5. **Security Scanning**: Regularly scan the container image for vulnerabilities

### Access Control

- Implement proper authentication and authorization at the MCP client level
- Use principle of least privilege for file system access
- Consider implementing audit logging for git operations
- Monitor for suspicious activity patterns

## Security Considerations

### Threat Model

This server is designed to be used in trusted environments where:

- The MCP client is trusted
- The user has legitimate access to the specified repositories
- The server runs with appropriate system-level restrictions

### Known Limitations

- The server inherits the security model of the underlying Git installation
- File system permissions are enforced by the OS, not the server
- Network operations (clone, fetch, push, pull) depend on git's security
- The server does not implement its own authentication mechanism

### Reporting Security Issues

If you discover a security vulnerability, please report it via:

- GitHub Security Advisories (preferred)
- Email to the maintainers with "SECURITY" in the subject line

Please do not report security vulnerabilities through public GitHub issues.

## Security Testing

The project includes comprehensive security tests covering:

- Path validation and traversal prevention
- Input validation for all parameters
- Error message sanitization
- Git operation security
- Docker security configuration

Run security tests with:

```bash
pytest tests/test_security.py -v
```

## Security Checklist

### Pre-deployment Checklist

- [ ] Review and approve all repository paths that will be accessible
- [ ] Configure Docker with appropriate security options
- [ ] Implement proper access controls at the client level
- [ ] Set up monitoring and logging
- [ ] Test security configurations in a staging environment

### Regular Security Maintenance

- [ ] Update base Docker images regularly
- [ ] Review and update dependency versions
- [ ] Monitor security advisories for GitPython and other dependencies
- [ ] Review access logs for suspicious activity
- [ ] Test security configurations after updates

### Incident Response

If you suspect a security incident:

1. Immediately isolate the affected system
2. Document the incident
3. Review logs for signs of compromise
4. Update security configurations as needed
5. Report the incident if required by your organization's policies

## Additional Resources

- [Git Security Best Practices](https://git-scm.com/book/en/v2/Git-on-the-Server-Securing-Git)
- [Docker Security Best Practices](https://docs.docker.com/develop/security-best-practices/)
- [Python Security Guidelines](https://python-security.readthedocs.io/guidelines.html)

---

**Last Updated**: [Current Date]
**Version**: 1.0
