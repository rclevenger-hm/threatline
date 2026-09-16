# Workspace setup

Threatline v1.0 uses a local first-run setup flow so Jira and GitHub can be configured without editing source files or maintaining a `.env` file.

## First run

Start Threatline and open `http://127.0.0.1:8080`. When no saved workspace exists, the root page opens the setup flow. Demo mode is available with no credentials and is the quickest way to evaluate the product loop.

The setup page supports:

- naming and saving local workspaces;
- enabling Demo, Jira, and GitHub providers independently;
- testing a provider connection before saving;
- selecting and activating an existing workspace;
- configuring GitHub.com or GitHub Enterprise Server URLs;
- configuring Jira Cloud, Server, or Data Center endpoints.

## Local configuration boundary

Ordinary workspace settings are written to `~/.threatline/config.json` by default. Provider credentials are written separately to `~/.threatline/secrets.json`. Both files are created with owner-only permissions where the operating system supports POSIX file modes.

Set `THREATLINE_CONFIG_DIR` to move both files to another local directory.

The browser setup API returns only ordinary settings plus booleans indicating whether credential fields are already populated. Stored credential values are not returned to the browser. Leaving an existing credential field blank in the setup page preserves the stored value.

## Environment configuration compatibility

Existing environment-based configuration remains supported. If `THREATLINE_PROVIDERS` or `THREATLINE_PROVIDER` is explicitly set, Threatline continues to build the provider registry from environment variables unless a saved workspace is active.

A saved workspace takes precedence for normal local startup because it is the configuration selected by the user in the product.

## Provider connection tests

Connection tests use the same provider health checks as the running workspace. A successful test reports provider health and discovered capabilities. Failed external connections are reported without taking down other providers or the local application.

Demo mode always remains available as a zero-credential path.
