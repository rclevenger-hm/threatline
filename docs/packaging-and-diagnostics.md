# Packaging and diagnostics

Threatline v1.0 is designed to run locally with Python 3.12+ or as a single Docker container. The browser setup flow is the preferred way to configure a workspace; environment-based provider configuration remains available for existing deployments.

## Direct local launch

From a source checkout:

```bash
python -m threatline
```

An installed package also exposes the same launcher:

```bash
threatline
```

The default listener is `127.0.0.1:8080`. Override it with `THREATLINE_HOST` and `THREATLINE_PORT` when needed.

Workspace configuration defaults to `~/.threatline`. Runtime journal data defaults to `.runtime` under the current working directory. Both locations can be changed without editing source:

- `THREATLINE_CONFIG_DIR` controls `config.json` and `secrets.json`.
- `THREATLINE_DATA_DIR` controls journal/runtime data.

These paths use Python's platform-neutral path handling and work on Windows, macOS, and Linux. Prefer absolute paths when launching Threatline from a service manager or another working directory.

## Docker Compose

Start the local container with:

```bash
docker compose up --build
```

The Compose definition binds the browser endpoint to loopback at `127.0.0.1:8080` and stores workspace configuration and runtime data in the named `threatline-state` volume. It does not force the demo provider. A fresh volume therefore opens first-run setup, while a configured volume restores the selected workspace on later starts.

The image includes a `/healthz` health check. Docker marks the container unhealthy when the local HTTP service cannot answer successfully.

To reset a Docker-only evaluation and remove its persisted local state:

```bash
docker compose down -v
```

## Startup and provider diagnostics

Startup output identifies the running Threatline version, bound address, configured provider names, and providers whose health check is unavailable. It deliberately does not print provider credentials.

Runtime diagnostics are available from:

- `GET /healthz` for a compact service/provider health result;
- `GET /api/diagnostics` for application, runtime, configuration-version, storage-presence, and provider diagnostic information;
- `GET /api/support-bundle` for the same safe diagnostic payload as a downloadable JSON support bundle.

Support bundles contain ordinary workspace configuration and runtime metadata because those values are useful for troubleshooting. Stored credential values are excluded and known active secret values are redacted from diagnostic strings. Review a bundle before sharing it if workspace names, repository names, internal service URLs, or similar non-secret metadata are sensitive in your environment.

## Configuration versioning

Workspace and secret documents carry an explicit schema version. v1.0 currently uses configuration schema version `1`.

Unversioned legacy documents are normalized to the current schema when they are loaded and are rewritten with the current version while preserving compatible workspace data. Documents declaring a schema newer than the running Threatline build are rejected instead of being silently rewritten. This provides a stable migration boundary for later releases.

## Validation

The repository regression suite runs on Python 3.12 across Linux, macOS, and Windows. CI also validates the Compose file and builds the release Docker image on Linux so packaging regressions fail before merge.
