# Server Deployment

This section specifies a defensible deployment model for `seal server`.

## Deployment architecture

A reference production topology is:

```text
operator/CI client
  -> authenticated gateway (mTLS or OIDC proxy)
  -> internal reverse proxy
  -> seal server (private network)
  -> sandbox backend runtime (for example Docker host)
```

The server should not be exposed directly to public networks.

## Minimal secure startup

```bash
seal server --bind 127.0.0.1:9090 \
  --compile-dir /var/lib/snapfzz-seal/compile \
  --output-dir /var/lib/snapfzz-seal/output
```

This should be placed behind an authenticated ingress layer.

## Configuration management

### Directory controls

- Compile and output directories should be isolated per environment.
- Directory ownership should be restricted to dedicated service identities.
- Artifact retention policy should be explicit and enforced.

### Environment controls

Recommended operational environment:

```bash
export RUST_LOG=info
export DOCKER_BIN=/usr/bin/docker
```

### Service unit example (systemd)

```ini
[Unit]
Description=Snapfzz Seal Server
After=network.target

[Service]
User=snapfzz
Group=snapfzz
ExecStart=/usr/local/bin/seal server --bind 127.0.0.1:9090 --compile-dir /var/lib/snapfzz-seal/compile --output-dir /var/lib/snapfzz-seal/output
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true

[Install]
WantedBy=multi-user.target
```

## Operational considerations

### Monitoring

- Track compile failures, dispatch failures, and timeout rates.
- Alert on repeated unauthorized request patterns.
- Record artifact hash and job identifiers for forensic traceability.

### Backup and retention

- Keep only required artifacts and logs according to policy.
- Store audit records in immutable or append-only systems where possible.

### Incident handling

If compromise is suspected:

1. Isolate server from network.
2. Revoke active signing and deployment trust as needed.
3. Rebuild artifacts and rotate keys.
4. Re-establish service from trusted infrastructure.

## Security considerations

- Server API is not authenticated by default and must be fronted by an explicit auth layer.
- TLS termination and client identity validation should be enforced at the gateway.
- Sandbox command execution paths should be constrained by runtime policy.

## Limitations

- Native RBAC and token-based auth are not implemented in core server endpoints.
- Multi-tenant isolation policies are deployment-managed, not server-native.
