# Server Deployment

## Security Requirements

⚠️ **The server API is unauthenticated.** Never expose beyond localhost without:
- mTLS gateway
- OAuth proxy
- VPN tunnel
- Unix socket + reverse proxy

## Recommended Setup

### Option 1: Unix Socket + Reverse Proxy

```bash
# Start server on Unix socket
seal server --bind /var/run/agent-seal.sock

# Nginx reverse proxy with auth
# /etc/nginx/sites-available/agent-seal
server {
    listen 443 ssl;
    server_name seal.example.com;

    ssl_certificate /etc/letsencrypt/live/seal.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/seal.example.com/privkey.pem;

    location / {
        proxy_pass http://unix:/var/run/agent-seal.sock;
        proxy_set_header Host $host;

        # Add authentication
        auth_basic "Agent Seal";
        auth_basic_user_file /etc/nginx/.htpasswd;
    }
}
```

### Option 2: Localhost + SSH Tunnel

```bash
# Server binds to localhost only
seal server --bind 127.0.0.1:9090

# Access via SSH tunnel
ssh -L 9090:127.0.0.1:9090 user@server
```

### Option 3: Cloudflare Access

1. Bind server to localhost
2. Use Cloudflare Tunnel (`cloudflared`)
3. Enable Cloudflare Access for authentication

## Production Checklist

- [ ] Server binds to localhost or Unix socket only
- [ ] Authentication layer in front of API
- [ ] TLS enabled for all connections
- [ ] `compile-dir` and `output-dir` on secure filesystem
- [ ] Logs captured and monitored
- [ ] Rate limiting configured

## Monitoring

```bash
# Health check
curl http://127.0.0.1:9090/health

# Response
{
  "status": "healthy",
  "job_count": 5
}
```