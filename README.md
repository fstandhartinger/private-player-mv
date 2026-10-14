# private-player

Minimal private video player served under secret path prefixes. Media are stored only as AES-256-GCM encrypted blobs in enc/ (pack.js); the key lives in the deployment env (V_KEY) and is never committed. Paths: V_PATHS env. noindex/nofollow everywhere.
