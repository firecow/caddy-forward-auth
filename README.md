# caddy-forward-auth
Forward auth middleware for caddyserver

[![Github Action](https://github.com/firecow/caddy-forward-auth/actions/workflows/go-qa.yml/badge.svg)](https://github.com/firecow/caddy-forward-auth/actions/workflows/go-qa.yml)
[![Release](https://img.shields.io/github/v/release/firecow/caddy-forward-auth?sort=semver)](https://github.com/firecow/caddy-forward-auth)
[![License](https://img.shields.io/github/license/firecow/gitlab-ci-local)](https://github.com/firecow/caddy-forward-auth)
[![Renovate](https://img.shields.io/badge/renovate-enabled-brightgreen.svg)](https://renovatebot.com)

```caddyfile
:80

route * {
    forward_auth https://sso.example.com/auth
    reverse_proxy http://webserver:3000
}
```