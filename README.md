# caddy-forward-auth

!!!!! DISCONTINUED !!!!!
This is now possible directly in Caddy 2.5.1
```
:80

route {
    reverse_proxy https://sso.firecow.dk {
        method GET
        rewrite /auth

        header_up Host {upstream_host}
        header_up X-Forwarded-Method {method}
        header_up X-Forwarded-Uri {uri}
        header_up X-Forwarded-Proto {header.X-Forwarded-Proto}

        @good status 2xx
        handle_response @good {
            request_header Remote-User {rp.header.Remote-User}
            request_header Authorization {rp.header.Authorization}       
        }
        handle_response {
            copy_response_headers {
                exclude Connection Keep-Alive Te Trailers Transfer-Encoding Upgrade
            }
            copy_response
        }
    }
    reverse_proxy http://webserver:8080
}
```


Forward auth middleware for caddyserver

Rougly based on https://doc.traefik.io/traefik/middlewares/http/forwardauth/

[![quality](https://img.shields.io/github/workflow/status/firecow/caddy-forward-auth/build)](https://github.com/firecow/caddy-forward-auth/actions)
[![License](https://img.shields.io/github/license/firecow/gitlab-ci-local)](https://github.com/firecow/caddy-forward-auth)
[![Renovate](https://img.shields.io/badge/renovate-enabled-brightgreen.svg)](https://renovatebot.com)
[![Release](https://img.shields.io/github/v/release/firecow/caddy-forward-auth?sort=semver)](https://github.com/firecow/caddy-forward-auth)

[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=firecow_caddy-forward-auth&metric=alert_status)](https://sonarcloud.io/dashboard?id=firecow_caddy-forward-auth)
[![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=firecow_caddy-forward-auth&metric=code_smells)](https://sonarcloud.io/dashboard?id=firecow_caddy-forward-auth)

```caddyfile
:80

route * {
    forward_auth https://sso.example.com/auth
    reverse_proxy http://webserver:3000
}
```
