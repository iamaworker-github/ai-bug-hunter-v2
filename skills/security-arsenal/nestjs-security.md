---
name: nestjs-security
description: Security testing playbook for NestJS applications — guards, pipes, decorators, microservice transport bypass
tools:
  - Bash
  - WebFetch
  - Read
triggers:
  - nest
  - nestjs
  - nest.js
  - typescript api
  - nodejs framework
---

# NestJS Security Testing

## Architecture Overview
- **Guards** (`@UseGuards`, `CanActivate`) — run before handler, return boolean
- **Pipes** (`ValidationPipe`, `ParseIntPipe`) — transform/validate input
- **Interceptors** (`@Interceptor`) — modify request/response, caching, logging
- **Filters** (`@Catch`) — exception handling, may leak info
- **Transports**: HTTP, WebSocket (`@WebSocketGateway`), Microservices (TCP/Redis/NATS/MQTT/gRPC/Kafka)

## Key Attack Surfaces

### Guard Gaps (#1 Finding)
| Issue | Test | Payload |
|-------|------|---------|
| Method missing `@UseGuards` | Map decorator stack per method | Call endpoint without auth |
| `@Public()` applied too broadly | Global AuthGuard skips on metadata check | Hit public-decorated admin endpoint |
| New method added without guard | Compare sibling methods in same controller | Register new route manually |
| Metadata key mismatch | Guard reads `'roles'` but decorator sets `'role'` | `@Roles()` silently ignored |
| `applyDecorators()` override | Composed decorator overrides stricter guard | Bypass via permissive decorator order |
| Cross-transport guard gap | HTTP guards don't apply to WebSocket | Same action via WS without auth |
| Guard handles HTTP only | `getRequest()` on WS/RPC context returns `true` | WebSocket method bypass |

### ValidationPipe Bypass
| Issue | Test | Payload |
|-------|------|---------|
| `whitelist: true` without `forbidNonWhitelisted: true` | Extra fields silently stripped | May not throw — earlier middleware may process |
| Missing `@Type()` on nested objects | `@ValidateNested()` without `@Type()` | Nested payload never validated |
| `transform: true` coercion | `"true"` → `true`, `"null"` → `null` | Truthiness exploits downstream |
| `@ValidateIf()` conditional skip | Fields skip validation entirely | Send malformed data through conditional path |
| String param without `ParseIntPipe` | `@Param('id')` → string hits ORM | SQL injection via non-numeric param |
| CSRF token bypass devtools | `@nestjs/devtools-integration` unsafe sandbox | RCE via `vm.runInNewContext()` |

### Serialization Leaks
| Issue | Test | Payload |
|-------|------|---------|
| `@Exclude()` not applied globally | Password field leaks in response | Call user endpoint as normal user |
| `excludeExtraneousValues: true` missing | Every entity property passes through | Full DB record returned |
| `@Expose()` with groups not enforced | Admin-only fields visible to regular user | Access group-restricted fields |
| CacheInterceptor without user key | One user's data served to another | Auth request → unauth cached 200 |

### Microservice Transport Bypass
| Issue | Test | Payload |
|-------|------|---------|
| `@MessagePattern` without auth | TCP/Redis/NATS handler accessible | Send message to internal transport |
| ValidationPipe only on HTTP | Microservice payloads skip validation | SQL/XSS via service message |
| JsonSocket TCP DoS | Many small JSON messages in one frame | ~47KB → stack overflow (CVE-2026-40879) |

### File Upload (CVE-2024-29409)
| Issue | Test | Payload |
|-------|------|---------|
| `FileInterceptor` without type check | `Content-Type` header injection | RCE via crafted Content-Type |
| Upload destination writable | Path traversal in filename | `../../../etc/cronjob` |

### Module Boundary Leaks
| Issue | Test | Payload |
|-------|------|---------|
| `@Global()` module | All providers accessible without import | Call internal service from untrusted module |
| `Scope.REQUEST` misconfigured as DEFAULT | Request context leaks across concurrent requests | User A sees User B's data |

### Swagger Exposure
| Issue | Test | Payload |
|-------|------|---------|
| Swagger in production | `/api`, `/api-docs`, `/api-json`, `/swagger` | Full API surface dump |
| Real example values | `@ApiProperty({ example: "real-user-123" })` | Real customer IDs in example |

## Testing Methodology
1. **Enumerate endpoints** — Swagger/OpenAPI, auth routes, admin controllers, file upload, GraphQL playground
2. **Guard audit** — Map decorator stack per method across controllers
3. **Cross-transport matrix** — Test each endpoint across: unauth/user/admin × HTTP/WS/TCP
4. **Validation probe** — Extra fields, wrong types, nested objects, `transform: true` coercion
5. **Serialization check** — Compare raw entity fields with API response
6. **Cache check** — Auth response cached, then served to unauth
7. **Dependency audit** — `npm audit`, check `tough-cookie` (CVE-2023-26136), `class-transformer` (CVE-2023-45133)

## Critical CVEs
| CVE | Component | Impact | Test |
|-----|-----------|--------|------|
| CVE-2025-69211 | platform-fastify (≤11.1.11) | Auth bypass via URL encoding | `/%61dmin` bypasses middleware |
| CVE-2025-54782 | devtools-integration (≤0.2.0) | RCE via unsafe sandbox | Cross-origin POST with `code` field |
| CVE-2024-29409 | nest v10.3.2 | RCE via Content-Type | Upload with crafted Content-Type |
| CVE-2026-40879 | JSONSocket TCP (≤11.1.18) | DoS via recursive `handleData` | ~47KB payload → stack overflow |
| CVE-2023-26136 | tough-cookie (dep) | Prototype pollution | npm audit |
| CVE-2023-45133 | class-transformer (≤0.5.1) | Prototype pollution | Deep nested objects |
| CVE-2024-21485 | mqtt (dep) | Prototype pollution | `@nestjs/microservices` with MQTT |

## Reporting Tips
- Guard gap: "Route X has no auth guard while sibling routes Y, Z have AuthGuard" — high impact if admin
- Cross-transport bypass: "WebSocket gateway /events has no guard but HTTP /events has" — medium/high
- Validation bypass: "$field accepted despite being undeclared in DTO" — medium (escalation if `isAdmin`-like)
- Serialization leak: "Response includes full DB entity with password hash" — critical
- Swagger exposure: "Production API docs at /api expose all internal endpoints" — medium
