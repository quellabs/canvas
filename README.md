# Canvas

[![Packagist](https://img.shields.io/packagist/v/quellabs/canvas.svg)](https://packagist.org/packages/quellabs/canvas)
[![PHPStan](https://img.shields.io/badge/PHPStan-level%209-brightgreen.svg)](https://phpstan.org)
[![License](https://img.shields.io/badge/license-MIT-brightgreen.svg)](LICENSE)

A PHP framework built for real-world projects — especially the messy ones. Canvas drops into existing PHP codebases without forcing a rewrite, while giving new projects a clean, annotation-driven architecture: aspect-oriented programming, a readable ORM, your choice of template engine, and auto-discovered packages for payments, shipments, and scheduling.

## The legacy problem

Most frameworks assume you're starting fresh. Canvas doesn't. Point it at your existing application, and it takes over routing while your old `.php` files keep working:

```php
// config/app.php
return [
    'legacy_enabled' => true,
    'legacy_path'    => dirname(__FILE__) . "/../legacy"
];
```

Canvas checks its own routes first. Unmatched URLs fall through to your legacy files — every existing page keeps working from day one. Your legacy code can immediately use Canvas services:

```php
// legacy/admin/dashboard.php — your existing file, now with Canvas services
$users = canvas()->get(EntityManager::class)->findBy(User::class, ['active' => true]);
```

`canvas()` returns the DI container; pass a DI context (string or array), as accepted by `Container::for()`, to scope resolution before calling `get()`:

```php
$cache = canvas('redis')->get(CacheInterface::class);
```

Legacy files using `header()`, `die()`, and `exit()` are automatically preprocessed to work within Canvas's request/response flow. The preprocessing is recursive — included files are transformed too, and results are cached.

Migrate one route at a time. When a Canvas controller claims a URL, it takes precedence over the legacy file. When every route is migrated, set `legacy_enabled` to `false`.

## Templating
Canvas uses [Smarty](https://www.smarty.net/) as its default template engine. Twig, Latte, Blade, Plates, and Handlebars are each available as a separate package and can be swapped in without touching controller code.

## Cross-cutting concerns without the mess

Canvas separates cross-cutting concerns — auth, caching, rate limiting, logging — into aspects: reusable classes applied via annotations instead of tangled into business logic.

```php
/**
 * @Route("/admin/users")
 * @InterceptWith(RequireAuthAspect::class, priority=100)
 * @InterceptWith(CacheAspect::class, ttl=300)
 * @InterceptWith(RateLimitAspect::class, limit=100, window=3600)
 */
public function manage() {
    $users = $this->em()->findBy(User::class, ['active' => true]);
    return $this->render('admin/users.tpl', compact('users'));
}
```

Each aspect is a standalone class — `BeforeAspect` for checks that can short-circuit the request, `AroundAspect` for wrapping behavior like caching, `AfterAspect` for post-processing. Aspects inherit through controller hierarchies — apply `@InterceptWith` on a base class and every child controller gets it automatically — with priority ordering controlling execution sequence within each inheritance level.

## Security headers & CORS

`config/app.php`'s `security_header_policy` accepts a single policy class or an ordered list, applied to every response in that order:

```php
// config/app.php
return [
    'security_header_policy' => [
        BasicSecurityHeaderPolicy::class,
        CorsSecurityHeaderPolicy::class,
    ],
];
```

A route-specific override uses the same syntax and replaces the *entire* list for that route, not just one entry:

```php
/**
 * @InterceptWith(SecurityHeadersAspect::class, policyClass={StrictSecurityHeaderPolicy::class, CorsSecurityHeaderPolicy::class})
 */
```

`CorsSecurityHeaderPolicy` is opt-in and reads its allowlists from `config/cors.php`, created with `php sculpt cors:init`. The generated file grants no cross-origin access until filled in:

```php
// config/cors.php
return [
    'allowed_origins'   => ['https://app.example.com'],
    'allowed_methods'   => ['GET', 'POST'],
    'allowed_headers'   => ['Content-Type', 'Authorization'],
    'exposed_headers'   => ['Location'],
    'allow_credentials' => true,
    'max_age'           => 600,
];
```

Only exact `scheme://host(:port)` origins are accepted — `*` and the opaque `null` origin are rejected. A preflight (`OPTIONS` with `Access-Control-Request-Method`) is approved only when the origin, requested method, and every requested header are allowed; Canvas's generated `OPTIONS` response already carries the route's matched methods in `Allow`, which the requested method must also appear in.

Existing single-class configurations keep working unchanged. Basic/Medium/Strict headers (clickjacking, MIME-sniffing, HSTS, CSP) are a separate concern from CORS's cross-origin permission headers — an application opting into CORS still needs one of them, and must list `CorsSecurityHeaderPolicy::class` in any route override that should keep it.

## ObjectQuel ORM

Canvas integrates with [ObjectQuel](https://objectquel.com) through the `quellabs/canvas-objectquel` package. Simple lookups use familiar `find` and `findBy` methods. Complex queries use ObjectQuel's declarative syntax:

```php
$results = $this->em()->executeQuery("
    range of p is App\\Entity\\Post
    range of u is App\\Entity\\User via p.authorId
    retrieve (p, u.name) where p.title = /^Tech/i
    sort by p.publishedAt desc
    window 0 using window_size 20
");
```

Pattern matching, regex, full-text search, and relationship traversal are first-class query expressions — not raw SQL escapes. ObjectQuel can also join database entities with JSON files in a single query via `json_source()`, something no other PHP ORM supports.

## How to Install

```bash
# New project
composer create-project quellabs/canvas-skeleton my-app

# Existing project
composer require quellabs/canvas
```

## Quick start

```php
class BlogController extends BaseController {

    /**
     * @Route("/posts/{id:int}")
     */
    public function show(int $id) {
        $post = $this->em()->find(Post::class, $id);
        return $this->render('post.tpl', compact('post'));
    }
}
```

Controllers are discovered automatically through Composer metadata. Routes are defined with annotations. Typed route parameters (`{id:int}`) are validated before your method runs. No configuration files, no route registration.

## Features

- **Legacy-first integration** — wrap existing PHP apps with route fallthrough, automatic preprocessing of `header()`/`die()`/`exit()`, and a `canvas()` helper for accessing the DI container from legacy code
- **Aspect-oriented programming** — Before, Around, and After aspects with annotation parameters, priority ordering, and inheritance through controller hierarchies
- **ObjectQuel ORM** — declarative query language with pattern matching, hybrid JSON sources, and Data Mapper architecture
- **Template engines** — Smarty by default, with Twig, Latte, Blade, Plates, and Handlebars available as drop-in packages
- **Contextual dependency injection** — resolve different interface implementations based on request context, without conditional logic in your code
- **Signal/slot event system** — Qt-style decoupled service communication with type checking and priority-based handlers
- **Task scheduling** — cron-style background jobs with timeouts, concurrent execution handling, and optional RabbitMQ/Redis-backed queues
- **Payments & shipments** — provider-agnostic routers that auto-discover installed payment and carrier packages via Composer metadata
- **Loom** — definition-driven builder for admin pages, forms, and settings panels with automatic data binding
- **Validation & sanitization** — declarative rules applied as aspects, keeping controllers clean
- **Visual inspector** — debug bar with database queries, request analysis, and custom panels
- **CLI tooling** — route listing, route matching, task management, asset publishing, entity generation

## Documentation

Full docs, guides, and API reference: **[canvasphp.com/docs](https://canvasphp.com/docs)**

## Contributing

Bug reports and feature requests via GitHub issues. PRs welcome — fork, branch, follow PSR-12, add tests.

## Support

If Canvas saves you time, consider [sponsoring development](https://github.com/sponsors/quellabs).

## License

MIT