# Canvas

[![Packagist](https://img.shields.io/packagist/v/quellabs/canvas.svg)](https://packagist.org/packages/quellabs/canvas)

A PHP framework built for real-world projects — especially the messy ones. Canvas drops into existing PHP codebases without forcing a rewrite, while giving new projects a clean, annotation-driven architecture with aspect-oriented programming and a readable ORM.

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
$users = canvas('EntityManager')->findBy(User::class, ['active' => true]);
```

Legacy files using `header()`, `die()`, and `exit()` are automatically preprocessed to work within Canvas's request/response flow. The preprocessing is recursive — included files are transformed too, and results are cached.

Migrate one route at a time. When a Canvas controller claims a URL, it takes precedence over the legacy file. When every route is migrated, set `legacy_enabled` to `false`.

## Cross-cutting concerns without the mess

Here's what a controller looks like when authentication, caching, and rate limiting are tangled into business logic:

```php
// The usual approach
public function manage() {
    if (!$this->auth->isAuthenticated()) {
        return redirect('/login');
    }

    $key = 'users_' . md5(serialize($params));
    if ($cached = $this->cache->get($key)) {
        return $cached;
    }

    if ($this->rateLimiter->tooManyAttempts($ip, 100)) {
        return response('Too many requests', 429);
    }

    $users = $this->em()->findBy(User::class, ['active' => true]);
    $result = $this->render('admin/users.tpl', compact('users'));
    $this->cache->set($key, $result, 300);
    return $result;
}
```

Canvas separates cross-cutting concerns into aspects — reusable classes applied via annotations:

```php
// Canvas: business logic only, concerns declared as aspects
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

Three lines of business logic. Authentication, caching, and rate limiting are declared, not coded. Each aspect is a standalone class — `BeforeAspect` for auth checks, `AroundAspect` for caching, `AfterAspect` for logging:

```php
class RequireAuthAspect implements BeforeAspect {
    public function __construct(private AuthService $auth) {}

    public function before(MethodContextInterface $context): ?Response {
        if (!$this->auth->isAuthenticated()) {
            return new RedirectResponse('/login');
        }
        return null; // proceed to method
    }
}
```

Aspects inherit through controller hierarchies — apply `@InterceptWith` on a base class and every child controller gets it automatically. Priority ordering controls execution sequence within each inheritance level.

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

Canvas uses [Smarty](https://www.smarty.net/) as its default template engine. Twig support is available through a separate package.

## Features

- **Legacy-first integration** — wrap existing PHP apps with route fallthrough, automatic preprocessing of `header()`/`die()`/`exit()`, and a `canvas()` helper for accessing services from legacy code
- **Aspect-oriented programming** — Before, Around, and After aspects with annotation parameters, priority ordering, and inheritance through controller hierarchies
- **ObjectQuel ORM** — declarative query language with pattern matching, hybrid JSON sources, and Data Mapper architecture
- **Contextual dependency injection** — resolve different interface implementations based on request context, without conditional logic in your code
- **Signal/slot event system** — Qt-style decoupled service communication with type checking and priority-based handlers
- **Task scheduling** — cron-style background jobs with timeouts and concurrent execution handling
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