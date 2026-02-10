# Canvas

[![Packagist](https://img.shields.io/packagist/v/quellabs/canvas.svg)](https://packagist.org/packages/quellabs/canvas)

A lightweight PHP framework built for real-world projects — especially the messy ones. Canvas drops into existing PHP codebases without forcing a rewrite, while giving new projects a clean, annotation-driven architecture with contextual dependency injection and a readable ORM.

## Why Canvas?

Most frameworks assume a greenfield project. Canvas doesn't. Its **legacy-first integration** lets you wrap an existing PHP application and incrementally modernize — new routes handled by Canvas controllers, old `.php` files served through route fallthrough. No big bang migration required.

On top of that, Canvas ships with things you'd normally bolt on separately: aspect-oriented programming for cross-cutting concerns, a Qt-style signal/slot event system, cron-style task scheduling, and a visual debug inspector. All without the weight of a full-stack monolith.

## Quick Start

```bash
# New project
composer create-project quellabs/canvas-skeleton my-app

# Existing project
composer require quellabs/canvas
```

```php
class BlogController extends BaseController {

    /**
     * @Route("/posts/{id:int}")
     */
    public function show(int $id) {
        $post = $this->em()->find(Post::class, $id);
        return $this->render('post.tpl', $post);
    }
}
```

Annotation-based routing, automatic controller discovery, typed route parameters — no configuration files.

## ObjectQuel ORM

Canvas includes ObjectQuel, an ORM with a query language inspired by QUEL. For simple lookups you get the familiar `find` and `findBy` methods. For complex queries, ObjectQuel's declarative syntax reads closer to intent than DQL or query builders:

```php
$results = $this->em()->executeQuery("
    range of p is App\\Entity\\Post
    range of u is App\\Entity\\User via p.authorId
    retrieve (p, u.name) where p.title = /^Tech/i
    sort by p.publishedAt desc
");
```

## Aspects for Cross-Cutting Concerns

Authentication, caching, rate limiting, CSRF — Canvas handles these as composable aspects applied via annotations, not scattered through controller logic:

```php
/**
 * @Route("/admin/users")
 * @InterceptWith(RequireAuthAspect::class, priority=100)
 * @InterceptWith(CacheAspect::class, ttl=300)
 * @InterceptWith(RateLimitAspect::class, limit=100, window=3600)
 */
public function manage() {
    return $this->em()->findBy(User::class, ['active' => true]);
}
```

Before, Around, and After aspects with priority ordering, inheritance through controller hierarchies, and parameterized configuration.

## Features

- **Legacy-first integration** — drop into existing PHP projects via route fallthrough
- **Annotation-based routing** — typed parameters, prefixes, method constraints
- **ObjectQuel ORM** — readable query language with relationship traversal and regex support
- **Aspect-oriented programming** — composable cross-cutting concerns with priority ordering
- **Contextual dependency injection** — different implementations per context
- **Signal/slot event system** — decoupled service communication
- **Task scheduling** — cron-style jobs with timeouts and concurrency handling
- **Visual inspector** — debug bar with queries, request analysis, and custom panels
- **Validation & sanitization** — declarative rules applied as aspects
- **CLI tooling** — route listing, route matching, task management, asset publishing

## Documentation

Full docs, guides, and API reference: **[canvasphp.com/docs](https://canvasphp.com/docs)**

## Contributing

Bug reports and feature requests via GitHub issues. PRs welcome — fork, branch, follow PSR-12, add tests.

## License

MIT