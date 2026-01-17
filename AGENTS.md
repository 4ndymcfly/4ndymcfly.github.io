# Repository Guidelines

## Project Structure & Module Organization
- Jekyll site using the Chirpy theme.
- Content lives in `_posts/` (blog entries) and `_tabs/` (top-level pages).
- Site configuration is `_config.yml`; data files are in `_data/`.
- Reusable templates and partials are in `_includes/`; custom plugins in `_plugins/`.
- Static assets go in `assets/` (CSS, JS, images). The generated site is `_site/`.

## Build, Test, and Development Commands
- `bundle install` installs Ruby dependencies from `Gemfile`.
- `bundle exec jekyll serve` runs the site locally at `http://localhost:4000`.
- `bundle exec jekyll build` generates the static site into `_site/`.

## Coding Style & Naming Conventions
- Use 2-space indentation for YAML, HTML, and Markdown blocks.
- Keep Markdown headings in sentence case and prefer short, descriptive titles.
- Posts in `_posts/` must follow `YYYY-MM-DD-title.md` naming (Jekyll standard).
- Use ASCII in filenames; avoid spaces.

## Content Guidelines
- Each post should include front matter keys like `title`, `date`, `categories`, and `tags`.
- Store post images in `assets/img/` and reference them with relative paths.
- Keep summaries short; prefer bullet lists for steps or commands.

## Testing Guidelines
- No automated test framework is configured.
- Validate locally by running `bundle exec jekyll serve` and checking key pages.
- For new posts, verify front matter renders correctly and links resolve.

## Commit & Pull Request Guidelines
- Recent commit messages use a short prefix and sentence case, e.g., `Fix: ...`, `SEO: ...`.
- Keep commits focused; one logical change per commit.
- PRs should include a clear description of changes and the affected pages.
- Include screenshots for visual changes and link related issues if applicable.

## Security & Configuration Tips
- Avoid committing secrets to `_config.yml` or front matter.
- Verify external links and scripts before adding to templates.
