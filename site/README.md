# Crossview landing site (GitHub Pages)

A single-page landing site with full Open Graph / Twitter metadata so the repo and
its links **populate correctly when shared on GitHub, LinkedIn, Slack, X, etc.**

```
site/
├── index.html       ← the page (OG/Twitter meta, hero GIFs, feature grid)
├── style.css        ← dark HUD theme
└── og-card.png      ← 1280×640 social/preview image (the featured card)
```

The hero GIFs (`flow-graph.gif`, `kev-ticker.gif`) are **not** duplicated here — the
deploy workflow copies them in from `examples/vulpy-engagement/assets/` at build time.

## Deploy (one-time)

1. Push to `main`.
2. Repo → **Settings → Pages → Source = "GitHub Actions"**.
3. The [`pages.yml`](../.github/workflows/pages.yml) workflow builds and deploys `site/`,
   rewriting `__SITE_URL__` / `__REPO_URL__` to the real URLs so OG tags are absolute
   (required for LinkedIn/Twitter image scraping).

Your site lands at `https://<user>.github.io/<repo>/`.

## Make it the *featured* preview

- **GitHub repo card** (what shows when the repo URL is shared): repo → **Settings →
  General → Social preview → Upload** `site/og-card.png`. GitHub social cards are images,
  not videos.
- **LinkedIn / Slack / X**: share the **Pages URL** (`https://<user>.github.io/<repo>/`) —
  they read the OG tags and show `og-card.png` with the title/description. If LinkedIn
  caches an old preview, re-scrape with the
  [Post Inspector](https://www.linkedin.com/post-inspector/).

## The featured video

The page **self-hosts the video**: `case-study.mp4` (a 720p/7.5 MB web-optimized cut, in
this folder) plays in an HTML5 `<video>` player, and `og:video` points at it so platforms
that support it show a play control. Regenerate the web cut from the 1080p master:

```bash
ffmpeg -i ~/Videos/visionlighter/crossview/case-study/case-study.mp4 \
  -vf scale=1280:720 -c:v libx264 -preset slow -crf 24 -pix_fmt yuv420p \
  -c:a aac -b:a 128k -movflags +faststart site/case-study.mp4
```

> **Note:** every major platform shows an **image** (the `og-card.png`), not an autoplaying
> video, in a *link* preview — so the card is what makes shares look good. For maximum
> LinkedIn reach, also upload `case-study.mp4` **natively** to the post (native video
> autoplays in-feed and out-reaches link previews).

## Regenerate the OG card

```bash
# from repo root — re-renders site/og-card.png from the cinematic flow-graph frame
python3 scripts/make_og_card.py     # (optional helper; see scripts/)
```
