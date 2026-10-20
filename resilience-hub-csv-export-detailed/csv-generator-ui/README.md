# csv-generator-ui

The RAP Assessment Report page that `csv-generator-nextgen.py` writes as its `.html` report. It's a small React app built with [Cloudscape](https://cloudscape.design), the design system of the AWS console. It uses:
- top navigation, side navigation, breadcrumbs and the app layout with a help panel
- tables, status indicators, key-value pairs, Flashbar notices and badges
- dark mode by default, with a light/dark button; printing switches to light and hides the navigation

`build.mjs` compiles React, the Cloudscape components and the Open Sans font into one HTML file and embeds it in `csv-generator-nextgen.py`, in the `REPORT_PAGE` block at the end. Partners still upload only the script. Python fills in the report data (`page_data()`), and the page reads it from `<script id="rap-data">`.

The page needs no network. Everything is inlined, and its Content-Security-Policy allows no request at all; only its own script, identified by its hash, can run. The page does need JavaScript; without it, it shows a note pointing to the `.xlsx` copy.

## Rebuild after changing `src/`

You need Node.js 18 or later. In this folder:

    npm ci --ignore-scripts
    npm run build

`npm run build` replaces the `REPORT_PAGE` block in `../csv-generator-nextgen.py` and writes `dist/report-page.html`, the page with the data placeholder. To build somewhere else, for example to keep `node_modules` out of a synced folder, copy this folder there and run `node build.mjs <path to csv-generator-nextgen.py>` instead.

## Licenses

Bundled packages:
- React and React DOM (MIT)
- `@cloudscape-design/components`, `collection-hooks` and `global-styles` (Apache-2.0), with their dependencies
- Open Sans (SIL Open Font License 1.1)

The build lists every bundled package in a comment at the top of the page and appends the license texts at the end.
