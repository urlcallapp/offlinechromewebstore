# Offline Chrome Web Store

This project is an offline version of the Chrome Web Store, allowing users to browse and download Chrome extensions in a local environment.

## Features

- Browse a list of available Chrome extensions.
- View details of each extension, including descriptions and download links.
- Download CRX files for offline installation.


## Frontends

The store ships two frontends, both served by the same FastAPI app with no
network access needed at runtime:

- `/` - server-rendered pages (Jinja templates). Works with JavaScript
  disabled; the default.
- `/app/` - a React single-page storefront with live search and tag
  filtering. Source lives in `frontend/` (Vite + React).

The React bundle is prebuilt two ways: the compiled assets are committed
under `app/static/app/` for bare `pip` installs, and the Docker image
rebuilds them from source in a Node build stage (no Node.js in the final
image). After changing `frontend/src`, run `npm run build` in `frontend/`
and commit the result; `npm test` runs the UI test suite.

Classification is assigned where extensions enter the store: entries in
`recommended_extensions.json` or `specified.json` accept optional `tags`
(display taxonomy), `origin` (`webstore` by default; `in-house` for
CRXs placed in the artifacts tree directly, which sync does
not download) and a `description` override. Plain ID strings and
`{id, name}` entries keep working. cwssync resolves this into
`artifacts/extension_metadata.json`, cwsbuild merges it into the index,
and the storefronts read it from `/json`: tag and origin filters in the
React app, badges on the server-rendered pages.

`origin` records where a CRX came from, nothing more: it is not a trust
verdict, and the malicious blocklist applies to in-house entries too. A
declared in-house extension whose CRX is missing from the artifacts tree
is reported as `in_house_missing` and never appears in the store. CRXs
found in the tree with no source entry are labeled `local` (unknown
provenance).

## Project Structure

```
offline-chrome-webstore
├── app
│   ├── __init__.py
│   ├── main.py
│   ├── templates
│   │   ├── base.html
│   │   ├── index.html
│   │   └── extension.html
│   ├── static
│   │   ├── css
│   │   │   └── styles.css
│   │   ├── js
│   │   │   └── scripts.js
│   │   └── extensions_info.json
│   └── routes
│       ├── __init__.py
│       └── extensions.py
├── requirements.txt
└── README.md
```

## Installation

1. Clone the repository:
   ```
   git clone <repository-url>
   cd offline-chrome-webstore
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Editing Extensions

1. **Edit `extensions_info.json`:**
   - The file is located at `app/static/extensions_info.json`.
   - Add new extensions by appending objects with the following structure:
     ```json
     {
         "extension_id": "unique_extension_id",
         "name": "Extension Name",
         "description": "Short description of the extension.",
         "version": "Extension version",
         "author": "Author or organization name",
         "iconUrl": "/static/icons/extension_icon.png",
         "downloadUrl": "/static/extensions/unique_extension_id.crx",
         "rating": 4.5
     }
     ```

2. **Add CRX Files:**
   - Place the `.crx` files for the extensions in the `app/static/extensions` directory.
   - Ensure the `downloadUrl` in `extensions_info.json` matches the file path.

## Usage

1. Start the FastAPI application:
   ```
   uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
   ```

2. Open your web browser and navigate to `http://localhost:8000` to access the Offline Chrome Web Store.

## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue for any suggestions or improvements.

## License

This project is licensed under the MIT License. See the LICENSE file for more details.