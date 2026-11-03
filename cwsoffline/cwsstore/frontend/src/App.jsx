import { useEffect, useMemo, useState } from 'react'

const ICON_SUN = (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <circle cx="12" cy="12" r="4"></circle>
    <line x1="12" y1="2" x2="12" y2="5"></line><line x1="12" y1="19" x2="12" y2="22"></line>
    <line x1="2" y1="12" x2="5" y2="12"></line><line x1="19" y1="12" x2="22" y2="12"></line>
    <line x1="4.9" y1="4.9" x2="7" y2="7"></line><line x1="17" y1="17" x2="19.1" y2="19.1"></line>
    <line x1="4.9" y1="19.1" x2="7" y2="17"></line><line x1="17" y1="7" x2="19.1" y2="4.9"></line>
  </svg>
)
const ICON_MOON = (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d="M21 12.8A9 9 0 1 1 11.2 3 7 7 0 0 0 21 12.8z"></path>
  </svg>
)
const ICON_DOWNLOAD = (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d="M12 3v12"></path><path d="M7 10l5 5 5-5"></path><path d="M4 21h16"></path>
  </svg>
)
const ICON_BACK = (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d="M15 18l-6-6 6-6"></path>
  </svg>
)

function useTheme() {
  const [theme, setTheme] = useState(() => document.documentElement.getAttribute('data-theme') || 'light')
  const toggle = () => {
    const next = theme === 'dark' ? 'light' : 'dark'
    setTheme(next)
    document.documentElement.setAttribute('data-theme', next)
    try { localStorage.setItem('theme', next) } catch (e) { /* private mode */ }
  }
  return [theme, toggle]
}

const ORIGIN_LABELS = {
  'in-house': 'In-house',
  'webstore': 'Web Store',
  'local': 'Local',
}

function OriginBadge({ origin }) {
  if (!origin) return null
  return <span className={'origin-badge origin-' + origin}>{ORIGIN_LABELS[origin] || origin}</span>
}

function TagChip({ tag, active, onToggle }) {
  return (
    <button
      type="button"
      className={active ? 'tag-chip tag-chip-active' : 'tag-chip'}
      aria-pressed={active}
      onClick={() => onToggle(tag)}
    >
      {tag}
    </button>
  )
}

function ExtensionCard({ ext, onOpen }) {
  const latest = ext.versions[0]
  return (
    <article className="extension-card">
      <button type="button" className="card-main" onClick={() => onOpen(ext.extension_id)}>
        <img className="extension-icon" src={'/' + ext.image_path_url} alt="" loading="lazy" width="48" height="48" />
        <div className="card-text">
          <div className="card-title-row">
            <h2 className="extension-name">{ext.name}</h2>
            <span className="version-badge">v{latest.version}</span>
            <OriginBadge origin={ext.origin} />
          </div>
          <p className="extension-description">{ext.description}</p>
          {ext.tags?.length > 0 && (
            <p className="card-tags">{ext.tags.map((t) => <span key={t} className="card-tag">{t}</span>)}</p>
          )}
          <p className="extension-id">{ext.extension_id}</p>
        </div>
      </button>
      <div className="card-actions">
        <a className="btn-primary" href={'/download/' + ext.extension_id}>{ICON_DOWNLOAD}Download .crx</a>
      </div>
    </article>
  )
}

function DetailView({ ext, onBack }) {
  return (
    <>
      <nav className="breadcrumb">
        <button type="button" className="back-link" onClick={onBack}>{ICON_BACK}All extensions</button>
      </nav>
      <section className="detail-hero">
        <img className="detail-icon" src={'/' + ext.image_path_url} alt="" width="96" height="96" />
        <div className="detail-heading">
          <div className="card-title-row">
            <h1>{ext.name}</h1>
            <span className="version-badge">v{ext.versions[0].version}</span>
            <OriginBadge origin={ext.origin} />
          </div>
          {ext.tags?.length > 0 && (
            <p className="card-tags">{ext.tags.map((t) => <span key={t} className="card-tag">{t}</span>)}</p>
          )}
          <p className="extension-id">{ext.extension_id}</p>
          <a className="btn-primary" href={'/download/' + ext.extension_id}>{ICON_DOWNLOAD}Download .crx</a>
        </div>
      </section>
      {ext.description && (
        <section className="detail-section">
          <h2>About</h2>
          <p className="detail-description">{ext.description}</p>
        </section>
      )}
      <section className="detail-section">
        <h2>Available versions</h2>
        <ul className="version-list">
          {ext.versions.map((v) => (
            <li className="version-row" key={v.version}>
              <span className="version-number">v{v.version}</span>
              <a className="btn-secondary" href={'/' + v.path_url}>Download .crx</a>
            </li>
          ))}
        </ul>
      </section>
    </>
  )
}

export default function App() {
  const [theme, toggleTheme] = useTheme()
  const [extensions, setExtensions] = useState(null)
  const [error, setError] = useState(null)
  const [query, setQuery] = useState('')
  const [selectedTags, setSelectedTags] = useState([])
  const [selectedOrigins, setSelectedOrigins] = useState([])
  const [openId, setOpenId] = useState(null)

  useEffect(() => {
    fetch('/json')
      .then((r) => { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json() })
      .then(setExtensions)
      .catch((e) => setError(e.message))
  }, [])

  const allTags = useMemo(() => {
    if (!extensions) return []
    const tags = new Set()
    extensions.forEach((e) => (e.tags || []).forEach((t) => tags.add(t)))
    return [...tags].sort((a, b) => a.localeCompare(b))
  }, [extensions])

  const allOrigins = useMemo(() => {
    if (!extensions) return []
    const origins = new Set()
    extensions.forEach((e) => e.origin && origins.add(e.origin))
    return [...origins].sort((a, b) => a.localeCompare(b))
  }, [extensions])

  const visible = useMemo(() => {
    if (!extensions) return []
    const term = query.trim().toLowerCase()
    return extensions.filter((e) => {
      if (selectedOrigins.length && !selectedOrigins.includes(e.origin)) return false
      if (selectedTags.length && !selectedTags.every((t) => (e.tags || []).includes(t))) return false
      if (!term) return true
      return (
        e.name.toLowerCase().includes(term) ||
        (e.description || '').toLowerCase().includes(term) ||
        e.extension_id.includes(term)
      )
    })
  }, [extensions, query, selectedTags, selectedOrigins])

  const toggleTag = (tag) =>
    setSelectedTags((cur) => (cur.includes(tag) ? cur.filter((t) => t !== tag) : [...cur, tag]))
  const toggleOrigin = (origin) =>
    setSelectedOrigins((cur) => (cur.includes(origin) ? cur.filter((o) => o !== origin) : [...cur, origin]))

  const open = openId && extensions ? extensions.find((e) => e.extension_id === openId) : null

  return (
    <>
      <header className="site-header">
        <div className="header-inner">
          <button type="button" className="brand" onClick={() => setOpenId(null)}>
            <img className="brand-icon" src="/static/images/favicon.png" alt="" />
            <span className="brand-name">Offline Chrome Web Store</span>
          </button>
          <div className="search-box" role="search">
            <svg className="search-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <circle cx="11" cy="11" r="7"></circle><line x1="16.5" y1="16.5" x2="21" y2="21"></line>
            </svg>
            <input
              id="searchInput"
              type="search"
              placeholder="Search extensions"
              aria-label="Search extensions"
              autoComplete="off"
              spellCheck="false"
              value={query}
              onChange={(e) => { setQuery(e.target.value); setOpenId(null) }}
            />
          </div>
          <button
            className="theme-toggle"
            type="button"
            onClick={toggleTheme}
            aria-label={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
          >
            {theme === 'dark' ? ICON_SUN : ICON_MOON}
          </button>
        </div>
      </header>
      <main className="page-content" id="main">
        {error && <p className="no-results">Could not load the extension index: {error}</p>}
        {!error && !extensions && <p className="no-results">Loading extensions…</p>}
        {extensions && open && <DetailView ext={open} onBack={() => setOpenId(null)} />}
        {extensions && !open && (
          <>
            <section className="store-hero">
              <h1>Extensions</h1>
              <p className="store-subtitle">{visible.length} of {extensions.length} mirrored locally</p>
            </section>
            {(allOrigins.length > 0 || allTags.length > 0) && (
              <div className="filter-bar">
                {allOrigins.length > 0 && (
                  <div className="tag-filter" role="group" aria-label="Filter by origin">
                    <span className="filter-label">Origin</span>
                    {allOrigins.map((origin) => (
                      <TagChip key={origin} tag={ORIGIN_LABELS[origin] || origin} active={selectedOrigins.includes(origin)} onToggle={() => toggleOrigin(origin)} />
                    ))}
                  </div>
                )}
                {allTags.length > 0 && (
                  <div className="tag-filter" role="group" aria-label="Filter by tag">
                    <span className="filter-label">Tags</span>
                    {allTags.map((tag) => (
                      <TagChip key={tag} tag={tag} active={selectedTags.includes(tag)} onToggle={toggleTag} />
                    ))}
                  </div>
                )}
              </div>
            )}
            {extensions.length === 0 ? (
              <div className="empty-store">
                <h2>No extensions mirrored yet</h2>
                <p>Run a sync to populate the store, then reload this page.</p>
              </div>
            ) : (
              <div className="extensions-grid">
                {visible.map((ext) => (
                  <ExtensionCard key={ext.extension_id} ext={ext} onOpen={setOpenId} />
                ))}
              </div>
            )}
            {extensions.length > 0 && visible.length === 0 && (
              <p className="no-results">No extensions match the current search and filters.</p>
            )}
          </>
        )}
      </main>
      <footer className="site-footer">
        <p>Offline Chrome Web Store &middot; self-hosted mirror &middot; <a href="https://github.com/ronel99/offlinechromewebstore">GitHub</a></p>
      </footer>
    </>
  )
}
