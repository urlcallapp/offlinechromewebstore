import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import App from './App.jsx'

const EXTENSIONS = [
  {
    name: 'Adblock Plus',
    extension_id: 'a'.repeat(32),
    description: 'Block ads and trackers.',
    image_path_url: 'assets/' + 'a'.repeat(32) + '/icon.png',
    tags: ['privacy', 'ad-blocking'],
    versions: [
      { version: '1.0.4', path_url: 'artifacts/extensions/' + 'a'.repeat(32) + '/1.0.4/x.crx' },
      { version: '1.0.0', path_url: 'artifacts/extensions/' + 'a'.repeat(32) + '/1.0.0/x.crx' },
    ],
  },
  {
    name: 'JSON Formatter Pro',
    extension_id: 'b'.repeat(32),
    description: 'Pretty-print JSON.',
    image_path_url: 'assets/' + 'b'.repeat(32) + '/icon.png',
    tags: ['devtools'],
    versions: [{ version: '1.5.0', path_url: 'artifacts/extensions/' + 'b'.repeat(32) + '/1.5.0/x.crx' }],
  },
  {
    // legacy index entry without a tags field at all
    name: 'Untagged Legacy',
    extension_id: 'c'.repeat(32),
    description: 'No tags key.',
    image_path_url: 'assets/' + 'c'.repeat(32) + '/icon.png',
    versions: [{ version: '0.1', path_url: 'artifacts/extensions/' + 'c'.repeat(32) + '/0.1/x.crx' }],
  },
]

function mockFetch(payload, ok = true) {
  global.fetch = vi.fn(() =>
    Promise.resolve({
      ok,
      status: ok ? 200 : 500,
      json: () => Promise.resolve(payload),
    })
  )
}

beforeEach(() => {
  localStorage.clear()
  document.documentElement.setAttribute('data-theme', 'light')
})

afterEach(() => {
  vi.restoreAllMocks()
})

test('loading state resolves into the grid', async () => {
  mockFetch(EXTENSIONS)
  render(<App />)
  expect(screen.getByText(/loading extensions/i)).toBeInTheDocument()
  expect(await screen.findByText('Adblock Plus')).toBeInTheDocument()
  expect(screen.getByText('3 of 3 mirrored locally')).toBeInTheDocument()
})

test('fetch failure shows the error state', async () => {
  mockFetch(null, false)
  render(<App />)
  expect(await screen.findByText(/could not load the extension index/i)).toBeInTheDocument()
})

test('empty index shows the empty-store state', async () => {
  mockFetch([])
  render(<App />)
  expect(await screen.findByText(/no extensions mirrored yet/i)).toBeInTheDocument()
})

test('search filters by name and updates the counter', async () => {
  mockFetch(EXTENSIONS)
  render(<App />)
  await screen.findByText('Adblock Plus')
  fireEvent.change(screen.getByLabelText('Search extensions'), { target: { value: 'json' } })
  expect(screen.queryByText('Adblock Plus')).not.toBeInTheDocument()
  expect(screen.getByText('JSON Formatter Pro')).toBeInTheDocument()
  expect(screen.getByText('1 of 3 mirrored locally')).toBeInTheDocument()
})

test('search with no hits shows the no-results state', async () => {
  mockFetch(EXTENSIONS)
  render(<App />)
  await screen.findByText('Adblock Plus')
  fireEvent.change(screen.getByLabelText('Search extensions'), { target: { value: 'zzzz' } })
  expect(screen.getByText(/no extensions match/i)).toBeInTheDocument()
})

test('tag chips combine with AND semantics and aria-pressed', async () => {
  mockFetch(EXTENSIONS)
  render(<App />)
  await screen.findByText('Adblock Plus')
  const privacy = screen.getByRole('button', { name: 'privacy' })
  const adblocking = screen.getByRole('button', { name: 'ad-blocking' })
  fireEvent.click(privacy)
  expect(privacy).toHaveAttribute('aria-pressed', 'true')
  expect(screen.getByText('1 of 3 mirrored locally')).toBeInTheDocument()
  fireEvent.click(adblocking)
  expect(screen.getByText('1 of 3 mirrored locally')).toBeInTheDocument()
  // deselecting one of two active tags still narrows by the other
  fireEvent.click(privacy)
  expect(screen.getByText('1 of 3 mirrored locally')).toBeInTheDocument()
  fireEvent.click(adblocking)
  expect(screen.getByText('Adblock Plus')).toBeInTheDocument()
  expect(screen.getByText('3 of 3 mirrored locally')).toBeInTheDocument()
})

test('entries without a tags field render and produce no chips', async () => {
  mockFetch([EXTENSIONS[2]])
  render(<App />)
  expect(await screen.findByText('Untagged Legacy')).toBeInTheDocument()
  expect(screen.queryByRole('group', { name: /filter by tag/i })).not.toBeInTheDocument()
})

test('detail view opens, lists versions and links downloads honestly', async () => {
  mockFetch(EXTENSIONS)
  render(<App />)
  fireEvent.click(await screen.findByText('Adblock Plus'))
  expect(screen.getByRole('heading', { level: 1, name: 'Adblock Plus' })).toBeInTheDocument()
  expect(screen.getAllByText('v1.0.4').length).toBeGreaterThan(0)
  const downloads = screen.getAllByRole('link', { name: /download \.crx/i })
  expect(downloads[0]).toHaveAttribute('href', '/download/' + 'a'.repeat(32))
  const rows = screen.getAllByRole('listitem')
  expect(within(rows[0]).getByText('v1.0.4')).toBeInTheDocument()
  expect(within(rows[0]).getByRole('link')).toHaveAttribute(
    'href', '/artifacts/extensions/' + 'a'.repeat(32) + '/1.0.4/x.crx'
  )
  fireEvent.click(screen.getByRole('button', { name: /all extensions/i }))
  expect(screen.getByText('3 of 3 mirrored locally')).toBeInTheDocument()
})

test('theme toggle flips the theme, persists it and updates its label', async () => {
  mockFetch(EXTENSIONS)
  render(<App />)
  const toggle = screen.getByRole('button', { name: 'Switch to dark mode' })
  fireEvent.click(toggle)
  expect(document.documentElement.getAttribute('data-theme')).toBe('dark')
  expect(localStorage.getItem('theme')).toBe('dark')
  expect(screen.getByRole('button', { name: 'Switch to light mode' })).toBeInTheDocument()
})
