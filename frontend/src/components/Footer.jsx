import { API_URL } from '../api/client.js'

export default function Footer() {
  return (
    <footer className="footer">
      <div className="container flex between center wrap gap-12">
        <div>
          EXO::OSINT — open-source intelligence console.{' '}
          <span className="muted">For authorized research &amp; defensive use only.</span>
        </div>
        <div className="muted">
          backend: <span className="text-2">{API_URL}</span>
        </div>
      </div>
    </footer>
  )
}
