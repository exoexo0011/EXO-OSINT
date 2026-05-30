import { NavLink, Link } from 'react-router-dom'

export default function Navbar() {
  return (
    <nav className="nav">
      <div className="container nav-inner">
        <Link to="/" className="brand">
          <span className="dot" />
          EXO<b>::</b>OSINT
        </Link>
        <div className="nav-links">
          <NavLink to="/" end>
            Home
          </NavLink>
          <NavLink to="/investigate">Investigate</NavLink>
          <NavLink to="/pricing">Pricing</NavLink>
          <Link to="/investigate" className="btn btn-primary btn-sm" style={{ marginLeft: 8 }}>
            Launch Console
          </Link>
        </div>
      </div>
    </nav>
  )
}
