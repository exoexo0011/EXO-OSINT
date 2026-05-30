import { Routes, Route, Navigate } from 'react-router-dom'
import Navbar from './components/Navbar.jsx'
import Footer from './components/Footer.jsx'
import Landing from './pages/Landing.jsx'
import Investigate from './pages/Investigate.jsx'
import Pricing from './pages/Pricing.jsx'

export default function App() {
  return (
    <div className="app-shell scanlines">
      <Navbar />
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route path="/investigate" element={<Investigate />} />
        <Route path="/pricing" element={<Pricing />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
      <Footer />
    </div>
  )
}
