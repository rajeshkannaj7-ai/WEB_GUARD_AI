import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'
import Navbar from './components/Navbar'
import Home from './pages/Home'
import Scan from './pages/Scan'
import Domain from './pages/Domain'

export default function App() {
  return (
    <Router>
      <div className="min-h-screen bg-grid" style={{ backgroundColor: '#080C14' }}>
        <Navbar />
        <main className="ml-56 min-h-screen p-6">
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/scan" element={<Scan />} />
            <Route path="/domain" element={<Domain />} />
          </Routes>
        </main>
      </div>
    </Router>
  )
}
