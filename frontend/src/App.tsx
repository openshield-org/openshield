import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'
import Navigation from './components/reusables/Navigation'
import Dashboard from './components/pages/Dashboard'
import Findings from './components/pages/Findings'
import Compliance from './components/pages/Compliance'
import About from './components/pages/About'
import Footer from './components/reusables/Footer'

function App() {
  return (
    <Router>
      <div className="min-h-screen">
        <Navigation />
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/findings" element={<Findings />} />
          <Route path="/compliance" element={<Compliance />} />
          <Route path="/about" element={<About />} />
        </Routes>
        <Footer/>
      </div>
    </Router>
  )
}

export default App