import { Routes, Route } from 'react-router-dom';
import UploadPage from './pages/UploadPage';
import ScanResultPage from './pages/ScanResultPage';
import ScanHistoryPage from './pages/ScanHistoryPage';
import ScanComparisonPage from './pages/ScanComparisonPage';
import AppPortfolioPage from './pages/AppPortfolioPage';
import MetricsDashboardPage from './pages/MetricsDashboardPage';

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<UploadPage />} />
      <Route path="/scans" element={<ScanHistoryPage />} />
      {/* /scans/compare must come before /scans/:id so the literal segment matches first */}
      <Route path="/scans/compare" element={<ScanComparisonPage />} />
      <Route path="/scans/:id" element={<ScanResultPage />} />
      <Route path="/apps" element={<AppPortfolioPage />} />
      <Route path="/metrics" element={<MetricsDashboardPage />} />
    </Routes>
  );
}
