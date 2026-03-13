import { Routes, Route } from 'react-router-dom';

// Pages — implemented in TES-12
const UploadPage = () => (
  <div className="flex items-center justify-center min-h-screen">
    <p className="text-gray-400">Upload page — coming in TES-12</p>
  </div>
);
const ScanResultPage = () => (
  <div className="flex items-center justify-center min-h-screen">
    <p className="text-gray-400">Scan result — coming in TES-12</p>
  </div>
);
const ScanHistoryPage = () => (
  <div className="flex items-center justify-center min-h-screen">
    <p className="text-gray-400">Scan history — coming in TES-12</p>
  </div>
);

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<UploadPage />} />
      <Route path="/scans" element={<ScanHistoryPage />} />
      <Route path="/scans/:id" element={<ScanResultPage />} />
    </Routes>
  );
}
