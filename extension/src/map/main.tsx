import React from 'react';
import ReactDOM from 'react-dom/client';
import { ThreatMap } from './ThreatMap';
import 'leaflet/dist/leaflet.css';
import '../ui/modern.css';
import './map.css';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ThreatMap />
  </React.StrictMode>
);
