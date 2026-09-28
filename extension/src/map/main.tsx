import React from 'react';
import ReactDOM from 'react-dom/client';
import { ThreatMap } from './ThreatMap';
import '../ui/modern.css';
import './map.css';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ThreatMap />
  </React.StrictMode>
);
