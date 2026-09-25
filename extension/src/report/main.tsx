import React from 'react';
import ReactDOM from 'react-dom/client';
import { Report } from './Report';
import '../styles/tokens.css';
import '../styles/components.css';
import './report.css';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <Report />
  </React.StrictMode>
);
