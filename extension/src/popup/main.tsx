import React from 'react';
import ReactDOM from 'react-dom/client';
import { Popup } from './Popup';
import '../ui/modern.css';
import './popup.css';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <Popup />
  </React.StrictMode>
);
