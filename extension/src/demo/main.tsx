import React from 'react';
import ReactDOM from 'react-dom/client';
import { App } from './App';
import { Footer, Landing } from './Landing';
import '../ui/modern.css';
import './demo.css';
import './landing.css';
import './alive.css';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <Landing />
    <App />
    <Footer />
  </React.StrictMode>
);
