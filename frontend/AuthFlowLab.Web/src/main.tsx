import React from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import './styles.css';

//  React 入口只负责挂载应用，业务逻辑放在 App 和组件文件中。
createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
