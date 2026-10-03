import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'
import { client } from './lib/appwrite.ts'
import { ErrorBoundary } from './lib/ErrorBoundary.tsx'

void client.ping().catch((error: unknown) => {
  console.warn('Appwrite connectivity check failed:', error);
});

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ErrorBoundary>
      <App />
    </ErrorBoundary>
  </StrictMode>,
)
