import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { ClerkProvider } from '@clerk/clerk-react'
import './index.css'
import App from './App.tsx'
import { CLERK_PUBLISHABLE_KEY, clerkAppearance } from './lib/clerk.ts'
import { ErrorBoundary } from './lib/ErrorBoundary.tsx'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ErrorBoundary>
      {CLERK_PUBLISHABLE_KEY ? (
        <ClerkProvider
          publishableKey={CLERK_PUBLISHABLE_KEY}
          appearance={clerkAppearance}
          afterSignOutUrl="/"
        >
          <App />
        </ClerkProvider>
      ) : (
        <App />
      )}
    </ErrorBoundary>
  </StrictMode>,
)
