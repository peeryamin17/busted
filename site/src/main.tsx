import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { ClerkProvider } from '@clerk/clerk-react'
import './index.css'
import App from './App.tsx'
import { client } from './lib/appwrite.ts'
import { CLERK_PUBLISHABLE_KEY, clerkAppearance } from './lib/clerk.ts'
import { ErrorBoundary } from './lib/ErrorBoundary.tsx'

void client.ping().catch((error: unknown) => {
  console.warn('Appwrite connectivity check failed:', error);
});

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ErrorBoundary>
      {CLERK_PUBLISHABLE_KEY ? (
        <ClerkProvider
          publishableKey={CLERK_PUBLISHABLE_KEY}
          proxyUrl="/__clerk"
          appearance={clerkAppearance}
          signInUrl="/signin"
          signUpUrl="/signup"
          signInFallbackRedirectUrl="/app"
          signUpFallbackRedirectUrl="/app"
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
