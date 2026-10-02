import type { ClerkProviderProps } from '@clerk/clerk-react';

/** Clerk's appearance type, derived from the provider props (the SDK
 *  doesn't export an `Appearance` type under that name). */
type ClerkAppearance = NonNullable<ClerkProviderProps['appearance']>;

/**
 * Clerk wiring for the site. The publishable key comes from the
 * environment (site/.env.local locally, the host's env settings in
 * production) — it is a public identifier, but it still never gets
 * hardcoded into source. When it's absent the app renders without the
 * Clerk provider (see main.tsx) instead of crashing.
 */
export const CLERK_PUBLISHABLE_KEY = import.meta.env.VITE_CLERK_PUBLISHABLE_KEY as
  | string
  | undefined;

/**
 * Whether Clerk is live on this deployment. EVERY Clerk hook/component
 * (useAuth, SignedIn, UserButton, …) throws when no ClerkProvider is
 * mounted — so consumers must branch on this flag and render a static
 * fallback when it's false. (A missing key on the host must degrade the
 * auth UI, never blank the whole site.)
 */
export const CLERK_ENABLED = Boolean(CLERK_PUBLISHABLE_KEY);

/**
 * The BugSeek look, translated into Clerk's appearance system: black
 * surfaces, white primary, bone text, quiet greys — so Clerk-rendered
 * surfaces (the user-button menu, account modals) match the site's
 * black-and-white design instead of arriving in stock Clerk colours.
 * (`colorPrimaryText` from older Clerk versions is `colorPrimaryForeground`
 * in this SDK — the dark text that sits on the white primary.)
 */
export const clerkAppearance: ClerkAppearance = {
  variables: {
    colorBackground: '#0A0A0A',
    colorPrimary: '#FFFFFF',
    colorPrimaryForeground: '#050505',
    colorText: '#F5F5F2',
    colorTextSecondary: '#A8A8A3',
    colorInputBackground: '#111111',
    colorInputText: '#FFFFFF',
    colorNeutral: '#FFFFFF',
    borderRadius: '0.9rem',
  },
  elements: {
    userButtonAvatarBox: {
      width: '2rem',
      height: '2rem',
    },
    userButtonTrigger: {
      borderRadius: '9999px',
      boxShadow: '0 0 0 1px rgba(255, 255, 255, 0.22)',
    },
  },
};
