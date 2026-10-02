import type { ClerkProviderProps } from '@clerk/clerk-react';

/** Clerk's appearance type, derived from the provider props (the SDK
 *  doesn't export an `Appearance` type under that name). */
type ClerkAppearance = NonNullable<ClerkProviderProps['appearance']>;

/**
 * Clerk wiring for the site.
 *
 * Until the custom domain lands, sign-in runs on Clerk's development
 * instance: the production key's sign-in host (clerk.bugseek-ai.vercel.app)
 * cannot resolve on a vercel.app domain, so any build carrying that key
 * can never load Clerk. The development instance's publishable key is
 * therefore pinned below — a publishable key is a public identifier that
 * ships inside every visitor's bundle anyway. A pk_test_ value from the
 * environment (site/.env.local) still wins locally; anything else —
 * a missing variable, a pk_live value — falls back to the pinned key,
 * so the host's env settings can no longer take sign-in down.
 * Launch step: once DNS points at Clerk, delete the pin and let the
 * host provide the pk_live key again.
 */
const DEVELOPMENT_KEY = 'pk_test_ZmFzdC1zdHVyZ2Vvbi03NTIuY2xlcmsuYWNjb3VudHMuZGV2JA';

const envKey = import.meta.env.VITE_CLERK_PUBLISHABLE_KEY as string | undefined;

export const CLERK_PUBLISHABLE_KEY: string | undefined =
  envKey && envKey.startsWith('pk_test_') ? envKey : DEVELOPMENT_KEY;

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
