import type { ClerkProviderProps } from '@clerk/clerk-react';

type ClerkAppearance = NonNullable<ClerkProviderProps['appearance']>;

export const CLERK_PUBLISHABLE_KEY = import.meta.env.VITE_CLERK_PUBLISHABLE_KEY as string | undefined;
export const CLERK_PROXY_URL = "/__clerk";
export const CLERK_ENABLED = Boolean(CLERK_PUBLISHABLE_KEY);

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
    userButtonAvatarBox: { width: '2rem', height: '2rem' },
    userButtonTrigger: {
      borderRadius: '9999px',
      boxShadow: '0 0 0 1px rgba(255, 255, 255, 0.22)',
    },
  },
};
