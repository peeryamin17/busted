// No checkout exists yet, so no plan is selected anywhere: every tier
// points at the in-app download section on /app, where the waitlist lives.
export function pricingCtaHref(): string {
  return '/app#download';
}
