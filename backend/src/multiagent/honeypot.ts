export interface ProbeObservation {
  url: string;
  status: number;
  bodyLength: number;
  latencyMs: number;
  headers: Record<string, string>;
  bodySnippet: string;
}

export interface BaselineProfile {
  random404Status: number;
  random404Length: number;
  meanLatencyMs: number;
  stdLatencyMs: number;
}

export interface HoneypotAssessment {
  trapProbability: number; // 0..1
  signals: string[];
  isLikelyTrap: boolean;
}

const CANARY_SIGNATURES = [
  /canarytokens\.(com|org)/i,
  /\.oast\.(pro|live|site|online|fun|me)/i,
  /AKIA[0-9A-Z]{16}.*canary/i,
  /x-honeypot|x-trap|cowrie|glastopf|conpot/i,
];

export function assessHoneypotSignals(
  obs: ProbeObservation,
  baseline: BaselineProfile
): HoneypotAssessment {
  const signals: string[] = [];
  let score = 0;

  // 1. Known canary / honeypot headers or body markers
  const headerBlob = Object.entries(obs.headers)
    .map(([k, v]) => `${k}: ${v}`)
    .join('\n');
  const combined = `${headerBlob}\n${obs.bodySnippet}`;

  for (const re of CANARY_SIGNATURES) {
    if (re.test(combined)) {
      signals.push(`Matched known canary/honeypot signature: ${re.source}`);
      score += 0.65;
    }
  }

  // 2. Soft-404 / Catch-all trap detection
  if (obs.status === 200 && baseline.random404Status === 200) {
    const lengthDelta = Math.abs(obs.bodyLength - baseline.random404Length);
    const relativeDiff = lengthDelta / Math.max(1, baseline.random404Length);
    if (relativeDiff < 0.03) {
      signals.push(
        `Catch-all 200 OK matches random nonexistent path within ${(relativeDiff * 100).toFixed(1)}% byte delta.`
      );
      score += 0.55;
    }
  }

  // 3. Tarpit latency z-score
  if (baseline.stdLatencyMs > 0) {
    const z = (obs.latencyMs - baseline.meanLatencyMs) / baseline.stdLatencyMs;
    if (z > 3.5 && obs.latencyMs > 4000) {
      signals.push(
        `Tarpit latency anomaly detected (${obs.latencyMs}ms, z=${z.toFixed(1)}).`
      );
      score += 0.3;
    }
  }

  const trapProbability = Math.min(1, Number(score.toFixed(2)));
  return {
    trapProbability,
    signals,
    isLikelyTrap: trapProbability >= 0.55,
  };
}
