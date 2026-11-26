import { useEffect, useState } from 'react';
import { formatKeyStatus, listAiKeys } from '../lib/aiKeys';

/**
 * One quiet line on the member site: AI keys are managed in the
 * extension, this just reports whether any are actually saved.
 * While the check is loading or fails, it stays neutral rather than
 * claiming keys exist (or don't) before it knows.
 */
export function AiKeyStatus() {
  const [line, setLine] = useState<string>(formatKeyStatus(null));

  useEffect(() => {
    let cancelled = false;
    listAiKeys().then((result) => {
      if (cancelled) return;
      setLine(result.ok ? formatKeyStatus(result.data.keys) : formatKeyStatus(null));
    });
    return () => {
      cancelled = true;
    };
  }, []);

  return <p className="text-sm leading-relaxed text-slate2">{line}</p>;
}
