/**
 * Source-map recovery (white-box, client-side).
 *
 * When a production bundle ships its source map exposed (already
 * detected by sourceMapScanner), the map's `sourcesContent` holds the
 * original, unminified sources. Minified code defeats most AST
 * analysis, so this re-runs the taint engine on the recovered original
 * sources instead.
 *
 * Limits, stated wherever results surface: finding positions are
 * positions in the recovered original source, not the minified bundle,
 * no VLQ mapping back to generated positions. Only sources embedded
 * in the map are analysed; a map that lists sources without embedding
 * them is skipped. A map that is absent, unparseable, or whose sources
 * fail to parse is skipped gracefully, the minified-bundle findings
 * still stand.
 */
import type { ExposedSourceMap } from '../scanners/sourceMapScanner';
import { DeepTaintEngine, scanVueHtmlBindings, type SourceToSinkFlow } from './taintEngine';

export interface RecoveredSourceResult {
  /** Taint flows found in the recovered original sources. */
  flows: SourceToSinkFlow[];
  /** Original source files actually analysed. */
  sourcesAnalysed: string[];
  /** Maps/files skipped and why (absent content, parse failure, caps). */
  skipped: string[];
}

const MAX_SOURCES_PER_MAP = 20;
const MAX_SOURCE_BYTES = 500 * 1024;
const MAX_TOTAL_BYTES = 2 * 1024 * 1024;

/** Map a `sources` entry to its embedded content, if present. */
function pairSources(map: ExposedSourceMap): Array<{ name: string; code: string }> {
  const out: Array<{ name: string; code: string }> = [];
  const contents = map.sourcesContent ?? [];
  map.sources.forEach((name, i) => {
    const code = contents[i];
    if (typeof code === 'string' && code.length > 0) {
      out.push({ name, code });
    }
  });
  return out;
}

/**
 * Run the taint engine over the original sources embedded in exposed maps.
 * Each flow's trace files are the original source paths (prefixed with the
 * map URL so the report can say where they came from).
 */
export function analyzeRecoveredSources(maps: ExposedSourceMap[]): RecoveredSourceResult {
  const flows: SourceToSinkFlow[] = [];
  const sourcesAnalysed: string[] = [];
  const skipped: string[] = [];
  let totalBytes = 0;

  for (const map of maps) {
    const paired = pairSources(map);
    if (paired.length === 0) {
      skipped.push(
        `${map.mapUrl}: map lists ${map.sources.length} source(s) but embeds no sourcesContent — originals not fetched`,
      );
      continue;
    }
    let analysedInMap = 0;
    for (const { name, code } of paired) {
      if (analysedInMap >= MAX_SOURCES_PER_MAP) {
        skipped.push(`${map.mapUrl}: source cap (${MAX_SOURCES_PER_MAP} per map) reached`);
        break;
      }
      if (code.length > MAX_SOURCE_BYTES) {
        skipped.push(`${name}: ${Math.round(code.length / 1024)} KB exceeds per-file cap — skipped`);
        continue;
      }
      if (totalBytes + code.length > MAX_TOTAL_BYTES) {
        skipped.push(`${map.mapUrl}: total recovered-source budget reached`);
        break;
      }
      totalBytes += code.length;
      const label = `${name} (via ${map.mapUrl})`;
      const engine = new DeepTaintEngine();
      try {
        const fileFlows = engine.analyzeSource(code, label);
        const vueFlows = scanVueHtmlBindings(
          code,
          label,
          engine.getTaintedVariableNames(),
        );
        for (const flow of [...fileFlows, ...vueFlows]) {
          flows.push({
            ...flow,
            note:
              (flow.note ? flow.note + ' ' : '') +
              'Found in the original source recovered from an exposed source map; line numbers refer to the original file, not the minified bundle.',
          });
        }
        sourcesAnalysed.push(label);
        analysedInMap++;
      } catch {
        skipped.push(`${name}: could not parse recovered source — skipped`);
      }
    }
  }

  return { flows, sourcesAnalysed, skipped };
}
