export function reportUrl(scanId: string, format: string): string {
  return `/api/scans/${encodeURIComponent(scanId)}/report?format=${encodeURIComponent(format)}`;
}

export function reportDownloadError(status: number, backendError?: string): string {
  if (backendError) return backendError;
  if (status === 401) return 'Sign in again to download this report.';
  if (status === 403) return 'This report format needs the Hunter plan or higher.';
  if (status === 404) return 'That report is no longer available.';
  if (status === 409) return 'This report is only available once the scan has finished.';
  return `Download failed (${status}).`;
}

export function reportFilename(contentDisposition: string | null, scanId: string, format: string): string {
  const fallback = `bugseek-report-${scanId.slice(0, 8)}.${format}`;
  if (!contentDisposition) return fallback;
  const quoted = /filename="([^"]+)"/.exec(contentDisposition);
  if (quoted?.[1]) return quoted[1];
  const bare = /filename=([^;]+)/.exec(contentDisposition);
  const name = bare?.[1]?.trim();
  return name ? name : fallback;
}
