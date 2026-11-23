/**
 * Assessment-identity header for outbound active-test requests only.
 * It carries no operator identity. Never add it to passive recon,
 * webcheck, or extension traffic.
 */
export const ASSESSMENT_HEADER_NAME = 'BugSeek-Assessment';
export const ASSESSMENT_HEADER_VALUE = '1.0';
export const ASSESSMENT_TASK_HEADER_NAME = 'BugSeek-Assessment-Task';

/**
 * Headers identifying an outbound request as a BugSeek assessment.
 * With a task id, exactly two headers; without, exactly one. Nothing
 * in either value identifies the operator.
 */
export function assessmentHeaders(taskId?: string): Record<string, string> {
  const headers: Record<string, string> = {
    [ASSESSMENT_HEADER_NAME]: ASSESSMENT_HEADER_VALUE,
  };
  if (taskId) {
    headers[ASSESSMENT_TASK_HEADER_NAME] = taskId;
  }
  return headers;
}
