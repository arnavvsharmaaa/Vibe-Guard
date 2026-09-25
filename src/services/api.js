const API_BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

export class ApiError extends Error {
  constructor(status, detail) {
    super(detail);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }
}

async function request(path, { method = "GET", body, signal } = {}) {
  let response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, { method, body, signal });
  } catch (err) {
    if (err.name === "AbortError") throw err;
    throw new ApiError(0, "Cannot reach the Vibe Guard API");
  }
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    const detail = typeof errorData.detail === "string" ? errorData.detail : `Request failed with status ${response.status}`;
    throw new ApiError(response.status, detail);
  }
  return response.json();
}

const segment = (value) => encodeURIComponent(String(value));

export function checkHealth() {
  return request("/api/health");
}

export function createScan(file, projectName, signal) {
  const formData = new FormData();
  formData.append("project_name", projectName);
  formData.append("file", file);
  return request("/api/scans", { method: "POST", body: formData, signal });
}

export function listScans(signal) {
  return request("/api/scans", { signal });
}

export function getScan(scanId, signal) {
  return request(`/api/scans/${segment(scanId)}`, { signal });
}

export function getScanStatus(scanId, signal) {
  return request(`/api/scans/${segment(scanId)}/status`, { signal });
}

export function listReports(signal) {
  return request("/api/reports", { signal });
}

export function getReport(scanId, signal) {
  return request(`/api/reports/${segment(scanId)}`, { signal });
}

export function getReportFindings(scanId, signal) {
  return request(`/api/reports/${segment(scanId)}/findings`, { signal });
}

// A finding is addressed by the composite "{scan_id}:{finding_id}" reference.
export function getFinding(scanId, findingId, signal) {
  return request(`/api/findings/${segment(`${scanId}:${findingId}`)}`, { signal });
}

// User-facing message for an API error. Server-error bodies are never shown.
export function describeError(err) {
  if (!(err instanceof ApiError) || err.status === 0) {
    return "The Vibe Guard API is unavailable. Make sure the backend is running, then try again.";
  }
  if (err.status >= 500) return "The Vibe Guard API returned an error. Try again.";
  return err.detail;
}
