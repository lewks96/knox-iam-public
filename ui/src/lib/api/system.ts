import { apiRequest } from "../api-client";

export interface HealthResponse {
  status: string;
  version: string;
  git_sha?: string;
}

export async function getHealth(): Promise<HealthResponse> {
  return apiRequest<HealthResponse>("/sys/health", { skipAuth: true });
}

export interface VersionResponse {
  version: string;
  git_sha: string;
  build_time: string;
}

export async function getVersion(): Promise<VersionResponse> {
  return apiRequest<VersionResponse>("/sys/version", { skipAuth: true });
}
