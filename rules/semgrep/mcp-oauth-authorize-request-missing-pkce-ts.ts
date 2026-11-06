export function buildAuthUrlBad(clientId: string, redirectUri: string, resource: string): string {
  // ruleid: mcp-oauth-authorize-request-missing-pkce-ts
  const params = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: redirectUri,
    resource,
  });
  return `https://as.example.com/authorize?${params}`;
}

export function buildAuthUrlGood(clientId: string, redirectUri: string, resource: string, challenge: string): string {
  // ok: mcp-oauth-authorize-request-missing-pkce-ts
  const params = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: redirectUri,
    resource,
    code_challenge: challenge,
    code_challenge_method: "S256",
  });
  return `https://as.example.com/authorize?${params}`;
}
