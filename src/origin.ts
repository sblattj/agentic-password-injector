function norm(o: string): string | null {
  try {
    const u = new URL(o);
    return `${u.protocol}//${u.hostname.toLowerCase()}${
      u.port && !((u.protocol === "https:" && u.port === "443") || (u.protocol === "http:" && u.port === "80"))
        ? ":" + u.port
        : ""
    }`;
  } catch {
    return null;
  }
}

export function originMatches(tabOrigin: string, savedOrigin: string): boolean {
  const a = norm(tabOrigin), b = norm(savedOrigin);
  return a !== null && b !== null && a === b;
}
