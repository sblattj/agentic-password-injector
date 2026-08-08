// src/domain.ts
//
// SHARED DATA ONLY — deliberately no functions and no imports.
//
// Two independent guards refuse a lookup key that matches everything:
// `tools.ts:isValidDomain` at the tool entry point, and
// `vault/arc.ts:isRegistrableDomain` inside the vault. Keeping BOTH functions is
// defence in depth (a bug in one is caught by the other), but keeping two copies
// of the SUFFIX LIST was not defence — it was drift: the vault's copy had fallen
// 78 entries behind, so `list_credentials({domain:"co.ke"})` was refused at the
// entry point while the vault layer would have happily swept it.
//
// So the data is single-sourced here and the logic stays split.
//
// Not a full PSL. A full list would be a dependency plus a freshness problem for
// a check whose only job is to make the SWEEP useless: the ≥2-label rule in each
// guard already kills every single-label suffix ("com"), and this covers the
// common multi-label ones that would otherwise slip through.
export const PUBLIC_SUFFIXES: ReadonlySet<string> = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk", "ltd.uk", "plc.uk",
  "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
  "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
  "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
  "co.kr", "or.kr", "ne.kr", "go.kr",
  "co.za", "org.za", "net.za", "gov.za", "ac.za",
  "com.br", "net.br", "org.br", "gov.br",
  "com.mx", "org.mx", "gob.mx",
  "com.ar", "net.ar", "org.ar", "gob.ar",
  "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
  "com.hk", "org.hk", "net.hk", "idv.hk",
  "com.tw", "org.tw", "net.tw",
  "com.sg", "net.sg", "org.sg", "edu.sg", "gov.sg",
  "com.tr", "net.tr", "org.tr", "gov.tr",
  "co.il", "org.il", "net.il", "ac.il", "gov.il",
  "co.in", "net.in", "org.in", "gov.in", "ac.in", "firm.in", "gen.in", "ind.in",
  "com.pl", "net.pl", "org.pl",
  "com.ua", "co.ua",
  "com.ru", "org.ru", "net.ru",
  "co.th", "in.th",
  "com.my", "net.my", "org.my",
  "com.ph", "net.ph", "org.ph",
  "com.vn", "net.vn", "org.vn",
  "co.id", "web.id", "or.id",
  "com.co", "net.co",
  "com.es", "org.es", "nom.es",
  "com.pt", "org.pt",
  "com.pe", "com.ve", "com.ec", "com.uy", "com.py", "com.bo",
  "com.eg", "com.sa", "com.ng", "com.gh", "com.pk", "com.bd",
  "co.ke", "co.tz", "co.ug", "co.zw",
  "s3.amazonaws.com", "github.io", "herokuapp.com", "web.app", "firebaseapp.com",
  "vercel.app", "netlify.app", "pages.dev", "workers.dev", "blogspot.com",
  "azurewebsites.net", "cloudfront.net", "appspot.com", "onmicrosoft.com",
]);
