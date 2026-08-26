// Secret Detector — an official RequestReaver Weapon (observer).
//
// Scans every request and response passing through the proxy for exposed
// secrets (cloud keys, tokens, private keys) and raises a finding when one is
// found. Reads traffic and reports only — it never modifies anything.
//
// Weapon contract: module.exports = (rr) => { ... }. `rr` is the sandboxed API;
// this Weapon only uses rr.onTransaction (traffic:observe) and rr.report
// (findings:write) — the two permissions it declares in weapon.json.

module.exports = (rr) => {
  // Each rule: a name, a regex, a severity and a short description. Patterns are
  // deliberately specific to keep false positives low.
  const RULES = [
    {
      id: 'aws-access-key',
      name: 'AWS access key ID',
      re: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b/g,
      severity: 'high',
      cwe: 'CWE-798'
    },
    {
      id: 'google-api-key',
      name: 'Google API key',
      re: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
      severity: 'high',
      cwe: 'CWE-798'
    },
    {
      id: 'slack-token',
      name: 'Slack token',
      re: /\bxox[baprs]-[0-9A-Za-z-]{10,48}\b/g,
      severity: 'high',
      cwe: 'CWE-798'
    },
    {
      id: 'github-token',
      name: 'GitHub token',
      re: /\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b/g,
      severity: 'high',
      cwe: 'CWE-798'
    },
    {
      id: 'stripe-secret-key',
      name: 'Stripe secret key',
      re: /\bsk_live_[0-9A-Za-z]{16,64}\b/g,
      severity: 'critical',
      cwe: 'CWE-798'
    },
    {
      id: 'private-key',
      name: 'Private key block',
      re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g,
      severity: 'critical',
      cwe: 'CWE-321'
    },
    {
      id: 'google-oauth-secret',
      name: 'Google OAuth client secret',
      re: /\bGOCSPX-[0-9A-Za-z\-_]{28}\b/g,
      severity: 'high',
      cwe: 'CWE-798'
    }
  ]

  // Redact the middle of a matched secret so the evidence does not itself leak
  // the full value in the findings list.
  const redact = (s) => {
    if (s.length <= 12) return s.slice(0, 3) + '***'
    return s.slice(0, 6) + '...' + s.slice(-4)
  }

  const scanText = (where, text, tx, seen) => {
    if (!text) return
    for (const rule of RULES) {
      rule.re.lastIndex = 0
      let m
      while ((m = rule.re.exec(text)) !== null) {
        const value = m[0]
        const key = rule.id + ':' + value
        if (seen.has(key)) continue
        seen.add(key)
        rr.report(
          {
            ruleId: rule.id,
            severity: rule.severity,
            title: rule.name + ' exposed in ' + where,
            description:
              'A ' +
              rule.name +
              ' was found in the ' +
              where +
              '. Secrets transmitted in traffic can be captured by anyone able to observe or proxy the connection.',
            evidence: where + ': ' + redact(value),
            impact:
              'An attacker who obtains this ' +
              rule.name +
              ' can use it to access the associated account, service or data.',
            mitigation:
              'Revoke and rotate the exposed secret immediately. Never transmit long-lived secrets to the client; keep them server-side and scope credentials narrowly.',
            cwe: rule.cwe
          },
          tx
        )
      }
    }
  }

  rr.onTransaction((tx) => {
    // De-duplicate identical secrets seen in both request and response of the
    // same transaction.
    const seen = new Set()
    scanText('request body', tx.request && tx.request.body, tx, seen)
    if (tx.response) scanText('response body', tx.response.body, tx, seen)
    // Authorization/cookie header values occasionally carry raw keys too.
    const scanHeaders = (label, headers) => {
      if (!headers) return
      for (const [name, value] of headers) {
        scanText(label + ' header ' + name, value, tx, seen)
      }
    }
    scanHeaders('request', tx.request && tx.request.headers)
    if (tx.response) scanHeaders('response', tx.response.headers)
  })
}
