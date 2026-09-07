// src/utils/summaryHelpers.js

/**
 * Severity from risk score.
 */
export function severityFromScore(score = 0) {
  if (score >= 90) return "critical";
  if (score >= 70) return "high";
  if (score >= 40) return "medium";
  return "low";
}

/**
 * Find origin country using origin IP.
 */
export function getOriginCountry(routing, domainIntelligence) {
  const originIp = routing?.origin_ip;
  if (!originIp) return "Unknown";

  const match = domainIntelligence?.ips?.find(
    (entry) => entry.ip === originIp
  );

  if (!match) return "Unknown";

  return match.network_country || match.abuseipdb?.country || "Unknown";
}

/**
 * Authentication summary.
 *
 * Summary card intentionally compresses detailed SPF states into
 * three buckets. AuthenticationPanel will expose the raw values.
 */
export function getAuthSummary(authentication) {
  if (!authentication) {
    return {
      status: "unknown",
      label: "Authentication Unknown",
      failed: [],
    };
  }

  const checks = ["spf", "dkim", "dmarc"];

  const failed = [];
  const warnings = [];

  checks.forEach((key) => {
    const value = authentication[key];

    if (value === "fail") {
      failed.push(key.toUpperCase());
    }

    if (
      key === "spf" &&
      ["softfail", "neutral", "temperror", "permerror"].includes(value)
    ) {
      warnings.push(`${key.toUpperCase()} (${value})`);
    }
  });

  if (failed.length === 3) {
    return {
      status: "critical",
      label: "SPF / DKIM / DMARC Failed",
      failed,
    };
  }

  if (failed.length || warnings.length) {
    return {
      status: "warning",
      label: "Authentication Issues",
      failed,
      warnings,
    };
  }

  return {
    status: "success",
    label: "SPF / DKIM / DMARC Passed",
    failed: [],
  };
}

/**
 * Return-Path mismatch comes directly from backend.
 */
export function hasReturnPathMismatch(authentication) {
  return authentication?.return_path_mismatch === true;
}

/**
 * AbuseIPDB summary for origin IP.
 */
export function getAbuseSummary(routing, domainIntelligence) {
  const originIp = routing?.origin_ip;
  if (!originIp) return null;

  const match = domainIntelligence?.ips?.find(
    (entry) => entry.ip === originIp
  );

  return match?.abuseipdb || null;
}

/**
 * Top findings shown on summary card.
 */
export function getTopFindings(risk, limit = 4) {
  if (!risk?.reasons) return [];
  return risk.reasons.slice(0, limit);
}