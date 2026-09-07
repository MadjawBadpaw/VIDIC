// src/components/summary/SummaryCard.jsx

import Badge from "../ui/Badge";

import {
  severityFromScore,
  getOriginCountry,
  getAuthSummary,
  hasReturnPathMismatch,
  getAbuseSummary,
  getTopFindings,
} from "../../utils/summaryHelpers";

export default function SummaryCard({
  risk,
  authentication,
  routing,
  domainIntelligence,
}) {
  const severity = severityFromScore(risk.score);

  const originCountry = getOriginCountry(routing, domainIntelligence);
  const authSummary = getAuthSummary(authentication);
  const returnMismatch = hasReturnPathMismatch(authentication);
  const abuse = getAbuseSummary(routing, domainIntelligence);
  const findings = getTopFindings(risk);

  return (
    <section className={`summary-card summary-${severity}`}>
      {/* Header */}
      <div className="summary-header">
        <div>
          <p className="summary-subtitle">Threat Assessment</p>

          <h2 className="summary-verdict">{risk.verdict}</h2>

          <p className="summary-confidence">
            Confidence {risk.confidence}%
          </p>
        </div>

        <div className="summary-score">
          <span>{risk.score}</span>
          <small>/100</small>
        </div>
      </div>

      {/* Quick Facts */}
      <div className="summary-grid">

        <FactCard label="Origin Country">
          <div className="fact-value">{originCountry}</div>
        </FactCard>

        <FactCard label="Authentication">
          <Badge variant={authSummary.status}>
            {authSummary.label}
          </Badge>
        </FactCard>

        <FactCard label="Return Path">
          <Badge variant={returnMismatch ? "critical" : "success"}>
            {returnMismatch ? "Mismatch" : "Matches Sender"}
          </Badge>
        </FactCard>

        <FactCard label="Origin IP Reputation">
          {abuse ? (
            <Badge
              variant={
                abuse.abuse_confidence_score >= 30
                  ? "critical"
                  : "success"
              }
            >
              {abuse.status} • {abuse.abuse_confidence_score}% Abuse Score
            </Badge>
          ) : (
            <span className="fact-value">Unavailable</span>
          )}
        </FactCard>
      </div>

      {/* Findings */}
      {findings.length > 0 && (
        <div className="summary-findings">
          <h3>Top Findings</h3>

          <div className="findings-list">
            {findings.map((reason, index) => (
              <span key={index} className="finding-chip">
                {reason}
              </span>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}

/* ------------------ */

function FactCard({ label, children }) {
  return (
    <div className="fact-card">
      <p className="fact-label">{label}</p>

      <div className="fact-content">
        {children}
      </div>
    </div>
  );
}