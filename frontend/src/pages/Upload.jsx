import { useState } from "react";
import {
  UploadCloud,
  ShieldAlert,
  ShieldCheck,
  Mail,
  Globe,
  Link2,
  Network,
  FileText,
  Hash,
  Clock,
  Server,
  Copy,
} from "lucide-react";

import AppLayout from "../components/layout/AppLayout";
import Badge, { severityFromScore } from "../components/ui/Badge";
import { uploadEmail } from "../services/api";

export default function Upload() {
  const [file, setFile] = useState(null);
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function handleAnalyze() {
    if (!file) return;

    setLoading(true);
    setError("");

    try {
      const result = await uploadEmail(file);
      setAnalysis(result);
    } catch (err) {
      console.error(err);
      setError(
        err.response?.data?.detail ||
          "Unable to analyze email. Make sure the backend is running."
      );
    } finally {
      setLoading(false);
    }
  }

  const risk = analysis?.risk;
  const copyText = (text) => navigator.clipboard.writeText(text);

  return (
    <AppLayout>
      <div className="space-y-6">
        {/* ---------------- Upload Card ---------------- */}
        <section className="rounded-[var(--radius-md)] border border-[var(--border)] bg-[var(--panel)] p-8">
          <div className="flex items-center gap-4">
            <div className="rounded-[var(--radius-sm)] bg-[var(--accent-soft)] p-3">
              <UploadCloud className="h-6 w-6 text-[var(--accent)]" />
            </div>

            <div>
              <h1 className="text-xl font-semibold text-[var(--text)]">
                Upload email sample
              </h1>
              <p className="text-sm text-[var(--muted)]">
                Upload an RFC5322 (.eml) email for phishing investigation.
              </p>
            </div>
          </div>

          <label className="mt-8 flex cursor-pointer flex-col items-center justify-center rounded-[var(--radius-md)] border-2 border-dashed border-[var(--border-strong)] py-10 transition hover:border-[var(--accent)] hover:bg-[var(--panel-hover)]">
            <UploadCloud className="mb-3 h-9 w-9 text-[var(--muted-dim)]" />

            <span className="text-sm text-[var(--text)]">
              {file ? file.name : "Choose .eml file"}
            </span>

            <span className="mt-1 text-xs text-[var(--muted)]">
              Click to browse your email sample
            </span>

            <input
              type="file"
              accept=".eml,message/rfc822"
              className="hidden"
              onChange={(e) => setFile(e.target.files[0])}
            />
          </label>

          <button
            onClick={handleAnalyze}
            disabled={!file || loading}
            className="mt-6 flex w-full items-center justify-center gap-2 rounded-[var(--radius-sm)] bg-[var(--accent)] py-3 font-semibold text-[#04120F] transition hover:bg-[var(--accent-strong)] disabled:cursor-not-allowed disabled:bg-[var(--border-strong)] disabled:text-[var(--muted)]"
          >
            {loading ? (
              <>
                <div className="h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent" />
                Analyzing...
              </>
            ) : (
              <>
                <ShieldAlert className="h-4 w-4" />
                Analyze email
              </>
            )}
          </button>

          {error && (
            <div className="mt-5 rounded-[var(--radius-sm)] border border-[var(--critical)]/30 bg-[var(--critical-soft)] p-4 text-sm text-[var(--critical)]">
              {error}
            </div>
          )}
        </section>

        {/* ---------------- Results ---------------- */}
        {analysis && (
          <>
            <ThreatCard risk={risk} />

            <section className="grid gap-4 md:grid-cols-3">
              <Card icon={<Hash />} title="Email SHA-256">
                <div className="flex items-start justify-between gap-2">
                  <code className="break-all text-xs text-[var(--accent)]">
                    {analysis.metadata.email_sha256}
                  </code>
                  <button
                    onClick={() => copyText(analysis.metadata.email_sha256)}
                    className="text-[var(--muted)] hover:text-[var(--text)]"
                  >
                    <Copy size={16} />
                  </button>
                </div>
              </Card>

              <Card icon={<Server />} title="Parser version">
                {analysis.metadata.parser_version}
              </Card>

              <Card icon={<FileText />} title="Email size">
                {(analysis.metadata.size_bytes / 1024).toFixed(2)} KB
              </Card>
            </section>

            <section className="grid gap-5 lg:grid-cols-2">
              <Card icon={<Mail />} title="Email headers">
                <Field label="Subject" value={analysis.headers.subject} />
                <Field label="From" value={analysis.headers.from} />
                <Field label="To" value={analysis.headers.to} />
                <Field label="Date" value={analysis.headers.date} />
                <Field label="Message-ID" value={analysis.headers.message_id} />
              </Card>

              <Card icon={<ShieldCheck />} title="Authentication">
                <AuthField label="SPF" value={analysis.authentication.spf} />
                <AuthField label="DKIM" value={analysis.authentication.dkim} />
                <AuthField label="DMARC" value={analysis.authentication.dmarc} />
                <Field label="Return-Path" value={analysis.authentication.return_path} />
              </Card>
            </section>

            <section className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
              <Stat icon={<Link2 />} label="URLs" value={analysis.iocs.counts.urls} />
              <Stat icon={<Globe />} label="Domains" value={analysis.iocs.counts.domains} />
              <Stat icon={<Mail />} label="Emails" value={analysis.iocs.counts.emails} />
              <Stat icon={<Network />} label="IPs" value={analysis.iocs.counts.ips} />
            </section>

            <section className="grid gap-5 lg:grid-cols-2">
              <Card icon={<Globe />} title="Indicators of compromise">
                <IOCGroup title="URLs" items={analysis.iocs.urls} />
                <IOCGroup title="Domains" items={analysis.iocs.domains} />
                <IOCGroup title="Emails" items={analysis.iocs.emails} />
                <IOCGroup title="IP addresses" items={analysis.iocs.ips} />
              </Card>

              <Card icon={<Network />} title="SMTP routing timeline">
                <div className="space-y-3">
                  <div className="rounded-[var(--radius-sm)] border border-[var(--accent)]/20 bg-[var(--accent-soft)] p-3">
                    <p className="text-xs text-[var(--accent)]">Origin IP</p>
                    <p className="mt-1 font-data text-sm text-[var(--text)]">
                      {analysis.routing.origin_ip || "Unknown"}
                    </p>
                    <p className="mt-2 text-xs text-[var(--muted)]">
                      {analysis.routing.hop_count} SMTP hop(s)
                    </p>
                  </div>

                  {analysis.routing.received_chain.map((hop) => {
                    const timestamp =
                      typeof hop.timestamp === "string"
                        ? hop.timestamp
                        : hop.timestamp?.display || "Unknown";

                    const iso =
                      typeof hop.timestamp === "string" ? hop.timestamp : hop.timestamp?.iso || "";

                    return (
                      <div
                        key={hop.hop}
                        className="rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--panel-hover)] p-4"
                      >
                        <div className="mb-3 flex items-center justify-between">
                          <span className="rounded-full bg-[var(--border)] px-2 py-1 text-xs text-[var(--muted)]">
                            Hop {hop.hop}
                          </span>
                          <div className="flex items-center gap-2 text-xs text-[var(--muted)]">
                            <Clock size={13} />
                            {timestamp}
                          </div>
                        </div>

                        <p className="font-medium text-[var(--text)]">{hop.server}</p>
                        <p className="mt-1 font-data text-sm text-[var(--muted)]">
                          {hop.ip || "Private / Unknown IP"}
                        </p>

                        {iso && (
                          <p className="mt-2 font-data text-xs text-[var(--muted-dim)]">{iso}</p>
                        )}

                        <details className="mt-3 text-xs text-[var(--muted)]">
                          <summary className="cursor-pointer">Raw Received header</summary>
                          <pre className="mt-2 whitespace-pre-wrap break-all rounded-[var(--radius-sm)] bg-black/30 p-3 font-data">
                            {hop.raw}
                          </pre>
                        </details>
                      </div>
                    );
                  })}
                </div>
              </Card>
            </section>

            <Card icon={<FileText />} title="Attachments">
              {analysis.attachments.length === 0 ? (
                <p className="text-sm text-[var(--muted)]">No attachments detected.</p>
              ) : (
                <div className="space-y-4">
                  {analysis.attachments.map((att, idx) => (
                    <div
                      key={idx}
                      className="rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--panel-hover)] p-4"
                    >
                      <p className="font-medium text-[var(--text)]">{att.filename}</p>

                      <div className="mt-2 grid gap-2 text-sm text-[var(--muted)] md:grid-cols-2">
                        <Field label="Extension" value={att.extension} />
                        <Field label="MIME type" value={att.mime_type} />
                        <Field label="Size" value={`${att.size} bytes`} />
                      </div>

                      <div className="mt-3">
                        <p className="mb-1 text-xs text-[var(--muted)]">SHA-256</p>
                        <code className="break-all text-xs text-[var(--accent)]">{att.sha256}</code>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </Card>

            <Card icon={<FileText />} title="Body preview">
              <pre className="overflow-x-auto whitespace-pre-wrap rounded-[var(--radius-sm)] bg-black/30 p-4 text-sm text-[var(--muted)] font-data">
                {analysis.body_preview}
              </pre>
              <p className="mt-3 text-xs text-[var(--muted-dim)]">
                {analysis.body_length} characters parsed.
              </p>
            </Card>
          </>
        )}
      </div>
    </AppLayout>
  );
}

/* ---------- Reusable pieces ---------- */

function ThreatCard({ risk }) {
  const severity = severityFromScore(risk.score);
  const color = `var(--${severity})`;
  const soft = `var(--${severity}-soft)`;

  return (
    <section
      className="rounded-[var(--radius-md)] border p-6"
      style={{ borderColor: `${color}4D`, background: soft }}
    >
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs text-[var(--muted)]">Threat assessment</p>
          <h2 className="mt-2 text-2xl font-bold" style={{ color }}>
            {risk.verdict}
          </h2>
          <p className="mt-2 text-sm text-[var(--muted)]">Confidence {risk.confidence}%</p>
        </div>

        <div className="text-right">
          <div className="text-5xl font-bold" style={{ color }}>
            {risk.score}
          </div>
          <div className="text-sm text-[var(--muted)]">Risk score</div>
        </div>
      </div>

      <div className="mt-6 flex flex-wrap gap-2">
        {risk.reasons.map((reason, idx) => (
          <span
            key={idx}
            className="rounded-full bg-black/20 px-3 py-1 text-xs text-[var(--text)]"
          >
            {reason}
          </span>
        ))}
      </div>
    </section>
  );
}

function Card({ icon, title, children }) {
  return (
    <section className="rounded-[var(--radius-md)] border border-[var(--border)] bg-[var(--panel)] p-6">
      <div className="mb-4 flex items-center gap-3">
        <div className="rounded-[var(--radius-sm)] bg-[var(--panel-hover)] p-2 text-[var(--accent)]">
          {icon}
        </div>
        <h2 className="font-semibold text-[var(--text)]">{title}</h2>
      </div>
      <div className="space-y-3">{children}</div>
    </section>
  );
}

function Field({ label, value }) {
  return (
    <div className="border-b border-[var(--border)] pb-2 last:border-none">
      <p className="text-xs text-[var(--muted)]">{label}</p>
      <p className="mt-1 break-all text-sm text-[var(--text)]">{value || "Unavailable"}</p>
    </div>
  );
}

function AuthField({ label, value }) {
  const failed = value?.toLowerCase().includes("fail") || value?.toLowerCase().includes("invalid");

  return (
    <div className="flex items-center justify-between rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--panel-hover)] px-4 py-3">
      <span className="text-sm text-[var(--text)]">{label}</span>
      <Badge variant={failed ? "critical" : "low"}>{value || "Unavailable"}</Badge>
    </div>
  );
}

function IOCGroup({ title, items }) {
  return (
    <div>
      <p className="mb-2 text-xs text-[var(--muted)]">{title}</p>
      {items.length === 0 ? (
        <p className="text-sm text-[var(--muted-dim)]">None detected.</p>
      ) : (
        <div className="flex flex-wrap gap-2">
          {items.map((item) => (
            <code
              key={item}
              className="rounded-[var(--radius-sm)] bg-[var(--panel-hover)] px-3 py-2 text-xs text-[var(--accent)]"
            >
              {item}
            </code>
          ))}
        </div>
      )}
    </div>
  );
}

function Stat({ icon, label, value }) {
  return (
    <div className="rounded-[var(--radius-md)] border border-[var(--border)] bg-[var(--panel)] p-5">
      <div className="mb-3 text-[var(--accent)]">{icon}</div>
      <p className="text-2xl font-semibold text-[var(--text)]">{value}</p>
      <p className="mt-1 text-sm text-[var(--muted)]">{label}</p>
    </div>
  );
}