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
  AlertTriangle,
  CheckCircle2,
  Copy,
} from "lucide-react";

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

  const severityColor = (score = 0) => {
    if (score >= 80)
      return "text-red-400 bg-red-500/10 border-red-500/30";
    if (score >= 50)
      return "text-yellow-400 bg-yellow-500/10 border-yellow-500/30";
    return "text-emerald-400 bg-emerald-500/10 border-emerald-500/30";
  };

  return (
    <div className="space-y-8">
      {/* ---------------- Upload Card ---------------- */}
      <section className="rounded-3xl border border-zinc-800 bg-zinc-950 p-8">
        <div className="flex items-center gap-4">
          <div className="rounded-2xl bg-blue-500/10 p-3">
            <UploadCloud className="h-7 w-7 text-blue-400" />
          </div>

          <div>
            <h1 className="text-2xl font-bold text-white">
              Upload Email Sample
            </h1>
            <p className="text-sm text-zinc-400">
              Upload an RFC5322 (.eml) email for offline phishing investigation.
            </p>
          </div>
        </div>

        <label className="mt-8 flex cursor-pointer flex-col items-center justify-center rounded-2xl border-2 border-dashed border-zinc-700 py-10 transition hover:border-blue-500/50 hover:bg-zinc-900">
          <UploadCloud className="mb-3 h-10 w-10 text-zinc-500" />

          <span className="text-sm text-zinc-300">
            {file ? file.name : "Choose .eml file"}
          </span>

          <span className="mt-1 text-xs text-zinc-500">
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
          className="mt-6 flex w-full items-center justify-center gap-2 rounded-xl bg-blue-600 py-3 text-white transition hover:bg-blue-500 disabled:cursor-not-allowed disabled:bg-zinc-700"
        >
          {loading ? (
            <>
              <div className="h-4 w-4 animate-spin rounded-full border-2 border-white border-t-transparent" />
              Analyzing...
            </>
          ) : (
            <>
              <ShieldAlert className="h-4 w-4" />
              Analyze Email
            </>
          )}
        </button>

        {error && (
          <div className="mt-5 rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300">
            {error}
          </div>
        )}
      </section>

      {/* ---------------- Results ---------------- */}
      {analysis && (
        <>
          {/* Threat Card */}
          <section
            className={`rounded-3xl border p-6 ${severityColor(risk.score)}`}
          >
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs uppercase tracking-widest text-zinc-400">
                  Threat Assessment
                </p>

                <h2 className="mt-2 text-3xl font-bold">{risk.verdict}</h2>

                <p className="mt-2 text-zinc-300">
                  Confidence {risk.confidence}%
                </p>
              </div>

              <div className="text-right">
                <div className="text-5xl font-black">{risk.score}</div>
                <div className="text-sm text-zinc-400">Risk Score</div>
              </div>
            </div>

            <div className="mt-6 flex flex-wrap gap-2">
              {risk.reasons.map((reason, idx) => (
                <span
                  key={idx}
                  className="rounded-full bg-white/5 px-3 py-1 text-xs text-zinc-300"
                >
                  {reason}
                </span>
              ))}
            </div>
          </section>

          {/* Metadata */}
          <section className="grid gap-4 md:grid-cols-3">
            <Card icon={<Hash />} title="Email SHA256">
              <div className="flex items-start justify-between gap-2">
                <code className="break-all text-xs text-blue-300">
                  {analysis.metadata.email_sha256}
                </code>

                <button
                  onClick={() =>
                    copyText(analysis.metadata.email_sha256)
                  }
                  className="text-zinc-500 hover:text-white"
                >
                  <Copy size={16} />
                </button>
              </div>
            </Card>

            <Card icon={<Server />} title="Parser Version">
              {analysis.metadata.parser_version}
            </Card>

            <Card icon={<FileText />} title="Email Size">
              {(analysis.metadata.size_bytes / 1024).toFixed(2)} KB
            </Card>
          </section>

          {/* Headers + Auth */}
          <section className="grid gap-6 lg:grid-cols-2">
            <Card icon={<Mail />} title="Email Headers">
              <Field label="Subject" value={analysis.headers.subject} />
              <Field label="From" value={analysis.headers.from} />
              <Field label="To" value={analysis.headers.to} />
              <Field label="Date" value={analysis.headers.date} />
              <Field
                label="Message-ID"
                value={analysis.headers.message_id}
              />
            </Card>

            <Card icon={<ShieldCheck />} title="Authentication">
              <AuthField
                label="SPF"
                value={analysis.authentication.spf}
              />
              <AuthField
                label="DKIM"
                value={analysis.authentication.dkim}
              />
              <AuthField
                label="DMARC"
                value={analysis.authentication.dmarc}
              />
              <Field
                label="Return-Path"
                value={analysis.authentication.return_path}
              />
            </Card>
          </section>

          {/* IOC Summary */}
          <section className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <Stat
              icon={<Link2 />}
              label="URLs"
              value={analysis.iocs.counts.urls}
            />
            <Stat
              icon={<Globe />}
              label="Domains"
              value={analysis.iocs.counts.domains}
            />
            <Stat
              icon={<Mail />}
              label="Emails"
              value={analysis.iocs.counts.emails}
            />
            <Stat
              icon={<Network />}
              label="IPs"
              value={analysis.iocs.counts.ips}
            />
          </section>

          {/* IOC Lists */}
          <section className="grid gap-6 lg:grid-cols-2">
            <Card icon={<Globe />} title="Indicators of Compromise">
              <IOCGroup
                title="URLs"
                items={analysis.iocs.urls}
              />

              <IOCGroup
                title="Domains"
                items={analysis.iocs.domains}
              />

              <IOCGroup
                title="Emails"
                items={analysis.iocs.emails}
              />

              <IOCGroup
                title="IP Addresses"
                items={analysis.iocs.ips}
              />
            </Card>

            <Card icon={<Network />} title="SMTP Routing Timeline">
              <div className="space-y-4">
                <div className="rounded-xl border border-blue-500/20 bg-blue-500/10 p-3">
                  <p className="text-xs uppercase text-blue-300">
                    Origin IP
                  </p>

                  <p className="mt-1 font-mono text-sm text-white">
                    {analysis.routing.origin_ip || "Unknown"}
                  </p>

                  <p className="mt-2 text-xs text-zinc-400">
                    {analysis.routing.hop_count} SMTP hop(s)
                  </p>
                </div>

                {analysis.routing.received_chain.map((hop) => {
                  const timestamp =
                    typeof hop.timestamp === "string"
                      ? hop.timestamp
                      : hop.timestamp?.display || "Unknown";

                  const iso =
                    typeof hop.timestamp === "string"
                      ? hop.timestamp
                      : hop.timestamp?.iso || "";

                  return (
                    <div
                      key={hop.hop}
                      className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-4"
                    >
                      <div className="mb-3 flex items-center justify-between">
                        <span className="rounded-full bg-zinc-800 px-2 py-1 text-xs text-zinc-300">
                          Hop {hop.hop}
                        </span>

                        <div className="flex items-center gap-2 text-xs text-zinc-400">
                          <Clock size={13} />
                          {timestamp}
                        </div>
                      </div>

                      <p className="font-medium text-white">
                        {hop.server}
                      </p>

                      <p className="mt-1 text-sm text-zinc-400">
                        {hop.ip || "Private / Unknown IP"}
                      </p>

                      {iso && (
                        <p className="mt-2 font-mono text-xs text-zinc-500">
                          {iso}
                        </p>
                      )}

                      <details className="mt-3 text-xs text-zinc-500">
                        <summary className="cursor-pointer">
                          Raw Received Header
                        </summary>

                        <pre className="mt-2 whitespace-pre-wrap break-all rounded-lg bg-black/40 p-3">
                          {hop.raw}
                        </pre>
                      </details>
                    </div>
                  );
                })}
              </div>
            </Card>
          </section>

          {/* Attachments */}
          <Card icon={<FileText />} title="Attachments">
            {analysis.attachments.length === 0 ? (
              <p className="text-sm text-zinc-500">
                No attachments detected.
              </p>
            ) : (
              <div className="space-y-4">
                {analysis.attachments.map((att, idx) => (
                  <div
                    key={idx}
                    className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-4"
                  >
                    <p className="font-medium text-white">
                      {att.filename}
                    </p>

                    <div className="mt-2 grid gap-2 text-sm text-zinc-400 md:grid-cols-2">
                      <Field label="Extension" value={att.extension} />
                      <Field label="MIME Type" value={att.mime_type} />
                      <Field
                        label="Size"
                        value={`${att.size} bytes`}
                      />
                    </div>

                    <div className="mt-3">
                      <p className="mb-1 text-xs text-zinc-500">
                        SHA256
                      </p>

                      <code className="break-all text-xs text-blue-300">
                        {att.sha256}
                      </code>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Card>

          {/* Body Preview */}
          <Card icon={<FileText />} title="Body Preview">
            <pre className="overflow-x-auto whitespace-pre-wrap rounded-xl bg-black/40 p-4 text-sm text-zinc-300">
              {analysis.body_preview}
            </pre>

            <p className="mt-3 text-xs text-zinc-500">
              {analysis.body_length} characters parsed.
            </p>
          </Card>
        </>
      )}
    </div>
  );
}

/* ---------- Reusable Components ---------- */

function Card({ icon, title, children }) {
  return (
    <section className="rounded-3xl border border-zinc-800 bg-zinc-950 p-6">
      <div className="mb-5 flex items-center gap-3">
        <div className="rounded-xl bg-zinc-900 p-2 text-blue-400">
          {icon}
        </div>

        <h2 className="font-semibold text-white">{title}</h2>
      </div>

      <div className="space-y-3">{children}</div>
    </section>
  );
}

function Field({ label, value }) {
  return (
    <div className="border-b border-zinc-800 pb-2 last:border-none">
      <p className="text-xs uppercase text-zinc-500">{label}</p>

      <p className="mt-1 break-all text-sm text-zinc-200">
        {value || "Unavailable"}
      </p>
    </div>
  );
}

function AuthField({ label, value }) {
  const failed =
    value?.toLowerCase().includes("fail") ||
    value?.toLowerCase().includes("invalid");

  return (
    <div className="flex items-center justify-between rounded-xl border border-zinc-800 bg-zinc-900/40 px-4 py-3">
      <span className="text-sm text-zinc-300">{label}</span>

      <span
        className={`rounded-full px-3 py-1 text-xs ${
          failed
            ? "bg-red-500/10 text-red-300"
            : "bg-emerald-500/10 text-emerald-300"
        }`}
      >
        {value || "Unavailable"}
      </span>
    </div>
  );
}

function IOCGroup({ title, items }) {
  return (
    <div>
      <p className="mb-2 text-xs uppercase text-zinc-500">{title}</p>

      {items.length === 0 ? (
        <p className="text-sm text-zinc-500">None detected.</p>
      ) : (
        <div className="flex flex-wrap gap-2">
          {items.map((item) => (
            <code
              key={item}
              className="rounded-lg bg-zinc-900 px-3 py-2 text-xs text-blue-300"
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
    <div className="rounded-2xl border border-zinc-800 bg-zinc-950 p-5">
      <div className="mb-3 text-blue-400">{icon}</div>

      <p className="text-3xl font-bold text-white">{value}</p>

      <p className="mt-1 text-sm text-zinc-500">{label}</p>
    </div>
  );
}