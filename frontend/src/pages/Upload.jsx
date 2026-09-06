import { useState } from "react";
import AppLayout from "../components/layout/AppLayout";
import Panel from "../components/ui/Panel";
import Button from "../components/ui/Button";
import Badge from "../components/ui/Badge";
import { uploadEmail } from "../services/api";

export default function Upload() {
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function handleUpload() {
    if (!file) return;

    setLoading(true);
    setError("");
    setResult(null);

    try {
      const data = await uploadEmail(file);
      setResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <AppLayout>
      <section className="mb-12">
        <p className="text-[11px] uppercase tracking-[0.25em] text-zinc-500 mb-3">
          Email Upload
        </p>

        <h1 className="text-4xl font-semibold tracking-tight">
          Upload Email Sample
        </h1>

        <p className="mt-3 max-w-2xl text-zinc-400">
          Upload a phishing email in .eml format. VIDIC extracts headers,
          authentication fields, indicators of compromise and attachment hashes.
        </p>
      </section>

      <Panel title="Email Sample" subtitle="UPLOAD .EML FILE">
        <div className="space-y-6">

          <label className="block cursor-pointer rounded-xl border border-dashed border-[#27272A] bg-[#0D0D10] p-10 text-center hover:border-blue-600 transition">
            <input
              type="file"
              accept=".eml"
              className="hidden"
              onChange={(e) => setFile(e.target.files[0])}
            />

            <p className="text-lg font-medium">
              {file ? file.name : "Choose an .eml file"}
            </p>

            <p className="mt-2 text-sm text-zinc-500">
              Drag & drop is coming later.
            </p>
          </label>

          <Button onClick={handleUpload}>
            {loading ? "Analyzing..." : "Analyze Email"}
          </Button>

          {error && (
            <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-red-400 text-sm">
              {error}
            </div>
          )}
        </div>
      </Panel>

      {result && (
        <div className="mt-8 space-y-6">

          <Panel title="Email Headers" subtitle="PARSED METADATA">
            <div className="grid md:grid-cols-2 gap-6 text-sm">

              <Field label="Subject" value={result.headers.subject} />
              <Field label="From" value={result.headers.from} />
              <Field label="To" value={result.headers.to} />
              <Field label="Date" value={result.headers.date} />
              <Field label="Return Path" value={result.headers.return_path} />
              <Field label="Message ID" value={result.headers.message_id} />

            </div>
          </Panel>

          <Panel title="Authentication" subtitle="SPF / DKIM">
            <div className="flex gap-4 flex-wrap">
              <Badge variant={result.headers.spf ? "red" : "neutral"}>
                SPF: {result.headers.spf || "Unavailable"}
              </Badge>

              <Badge variant={result.headers.dkim ? "red" : "neutral"}>
                DKIM: {result.headers.dkim ? "Present" : "Unavailable"}
              </Badge>
            </div>
          </Panel>

          <Panel title="Indicators of Compromise" subtitle="IOC EXTRACTION">
            <IOC title="URLs" items={result.iocs.urls} />
            <IOC title="Domains" items={result.iocs.domains} />
            <IOC title="Email Addresses" items={result.iocs.emails} />
            <IOC title="IP Addresses" items={result.iocs.ips} />
          </Panel>

          <Panel title="Attachments" subtitle="FILE ANALYSIS">
            {result.attachments.length === 0 ? (
              <p className="text-zinc-500 text-sm">
                No attachments detected.
              </p>
            ) : (
              result.attachments.map((att) => (
                <div
                  key={att.sha256}
                  className="border-b border-[#27272A] py-4 text-sm space-y-1"
                >
                  <p className="font-medium">{att.filename}</p>
                  <p className="text-zinc-400">{att.content_type}</p>
                  <p className="text-zinc-500">{att.size} bytes</p>
                  <code className="block break-all text-xs text-blue-400">
                    {att.sha256}
                  </code>
                </div>
              ))
            )}
          </Panel>

          <Panel title="Body Preview" subtitle="FIRST 600 CHARACTERS">
            <pre className="whitespace-pre-wrap text-sm text-zinc-300 leading-7">
              {result.body_preview}
            </pre>
          </Panel>

        </div>
      )}
    </AppLayout>
  );
}

function Field({ label, value }) {
  return (
    <div>
      <p className="mb-2 text-xs uppercase tracking-[0.2em] text-zinc-500">
        {label}
      </p>

      <p className="break-words text-zinc-200">{value || "Unavailable"}</p>
    </div>
  );
}

function IOC({ title, items }) {
  return (
    <div className="mb-6">
      <p className="mb-3 text-xs uppercase tracking-[0.2em] text-zinc-500">
        {title}
      </p>

      {items.length === 0 ? (
        <p className="text-sm text-zinc-500">None detected.</p>
      ) : (
        <div className="space-y-2">
          {items.map((item) => (
            <code
              key={item}
              className="block rounded-lg bg-[#0D0D10] px-3 py-2 text-xs text-blue-400 break-all"
            >
              {item}
            </code>
          ))}
        </div>
      )}
    </div>
  );
}