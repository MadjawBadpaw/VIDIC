import { useState } from "react";
import AppLayout from "../components/layout/AppLayout";
import {
  UploadCloud,
  FileText,
  Shield,
  CheckCircle2,
  AlertTriangle,
} from "lucide-react";

export default function Upload() {
  const [file, setFile] = useState(null);
  const [hash, setHash] = useState("");

  async function handleFile(selected) {
    if (!selected) return;

    setFile(selected);

    const buffer = await selected.arrayBuffer();
    const digest = await crypto.subtle.digest("SHA-256", buffer);

    const hex = Array.from(new Uint8Array(digest))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    setHash(hex);
  }

  function handleDrop(e) {
    e.preventDefault();
    handleFile(e.dataTransfer.files[0]);
  }

  function handleBrowse(e) {
    handleFile(e.target.files[0]);
  }

  return (
    <AppLayout>
      <div className="mt-8">

        <p className="text-blue-400 uppercase text-sm tracking-widest">
          Dashboard / Email Upload
        </p>

        <h1 className="text-4xl font-bold mt-2">
          Upload Threat Sample
        </h1>

        <p className="text-slate-400 mt-3 max-w-2xl">
          Upload an email (.eml or .msg) or attachment (PDF, ZIP, PNG) for
          offline phishing analysis and IOC extraction.
        </p>

        {/* Upload Zone */}

        <div
          onDragOver={(e) => e.preventDefault()}
          onDrop={handleDrop}
          className="mt-8 border-2 border-dashed border-blue-500/40 rounded-3xl p-12 text-center bg-[#111827] hover:border-blue-500 transition"
        >
          <UploadCloud className="mx-auto text-blue-400" size={64} />

          <h2 className="text-2xl font-semibold mt-4">
            Drag & Drop Email Here
          </h2>

          <p className="text-slate-400 mt-2">
            Supported: .eml .msg .pdf .zip .png
          </p>

          <label className="mt-6 inline-block cursor-pointer rounded-xl bg-blue-600 hover:bg-blue-700 px-6 py-3 transition">
            Browse File
            <input
              type="file"
              accept=".eml,.msg,.pdf,.zip,.png"
              className="hidden"
              onChange={handleBrowse}
            />
          </label>
        </div>

        {/* File Preview */}

        {file && (
          <section className="grid lg:grid-cols-2 gap-6 mt-8">

            {/* Left */}

            <div className="rounded-2xl bg-[#111827] border border-slate-800 p-6">
              <div className="flex items-center gap-3 mb-5">
                <FileText className="text-blue-400" />

                <h2 className="text-xl font-semibold">File Preview</h2>
              </div>

              <InfoRow title="Filename" value={file.name} />

              <InfoRow title="Size" value={`${(file.size / 1024).toFixed(2)} KB`} />

              <InfoRow title="Type" value={file.type || "Unknown"} />

              <div className="mt-6">
                <p className="text-sm text-slate-400 mb-2">
                  SHA-256 Hash
                </p>

                <div className="rounded-xl bg-[#1F2937] p-3 text-xs text-green-400 break-all font-mono">
                  {hash}
                </div>
              </div>
            </div>

            {/* Right */}

            <div className="rounded-2xl bg-[#111827] border border-slate-800 p-6">
              <div className="flex items-center gap-3 mb-5">
                <Shield className="text-green-400" />

                <h2 className="text-xl font-semibold">
                  Email Authentication Preview
                </h2>
              </div>

              <StatusRow
                label="SPF"
                status="Pass"
                color="green"
              />

              <StatusRow
                label="DKIM"
                status="Fail"
                color="red"
              />

              <StatusRow
                label="DMARC"
                status="Quarantine"
                color="yellow"
              />

              <StatusRow
                label="Suspicious URLs"
                status="3 Found"
                color="red"
              />

              <StatusRow
                label="Attachments"
                status="2 Detected"
                color="yellow"
              />
            </div>

          </section>
        )}

        {/* AI Verdict */}

        {file && (
          <section className="mt-8 rounded-2xl bg-[#111827] border border-red-500/20 p-6">

            <div className="flex items-center gap-3 mb-5">
              <AlertTriangle className="text-red-400" />

              <h2 className="text-xl font-semibold">
                AI Threat Verdict
              </h2>
            </div>

            <div className="grid lg:grid-cols-2 gap-6">

              <div>
                <p className="text-sm text-slate-400">
                  Risk Score
                </p>

                <h1 className="text-6xl font-bold text-red-400 mt-2">
                  82%
                </h1>

                <span className="mt-3 inline-block rounded-full bg-red-500/20 text-red-400 px-3 py-1 text-sm">
                  High Risk
                </span>
              </div>

              <div className="space-y-3 text-slate-300 text-sm leading-7">
                <p>
                  • Sender domain resembles a trusted brand.
                </p>

                <p>
                  • DKIM authentication failed.
                </p>

                <p>
                  • Multiple shortened URLs detected.
                </p>

                <p>
                  • Attachment requests credential verification.
                </p>

                <p className="text-green-400">
                  AI explanation will come from Ollama after backend integration.
                </p>
              </div>

            </div>

          </section>
        )}

        {/* IOC Preview */}

        {file && (
          <section className="mt-8 rounded-2xl bg-[#111827] border border-slate-800 p-6">

            <div className="flex items-center gap-3 mb-5">
              <CheckCircle2 className="text-blue-400" />

              <h2 className="text-xl font-semibold">
                Indicators of Compromise (IOC)
              </h2>
            </div>

            <div className="grid lg:grid-cols-3 gap-4">

              {[
                "paypal-security.com",
                "hxxps://login-paypal-check[.]xyz",
                "185.23.91.18",
                "invoice_update.pdf",
                "credential.zip",
                "shorturl.at/a12BC",
              ].map((ioc) => (
                <div
                  key={ioc}
                  className="rounded-xl bg-[#1F2937] border border-slate-700 p-3 font-mono text-xs break-all"
                >
                  {ioc}
                </div>
              ))}

            </div>

          </section>
        )}

      </div>
    </AppLayout>
  );
}

function InfoRow({ title, value }) {
  return (
    <div className="flex justify-between border-b border-slate-800 py-3">
      <span className="text-slate-400">{title}</span>

      <span className="font-medium text-right break-all ml-6">
        {value}
      </span>
    </div>
  );
}

function StatusRow({ label, status, color }) {
  const colors = {
    green: "text-green-400 bg-green-500/10",
    red: "text-red-400 bg-red-500/10",
    yellow: "text-yellow-400 bg-yellow-500/10",
  };

  return (
    <div className="flex justify-between items-center border-b border-slate-800 py-3">
      <span className="text-slate-300">{label}</span>

      <span className={`rounded-full px-3 py-1 text-sm ${colors[color]}`}>
        {status}
      </span>
    </div>
  );
}