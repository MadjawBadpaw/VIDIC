import AppLayout from "../components/layout/AppLayout";
import Panel from "../components/ui/Panel";
import { FileText } from "lucide-react";

export default function Reports() {
  return (
    <AppLayout>
      <section className="mb-10">
        <h1 className="text-[32px] font-semibold tracking-tight text-[var(--text)]">
          Investigation reports
        </h1>
        <p className="mt-3 max-w-2xl text-sm leading-6 text-[var(--muted)]">
          Export completed phishing investigations as shareable reports.
        </p>
      </section>

      <Panel>
        <div className="flex flex-col items-center gap-3 py-10 text-center">
          <div className="rounded-full bg-[var(--panel-hover)] p-3">
            <FileText className="text-[var(--muted)]" size={28} />
          </div>

          <h2 className="text-base font-semibold text-[var(--text)]">
            No reports yet
          </h2>

          <p className="max-w-sm text-sm text-[var(--muted)]">
            Analyze an email from the Email Upload page. Completed
            investigations will appear here for export.
          </p>
        </div>
      </Panel>
    </AppLayout>
  );
}