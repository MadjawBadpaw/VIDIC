import AppLayout from "../components/layout/AppLayout";
import { FileText } from "lucide-react";

export default function Reports() {
  return (
    <AppLayout>
      <div className="mt-8">
        <p className="text-blue-400 uppercase text-sm tracking-widest">
          Dashboard / Reports
        </p>

        <h1 className="text-4xl font-bold mt-2">Investigation Reports</h1>

        <p className="text-slate-400 mt-3">
          Export phishing investigations as PDF reports.
        </p>

        <div className="mt-8 rounded-2xl bg-[#111827] border border-slate-800 p-6">
          <div className="flex items-center gap-4">
            <FileText className="text-blue-400" size={40} />

            <div>
              <h2 className="text-xl font-semibold">
                No reports generated yet.
              </h2>

              <p className="text-slate-500 text-sm">
                Completed investigations will appear here.
              </p>
            </div>
          </div>
        </div>
      </div>
    </AppLayout>
  );
}