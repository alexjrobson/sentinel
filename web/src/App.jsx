import { useCallback, useEffect, useMemo, useState } from "react";

const NAV = [
  { id: "cases", label: "Cases" },
  { id: "scan", label: "Scan" },
  { id: "flags", label: "Flags" },
  { id: "vault", label: "Vault" },
];

const SEV = {
  critical: "bg-red-900/80 text-red-100",
  high: "bg-orange-900/80 text-orange-100",
  medium: "bg-amber-900/70 text-amber-100",
  low: "bg-cyan-900/70 text-cyan-100",
};

async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  const text = await res.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }
  if (!res.ok) {
    const detail = data?.detail || data || res.statusText;
    throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  return data;
}

function Badge({ severity }) {
  return (
    <span className={`rounded-full px-2 py-0.5 text-[11px] uppercase tracking-wide ${SEV[severity] || "bg-slate-700"}`}>
      {severity}
    </span>
  );
}

export default function App() {
  const [view, setView] = useState("cases");
  const [cases, setCases] = useState([]);
  const [activeId, setActiveId] = useState(null);
  const [detail, setDetail] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [vault, setVault] = useState({ exists: false, unlocked: false, entry_count: 0 });
  const [entries, setEntries] = useState([]);
  const [showSecrets, setShowSecrets] = useState(false);

  const loadCases = useCallback(async () => {
    const rows = await api("/api/cases");
    setCases(rows);
    if (!activeId && rows.length) setActiveId(rows[0].id);
  }, [activeId]);

  const loadDetail = useCallback(async (id) => {
    if (!id) {
      setDetail(null);
      return;
    }
    const data = await api(`/api/cases/${id}`);
    setDetail(data);
  }, []);

  const loadVault = useCallback(async () => {
    const status = await api("/api/vault/status");
    setVault(status);
    if (status.unlocked) {
      const list = await api(`/api/vault/entries?secrets=${showSecrets ? "true" : "false"}`);
      setEntries(list);
    } else {
      setEntries([]);
    }
  }, [showSecrets]);

  useEffect(() => {
    api("/api/health").then(() => loadCases()).catch((err) => setError(err.message));
    loadVault().catch(() => {});
  }, []);

  useEffect(() => {
    if (activeId) loadDetail(activeId).catch((err) => setError(err.message));
  }, [activeId, loadDetail]);

  useEffect(() => {
    if (vault.unlocked) loadVault().catch(() => {});
  }, [showSecrets]);

  const findings = detail?.findings || [];
  const files = detail?.files || [];
  const timeline = detail?.timeline || [];

  const sevCounts = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    findings.forEach((f) => {
      counts[f.severity] = (counts[f.severity] || 0) + 1;
    });
    return counts;
  }, [findings]);

  return (
    <div className="flex min-h-screen">
      <aside className="flex w-56 flex-col border-r border-slate-800 bg-ink-900">
        <div className="border-b border-slate-800 px-5 py-6">
          <div className="font-mono text-xs tracking-[0.35em] text-mint">SENTINEL</div>
          <div className="mt-1 text-sm text-slate-400">DFIR workstation</div>
        </div>
        <nav className="flex-1 p-3">
          {NAV.map((item) => (
            <button
              key={item.id}
              onClick={() => setView(item.id)}
              className={`mb-1 w-full rounded-md px-3 py-2 text-left text-sm ${
                view === item.id ? "bg-ink-700 text-mint" : "text-slate-300 hover:bg-ink-800"
              }`}
            >
              {item.label}
            </button>
          ))}
        </nav>
        <div className="border-t border-slate-800 p-4 text-xs text-slate-500">
          Local-only · hash-only VT
        </div>
      </aside>

      <main className="flex-1 overflow-auto p-8">
        {error && (
          <div className="mb-4 rounded-md border border-red-900 bg-red-950/60 px-4 py-2 text-sm text-red-200">
            {error}
            <button className="ml-3 text-red-400" onClick={() => setError("")}>
              dismiss
            </button>
          </div>
        )}

        {view === "cases" && (
          <CasesView
            cases={cases}
            activeId={activeId}
            onSelect={setActiveId}
            detail={detail}
            sevCounts={sevCounts}
          />
        )}
        {view === "scan" && (
          <ScanView
            busy={busy}
            onScan={async (payload) => {
              setBusy(true);
              setError("");
              try {
                const created = await api("/api/scan", { method: "POST", body: JSON.stringify(payload) });
                await loadCases();
                setActiveId(created.id);
                setView("flags");
              } catch (err) {
                setError(err.message);
              } finally {
                setBusy(false);
              }
            }}
          />
        )}
        {view === "flags" && (
          <FlagsView
            cases={cases}
            activeId={activeId}
            onSelect={setActiveId}
            findings={findings}
            files={files}
            timeline={timeline}
            onVt={async (fileId) => {
              setBusy(true);
              setError("");
              try {
                await api("/api/intel/vt-lookup", {
                  method: "POST",
                  body: JSON.stringify({ case_id: activeId, file_id: fileId }),
                });
                await loadDetail(activeId);
              } catch (err) {
                setError(err.message);
              } finally {
                setBusy(false);
              }
            }}
          />
        )}
        {view === "vault" && (
          <VaultView
            vault={vault}
            entries={entries}
            showSecrets={showSecrets}
            setShowSecrets={setShowSecrets}
            reload={loadVault}
            onError={setError}
          />
        )}
      </main>
    </div>
  );
}

function CasesView({ cases, activeId, onSelect, detail, sevCounts }) {
  return (
    <div>
      <Header title="Cases" subtitle="Investigations stored in the local SQLite case file." />
      <div className="grid grid-cols-12 gap-6">
        <div className="col-span-4 space-y-2">
          {cases.length === 0 && <p className="text-sm text-slate-500">No cases yet. Run a scan.</p>}
          {cases.map((c) => (
            <button
              key={c.id}
              onClick={() => onSelect(c.id)}
              className={`w-full rounded-lg border px-4 py-3 text-left ${
                c.id === activeId ? "border-mint/40 bg-ink-800" : "border-slate-800 bg-ink-900 hover:border-slate-700"
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="font-medium">{c.name}</span>
                <span className="font-mono text-xs text-slate-500">#{c.id}</span>
              </div>
              <div className="mt-1 text-xs text-slate-400">
                {c.file_count} files · {c.finding_count} flags
              </div>
            </button>
          ))}
        </div>
        <div className="col-span-8">
          {!detail ? (
            <Empty>Select a case</Empty>
          ) : (
            <div className="space-y-4">
              <div className="grid grid-cols-4 gap-3">
                {Object.entries(sevCounts).map(([k, v]) => (
                  <div key={k} className="rounded-lg border border-slate-800 bg-ink-900 p-4">
                    <div className="text-xs uppercase text-slate-500">{k}</div>
                    <div className="mt-1 font-mono text-2xl">{v}</div>
                  </div>
                ))}
              </div>
              <Card>
                <div className="text-xs uppercase text-slate-500">Target</div>
                <code className="mt-1 block break-all text-sm text-mint">{detail.case.target_path}</code>
                <div className="mt-3 text-xs text-slate-500">Created {detail.case.created_at}</div>
                <div className="mt-4 flex gap-3">
                  <a
                    className="rounded-md bg-mint/15 px-3 py-1.5 text-sm text-mint"
                    href={`/api/cases/${detail.case.id}/report.html`}
                    target="_blank"
                    rel="noreferrer"
                  >
                    HTML report
                  </a>
                  <a
                    className="rounded-md border border-slate-700 px-3 py-1.5 text-sm"
                    href={`/api/cases/${detail.case.id}/report.json`}
                    target="_blank"
                    rel="noreferrer"
                  >
                    JSON
                  </a>
                </div>
              </Card>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function ScanView({ onScan, busy }) {
  const [path, setPath] = useState("samples");
  const [name, setName] = useState("demo-case");
  const [notes, setNotes] = useState("");
  return (
    <div className="max-w-xl">
      <Header title="New scan" subtitle="Hashes, magic bytes, entropy, YARA, and IOC strings — then ATT&CK flags." />
      <form
        className="space-y-4"
        onSubmit={(e) => {
          e.preventDefault();
          onScan({ path, case: name, notes });
        }}
      >
        <Field label="Case name">
          <input className={inputClass} value={name} onChange={(e) => setName(e.target.value)} required />
        </Field>
        <Field label="Path (file or directory on this machine)">
          <input className={inputClass} value={path} onChange={(e) => setPath(e.target.value)} required />
        </Field>
        <Field label="Notes (chain of custody / context)">
          <textarea className={inputClass} rows={3} value={notes} onChange={(e) => setNotes(e.target.value)} />
        </Field>
        <button disabled={busy} className="rounded-md bg-mint px-4 py-2 text-sm font-medium text-ink-950 disabled:opacity-50">
          {busy ? "Scanning…" : "Run scan"}
        </button>
      </form>
    </div>
  );
}

function FlagsView({ cases, activeId, onSelect, findings, files, timeline, onVt }) {
  const [tab, setTab] = useState("flags");
  return (
    <div>
      <Header title="Security flags" subtitle="Rule hits mapped to MITRE ATT&CK techniques." />
      <div className="mb-4 flex items-center gap-3">
        <select
          className={inputClass + " w-64"}
          value={activeId || ""}
          onChange={(e) => onSelect(Number(e.target.value))}
        >
          <option value="">Select case</option>
          {cases.map((c) => (
            <option key={c.id} value={c.id}>
              #{c.id} {c.name}
            </option>
          ))}
        </select>
        <div className="flex rounded-md border border-slate-800">
          {["flags", "files", "timeline"].map((id) => (
            <button
              key={id}
              onClick={() => setTab(id)}
              className={`px-3 py-1.5 text-sm capitalize ${tab === id ? "bg-ink-700 text-mint" : "text-slate-400"}`}
            >
              {id}
            </button>
          ))}
        </div>
      </div>

      {tab === "flags" && (
        <Table
          headers={["Sev", "Rule", "ATT&CK", "Title", "Evidence", "File"]}
          rows={findings.map((f) => [
            <Badge key="s" severity={f.severity} />,
            <code key="r">{f.rule_id}</code>,
            (f.attack_ids || []).join(", "),
            f.title,
            f.evidence,
            <span key="p" className="font-mono text-xs">{f.file_path}</span>,
          ])}
        />
      )}
      {tab === "files" && (
        <Table
          headers={["ID", "Path", "SHA-256", "Entropy", "Type", "VT"]}
          rows={files.map((f) => [
            f.id,
            <span key="p" className="font-mono text-xs">{f.path}</span>,
            <span key="h" className="font-mono text-xs">{(f.sha256 || "").slice(0, 16)}…</span>,
            f.entropy,
            `${f.detected_type} ${f.extension || ""}`,
            <button key="vt" className="text-mint text-xs" onClick={() => onVt(f.id)}>
              hash lookup
            </button>,
          ])}
        />
      )}
      {tab === "timeline" && (
        <Table
          headers={["Timestamp", "Event", "Path"]}
          rows={timeline.map((e) => [e.timestamp, e.event, <span key="p" className="font-mono text-xs">{e.path}</span>])}
        />
      )}
    </div>
  );
}

function VaultView({ vault, entries, showSecrets, setShowSecrets, reload, onError }) {
  const [password, setPassword] = useState("");
  const [form, setForm] = useState({ name: "", type: "credential", username: "", secret: "", notes: "" });
  const [generated, setGenerated] = useState("");

  async function initOrUnlock(kind) {
    onError("");
    try {
      await api(`/api/vault/${kind}`, { method: "POST", body: JSON.stringify({ password }) });
      setPassword("");
      await reload();
    } catch (err) {
      onError(err.message);
    }
  }

  if (!vault.exists || !vault.unlocked) {
    return (
      <div className="max-w-md">
        <Header
          title="Investigator vault"
          subtitle="Argon2id key derivation, AES-256-GCM at rest. Master password is never stored."
        />
        <Field label="Master password">
          <input type="password" className={inputClass} value={password} onChange={(e) => setPassword(e.target.value)} />
        </Field>
        <div className="mt-4 flex gap-2">
          {!vault.exists && (
            <button className="rounded-md bg-mint px-4 py-2 text-sm text-ink-950" onClick={() => initOrUnlock("init")}>
              Create vault
            </button>
          )}
          {vault.exists && (
            <button className="rounded-md bg-mint px-4 py-2 text-sm text-ink-950" onClick={() => initOrUnlock("unlock")}>
              Unlock
            </button>
          )}
        </div>
      </div>
    );
  }

  return (
    <div>
      <Header title="Investigator vault" subtitle={`${vault.entry_count} entries · auto-lock ${vault.lock_seconds}s`} />
      <div className="mb-4 flex flex-wrap gap-3">
        <button className="rounded-md border border-slate-700 px-3 py-1.5 text-sm" onClick={() => api("/api/vault/lock", { method: "POST" }).then(reload)}>
          Lock
        </button>
        <label className="flex items-center gap-2 text-sm text-slate-400">
          <input type="checkbox" checked={showSecrets} onChange={(e) => setShowSecrets(e.target.checked)} />
          Show secrets
        </label>
        <a className="rounded-md border border-slate-700 px-3 py-1.5 text-sm" href="/api/vault/backup">
          Encrypted backup
        </a>
        <button
          className="rounded-md border border-slate-700 px-3 py-1.5 text-sm"
          onClick={async () => {
            const data = await api("/api/vault/generate", { method: "POST", body: JSON.stringify({ length: 20 }) });
            setGenerated(data.password);
            setForm((f) => ({ ...f, secret: data.password }));
          }}
        >
          Generate password
        </button>
        {generated && <code className="self-center text-mint">{generated}</code>}
      </div>

      <div className="grid grid-cols-12 gap-6">
        <div className="col-span-7">
          <Table
            headers={["Name", "Type", "Username", "Secret", ""]}
            rows={entries.map((e) => [
              e.name,
              e.type,
              e.username,
              <span key="s" className="font-mono text-xs">{e.secret}</span>,
              <button
                key="d"
                className="text-red-400 text-xs"
                onClick={async () => {
                  await api(`/api/vault/entries/${e.id}`, { method: "DELETE" });
                  reload();
                }}
              >
                delete
              </button>,
            ])}
          />
        </div>
        <form
          className="col-span-5 space-y-3"
          onSubmit={async (e) => {
            e.preventDefault();
            try {
              await api("/api/vault/entries", { method: "POST", body: JSON.stringify(form) });
              setForm({ name: "", type: "credential", username: "", secret: "", notes: "" });
              reload();
            } catch (err) {
              onError(err.message);
            }
          }}
        >
          <Card>
            <div className="mb-3 text-sm font-medium">Add entry</div>
            <Field label="Name">
              <input className={inputClass} value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
            </Field>
            <Field label="Type">
              <select className={inputClass} value={form.type} onChange={(e) => setForm({ ...form, type: e.target.value })}>
                <option value="credential">credential</option>
                <option value="api_key">api_key</option>
                <option value="note">note</option>
              </select>
            </Field>
            <Field label="Username">
              <input className={inputClass} value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} />
            </Field>
            <Field label="Secret">
              <input className={inputClass} value={form.secret} onChange={(e) => setForm({ ...form, secret: e.target.value })} />
            </Field>
            <button className="mt-2 rounded-md bg-mint px-3 py-1.5 text-sm text-ink-950">Store</button>
          </Card>
        </form>
      </div>
    </div>
  );
}

function Header({ title, subtitle }) {
  return (
    <div className="mb-6">
      <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
      <p className="mt-1 text-sm text-slate-400">{subtitle}</p>
    </div>
  );
}

function Card({ children }) {
  return <div className="rounded-lg border border-slate-800 bg-ink-900 p-5">{children}</div>;
}

function Empty({ children }) {
  return <div className="rounded-lg border border-dashed border-slate-800 p-10 text-center text-slate-500">{children}</div>;
}

function Field({ label, children }) {
  return (
    <label className="block text-sm">
      <span className="mb-1 block text-slate-400">{label}</span>
      {children}
    </label>
  );
}

function Table({ headers, rows }) {
  if (!rows.length) return <Empty>Nothing to show</Empty>;
  return (
    <div className="overflow-auto rounded-lg border border-slate-800">
      <table className="w-full text-left text-sm">
        <thead className="bg-ink-900 text-xs uppercase text-slate-500">
          <tr>
            {headers.map((h) => (
              <th key={h} className="px-3 py-2 font-medium">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i} className="border-t border-slate-800 align-top">
              {row.map((cell, j) => (
                <td key={j} className="max-w-xs break-words px-3 py-2 align-top text-slate-200">
                  {cell}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

const inputClass =
  "w-full rounded-md border border-slate-700 bg-ink-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-mint";
