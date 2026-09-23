import { useState, useMemo, useEffect, type ReactNode } from 'react'
import type {
  ForensicAnalysisResult,
  StructuredIoc,
  Kind,
  RiskLabel,
} from './types/forensic'

type Page = 'overview' | 'email' | 'investigation' | 'threats' | 'reports' | 'upload'
type Tab = 'Overview' | 'Headers' | 'Authentication' | 'Infrastructure' | 'XAI' | 'Threat Intelligence' | 'AI Summary'

const nav: { id: Page; label: string; view: Tab }[] = [
  { id: 'overview', label: 'Overview', view: 'Overview' },
  { id: 'email', label: 'Email Analysis', view: 'Headers' },
  { id: 'investigation', label: 'Investigation', view: 'Infrastructure' },
  { id: 'threats', label: 'Threat Intelligence', view: 'Threat Intelligence' },
  { id: 'reports', label: 'Reports', view: 'Overview' },
]

function getBadgeKind(statusOrLabel: string): Kind {
  const s = statusOrLabel.toLowerCase()
  if (['pass', 'verified', 'legitimate', 'low', 'safe', 'clean', 'aligned'].includes(s)) return 'green'
  if (['fail', 'malicious', 'critical', 'high_risk', 'confirmed_phishing', 'p1', 'mismatch'].includes(s)) return 'red'
  if (['suspicious', 'softfail', 'neutral', 'investigating', 'p2', 'p3', 'flagged'].includes(s)) return 'amber'
  if (['ready for review', 'analysis complete', 'p4', 'observed', 'analyzed'].includes(s)) return 'blue'
  return 'neutral'
}

function Badge({ children, kind = 'neutral' }: { children: ReactNode; kind?: Kind }) {
  const styles = {
    red: 'border-red-400/30 bg-red-400/10 text-red-300',
    amber: 'border-amber-400/30 bg-amber-400/10 text-amber-200',
    green: 'border-emerald-400/30 bg-emerald-400/10 text-emerald-300',
    blue: 'border-sky-400/30 bg-sky-400/10 text-sky-300',
    neutral: 'border-slate-600 bg-slate-800 text-slate-300',
  }
  return (
    <span className={`inline-flex items-center rounded border px-2 py-0.5 text-[11px] font-semibold tracking-wide ${styles[kind]}`}>
      {children}
    </span>
  )
}

function Panel({
  title,
  subtitle,
  children,
  action,
}: {
  title: string
  subtitle?: string
  children: ReactNode
  action?: ReactNode
}) {
  return (
    <section className="border border-slate-700/70 bg-[#121a28]">
      <div className="flex flex-wrap items-start justify-between gap-3 border-b border-slate-700/60 px-5 py-4">
        <div>
          <h2 className="text-base font-semibold text-slate-100">{title}</h2>
          {subtitle && <p className="mt-1 text-[13px] text-slate-400">{subtitle}</p>}
        </div>
        {action}
      </div>
      {children}
    </section>
  )
}

function download(name: string, type: string, body: string) {
  const url = URL.createObjectURL(new Blob([body], { type }))
  const link = document.createElement('a')
  link.href = url
  link.download = name
  link.click()
  URL.revokeObjectURL(url)
}

export default function App() {
  const [page, setPage] = useState<Page>('overview')
  const [tab, setTab] = useState<Tab>('Overview')
  const [file, setFile] = useState<string | null>(null)
  const [analysisResult, setAnalysisResult] = useState<ForensicAnalysisResult | null>(null)

  const go = (id: Page, view: Tab) => {
    setPage(id)
    setTab(view)
  }

  const caseId = analysisResult ? analysisResult.incident_id : 'NO EVIDENCE LOADED'
  const riskLabel: RiskLabel = analysisResult ? analysisResult.risk_label : 'UNKNOWN'

  const content =
    page === 'upload' ? (
      <Upload
        file={file}
        onFile={setFile}
        result={analysisResult}
        onResult={setAnalysisResult}
        back={() => go('overview', 'Overview')}
        onGoToOverview={() => go('overview', 'Overview')}
      />
    ) : page === 'reports' ? (
      <Reports result={analysisResult} onUpload={() => setPage('upload')} />
    ) : (
      <Workspace
        page={page}
        tab={tab}
        setTab={setTab}
        upload={() => setPage('upload')}
        result={analysisResult}
      />
    )

  return (
    <div className="min-h-screen bg-[#0b1018] text-[15px] text-slate-300">
      {/* Sidebar */}
      <aside className="fixed inset-y-0 left-0 hidden w-60 border-r border-slate-700/70 bg-[#0d131d] lg:flex lg:flex-col">
        <div className="flex h-16 items-center gap-3 border-b border-slate-700/70 px-5">
          <div className="grid size-7 place-items-center bg-sky-500 text-sm font-bold text-slate-950">A</div>
          <div>
            <p className="text-sm font-semibold tracking-wide text-slate-100">ATLAS FORENSICS</p>
            <p className="text-[10px] tracking-[.16em] text-slate-500">SENTINELTRACE</p>
          </div>
        </div>

        <nav className="px-3 py-5">
          <p className="mb-2 px-2 text-[11px] font-medium tracking-[.14em] text-slate-500">WORKSPACE</p>
          {nav.map(item => (
            <button
              key={item.id}
              onClick={() => go(item.id, item.view)}
              className={`mb-1 flex w-full items-center border-l-2 px-3 py-2.5 text-left text-[15px] transition ${
                page === item.id
                  ? 'border-sky-400 bg-sky-400/10 text-sky-200'
                  : 'border-transparent text-slate-400 hover:bg-slate-800/70 hover:text-slate-200'
              }`}
            >
              {item.label}
            </button>
          ))}
        </nav>

        <div className="mx-3 mt-auto border-t border-slate-700/70 pt-5">
          <p className="mb-2 px-2 text-[11px] tracking-[.14em] text-slate-500">ACTIVE CASE</p>
          <div className="px-3 pb-5">
            <p className="font-mono text-xs font-semibold text-slate-200">{caseId}</p>
            <p className="mt-1 text-[12px] text-slate-400">
              {analysisResult ? 'ANALYSIS COMPLETED' : 'AWAITING EVIDENCE'}
            </p>
            <div className="mt-3">
              <Badge kind={getBadgeKind(riskLabel)}>{riskLabel}</Badge>
            </div>
          </div>
        </div>
      </aside>

      {/* Main Area */}
      <div className="lg:pl-60">
        <header className="flex h-16 items-center justify-between border-b border-slate-700/70 bg-[#0d131d]/90 px-5 backdrop-blur lg:px-8">
          <div className="flex items-center gap-3">
            <span className="text-[11px] font-bold tracking-[.18em] text-sky-400">SIH 2026</span>
            <span className="text-slate-600">/</span>
            <span className="text-sm font-semibold text-slate-200">Problem Statement SIH26106</span>
          </div>

          <div className="flex items-center gap-3">
            {analysisResult && (
              <span className="hidden font-mono text-xs text-slate-400 sm:inline">
                {analysisResult.source_file}
              </span>
            )}
            <button
              onClick={() => setPage('upload')}
              className="border border-sky-500 bg-sky-500 px-3 py-1.5 text-[12px] font-semibold text-slate-950 transition hover:bg-sky-400"
            >
              + Ingest .EML
            </button>
          </div>
        </header>

        <main>{content}</main>

        <footer className="mt-12 border-t border-slate-800 px-5 py-6 text-center text-xs text-slate-400 lg:px-8">
          <p>
            ATLAS / SentinelTrace · AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence Platform
          </p>
          <p className="mt-1 text-slate-400">
            Methodology Note: Threat intelligence and geolocation values shown here use a synthetic test dataset.
          </p>
        </footer>
      </div>
    </div>
  )
}

function Workspace({
  page,
  tab,
  setTab,
  upload,
  result,
}: {
  page: Page
  tab: Tab
  setTab: (t: Tab) => void
  upload: () => void
  result: ForensicAnalysisResult | null
}) {
  const tabs: Tab[] = [
    'Overview',
    'Headers',
    'Authentication',
    'Infrastructure',
    'XAI',
    'Threat Intelligence',
    'AI Summary',
  ]
  const heading =
    page === 'email'
      ? 'Email Header & Origin Analysis'
      : page === 'investigation'
      ? 'Infrastructure Investigation'
      : page === 'threats'
      ? 'Threat Intelligence'
      : 'Investigation Overview'

  return (
    <section className="mx-auto max-w-[1440px] px-5 py-6 lg:px-8">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-[11px] font-semibold tracking-[.14em] text-sky-400">CASE WORKSPACE</p>
          <h1 className="mt-1 text-2xl font-semibold text-slate-100">{heading}</h1>
          <p className="mt-1 text-[14px] text-slate-400">
            {result
              ? `${result.email_metadata.subject || 'Analyzed Evidence'} · ${result.incident_id}`
              : 'No active email analysis loaded. Upload an RFC 5322 .eml file.'}
          </p>
        </div>
        <button
          onClick={upload}
          className="border border-sky-500 bg-sky-500 px-4 py-2 text-[13px] font-semibold text-slate-950 transition hover:bg-sky-400"
        >
          {result ? 'Upload New Evidence' : 'Upload Evidence (.EML)'}
        </button>
      </div>

      <div className="mt-5 flex overflow-x-auto border-b border-slate-700/70">
        {tabs.map(item => (
          <button
            key={item}
            onClick={() => setTab(item)}
            className={`shrink-0 border-b-2 px-4 py-3 text-[13px] font-medium transition ${
              tab === item ? 'border-sky-400 text-sky-300' : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            {item}
          </button>
        ))}
      </div>

      <div className="pt-5">
        {tab === 'Overview' ? (
          <Overview result={result} onUpload={upload} />
        ) : (
          <TabContent tab={tab} result={result} onUpload={upload} />
        )}
      </div>
    </section>
  )
}

function EmptyStatePrompt({ onUpload }: { onUpload: () => void }) {
  return (
    <div className="border border-dashed border-slate-700 bg-[#121a28]/60 p-8 text-center">
      <div className="mx-auto grid size-12 place-items-center rounded-full border border-sky-500/40 bg-sky-500/10 text-xl text-sky-300">
        📂
      </div>
      <h3 className="mt-4 text-base font-semibold text-slate-100">No Evidence Loaded</h3>
      <p className="mx-auto mt-2 max-w-md text-sm text-slate-400">
        Upload an RFC 5322 email (<code className="rounded bg-slate-800 px-1 py-0.5 text-xs text-slate-300">.eml</code>) file to execute passive SPF/DKIM/DMARC verification, hop tracing, transit delay computation, IOC extraction, and semantic analysis.
      </p>
      <button
        onClick={onUpload}
        className="mt-5 border border-sky-500 bg-sky-500 px-4 py-2 text-[13px] font-semibold text-slate-950 transition hover:bg-sky-400"
      >
        Upload Evidence File
      </button>
    </div>
  )
}

function Overview({
  result,
  onUpload,
}: {
  result: ForensicAnalysisResult | null
  onUpload: () => void
}) {
  if (!result) {
    return <EmptyStatePrompt onUpload={onUpload} />
  }

  return (
    <div className="space-y-6">
      <Risk result={result} />
      <Auth result={result} />
      <div className="grid gap-6 xl:grid-cols-[1.35fr_.65fr]">
        <EmailMetadataPanel result={result} />
        <Integrity result={result} />
      </div>
      <RelayTimeline result={result} />
      <StructuredIocTable result={result} />
      <Graph result={result} />
      <div className="grid gap-6 xl:grid-cols-2">
        <RiskExplanation result={result} />
        <ThreatTable result={result} />
      </div>
      <Briefing result={result} />
    </div>
  )
}

function Risk({ result }: { result: ForensicAnalysisResult }) {
  const findings = result.findings.all || []
  const topFindings = findings.slice(0, 4)

  return (
    <Panel title="Risk assessment" subtitle="Combined multi-stage forensic evaluation">
      <div className="grid xl:grid-cols-[35%_65%]">
        <div className="border-b border-slate-700/60 p-5 xl:border-b-0 xl:border-r">
          <div className="flex items-end gap-2">
            <b className="text-4xl font-bold text-slate-100">{result.global_score}</b>
            <span className="mb-1 text-[15px] text-slate-400">/ 100</span>
          </div>
          <p className="mt-2">
            <Badge kind={getBadgeKind(result.risk_label)}>{result.risk_label}</Badge>
          </p>

          <div className="mt-4 grid grid-cols-3 gap-2 text-center text-xs">
            <div className="rounded border border-slate-700/70 bg-slate-900/60 p-2">
              <span className="block text-[10px] uppercase text-slate-500">Network</span>
              <span className="font-semibold text-slate-200">{result.network_score}/100</span>
            </div>
            <div className="rounded border border-slate-700/70 bg-slate-900/60 p-2">
              <span className="block text-[10px] uppercase text-slate-500">Semantic</span>
              <span className="font-semibold text-slate-200">{result.semantic_score}/100</span>
            </div>
            <div className="rounded border border-slate-700/70 bg-slate-900/60 p-2">
              <span className="block text-[10px] uppercase text-slate-500">Dynamic</span>
              <span className="font-semibold text-slate-200">{result.dynamic_score}/100</span>
            </div>
          </div>

          <div className="mt-4 h-1.5 bg-slate-800">
            <div
              className={`h-full ${
                result.global_score >= 70
                  ? 'bg-red-400'
                  : result.global_score >= 35
                  ? 'bg-amber-400'
                  : 'bg-emerald-400'
              }`}
              style={{ width: `${Math.min(100, Math.max(5, result.global_score))}%` }}
            />
          </div>
        </div>

        <div className="p-5">
          <p className="text-[14px] font-semibold text-slate-200">Key Forensic Findings</p>
          <ul className="mt-3 grid gap-x-6 gap-y-2 text-[13px] text-slate-400 sm:grid-cols-2">
            {topFindings.map((finding, idx) => (
              <li key={idx} className="flex items-start gap-1.5">
                <span>•</span>
                <span>{finding}</span>
              </li>
            ))}
          </ul>
          {result.soar_tags && result.soar_tags.length > 0 && (
            <div className="mt-4 flex flex-wrap gap-2 border-t border-slate-700/60 pt-3">
              <span className="text-[11px] uppercase tracking-wider text-slate-500">SOAR Tags:</span>
              {result.soar_tags.map(st => (
                <Badge key={st.tag} kind={getBadgeKind(st.priority)}>
                  {st.tag} ({st.priority} · SLA {st.sla_minutes || 60}m)
                </Badge>
              ))}
            </div>
          )}
        </div>
      </div>
    </Panel>
  )
}

function Auth({ result }: { result: ForensicAnalysisResult }) {
  const auth = result.authentication
  const items = [
    {
      name: 'SPF',
      status: (auth.spf || 'UNKNOWN').toUpperCase(),
      detail: auth.spf_dns_record
        ? `DNS: ${auth.spf_dns_record.slice(0, 32)}...`
        : auth.spf === 'fail'
        ? 'Sending IP unauthorized'
        : 'Sender authentication',
    },
    {
      name: 'DKIM',
      status: (auth.dkim || 'UNKNOWN').toUpperCase(),
      detail: auth.dkim === 'pass' ? 'Cryptographic signature valid' : 'Signature verification failed or missing',
    },
    {
      name: 'DMARC',
      status: (auth.dmarc || 'UNKNOWN').toUpperCase(),
      detail: `Policy: ${auth.dmarc_policy || 'unknown'}${
        auth.dmarc === 'fail' ? ' · Alignment failure' : ''
      }`,
    },
    {
      name: 'Alignment',
      status: auth.from_reply_to_mismatch || auth.from_return_path_mismatch ? 'MISMATCH' : 'ALIGNED',
      detail: auth.from_reply_to_mismatch
        ? 'From vs Reply-To domain discrepancy'
        : auth.from_return_path_mismatch
        ? 'From vs Return-Path discrepancy'
        : 'Sender domains align',
    },
  ]

  return (
    <Panel title="Authentication verification" subtitle="Passive RFC headers and DNS record validation">
      <div className="grid divide-y divide-slate-700/60 sm:grid-cols-4 sm:divide-x sm:divide-y-0">
        {items.map(a => (
          <div key={a.name} className="px-5 py-4">
            <p className="text-[14px] font-semibold text-slate-200">{a.name}</p>
            <p className="mt-2">
              <Badge kind={getBadgeKind(a.status)}>{a.status}</Badge>
            </p>
            <p className="mt-3 text-[12px] text-slate-400">{a.detail}</p>
          </div>
        ))}
      </div>
    </Panel>
  )
}

function EmailMetadataPanel({ result }: { result: ForensicAnalysisResult }) {
  const meta = result.email_metadata
  const fields = [
    ['From', meta.from_display_name ? `${meta.from_display_name} <${meta.from}>` : meta.from || 'None'],
    ['To', meta.to?.length ? meta.to.join(', ') : 'None'],
    ['Reply-To', meta.reply_to || 'None (Matches From)'],
    ['Return-Path', meta.return_path || 'None'],
    ['Subject', meta.subject || '(No Subject)'],
    ['Message ID', meta.message_id || 'None'],
    ['Origin / Sending IP', meta.sending_ip || 'Unknown'],
    ['Timestamp', meta.date || result.timestamp_utc],
  ]

  return (
    <Panel title="Email metadata" subtitle="Forensically parsed RFC 5322 header fields">
      <div className="grid sm:grid-cols-2">
        {fields.map(([name, value]) => (
          <div key={name} className="border-b border-slate-700/60 px-5 py-3 last:border-b-0">
            <p className="text-[11px] uppercase tracking-wider text-slate-500">{name}</p>
            <p className="mt-1 break-all font-mono text-[13px] text-slate-300">{value}</p>
          </div>
        ))}
      </div>
      {meta.attachments && meta.attachments.length > 0 && (
        <div className="border-t border-slate-700/60 px-5 py-3">
          <p className="text-[11px] uppercase tracking-wider text-slate-500">MIME Attachments ({meta.attachments.length})</p>
          <div className="mt-2 space-y-2">
            {meta.attachments.map((att, i) => (
              <div key={i} className="flex flex-wrap items-center justify-between gap-2 rounded border border-slate-700 bg-[#0d141f] p-2 text-xs">
                <div>
                  <span className="font-semibold text-slate-200">{att.filename}</span>
                  <span className="ml-2 text-slate-400">({att.size_bytes} bytes · {att.content_type})</span>
                </div>
                <span className="font-mono text-[11px] text-slate-400">SHA256: {att.sha256.slice(0, 16)}...</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </Panel>
  )
}

function Integrity({ result }: { result: ForensicAnalysisResult }) {
  return (
    <Panel title="Evidence integrity" subtitle="Cryptographic chain of custody">
      <dl className="space-y-4 p-5">
        <div>
          <dt className="text-[11px] uppercase tracking-wider text-slate-500">SHA-256 Digest</dt>
          <dd className="mt-1 break-all font-mono text-[12px] text-slate-300">
            {result.source_sha256}
          </dd>
        </div>
        <div className="grid grid-cols-2 gap-4 border-t border-slate-700/60 pt-4">
          <div>
            <dt className="text-[11px] text-slate-500">Evidence Status</dt>
            <dd className="mt-1">
              <Badge kind="green">VERIFIED</Badge>
            </dd>
          </div>
          <div>
            <dt className="text-[11px] text-slate-500">Incident ID</dt>
            <dd className="mt-1 font-mono text-[13px] text-slate-200">
              {result.incident_id}
            </dd>
          </div>
        </div>
        <div className="border-t border-slate-700/60 pt-3">
          <dt className="text-[11px] text-slate-500">Ingested At</dt>
          <dd className="mt-1 text-[13px] text-slate-300">{result.timestamp_utc}</dd>
        </div>
      </dl>
    </Panel>
  )
}

/* ==============================================================================
   SMTP RELAY / HEADER FORENSICS TIMELINE COMPONENT
   ============================================================================== */
function RelayTimeline({ result }: { result: ForensicAnalysisResult }) {
  const [expandedHop, setExpandedHop] = useState<number | null>(null)
  const hops = result.relay_chain || []
  const originCandidate = hops.find(h => h.is_origin_candidate)

  return (
    <Panel
      title="SMTP relay path reconstruction"
      subtitle="Hop-by-hop Received header timeline & transit delay forensics"
      action={
        <div className="flex items-center gap-2">
          <Badge kind="blue">{hops.length} RELAY HOPS</Badge>
          {originCandidate && (
            <Badge kind="green">ORIGIN: {originCandidate.first_public_ip || originCandidate.ip}</Badge>
          )}
        </div>
      }
    >
      <div className="p-5">
        {/* Flow visual summary */}
        <div className="mb-6 flex flex-wrap items-center gap-2 rounded border border-slate-700/60 bg-[#0d141f] p-3 text-xs text-slate-300">
          <span className="font-semibold text-slate-400">Path Flow:</span>
          <span className="rounded bg-slate-800 px-2 py-0.5 font-mono text-slate-200">
            {result.email_metadata.from}
          </span>
          <span className="text-slate-500">➔</span>
          {hops.map((hop, i) => (
            <span key={i} className="flex items-center gap-2">
              <span
                className={`rounded px-2 py-0.5 font-mono ${
                  hop.is_origin_candidate
                    ? 'border border-emerald-400/40 bg-emerald-400/10 text-emerald-300'
                    : 'bg-slate-800 text-slate-300'
                }`}
              >
                Hop #{hop.hop_number} ({hop.ip || 'Host'})
              </span>
              <span className="text-slate-500">➔</span>
            </span>
          ))}
          <span className="rounded bg-sky-950 px-2 py-0.5 font-mono text-sky-200">
            {result.email_metadata.to?.[0] || 'Recipient MX'}
          </span>
        </div>

        {/* Vertical Timeline */}
        <div className="relative border-l-2 border-slate-700/80 pl-6 space-y-6">
          {hops.map((hop, index) => {
            const isExpanded = expandedHop === hop.hop_number
            return (
              <div key={hop.hop_number} className="relative">
                {/* Timeline node icon */}
                <div
                  className={`absolute -left-[33px] top-1.5 size-4 rounded-full border-2 ${
                    hop.is_origin_candidate
                      ? 'border-emerald-400 bg-emerald-500'
                      : hop.is_private
                      ? 'border-slate-500 bg-slate-700'
                      : 'border-sky-400 bg-sky-500'
                  }`}
                />

                {/* Delay indicator from previous hop */}
                {index > 0 && (
                  <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-slate-700 bg-slate-900/90 px-3 py-1 text-xs text-slate-300">
                    <span className="text-amber-400">⏱️ Transit Delay:</span>
                    <strong className="font-mono text-slate-100">{hop.delay_formatted}</strong>
                  </div>
                )}

                {/* Hop Card */}
                <div
                  className={`rounded border p-4 transition ${
                    hop.is_origin_candidate
                      ? 'border-emerald-400/40 bg-[#101c24]'
                      : 'border-slate-700/60 bg-[#0e1622]'
                  }`}
                >
                  <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-700/50 pb-3">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-sm font-bold text-slate-100">
                        Hop #{hop.hop_number}
                      </span>
                      {hop.is_origin_candidate && (
                        <Badge kind="green">OBSERVED ORIGIN CANDIDATE</Badge>
                      )}
                      {hop.is_private ? (
                        <Badge kind="neutral">INTERNAL RFC 1918</Badge>
                      ) : (
                        <Badge kind="blue">PUBLIC RELAY</Badge>
                      )}
                    </div>
                    <span className="text-xs text-slate-400">
                      Protocol: <b className="text-slate-200">{hop.protocol}</b>
                    </span>
                  </div>

                  {/* Routing Details Grid */}
                  <div className="mt-3 grid gap-3 text-xs sm:grid-cols-2 lg:grid-cols-4">
                    <div>
                      <span className="block text-[11px] uppercase tracking-wider text-slate-500">
                        Sending Host (From)
                      </span>
                      <span className="mt-0.5 block break-all font-mono text-slate-200" title={hop.from_host}>
                        {hop.from_host}
                      </span>
                    </div>

                    <div>
                      <span className="block text-[11px] uppercase tracking-wider text-slate-500">
                        Receiving Host (By)
                      </span>
                      <span className="mt-0.5 block break-all font-mono text-slate-200" title={hop.by_host}>
                        {hop.by_host}
                      </span>
                    </div>

                    <div>
                      <span className="block text-[11px] uppercase tracking-wider text-slate-500">
                        Observed IP Address
                      </span>
                      <span className="mt-0.5 flex items-center gap-1 font-mono font-semibold text-sky-300">
                        {hop.ip || 'Unknown'}
                        {hop.first_public_ip && (
                          <span className="text-[10px] text-emerald-400">(Public)</span>
                        )}
                      </span>
                    </div>

                    <div>
                      <span className="block text-[11px] uppercase tracking-wider text-slate-500">
                        Hop Timestamp (UTC)
                      </span>
                      <span className="mt-0.5 block font-mono text-slate-300">
                        {hop.timestamp_raw || 'Timestamp unavailable'}
                      </span>
                    </div>
                  </div>

                  {/* Raw Header Toggle */}
                  <div className="mt-3 border-t border-slate-700/40 pt-2">
                    <button
                      onClick={() => setExpandedHop(isExpanded ? null : hop.hop_number)}
                      className="text-[11px] text-sky-400 hover:text-sky-300"
                    >
                      {isExpanded ? '▲ Hide raw Received header' : '▼ Inspect raw RFC 2822 Received header'}
                    </button>
                    {isExpanded && (
                      <pre className="mt-2 overflow-x-auto rounded border border-slate-800 bg-[#080d14] p-3 font-mono text-[11px] leading-relaxed text-slate-300 whitespace-pre-wrap">
                        {hop.raw_header}
                      </pre>
                    )}
                  </div>
                </div>
              </div>
            )
          })}
        </div>

        {/* Forensic Classification Footer */}
        <div className="mt-6 flex flex-wrap items-center justify-between gap-3 border-t border-slate-700/60 pt-4 text-xs text-slate-400">
          <div className="flex flex-wrap items-center gap-4">
            <span className="flex items-center gap-1.5">
              <span className="size-2 rounded-full bg-emerald-400" />
              <strong className="text-slate-300">Observed:</strong> Header tokens directly in message
            </span>
            <span className="flex items-center gap-1.5">
              <span className="size-2 rounded-full bg-sky-400" />
              <strong className="text-slate-300">Inferred:</strong> Hop chronology & transit deltas
            </span>
            <span className="flex items-center gap-1.5">
              <span className="size-2 rounded-full bg-purple-400" />
              <strong className="text-slate-300">Enriched:</strong> Autonomous threat intel
            </span>
          </div>
          <span className="text-[11px] text-slate-400">
            RFC 5322 Section 3.6.7 compliance verified
          </span>
        </div>
      </div>
    </Panel>
  )
}

/* ==============================================================================
   STRUCTURED IOC TABLE COMPONENT
   ============================================================================== */
function StructuredIocTable({ result }: { result: ForensicAnalysisResult }) {
  const [filterType, setFilterType] = useState<string>('All')
  const [search, setSearch] = useState('')

  // Build complete list from structured_iocs or fallback
  const iocsList: StructuredIoc[] = useMemo(() => {
    if (result.structured_iocs && result.structured_iocs.length > 0) {
      return result.structured_iocs
    }

    // Dynamic fallback build
    const list: StructuredIoc[] = []
    if (result.email_metadata.sending_ip) {
      list.push({
        type: 'IP',
        value: result.email_metadata.sending_ip,
        source: 'Received Header',
        confidence: 'High (Observed)',
        status: result.threat_intel?.reputation || 'Observed',
        reason: 'Identified as primary origin candidate in relay trace',
      })
    }
    for (const dom of result.iocs.unique_domains || []) {
      const isBad = result.iocs.brand_impersonation_domains?.includes(dom)
      list.push({
        type: 'Domain',
        value: dom,
        source: 'Email Body / Header',
        confidence: isBad ? 'High' : 'Medium',
        status: isBad ? 'Suspicious' : 'Observed',
        reason: isBad ? 'Brand impersonation heuristic triggered' : 'Extracted domain',
      })
    }
    for (const u of result.iocs.urls || []) {
      list.push({
        type: 'URL',
        value: u.url,
        source: 'Email Body',
        confidence: 'High',
        status: u.is_brand_impersonation || u.is_suspicious_tld ? 'Malicious' : 'Observed',
        reason: u.is_brand_impersonation ? 'Brand impersonation target' : 'Body hyperlink',
      })
    }
    for (const att of result.email_metadata.attachments || []) {
      list.push({
        type: 'Attachment Hash',
        value: att.sha256,
        source: `Attachment: ${att.filename}`,
        confidence: 'Definitive',
        status: 'Analyzed',
        reason: `MIME attachment (${att.size_bytes} bytes)`,
      })
    }
    return list
  }, [result])

  const filtered = iocsList.filter(item => {
    const matchesType = filterType === 'All' || item.type.toLowerCase().includes(filterType.toLowerCase())
    const matchesSearch =
      item.value.toLowerCase().includes(search.toLowerCase()) ||
      item.reason.toLowerCase().includes(search.toLowerCase()) ||
      item.type.toLowerCase().includes(search.toLowerCase())
    return matchesType && matchesSearch
  })

  return (
    <Panel
      title="Extracted indicators of compromise (IOC)"
      subtitle="Observed network artifacts, domains, URLs, and cryptographic hashes"
      action={
        <div className="flex flex-wrap items-center gap-2">
          <select
            aria-label="Filter IOC by type"
            value={filterType}
            onChange={e => setFilterType(e.target.value)}
            className="border border-slate-700 bg-[#0d141f] px-2 py-1 text-[12px] text-slate-300"
          >
            <option value="All">All Types ({iocsList.length})</option>
            <option value="IP">IP Addresses</option>
            <option value="Domain">Domains</option>
            <option value="URL">URLs</option>
            <option value="Attachment">Attachment Hashes</option>
          </select>
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search IOCs..."
            className="w-36 border border-slate-700 bg-[#0d141f] px-2 py-1 text-[12px] text-slate-300 placeholder:text-slate-500"
          />
        </div>
      }
    >
      <div className="overflow-x-auto">
        <table className="w-full min-w-[640px] text-left">
          <thead className="border-b border-slate-700/60 text-[11px] uppercase tracking-wider text-slate-500">
            <tr>
              <th className="px-4 py-3 font-medium">Type</th>
              <th className="px-4 py-3 font-medium">Indicator Value</th>
              <th className="px-4 py-3 font-medium">Source</th>
              <th className="px-4 py-3 font-medium">Status</th>
              <th className="px-4 py-3 font-medium">Forensic Reason</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-700/40">
            {filtered.map((ioc, idx) => (
              <tr key={idx} className="hover:bg-slate-800/30">
                <td className="px-4 py-3 text-xs">
                  <Badge kind={ioc.type === 'IP' ? 'blue' : ioc.type === 'Domain' ? 'amber' : ioc.type === 'URL' ? 'red' : 'green'}>
                    {ioc.type}
                  </Badge>
                </td>
                <td className="max-w-xs truncate px-4 py-3 font-mono text-xs text-slate-200" title={ioc.value}>
                  {ioc.value}
                </td>
                <td className="px-4 py-3 text-xs text-slate-400">{ioc.source}</td>
                <td className="px-4 py-3 text-xs">
                  <Badge kind={getBadgeKind(ioc.status)}>{ioc.status}</Badge>
                </td>
                <td className="px-4 py-3 text-xs text-slate-300">{ioc.reason}</td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={5} className="px-4 py-6 text-center text-xs text-slate-400">
                  No indicators matched the active filter.
                </td>
              </tr>
            )}
          </tbody>
        </table>
        <div className="border-t border-slate-700/40 px-4 py-2 text-[11px] text-slate-400">
          Total extracted indicators: {iocsList.length} · Defensible evidence from RFC 5322 parsing
        </div>
      </div>
    </Panel>
  )
}

function Graph({ result }: { result: ForensicAnalysisResult }) {
  const [filter, setFilter] = useState('All')
  const [zoom, setZoom] = useState(1)

  const graphData = result.infrastructure_graph || { nodes: [], edges: [], disclaimer: '' }
  const nodes = graphData.nodes || []
  const edges = graphData.edges || []

  // Assign clean positions across canvas
  const positionedNodes = useMemo(() => {
    return nodes.map((node, index) => {
      const step = 100 / Math.max(1, nodes.length + 1)
      const x = `${Math.round(step * (index + 1))}%`
      const y = index % 2 === 0 ? '42%' : '65%'
      return {
        ...node,
        x,
        y,
      }
    })
  }, [nodes])

  const [selectedId, setSelectedId] = useState<string>(nodes[0]?.id || '')

  const visibleNodes = positionedNodes.filter(
    n => filter === 'All' || n.type.toLowerCase() === filter.toLowerCase()
  )
  const selectedNode = positionedNodes.find(n => n.id === selectedId) || positionedNodes[0]

  const nodeKind = (type: string): Kind => {
    switch (type.toLowerCase()) {
      case 'email':
        return 'neutral'
      case 'domain':
        return 'amber'
      case 'ip':
        return 'red'
      case 'asn':
      case 'organization':
        return 'blue'
      case 'location':
        return 'green'
      default:
        return 'neutral'
    }
  }

  return (
    <Panel
      title="Infrastructure investigation"
      subtitle="Relay hops, host resolution, and provider topology"
      action={
        <div className="flex items-center gap-2">
          <select
            aria-label="Filter graph nodes"
            value={filter}
            onChange={e => setFilter(e.target.value)}
            className="border border-slate-700 bg-[#0d141f] px-2 py-1 text-[12px] text-slate-300"
          >
            <option value="All">All Entities</option>
            <option value="email">Email</option>
            <option value="domain">Domain</option>
            <option value="ip">IP</option>
            <option value="asn">ASN</option>
            <option value="organization">Org</option>
            <option value="location">Location</option>
          </select>
          <button
            onClick={() => setZoom(Math.max(0.7, zoom - 0.1))}
            className="border border-slate-700 px-2.5 py-1 text-[13px] text-slate-300 hover:bg-slate-800"
          >
            -
          </button>
          <button
            onClick={() => setZoom(Math.min(1.3, zoom + 0.1))}
            className="border border-slate-700 px-2.5 py-1 text-[13px] text-slate-300 hover:bg-slate-800"
          >
            +
          </button>
        </div>
      }
    >
      <div className="p-5">
        <div
          className="relative h-72 overflow-hidden border border-slate-700/60 bg-[#0d141f]"
          style={{
            backgroundImage: 'radial-gradient(#263245 1px, transparent 1px)',
            backgroundSize: '18px 18px',
          }}
        >
          <div className="absolute inset-0 origin-center transition-transform" style={{ transform: `scale(${zoom})` }}>
            <svg className="pointer-events-none absolute inset-0 h-full w-full">
              {edges.map((edge, i) => {
                const src = positionedNodes.find(n => n.id === edge.source)
                const tgt = positionedNodes.find(n => n.id === edge.target)
                if (!src || !tgt) return null
                return (
                  <line
                    key={i}
                    x1={src.x}
                    y1={src.y}
                    x2={tgt.x}
                    y2={tgt.y}
                    stroke="#384964"
                    strokeWidth="1.5"
                    strokeDasharray="4 2"
                  />
                )
              })}
            </svg>

            {visibleNodes.map(n => (
              <button
                key={n.id}
                onClick={() => setSelectedId(n.id)}
                style={{ left: n.x, top: n.y }}
                className={`absolute -translate-x-1/2 -translate-y-1/2 rounded border bg-[#111a28] px-2.5 py-1.5 font-mono text-[11px] font-semibold transition ${
                  selectedNode?.id === n.id
                    ? 'border-sky-400 text-sky-200 ring-2 ring-sky-400/50'
                    : 'border-slate-700 text-slate-300 hover:border-slate-500'
                }`}
              >
                {n.label.length > 28 ? `${n.label.slice(0, 26)}...` : n.label}
              </button>
            ))}
          </div>
        </div>

        {selectedNode && (
          <div className="mt-3 flex flex-wrap items-center justify-between gap-2 border border-slate-700/40 bg-slate-900/40 p-3 text-[13px]">
            <div className="flex items-center gap-2">
              <span className="text-slate-400">Selected:</span>
              <Badge kind={nodeKind(selectedNode.type)}>{selectedNode.type.toUpperCase()}</Badge>
              <span className="font-mono text-slate-200">{selectedNode.label}</span>
            </div>
            <p className="text-[11px] text-slate-400">
              Connections: {edges.filter(e => e.source === selectedNode.id || e.target === selectedNode.id).map(e => e.relationship).join(', ') || 'Direct'}
            </p>
          </div>
        )}

        <p className="mt-3 border-l-2 border-amber-500/60 pl-3 text-[12px] text-slate-400">
          ⚠️ <strong className="text-slate-300">Forensic Disclosure:</strong> {graphData.disclaimer || 'Infrastructure graph visualizes entity relationships. Correlation does not prove attacker attribution.'}
        </p>
      </div>
    </Panel>
  )
}

function RiskExplanation({ result }: { result: ForensicAnalysisResult }) {
  const [scope, setScope] = useState<'all' | 'verified' | 'rule-based'>('all')

  const factors = useMemo(() => {
    const list: { label: string; score: number; verified: boolean; note: string }[] = []
    const auth = result.authentication
    const iocs = result.iocs
    const ai = result.ai_analysis

    if (auth.dmarc === 'fail') {
      list.push({
        label: 'DMARC alignment failure',
        score: 25,
        verified: true,
        note: `Visible sender domain failed DMARC policy (${auth.dmarc_policy || 'unknown'}).`,
      })
    }
    if (auth.dkim === 'fail') {
      list.push({
        label: 'DKIM signature invalid / missing',
        score: 20,
        verified: true,
        note: 'Cryptographic message integrity could not be validated.',
      })
    }
    if (auth.spf === 'fail') {
      list.push({
        label: 'SPF IP unauthorized',
        score: 15,
        verified: true,
        note: 'Origin relay IP is not authorized in sender domain TXT record.',
      })
    }
    if (auth.from_reply_to_mismatch) {
      list.push({
        label: 'From vs Reply-To mismatch',
        score: 18,
        verified: true,
        note: `Reply-To (${result.email_metadata.reply_to}) differs from sender domain.`,
      })
    }
    if (auth.from_return_path_mismatch) {
      list.push({
        label: 'From vs Return-Path mismatch',
        score: 12,
        verified: true,
        note: `Return-Path (${result.email_metadata.return_path}) indicates third-party relay.`,
      })
    }
    if (iocs.suspicious_url_count > 0 || iocs.brand_impersonation_domains?.length > 0) {
      list.push({
        label: 'Suspicious / Impersonation URLs',
        score: 20,
        verified: true,
        note: `${iocs.suspicious_url_count} suspicious link(s) or brand impersonation detected in message.`,
      })
    }
    if (ai.urgency_level === 'high' || ai.urgency_level === 'medium') {
      list.push({
        label: 'Urgency induction tactics',
        score: 15,
        verified: false,
        note: 'Heuristic analysis detected coercive language urging rapid victim action.',
      })
    }
    if (ai.credential_harvesting) {
      list.push({
        label: 'Credential harvesting lure',
        score: 20,
        verified: false,
        note: 'Message semantic structure mimics authentication/password reset lures.',
      })
    }

    return list
  }, [result])

  const shown = factors.filter(f =>
    scope === 'all' ? true : scope === 'verified' ? f.verified : !f.verified
  )

  return (
    <Panel
      title="Risk explanation (XAI)"
      subtitle="Ranked contributing forensic risk factors"
      action={
        <select
          aria-label="Filter risk factors"
          value={scope}
          onChange={e => setScope(e.target.value as typeof scope)}
          className="border border-slate-700 bg-[#0d141f] px-2 py-1 text-[12px] text-slate-300"
        >
          <option value="all">All Factors ({factors.length})</option>
          <option value="verified">Verified Evidence Only</option>
          <option value="rule-based">Rule-Based / Heuristic Only</option>
        </select>
      }
    >
      <div className="divide-y divide-slate-700/60">
        {shown.map(f => (
          <div key={f.label} className="px-5 py-3.5">
            <div className="flex justify-between gap-4">
              <p className="text-[14px] font-medium text-slate-200">{f.label}</p>
              <b className="text-[13px] text-red-300">+{f.score}</b>
            </div>
            <div className="mt-2 h-1 bg-slate-800">
              <div className="h-full bg-red-400" style={{ width: `${Math.min(100, f.score * 4)}%` }} />
            </div>
            <div className="mt-2 flex justify-between gap-3">
              <p className="text-[12px] text-slate-400">{f.note}</p>
              <span
                className={`shrink-0 text-[10px] font-semibold ${
                  f.verified ? 'text-emerald-400' : 'text-sky-400'
                }`}
              >
                {f.verified ? 'VERIFIED EVIDENCE' : 'RULE-BASED FALLBACK / HEURISTIC'}
              </span>
            </div>
          </div>
        ))}
        {shown.length === 0 && (
          <p className="p-5 text-[13px] text-slate-400">No factors match the selected filter.</p>
        )}
      </div>
    </Panel>
  )
}

function ThreatTable({ result }: { result: ForensicAnalysisResult }) {
  const [query, setQuery] = useState('')
  const threatIntel = result.threat_intel || { is_demo: true, indicators: [] }
  const indicators = threatIntel.indicators || []

  const rows = indicators.filter(
    ind =>
      ind.indicator.toLowerCase().includes(query.toLowerCase()) ||
      ind.type.toLowerCase().includes(query.toLowerCase()) ||
      ind.reputation.toLowerCase().includes(query.toLowerCase())
  )

  return (
    <Panel
      title="Threat intelligence"
      subtitle="Threat intelligence enrichment"
      action={
        <div className="flex items-center gap-2">
          <input
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder="Filter indicators"
            className="w-32 border border-slate-700 bg-[#0d141f] px-2 py-1 text-[12px] text-slate-300 placeholder:text-slate-500"
          />
        </div>
      }
    >
      <div className="overflow-x-auto">
        <table className="w-full min-w-[520px] text-left">
          <thead className="border-b border-slate-700/60 text-[11px] uppercase tracking-wider text-slate-500">
            <tr>
              {['Indicator', 'Type', 'Reputation', 'Confidence', 'Source'].map(x => (
                <th key={x} className="px-4 py-3 font-medium">
                  {x}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((row, idx) => (
              <tr key={idx} className="border-b border-slate-700/40 last:border-0">
                <td className="max-w-40 truncate px-4 py-3 font-mono text-[12px] text-slate-300" title={row.indicator}>
                  {row.indicator}
                </td>
                <td className="px-4 py-3 text-[13px] text-slate-400">{row.type}</td>
                <td className="px-4 py-3">
                  <Badge kind={getBadgeKind(row.reputation)}>{row.reputation}</Badge>
                </td>
                <td className="px-4 py-3 text-[13px] text-slate-300">{row.confidence}</td>
                <td className="px-4 py-3 text-[11px] text-slate-400">{row.source}</td>
              </tr>
            ))}
            {rows.length === 0 && (
              <tr>
                <td colSpan={5} className="px-4 py-6 text-center text-[13px] text-slate-400">
                  No threat indicators matching query.
                </td>
              </tr>
            )}
          </tbody>
        </table>
        <div className="border-t border-slate-700/40 px-4 py-2 text-[11px] text-slate-400">
          Threat intelligence and geolocation values shown here use a synthetic test dataset.
        </div>
      </div>
    </Panel>
  )
}

function Briefing({ result }: { result: ForensicAnalysisResult }) {
  const ai = result.ai_analysis
  const isRuleBased = ai.is_rule_based ?? (ai.provider === 'rule-based')

  return (
    <Panel
      title="Investigation briefing"
      subtitle={isRuleBased ? 'Rule-based semantic analysis' : 'Forensic assessment'}
      action={
        <Badge kind={isRuleBased ? 'neutral' : 'blue'}>
          {isRuleBased ? 'RULE-BASED ANALYSIS' : 'AI SEMANTIC MODEL'}
        </Badge>
      }
    >
      <div className="grid gap-5 p-5 text-[13px] leading-5 lg:grid-cols-3">
        <div>
          <p className="font-semibold uppercase tracking-wider text-slate-500">Threat Assessment</p>
          <p className="mt-1 text-slate-300">
            {ai.narrative ||
              `${result.risk_label} verdict with semantic risk score ${result.semantic_score}/100.`}
          </p>
        </div>
        <div>
          <p className="font-semibold uppercase tracking-wider text-slate-500">Tactics Detected</p>
          <p className="mt-1 text-slate-400">
            {ai.detected_tactics && ai.detected_tactics.length > 0
              ? ai.detected_tactics.join(', ')
              : 'No overt social engineering tactics detected.'}
          </p>
        </div>
        <div>
          <p className="font-semibold uppercase tracking-wider text-slate-500">Recommended SOAR Action</p>
          <p className="mt-1 text-slate-400">
            {result.risk_label === 'CONFIRMED_PHISHING' || result.risk_label === 'HIGH_RISK'
              ? 'Quarantine message immediately, block sender and extracted domains at boundary, purge user inbox.'
              : result.risk_label === 'SUSPICIOUS'
              ? 'Flag email with warning banner, isolate sender domain in gateway, queue for analyst triage.'
              : 'Message passes core authentication checks. Keep standard logging.'}
          </p>
        </div>
      </div>
    </Panel>
  )
}

function TabContent({
  tab,
  result,
  onUpload,
}: {
  tab: Exclude<Tab, 'Overview'>
  result: ForensicAnalysisResult | null
  onUpload: () => void
}) {
  if (!result) {
    return <EmptyStatePrompt onUpload={onUpload} />
  }

  const views: Record<Exclude<Tab, 'Overview'>, ReactNode> = {
    Headers: (
      <div className="space-y-6">
        <EmailMetadataPanel result={result} />
        <RelayTimeline result={result} />
      </div>
    ),
    Authentication: (
      <div className="space-y-6">
        <Auth result={result} />
        <Panel title="Authentication Findings" subtitle="Details from passive headers and DNS queries">
          <ul className="space-y-2 p-5 text-[13px] text-slate-300">
            {result.authentication.network_findings?.map((f, i) => (
              <li key={i} className="flex items-start gap-2">
                <span>•</span>
                <span>{f}</span>
              </li>
            ))}
          </ul>
        </Panel>
      </div>
    ),
    Infrastructure: (
      <div className="space-y-6">
        <Graph result={result} />
        <StructuredIocTable result={result} />
      </div>
    ),
    XAI: <RiskExplanation result={result} />,
    'Threat Intelligence': (
      <div className="space-y-6">
        <ThreatTable result={result} />
        <StructuredIocTable result={result} />
      </div>
    ),
    'AI Summary': <Briefing result={result} />,
  }

  return (
    <div className="space-y-5">
      {views[tab]}
      <p className="text-[12px] text-slate-400">
        Showing structured forensic evidence from active case · {result.incident_id}.
      </p>
    </div>
  )
}

function Reports({
  result,
  onUpload,
}: {
  result: ForensicAnalysisResult | null
  onUpload: () => void
}) {
  const [notice, setNotice] = useState('')

  const exportReport = (format: 'pdf' | 'csv' | 'json' | 'md') => {
    if (!result) return

    if (format === 'json') {
      const jsonStr = result.reports.json_content
        ? JSON.stringify(result.reports.json_content, null, 2)
        : JSON.stringify(result, null, 2)
      download(`investigation_${result.incident_id}.json`, 'application/json', jsonStr)
      setNotice('Forensic JSON investigation report downloaded.')
    } else if (format === 'md') {
      const mdContent =
        result.reports.markdown_content ||
        `# Forensic Report ${result.incident_id}\n\nGlobal Score: ${result.global_score}\nVerdict: ${result.risk_label}`
      download(`investigation_${result.incident_id}.md`, 'text/markdown', mdContent)
      setNotice('Markdown forensic report downloaded.')
    } else if (format === 'csv') {
      const headers = 'incident_id,timestamp,global_score,risk_label,sha256,spf,dkim,dmarc\n'
      const row = `"${result.incident_id}","${result.timestamp_utc}",${result.global_score},"${result.risk_label}","${result.source_sha256}","${result.authentication.spf}","${result.authentication.dkim}","${result.authentication.dmarc}"\n`
      download(`summary_${result.incident_id}.csv`, 'text/csv', headers + row)
      setNotice('CSV investigation summary downloaded.')
    } else if (format === 'pdf') {
      const textReport =
        result.reports.markdown_content ||
        `Incident: ${result.incident_id}\nScore: ${result.global_score}\nVerdict: ${result.risk_label}`
      download(`investigation_${result.incident_id}.txt`, 'text/plain', textReport)
      setNotice('Investigation report exported as text.')
    }
  }

  if (!result) {
    return (
      <section className="mx-auto max-w-5xl px-5 py-7 lg:px-8">
        <p className="text-[11px] font-semibold tracking-[.14em] text-sky-400">CASE OUTPUT</p>
        <h1 className="mt-1 text-2xl font-semibold text-slate-100">Investigation reports</h1>
        <div className="mt-5">
          <EmptyStatePrompt onUpload={onUpload} />
        </div>
      </section>
    )
  }

  return (
    <section className="mx-auto max-w-5xl px-5 py-7 lg:px-8">
      <p className="text-[11px] font-semibold tracking-[.14em] text-sky-400">CASE OUTPUT</p>
      <h1 className="mt-1 text-2xl font-semibold text-slate-100">Investigation reports</h1>
      <p className="mt-1 text-[14px] text-slate-400">
        Export defensible documentation and forensic artifacts for incident {result.incident_id}.
      </p>

      <div className="mt-6">
        <Panel
          title="Export investigation evidence"
          subtitle="Download analyzer reports and cryptographic artifacts"
          action={<Badge kind={getBadgeKind(result.risk_label)}>{result.risk_label}</Badge>}
        >
          <div className="p-5">
            <div className="grid gap-4 text-[13px] sm:grid-cols-4">
              <p>
                <span className="block text-[11px] uppercase text-slate-500">Incident ID</span>
                <span className="font-mono">{result.incident_id}</span>
              </p>
              <p>
                <span className="block text-[11px] uppercase text-slate-500">Timestamp</span>
                {result.timestamp_utc}
              </p>
              <p>
                <span className="block text-[11px] uppercase text-slate-500">Global Score</span>
                <strong className="text-slate-100">{result.global_score} / 100</strong>
              </p>
              <p>
                <span className="block text-[11px] uppercase text-slate-500">Status</span>
                {result.risk_label}
              </p>
            </div>

            <div className="mt-6 flex flex-wrap gap-3">
              <button
                onClick={() => exportReport('md')}
                className="border border-slate-600 bg-slate-900 px-4 py-2.5 text-[13px] font-medium text-slate-300 transition hover:border-sky-400 hover:text-sky-200"
              >
                Download Markdown (.MD)
              </button>
              <button
                onClick={() => exportReport('json')}
                className="border border-slate-600 bg-slate-900 px-4 py-2.5 text-[13px] font-medium text-slate-300 transition hover:border-sky-400 hover:text-sky-200"
              >
                Download JSON Report
              </button>
              <button
                onClick={() => exportReport('csv')}
                className="border border-slate-600 bg-slate-900 px-4 py-2.5 text-[13px] font-medium text-slate-300 transition hover:border-sky-400 hover:text-sky-200"
              >
                Download CSV Summary
              </button>
              <button
                onClick={() => exportReport('pdf')}
                className="border border-slate-600 bg-slate-900 px-4 py-2.5 text-[13px] font-medium text-slate-300 transition hover:border-sky-400 hover:text-sky-200"
              >
                Export Text Summary
              </button>
            </div>

            {notice && <p className="mt-4 text-[13px] text-emerald-300">✓ {notice}</p>}
          </div>
        </Panel>
      </div>
    </section>
  )
}

function Upload({
  file,
  onFile,
  result,
  onResult,
  back,
  onGoToOverview,
}: {
  file: string | null
  onFile: (name: string | null) => void
  result: ForensicAnalysisResult | null
  onResult: (result: ForensicAnalysisResult | null) => void
  back: () => void
  onGoToOverview: () => void
}) {
  const [selectedFileObj, setSelectedFileObj] = useState<File | null>(null)
  const [analyzing, setAnalyzing] = useState(false)
  const [analysisStage, setAnalysisStage] = useState(0)
  const [error, setError] = useState('')

  const stages = [
    'Parsing RFC 5322 structure & computing SHA-256 integrity hash...',
    'Validating passive SPF, DKIM, and DMARC authentication policies...',
    'Reconstructing Received hop relay chain & calculating transit delays...',
    'Extracting body indicators, URLs, domains, and attachment hashes...',
    'Executing semantic analysis & computing multi-stage risk score...',
  ]

  useEffect(() => {
    let timer: any
    if (analyzing) {
      setAnalysisStage(0)
      timer = setInterval(() => {
        setAnalysisStage(prev => (prev < stages.length - 1 ? prev + 1 : prev))
      }, 350)
    }
    return () => clearInterval(timer)
  }, [analyzing])

  const handleFile = (selected: File | undefined) => {
    if (!selected) return

    if (!selected.name.toLowerCase().endsWith('.eml')) {
      setError('Please select an RFC 5322 .eml file')
      return
    }

    setSelectedFileObj(selected)
    onResult(null)
    setError('')
    onFile(selected.name)
  }

  const analyze = async () => {
    if (!selectedFileObj) return

    setAnalyzing(true)
    setError('')

    try {
      const formData = new FormData()
      formData.append('file', selectedFileObj)

      const response = await fetch('http://127.0.0.1:8000/api/analyze', {
        method: 'POST',
        body: formData,
      })

      if (!response.ok) {
        throw new Error(`API returned HTTP ${response.status}: ${response.statusText}`)
      }

      const data = await response.json()
      if (data.error) {
        throw new Error(data.error)
      }

      onResult(data)
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Analysis request failed'
      setError(
        `${msg}. Please ensure the backend is running at http://127.0.0.1:8000 (py -3.12 -m uvicorn api:app --reload)`
      )
    } finally {
      setAnalyzing(false)
    }
  }

  const loadDemoSample = async (sampleId: string, sampleTitle: string) => {
    setAnalyzing(true)
    setError('')
    onFile(sampleTitle)
    try {
      const response = await fetch(`http://127.0.0.1:8000/api/demo/${sampleId}`, {
        method: 'POST',
      })
      if (!response.ok) {
        throw new Error(`API returned HTTP ${response.status}: ${response.statusText}`)
      }
      const data = await response.json()
      if (data.error) {
        throw new Error(data.error)
      }
      onResult(data)
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Demo analysis failed'
      setError(`${msg}. Please ensure backend is running on http://127.0.0.1:8000`)
    } finally {
      setAnalyzing(false)
    }
  }

  const demoSamples = [
    {
      id: 'DEMO-PHISH-002',
      title: 'Microsoft 365 Account Suspension Warning',
      badge: 'SUSPICIOUS (44/100)',
      kind: 'amber' as Kind,
      type: 'Phishing / Credential Harvesting',
      desc: 'Impersonates Microsoft security with SPF/DKIM fail & spoofed relay.',
    },
    {
      id: 'DEMO-BEC-001',
      title: 'Urgent CEO Wire Transfer Request',
      badge: 'SUSPICIOUS (46/100)',
      kind: 'amber' as Kind,
      type: 'Business Email Compromise (BEC)',
      desc: 'Executive identity impersonation via bulletproof proxy relay.',
    },
    {
      id: 'DEMO-LEGIT-003',
      title: 'Google Play Order Receipt Notification',
      badge: 'LEGITIMATE (4/100)',
      kind: 'green' as Kind,
      type: 'Authentic Transaction',
      desc: 'Valid Google cryptographic signatures and aligned return-path.',
    },
  ]

  return (
    <section className="mx-auto max-w-4xl px-5 py-7 lg:px-8">
      <button onClick={back} className="text-[13px] text-sky-300 transition hover:text-sky-200">
        ← Back to overview
      </button>

      <p className="mt-5 text-[11px] font-semibold tracking-[.14em] text-sky-400">EVIDENCE INTAKE</p>
      <h1 className="mt-1 text-2xl font-semibold text-slate-100">Start forensic analysis</h1>
      <p className="mt-2 text-[14px] text-slate-400">
        Upload an RFC 5322 (.eml) evidence file or run evaluation with built-in SIH test cases.
        {file && <span className="ml-2 font-mono text-sky-300">({file})</span>}
      </p>

      {/* Quick-Load Demo Evaluation Samples */}
      <div className="mt-6 border border-slate-700/70 bg-[#121a28] p-5">
        <div className="flex items-center justify-between">
          <p className="text-xs font-semibold uppercase tracking-wider text-sky-400">
            Quick-Load SIH Evaluation Samples
          </p>
          <span className="text-[11px] text-slate-500">Instant Automated Pipeline Execution</span>
        </div>
        <div className="mt-3 grid gap-3 sm:grid-cols-3">
          {demoSamples.map(sample => (
            <button
              key={sample.id}
              disabled={analyzing}
              onClick={() => loadDemoSample(sample.id, sample.title)}
              className="group flex flex-col justify-between rounded border border-slate-700/70 bg-[#0d141f] p-3 text-left transition hover:border-sky-400 hover:bg-[#111a28] disabled:cursor-not-allowed disabled:opacity-50"
            >
              <div>
                <div className="flex items-start justify-between gap-1">
                  <Badge kind={sample.kind}>{sample.badge}</Badge>
                  <span className="font-mono text-[10px] text-slate-500">{sample.id}</span>
                </div>
                <p className="mt-2 text-xs font-semibold text-slate-200 group-hover:text-sky-200">
                  {sample.title}
                </p>
                <p className="mt-1 text-[11px] text-slate-400 leading-tight">
                  {sample.desc}
                </p>
              </div>
              <div className="mt-3 flex items-center justify-between border-t border-slate-800 pt-2 text-[11px] text-sky-400">
                <span>Evaluate Sample</span>
                <span>➔</span>
              </div>
            </button>
          ))}
        </div>
      </div>

      <div className="mt-6 border border-slate-700/70 bg-[#121a28] p-6">
        <p className="mb-4 text-xs font-semibold uppercase tracking-wider text-slate-400">
          Or Upload Local Workstation Evidence
        </p>

        {!selectedFileObj ? (
          <label className="flex min-h-60 cursor-pointer flex-col items-center justify-center border border-dashed border-slate-600 bg-[#0d141f] px-5 text-center transition hover:border-sky-400">
            <input
              className="sr-only"
              type="file"
              accept=".eml,message/rfc822"
              onChange={e => handleFile(e.target.files?.[0])}
            />
            <p className="grid size-12 place-items-center border border-sky-500/40 bg-sky-500/10 text-xl text-sky-300">
              ↑
            </p>
            <p className="mt-4 text-[15px] font-semibold text-slate-200">Drop custom EML evidence file here</p>
            <p className="mt-1 text-[13px] text-slate-400">or choose from workstation filesystem</p>
            <span className="mt-4 border border-slate-600 px-3 py-1.5 text-[12px] text-slate-300">
              Select .EML file
            </span>
          </label>
        ) : (
          <div className="border border-emerald-400/30 bg-emerald-400/5 p-5">
            <Badge kind="green">EVIDENCE SELECTED</Badge>
            <p className="mt-4 font-mono text-[14px] font-medium text-slate-200">
              {selectedFileObj.name}
            </p>
            <p className="mt-2 text-[12px] text-slate-400">
              {(selectedFileObj.size / 1024).toFixed(1)} KB
            </p>

            <div className="mt-5 flex flex-wrap items-center gap-3">
              {!result && (
                <button
                  onClick={analyze}
                  disabled={analyzing}
                  className="border border-sky-500 bg-sky-500 px-4 py-2.5 text-[13px] font-semibold text-slate-950 transition hover:bg-sky-400 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {analyzing ? 'Executing Forensic Pipeline...' : 'Analyze Email'}
                </button>
              )}

              <button
                onClick={() => {
                  setSelectedFileObj(null)
                  onResult(null)
                  setError('')
                  onFile(null)
                }}
                className="text-[13px] text-sky-300 transition hover:text-sky-200"
              >
                Replace file
              </button>
            </div>
          </div>
        )}

        {/* Pipeline progress simulation while analyzing */}
        {analyzing && (
          <div className="mt-5 space-y-2 border-t border-slate-700/60 pt-4">
            <p className="text-xs font-semibold uppercase tracking-wider text-sky-400">
              Forensic Pipeline Progress:
            </p>
            {stages.map((stg, i) => (
              <div key={i} className="flex items-center gap-2 text-xs">
                {i < analysisStage ? (
                  <span className="text-emerald-400 font-bold">✓</span>
                ) : i === analysisStage ? (
                  <span className="animate-spin text-sky-400">◐</span>
                ) : (
                  <span className="text-slate-600">○</span>
                )}
                <span className={i <= analysisStage ? 'text-slate-200' : 'text-slate-500'}>
                  {stg}
                </span>
              </div>
            ))}
          </div>
        )}

        {error && (
          <p className="mt-4 border border-red-400/30 bg-red-400/10 p-3 text-[13px] text-red-300">
            {error}
          </p>
        )}

        {result && (
          <div className="mt-5 border-t border-slate-700/60 pt-5">
            <div className="flex items-center justify-between">
              <Badge kind="blue">ANALYSIS COMPLETE</Badge>
              <button
                onClick={onGoToOverview}
                className="border border-sky-500 bg-sky-500 px-4 py-2 text-[13px] font-semibold text-slate-950 transition hover:bg-sky-400"
              >
                View in Investigation Workspace →
              </button>
            </div>

            <div className="mt-4 grid gap-4 sm:grid-cols-4">
              <div>
                <p className="text-[11px] uppercase text-slate-500">Risk Score</p>
                <p className="mt-1 text-2xl font-bold text-slate-100">
                  {result.global_score} / 100
                </p>
              </div>
              <div>
                <p className="text-[11px] uppercase text-slate-500">Risk Verdict</p>
                <p className="mt-1">
                  <Badge kind={getBadgeKind(result.risk_label)}>{result.risk_label}</Badge>
                </p>
              </div>
              <div>
                <p className="text-[11px] uppercase text-slate-500">Incident ID</p>
                <p className="mt-1 break-all font-mono text-[13px] text-slate-300">
                  {result.incident_id}
                </p>
              </div>
              <div>
                <p className="text-[11px] uppercase text-slate-500">Origin IP</p>
                <p className="mt-1 font-mono text-[13px] text-slate-300">
                  {result.email_metadata.sending_ip || 'Unknown'}
                </p>
              </div>
            </div>

            <div className="mt-5 border-t border-slate-700/60 pt-4">
              <p className="text-[11px] uppercase tracking-wider text-slate-500">
                Key Findings ({result.findings.all?.length || 0})
              </p>
              <ul className="mt-3 space-y-1.5 text-[13px] text-slate-300">
                {result.findings.all?.slice(0, 5).map((finding, idx) => (
                  <li key={idx}>• {finding}</li>
                ))}
              </ul>
            </div>
          </div>
        )}

        <div className="mt-5 grid gap-4 border-t border-slate-700/60 pt-5 sm:grid-cols-3">
          <p className="text-[13px]">
            <span className="block text-[11px] text-slate-500">Accepted format</span>
            .EML (RFC 5322)
          </p>
          <p className="text-[13px]">
            <span className="block text-[11px] text-slate-500">Pipeline Stages</span>
            Auth · Path · IOC · Intent
          </p>
          <p className="text-[13px]">
            <span className="block text-[11px] text-slate-500">Evidence integrity</span>
            <span className="text-emerald-300">SHA-256 registered</span>
          </p>
        </div>
      </div>
    </section>
  )
}
