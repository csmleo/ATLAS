export type ThreatLevel = 'Critical' | 'High' | 'Medium' | 'Low'
export type RiskLabel = 'LEGITIMATE' | 'SUSPICIOUS' | 'HIGH_RISK' | 'CONFIRMED_PHISHING' | 'UNKNOWN'
export type AuthStatus = 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'unknown' | 'PASS' | 'FAIL' | 'UNKNOWN'
export type Kind = 'red' | 'amber' | 'green' | 'blue' | 'neutral'

export interface AttachmentMetadata {
  filename: string
  content_type: string
  size_bytes: number
  sha256: string
  content_transfer_encoding: string
}

export interface RelayHop {
  hop_number: number
  from_host: string
  by_host: string
  protocol: string
  ip: string | null
  all_ips: string[]
  first_public_ip: string | null
  timestamp_raw: string | null
  timestamp_iso: string | null
  delay_seconds: number | null
  delay_formatted: string
  is_origin_candidate: boolean
  is_private: boolean
  raw_header: string
}

export interface StructuredIoc {
  type: string
  value: string
  source: string
  confidence: string
  status: string
  reason: string
}

export interface EmailMetadata {
  from: string
  from_display_name: string
  to: string[]
  reply_to: string | null
  return_path: string | null
  subject: string
  message_id: string
  sending_ip: string | null
  date: string
  total_hops: number
  received_hops: string[]
  attachments?: AttachmentMetadata[]
}

export interface AuthVerification {
  spf: string
  dkim: string
  dmarc: string
  dmarc_policy: string
  spf_dns_record: string | null
  dmarc_dns_record: string | null
  from_reply_to_mismatch: boolean
  from_return_path_mismatch: boolean
  network_findings: string[]
}

export interface UrlIndicator {
  url: string
  anchor_text: string
  domain: string
  is_mismatch: boolean
  is_suspicious_tld: boolean
  is_brand_impersonation: boolean
}

export interface IocExtraction {
  urls: UrlIndicator[]
  unique_domains: string[]
  suspicious_url_count: number
  brand_impersonation_domains: string[]
  anchor_mismatch_count: number
  ioc_findings: string[]
}

export interface AiSemanticAnalysis {
  provider: string
  model_used: string
  urgency_level: string
  executive_impersonation: boolean
  credential_harvesting: boolean
  financial_request: boolean
  brand_impersonation: boolean
  detected_tactics: string[]
  narrative: string
  semantic_findings: string[]
  is_rule_based: boolean
}

export interface ThreatIntelIndicator {
  indicator: string
  type: string
  reputation: string
  confidence: string
  source: string
}

export interface ThreatIntelData {
  is_demo: boolean
  disclaimer: string
  ip: string | null
  country: string
  city: string
  asn: string
  organization: string
  reputation: string
  sources: string[]
  indicators: ThreatIntelIndicator[]
}

export interface GraphNode {
  id: string
  label: string
  type: 'email' | 'domain' | 'ip' | 'asn' | 'organization' | 'location' | string
}

export interface GraphEdge {
  source: string
  target: string
  relationship: string
}

export interface InfrastructureGraphData {
  disclaimer: string
  nodes: GraphNode[]
  edges: GraphEdge[]
}

export interface SoarTagData {
  tag: string
  priority: string
  sla_minutes: number | null
  color: string
}

export interface ReportReferences {
  markdown_path: string | null
  json_path: string | null
  markdown_content?: string | null
  json_content?: any | null
}

export interface ForensicAnalysisResult {
  incident_id: string
  timestamp_utc: string
  source_file: string
  source_sha256: string
  global_score: number
  risk_label: RiskLabel
  network_score: number
  semantic_score: number
  dynamic_score: number
  email_metadata: EmailMetadata
  relay_chain?: RelayHop[]
  authentication: AuthVerification
  iocs: IocExtraction
  structured_iocs?: StructuredIoc[]
  ai_analysis: AiSemanticAnalysis
  threat_intel: ThreatIntelData
  infrastructure_graph: InfrastructureGraphData
  findings: {
    all: string[]
    network: string[]
    semantic: string[]
    dynamic: string[]
  }
  soar_tags: SoarTagData[]
  reports: ReportReferences
}

