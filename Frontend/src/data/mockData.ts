export type ThreatLevel = 'Critical' | 'High' | 'Medium' | 'Low'

export interface InvestigationEmail {
  id: string
  subject: string
  sender: string
  recipient: string
  receivedAt: string
  score: number
  threatLevel: ThreatLevel
  status: 'Investigating' | 'Resolved' | 'Flagged'
}

export interface Metric { label: string; value: string; change: string; tone: 'cyan' | 'red' | 'amber' | 'lime' }

export const dashboardMetrics: Metric[] = [
  { label: 'Emails analyzed', value: '1,284', change: '+12.5% this week', tone: 'cyan' },
  { label: 'Threats detected', value: '47', change: '8 require review', tone: 'red' },
  { label: 'Critical incidents', value: '06', change: '2 new today', tone: 'amber' },
  { label: 'Safe verdicts', value: '1,137', change: '88.6% of total', tone: 'lime' },
]

export const recentEmails: InvestigationEmail[] = [
  { id: 'EML-7821', subject: 'Urgent: Verify your account access', sender: 'security@micros0ft-support.co', recipient: 'nina.patel@acme.co', receivedAt: 'Today, 10:42', score: 94, threatLevel: 'Critical', status: 'Investigating' },
  { id: 'EML-7820', subject: 'September invoice — payment required', sender: 'billing@northstar-logistics.com', recipient: 'finance@acme.co', receivedAt: 'Today, 10:15', score: 76, threatLevel: 'High', status: 'Flagged' },
  { id: 'EML-7819', subject: 'Updated benefits enrollment guide', sender: 'hr@acme.co', recipient: 'all-staff@acme.co', receivedAt: 'Today, 09:58', score: 12, threatLevel: 'Low', status: 'Resolved' },
  { id: 'EML-7818', subject: 'Shared document: Q3 planning', sender: 'david.chen@partners-mail.net', recipient: 'ops@acme.co', receivedAt: 'Today, 09:36', score: 61, threatLevel: 'Medium', status: 'Investigating' },
]

export const threatDistribution = [
  { label: 'Critical', value: 6, color: 'bg-rose-400' },
  { label: 'High', value: 15, color: 'bg-orange-400' },
  { label: 'Medium', value: 26, color: 'bg-amber-300' },
  { label: 'Low', value: 1137, color: 'bg-emerald-400' },
]
