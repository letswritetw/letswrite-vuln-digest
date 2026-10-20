export type Audience = '全員電腦' | '伺服器管理者' | '開發者';
export type ActionType = 'must_do' | 'routine' | 'fyi';

export interface IntelRecord {
  id: string;
  sourceType?: 'NVD' | 'GHSA';
  published?: string | null;
  lastModified?: string | null;
  descriptionEn?: string | null;
  cvss?: number | null;
  cvssVersion?: string | null;
  cwes: string[];
  cpes?: string[];
  matchedKeywords?: string[];
  isKev: boolean;
  kevDateAdded?: string | null;
  kevVendor?: string | null;
  kevProduct?: string | null;
  kevRequiredAction?: string | null;
  sourceUrl?: string | null;
  kevUrl?: string | null;
  analysisStatus: string;
  summaryZh?: string | null;
  relevance?: string | null;
  priority?: string | null;
  reasonZh?: string | null;
  actionZh?: string | null;
  inventoryImpactConfirmed?: boolean;
  ghsaId?: string | null;
  advisoryType?: 'reviewed' | 'malware' | null;
  patchedVersions?: string[];
  packages?: string[];
  affectedVersions?: string[];
  audience?: Audience[];
  routine?: boolean;
  vendorManaged?: boolean;
  disputed?: boolean;
  vendorAdvisoryUrls?: string[];
  owasp?: string[];
  product?: string | null;
  isCompanyProduct?: boolean | null;
  fixVersionZh?: string | null;
  fixQuoteEn?: string | null;
  fixQuoteZh?: string | null;
  kevActionZh?: string | null;
  fixVerified?: boolean;
  actionType?: ActionType;
}

export interface ActionItem {
  kind: 'update' | 'kev' | 'malware';
  product: string;
  audience: Audience[];
  fixVersions: string[];
  owasp: string[];
  recordIds: string[];
}

export interface ActionPlan {
  mustDo: ActionItem[];
  routineCount: number;
  routineByKeyword: Record<string, number>;
  fyiCount: number;
  unanalyzedCandidates?: number;
}

export interface CweGuide {
  cwe: string;
  nameZh: string;
  riskZh: string;
  handlingZh: string;
  nameEn?: string | null;
  owasp?: string[];
}

export interface DailyReport {
  schemaVersion: 1;
  date: string;
  generatedAt: string;
  model: string;
  coverage: {
    fromUtc: string;
    toUtc: string;
    note?: string;
    sources?: string[];
    filter?: { keywords?: string[]; dateField?: string; requiresCwe?: boolean };
    nvd?: {
      status: string;
      limitPerKeyword?: number;
      keepPerKeyword?: number;
      queries?: { keyword: string; totalResults: number; returnedCount: number; eligibleCount?: number; keptCount?: number; truncated: boolean }[];
    };
    ghsa?: { status: string; packages?: string[]; reviewedCount?: number; malwareCount?: number };
  };
  stats: {
    totalNvdInWindow: number;
    totalRecords: number;
    analyzedCount: number;
    unanalyzedCount: number;
    kevAddedInWindow: number;
    mustDoCount?: number;
    routineCount?: number;
    fyiCount?: number;
    cweGuidesMissing?: number;
  };
  executiveSummaryZh: string;
  actionPlan?: ActionPlan | null;
  cweGuides?: CweGuide[];
  records: IntelRecord[];
}
