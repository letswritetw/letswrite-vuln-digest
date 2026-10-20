<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue';
import { ArrowDownToLine, ArrowUpRight, BookOpen, ListChecks, RefreshCw, ShieldCheck, X } from '@lucide/vue';
import DOMPurify from 'dompurify';
import { marked } from 'marked';
import Alert from './components/ui/Alert.vue';
import Badge from './components/ui/Badge.vue';
import Button from './components/ui/Button.vue';
import Card from './components/ui/Card.vue';
import Checkbox from './components/ui/Checkbox.vue';
import Collapsible from './components/ui/Collapsible.vue';
import Input from './components/ui/Input.vue';
import Link from './components/ui/Link.vue';
import Select from './components/ui/Select.vue';
import Skeleton from './components/ui/Skeleton.vue';
import Table from './components/ui/Table.vue';
import Tabs from './components/ui/Tabs.vue';
import MetricGridCard from './components/compositions/MetricGridCard.vue';
import MustDoCard from './components/MustDoCard.vue';
import { cweUrl, safeUrl } from './links';
import { NO_OWASP, owaspLabel } from './owasp';
import type { ActionItem, ActionType, CweGuide, DailyReport, IntelRecord } from './types';

const report = ref<DailyReport | null>(null);
const dates = ref<{ date: string }[]>([]);
const selectedDate = ref('latest');
const view = ref('intel');
const loading = ref(true);
const error = ref('');
const missing = ref(false);
const historyError = ref('');
const search = ref<string | number>('');
const priority = ref('');
const analysis = ref('');
const category = ref('');
const kevOnly = ref(false);
const fyiOpen = ref(false);
const routineOpen = ref(false);
const footerOpen = ref(false);
const selected = ref<IntelRecord | null>(null);
const detailHeading = ref<HTMLElement | null>(null);
let openedBy: HTMLElement | null = null;
let controller: AbortController | null = null;
let requestId = 0;
const markdown = ref('');
const markdownLoading = ref(false);
const markdownError = ref('');
let markdownController: AbortController | null = null;
let markdownId = 0;
const datePattern = /^\d{4}-\d{2}-\d{2}$/;
const ACTION_LABELS: Record<ActionType, string> = { must_do: '必做', routine: '例行更新', fyi: '知悉即可' };
const viewTabs = [
  { id: 'intel', label: '情報總覽', icon: ListChecks },
  { id: 'markdown', label: '日報閱讀', icon: BookOpen },
];
const categoryOptions = [
  { label: '全部', value: '' }, { label: '必做', value: 'must_do' },
  { label: '例行更新', value: 'routine' }, { label: '知悉即可', value: 'fyi' },
];
const priorityOptions = [{ label: '全部優先級', value: '' }, ...['P0', 'P1', 'P2', 'P3'].map(p => ({ label: p, value: p }))];
const analysisOptions = [
  { label: '全部狀態', value: '' }, { label: 'AI 已分析', value: 'ai_analyzed' }, { label: '未分析', value: 'not_analyzed' },
];

function formatTime(value?: string | null): string {
  if (!value) return '來源未涵蓋';
  const utcValue = /(?:Z|[+-]\d\d:\d\d)$/i.test(value) ? value : `${value}Z`;
  const date = new Date(utcValue);
  return Number.isFinite(date.getTime())
    ? new Intl.DateTimeFormat('zh-TW', { timeZone: 'Asia/Taipei', dateStyle: 'short', timeStyle: 'short', hour12: false }).format(date)
    : '來源未涵蓋';
}

async function loadHistory(signal: AbortSignal, id: number) {
  try {
    const response = await fetch('/api/reports', { signal, cache: 'no-store' });
    if (!response.ok) throw new Error();
    const data = await response.json();
    if (!Array.isArray(data.reports)) throw new Error();
    if (id === requestId) {
      dates.value = data.reports.filter((entry: { date?: unknown }) => typeof entry?.date === 'string' && datePattern.test(entry.date));
      historyError.value = '';
    }
  } catch {
    if (!signal.aborted && id === requestId) historyError.value = '歷史日期讀取失敗；仍可查看目前日報，請重新整理再試。';
  }
}

async function loadReport() {
  controller?.abort();
  markdownController?.abort();
  const current = new AbortController();
  controller = current;
  const id = ++requestId;
  loading.value = true;
  error.value = '';
  missing.value = false;
  selected.value = null;
  report.value = null;
  markdown.value = '';
  markdownError.value = '';
  ++markdownId;
  void loadHistory(current.signal, id);
  try {
    const response = await fetch(`/api/reports/${selectedDate.value}`, { signal: current.signal, cache: 'no-store' });
    if (id !== requestId) return;
    if (response.status === 404) {
      missing.value = true;
      return;
    }
    if (!response.ok) throw new Error(response.status === 422 ? '日報資料損毀或格式不符，請檢查 n8n 產出的 JSON。' : '無法讀取日報，請確認儀表板服務正常後重新整理。');
    let data: DailyReport;
    try { data = await response.json(); } catch { throw new Error('日報資料無法解析，請檢查 n8n 產出的 JSON。'); }
    if (data.schemaVersion !== 1 || !datePattern.test(data.date) || !Array.isArray(data.records) || !data.stats || !data.coverage) throw new Error('日報格式不符，請檢查 n8n 產出的 JSON。');
    if (id !== requestId) return;
    category.value = data.actionPlan ? 'fyi' : '';
    fyiOpen.value = !data.actionPlan;
    report.value = data;
    if (view.value === 'markdown') void loadMarkdown();
  } catch (cause) {
    if (!current.signal.aborted && id === requestId) error.value = cause instanceof Error ? cause.message : '讀取失敗，請重新整理。';
  } finally {
    if (id === requestId) loading.value = false;
  }
}

async function loadMarkdown() {
  markdownController?.abort();
  if (!report.value || markdown.value) return;
  const date = report.value.date;
  const current = new AbortController();
  markdownController = current;
  const id = ++markdownId;
  markdownLoading.value = true;
  markdownError.value = '';
  try {
    const response = await fetch(`/api/reports/${date}/markdown`, { signal: current.signal, cache: 'no-store' });
    if (!response.ok) throw new Error(response.status === 404 ? '這份日報沒有 Markdown 檔案；仍可在情報清單閱讀 JSON 內容。' : 'Markdown 讀取失敗，請稍後重試。');
    const text = await response.text();
    if (id === markdownId && report.value?.date === date) markdown.value = text;
  } catch (cause) {
    if (!current.signal.aborted && id === markdownId) markdownError.value = cause instanceof Error ? cause.message : 'Markdown 讀取失敗。';
  } finally {
    if (id === markdownId) markdownLoading.value = false;
  }
}

const renderedMarkdown = computed(() => {
  const cleaned = DOMPurify.sanitize(marked.parse(markdown.value, { async: false, breaks: true }), {
    USE_PROFILES: { html: true }, FORBID_TAGS: ['img', 'form', 'input', 'button', 'style'], FORBID_ATTR: ['style'],
  });
  const doc = new DOMParser().parseFromString(cleaned, 'text/html');
  doc.querySelectorAll('a').forEach(link => {
    const url = safeUrl(link.getAttribute('href'));
    if (url) { link.setAttribute('href', url); link.setAttribute('target', '_blank'); link.setAttribute('rel', 'noopener noreferrer'); }
    else link.removeAttribute('href');
  });
  return doc.body.innerHTML;
});
const dateOptions = computed(() => [{ label: '最新日報', value: 'latest' }, ...dates.value.map(item => ({ label: item.date, value: item.date }))]);
const plan = computed(() => report.value?.actionPlan ?? null);
const defaultCategory = computed(() => plan.value ? 'fyi' : '');
const recordsById = computed(() => new Map((report.value?.records ?? []).map(record => [record.id, record])));
const guidesByCwe = computed<Record<string, CweGuide>>(() => Object.fromEntries((report.value?.cweGuides ?? []).map(guide => [guide.cwe, guide])));
const cardRecords = (item: ActionItem) => item.recordIds.map(id => recordsById.value.get(id)).filter((r): r is IntelRecord => Boolean(r));
const routineEntries = computed(() => Object.entries(plan.value?.routineByKeyword ?? {}));
const filtered = computed(() => {
  const term = String(search.value).trim().toLocaleLowerCase();
  return (report.value?.records ?? []).filter(record => {
    if (category.value && record.actionType !== category.value) return false;
    if (priority.value && record.priority !== priority.value) return false;
    if (analysis.value && (record.analysisStatus === 'ai_analyzed' ? 'ai_analyzed' : 'not_analyzed') !== analysis.value) return false;
    if (kevOnly.value && !record.isKev) return false;
    return !term || [record.id, ...(record.cwes ?? []), ...(record.matchedKeywords ?? []), ...(record.cpes ?? []), ...(record.packages ?? []), record.product, record.descriptionEn, record.summaryZh, record.kevProduct, record.kevVendor, record.reasonZh, record.actionZh].join(' ').toLocaleLowerCase().includes(term);
  });
});
const kevCount = computed(() => report.value?.records.filter(record => record.isKev).length ?? 0);
const metrics = computed(() => report.value ? [
  { label: 'NVD 實際取得', value: String(report.value.stats.totalNvdInWindow), detail: '跨關鍵字去重、篩選前' },
  { label: '保留情報', value: String(report.value.stats.totalRecords), detail: '含 GitHub Advisory' },
  { label: 'AI 已分析', value: String(report.value.stats.analyzedCount), detail: `${report.value.stats.unanalyzedCount} 筆未分析` },
  { label: 'CISA KEV', value: String(kevCount.value), detail: '已知被利用，不代表使用環境受害' },
] : []);
const stale = computed(() => report.value && Date.now() - Date.parse(report.value.generatedAt) > 36 * 3600 * 1000);
const historical = computed(() => selectedDate.value !== 'latest');
const activeFilters = computed(() => !!(search.value || priority.value || analysis.value || kevOnly.value || category.value !== defaultCategory.value));

watch(selectedDate, () => { void loadReport(); });
watch(view, next => { if (next === 'markdown') void loadMarkdown(); });

function clearFilters() { search.value = ''; priority.value = ''; analysis.value = ''; kevOnly.value = false; category.value = defaultCategory.value; }
async function openDetail(record: IntelRecord, event: Event) {
  selected.value = record;
  openedBy = event.currentTarget as HTMLElement;
  await nextTick();
  detailHeading.value?.focus();
  detailHeading.value?.scrollIntoView({ behavior: 'auto', block: 'nearest' });
}
async function closeDetail() {
  selected.value = null;
  await nextTick();
  if (openedBy?.isConnected) openedBy.focus();
  else document.getElementById('intel-search')?.focus();
}
onMounted(loadReport);
onBeforeUnmount(() => { controller?.abort(); markdownController?.abort(); });
</script>

<template>
  <a class="skip-link" href="#main">跳到主要內容</a>
  <header class="app-header">
    <div class="page">
      <div class="brand"><ShieldCheck :size="22" aria-hidden="true" /><span>Let's Write 資安戰情室</span></div>
      <div class="header-tools">
        <Select id="report-date" v-model="selectedDate" label="日報日期" :options="dateOptions" size="sm" variant="surface" class="date-select" />
        <Button variant="outline" color="neutral" size="sm" :prefix-icon="RefreshCw" :loading="loading" @click="loadReport">重新整理</Button>
      </div>
    </div>
  </header>

  <main id="main" class="page main" tabindex="-1">
    <Alert persistent v-if="historyError" id="history-error" title="歷史日期讀取失敗" :description="historyError" color="neutral" variant="soft" size="sm" />

    <Card v-if="loading" variant="surface" padding="lg" aria-label="正在載入日報" aria-busy="true">
      <Skeleton shape="text" :lines="1" class="skeleton-title" />
      <Skeleton shape="rect" class="skeleton-block" />
      <Skeleton shape="text" :lines="3" />
      <p class="muted small">正在讀取日報…</p>
    </Card>
    <Alert persistent v-else-if="error" id="report-error" title="日報暫時無法讀取" :description="error" color="destructive" variant="soft">
      <template #actions><Button variant="outline" size="sm" @click="loadReport">重新讀取</Button></template>
    </Alert>
    <Card v-else-if="missing" variant="surface" padding="lg" class="empty-state">
      <h2>{{ historical ? '這一天尚無日報' : '尚未收到日報' }}</h2>
      <p class="muted">請確認 n8n 工作流已成功產出報告，且報告目錄已唯讀掛載到儀表板。</p>
      <Button variant="outline" @click="loadReport">檢查新報告</Button>
    </Card>

    <template v-else-if="report">
      <div class="report-meta">
        <h1>{{ report.date }} {{ historical ? '歷史日報' : '每日日報' }}</h1>
        <span class="muted small">成功產出 {{ formatTime(report.generatedAt) }}</span>
        <span class="download-links">
          <Link :href="`/api/reports/${report.date}?download=1`" download size="sm" :prefix-icon="ArrowDownToLine">JSON</Link>
          <Link :href="`/api/reports/${report.date}/markdown?download=1`" download size="sm" :prefix-icon="ArrowDownToLine">Markdown</Link>
        </span>
      </div>

      <Alert persistent v-if="stale" id="stale-alert" color="warning" variant="soft" size="sm"
        :title="historical ? '歷史資料：此報告距今超過 36 小時' : '資料已超過 36 小時：此報告距今超過 36 小時'"
        :description="historical ? '請切回最新日報查閱近期情報。' : '請檢查 n8n 排程；目前顯示最後一次成功的內容。'" />

      <Tabs id="report-view" v-model="view" :items="viewTabs" label="日報檢視方式" type="segmented" :panel-surface="false" class="view-tabs">
        <template #intel>
          <section v-if="plan" class="stack" aria-labelledby="action-title">
            <h2 id="action-title">{{ historical ? '當日要做的事' : '今天要做的事' }}（{{ plan.mustDo.length }}）</h2>
            <Alert persistent v-if="!plan.mustDo.length" id="no-action" title="今天沒有必做項目" description="沒有符合條件的更新，不代表使用環境沒有風險。" color="success" variant="soft" size="sm" />
            <MustDoCard v-for="item in plan.mustDo" :key="`${item.kind}-${item.product}`" :item="item" :records="cardRecords(item)" :guides="guidesByCwe" />
            <Alert persistent v-if="plan.unanalyzedCandidates" id="unanalyzed-alert" color="info" variant="soft" size="sm"
              title="有情報尚未判定" :description="`另有 ${plan.unanalyzedCandidates} 筆可能必做的情報因 AI 分析上限未判定，列於知悉即可。`" />
            <Collapsible v-if="plan.routineCount" id="routine-line" v-model="routineOpen" variant="outline" class="routine-line"
              :title="`例行更新涵蓋 ${plan.routineCount} 則，多數由系統例行更新修補`">
              <p>微軟產品、Ubuntu、Linux kernel 的漏洞多數由每月或 apt 例行更新修補，不逐則列為必做；若為第三方軟體請另行確認，列入 CISA KEV 者會單獨列在上方。</p>
              <ul class="plain-list"><li v-for="[keyword, n] in routineEntries" :key="keyword">{{ keyword }}：{{ n }} 則</li></ul>
            </Collapsible>
          </section>
          <Alert persistent v-else id="legacy-alert" title="此日報產生於分類功能上線前，以下為完整情報清單。" color="info" variant="soft" size="sm" />

          <Card variant="surface" padding="lg" class="summary-card stack">
            <div class="section-heading"><h2>{{ historical ? '當日摘要' : '今日摘要' }}</h2><Badge variant="outline" color="secondary" size="sm">{{ report.stats.analyzedCount ? `${report.model || '模型未記錄'} AI 解讀` : '本次無 AI 分析' }}</Badge></div>
            <p class="executive-summary">{{ report.executiveSummaryZh }}</p>
            <p class="muted small">必做代表「若有在用就要處理」，不代表使用環境已受影響；受影響版本與資產狀態仍待確認。</p>
          </Card>
          <div class="stats-strip"><MetricGridCard title="情報統計" description="本次日報的蒐集與分析筆數" :metrics="metrics" :heading-level="2" /></div>

          <Collapsible id="fyi-section" v-model="fyiOpen" variant="surface" class="fyi-section"
            :title="plan ? `知悉即可（${plan.fyiCount} 則）` : `完整情報清單（${report.records.length} 則）`">
            <div class="stack">
              <div class="filters">
                <Input id="intel-search" v-model="search" label="搜尋情報" placeholder="CVE、CWE 或產品" autocomplete="off" class="search-input" />
                <Select v-if="plan" id="category" v-model="category" label="分類" :options="categoryOptions" size="sm" />
                <Select id="priority" v-model="priority" label="查核優先級" :options="priorityOptions" size="sm" />
                <Select id="analysis" v-model="analysis" label="分析狀態" :options="analysisOptions" size="sm" />
                <Checkbox id="kev-only" v-model="kevOnly" label="僅 CISA KEV" size="sm" />
                <Button v-if="activeFilters" variant="outline" color="neutral" size="sm" @click="clearFilters">清除篩選</Button>
              </div>
              <p class="muted small" aria-live="polite">顯示 {{ filtered.length }} / {{ report.records.length }} 筆</p>

              <Card v-if="selected" variant="outline" padding="lg" class="detail-panel" aria-labelledby="detail-title" @keydown.esc="closeDetail">
                <div class="detail-top"><h3 id="detail-title" ref="detailHeading" class="mono" tabindex="-1">{{ selected.id }}</h3><Button size="sm" variant="outline" color="neutral" shape="fab" aria-label="關閉情報詳情" :prefix-icon="X" @click="closeDetail" /></div>
                <div class="badge-row"><Badge v-if="selected.actionType" variant="soft" color="secondary">{{ ACTION_LABELS[selected.actionType] }}</Badge><Badge variant="soft" color="secondary">{{ selected.priority || '優先級待查核' }}</Badge><Badge variant="soft" :color="selected.analysisStatus === 'ai_analyzed' ? 'secondary' : 'warning'">{{ selected.analysisStatus === 'ai_analyzed' ? 'AI 已分析' : '未分析' }}</Badge><Badge v-if="selected.isKev" variant="soft" color="warning">CISA KEV</Badge></div>
                <h4 class="detail-summary">{{ selected.summaryZh || '此筆尚無 AI 中文摘要' }}</h4>
                <Alert persistent id="detail-note" title="受影響版本待確認；本系統未驗證實際資產曝險。" color="neutral" variant="soft" size="sm" />
                <section class="detail-block"><h4>官方來源事實</h4>
                  <dl class="fact-list">
                    <div><dt>CWE 弱點類型</dt><dd><template v-if="selected.cwes?.length"><Link v-for="cwe in selected.cwes" :key="cwe" :href="cweUrl(cwe) || '#'" external size="sm">{{ cwe }}</Link></template><template v-else>來源未涵蓋</template></dd></div>
                    <div><dt>OWASP</dt><dd>{{ selected.owasp?.length ? selected.owasp.map(owaspLabel).join('、') : selected.owasp ? NO_OWASP : '此日報未記錄' }}</dd></div>
                    <div><dt>CVSS</dt><dd>{{ selected.cvss ?? '來源未涵蓋' }} <span v-if="selected.cvssVersion">（{{ selected.cvssVersion }}）</span></dd></div>
                    <div><dt>首次公布</dt><dd>{{ formatTime(selected.published) }}</dd></div>
                    <div><dt>最後修改</dt><dd>{{ formatTime(selected.lastModified) }}</dd></div>
                    <div><dt>已知被利用</dt><dd>{{ selected.isKev ? '已列入 CISA KEV；非使用環境受害確認' : '此日報未標記 KEV；不代表未被利用' }}</dd></div>
                    <div v-if="selected.isKev"><dt>加入 KEV</dt><dd>{{ selected.kevDateAdded || '來源未涵蓋' }}</dd></div>
                  </dl>
                  <p class="source-description" lang="en">{{ selected.descriptionEn || '來源未涵蓋官方原文。' }}</p>
                  <p class="link-row">
                    <Link v-if="safeUrl(selected.sourceUrl)" :href="safeUrl(selected.sourceUrl)!" external size="sm" :suffix-icon="ArrowUpRight">{{ selected.sourceType === 'GHSA' ? 'GitHub 官方公告' : 'NVD 官方公告' }}</Link>
                    <Link v-if="safeUrl(selected.kevUrl)" :href="safeUrl(selected.kevUrl)!" external size="sm" :suffix-icon="ArrowUpRight">CISA KEV 來源</Link>
                  </p>
                </section>
                <section class="detail-block"><h4>AI 分析 <Badge variant="outline" color="secondary" size="sm">未經人工確認</Badge></h4>
                  <dl v-if="selected.analysisStatus === 'ai_analyzed'" class="fact-list"><div><dt>技術相關性</dt><dd>{{ selected.relevance || '待確認' }}</dd></div><div><dt>判斷依據</dt><dd>{{ selected.reasonZh || '來源未涵蓋' }}</dd></div><div><dt>建議查核</dt><dd>{{ selected.actionZh || '待確認受影響版本' }}</dd></div></dl>
                  <p v-else class="muted">此筆保留官方來源資料，尚未經 Gemini 分析。沒有 AI 優先級不代表風險較低。</p>
                </section>
              </Card>

              <Table caption="情報清單" variant="surface" density="compact" :hover="false" :column-count="4" :empty="!filtered.length" class="intel-table">
                <template #header><thead><tr><th scope="col">情報</th><th scope="col">弱點類型</th><th scope="col">產品</th><th scope="col">狀態</th></tr></thead></template>
                <template #empty>
                  <template v-if="!report.records.length"><strong>本次沒有符合條件的情報</strong><br />資料已成功產出；零筆不代表抓取失敗，也不代表使用環境沒有風險。</template>
                  <template v-else>沒有符合篩選的情報。<Button variant="outline" size="sm" @click="clearFilters">清除篩選</Button></template>
                </template>
                <tbody><tr v-for="record in filtered" :key="record.id" class="intel-row" :data-selected="selected?.id === record.id" @click="openDetail(record, $event)">
                  <th scope="row">
                    <Button size="sm" variant="soft" color="neutral" class="row-button mono" :aria-pressed="selected?.id === record.id" @click.stop="openDetail(record, $event)">{{ record.id }}</Button>
                    <Badge v-if="record.isKev" variant="soft" color="warning" size="sm">KEV</Badge>
                    <span class="row-title">{{ record.summaryZh || record.descriptionEn || '來源未涵蓋摘要' }}</span>
                  </th>
                  <td>{{ (record.cwes ?? []).join('、') || '來源未涵蓋' }}</td>
                  <td>{{ record.product || (record.matchedKeywords ?? []).join(' / ') || '待確認' }}</td>
                  <td>{{ record.priority || '待查核' }}<br /><span class="muted small">{{ record.analysisStatus === 'ai_analyzed' ? 'AI 已分析' : '未分析' }}</span></td>
                </tr></tbody>
              </Table>
            </div>
          </Collapsible>
        </template>

        <template #markdown>
          <Card variant="surface" padding="lg" class="stack">
            <div class="section-heading"><h2>完整 Markdown 日報</h2><Badge variant="outline" color="secondary" size="sm">已過濾不安全 HTML</Badge></div>
            <p v-if="markdownLoading" role="status" class="muted">正在載入日報內容…</p>
            <Alert persistent v-else-if="markdownError" id="markdown-error" title="Markdown 讀取失敗" :description="markdownError" color="destructive" variant="soft" size="sm">
              <template #actions><Button variant="outline" size="sm" @click="loadMarkdown">重試</Button></template>
            </Alert>
            <article v-else class="markdown-body" v-html="renderedMarkdown"></article>
          </Card>
        </template>
      </Tabs>

      <Collapsible id="coverage-footer" v-model="footerOpen" title="資料範圍與限制" variant="underline" class="coverage-footer">
        <p>查詢區間：{{ formatTime(report.coverage.fromUtc) }} 至 {{ formatTime(report.coverage.toUtc) }}（台灣時間）。{{ report.coverage.filter?.dateField === 'published' ? '依首次公布時間篩選。' : report.coverage.filter?.dateField === 'lastModified' ? '依最後修改時間篩選。' : '時間篩選欄位未記錄，請參考該日日報。' }}</p>
        <p>{{ report.coverage.note || '此舊版報告未記錄完整涵蓋說明；資料範圍待確認。' }}</p>
        <p v-if="report.coverage.filter?.keywords?.length">技術關鍵字：{{ report.coverage.filter.keywords.join('、') }}</p>
        <p>來源：{{ report.coverage.sources?.join('、') || '來源未涵蓋' }}。CVE 是漏洞編號，CWE 是弱點類型，KEV 是已知被利用漏洞清單，OWASP Top 10:2025 是稽核用的弱點分類。</p>
        <p class="muted small">唯讀儀表板，不額外呼叫 Gemini API</p>
      </Collapsible>
    </template>
  </main>

  <footer class="site-footer">
    <div class="page">
      <span>由 Let's Write 製作</span>
      <Link href="https://www.letswrite.tw/" external size="sm" :suffix-icon="ArrowUpRight">www.letswrite.tw</Link>
    </div>
  </footer>
</template>
