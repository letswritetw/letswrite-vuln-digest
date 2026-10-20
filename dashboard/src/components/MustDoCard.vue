<script setup lang="ts">
import { computed, ref } from 'vue';
import { ArrowUpRight } from '@lucide/vue';
import Badge from './ui/Badge.vue';
import Collapsible from './ui/Collapsible.vue';
import Link from './ui/Link.vue';
import type { ActionItem, CweGuide, IntelRecord } from '../types';
import { NO_OWASP, owaspLabel } from '../owasp';
import { cweUrl, safeUrl } from '../links';

const props = defineProps<{ item: ActionItem; records: IntelRecord[]; guides: Record<string, CweGuide> }>();
const open = ref(false);
const unique = <T,>(values: T[]) => [...new Set(values)];

const title = computed(() => props.item.kind === 'malware' ? `${props.item.product} 出現惡意版本`
  : props.item.kind === 'kev' ? `處理 ${props.item.product} 已知被利用漏洞` : `更新 ${props.item.product}`);
const versions = computed(() => props.item.fixVersions.length ? props.item.fixVersions
  : props.item.kind === 'kev' ? ['請見廠商公告'] : []);
const affected = computed(() => unique(props.records.flatMap(r => r.affectedVersions ?? [])));
const quotes = computed(() => unique(props.records
  .filter(r => r.fixVerified && r.sourceType === 'NVD' && r.fixQuoteEn && !r.patchedVersions?.length)
  .map(r => JSON.stringify([r.fixQuoteEn, r.fixQuoteZh ?? '']))).map(text => JSON.parse(text) as [string, string]));
const patched = computed(() => props.records.filter(r => r.patchedVersions?.length));
const kevActions = computed(() => unique(props.records.filter(r => r.isKev && r.kevRequiredAction)
  .map(r => JSON.stringify([r.kevRequiredAction, r.kevActionZh ?? '']))).map(text => JSON.parse(text) as [string, string]));
const kevDates = computed(() => unique(props.records.map(r => r.kevDateAdded).filter((d): d is string => Boolean(d))));
const advisories = computed(() => unique(props.records.flatMap(r => r.vendorAdvisoryUrls ?? []))
  .map(url => safeUrl(url)).filter((url): url is string => Boolean(url)));
const cwes = computed(() => unique(props.records.flatMap(r => r.cwes)));
const aiCompanyProduct = computed(() => props.records.some(r => r.isCompanyProduct === true));
const panelId = computed(() => `must-do-${props.item.kind}-${props.item.product}`.replace(/[^\w-]+/g, '-'));
</script>

<template>
  <Collapsible :id="panelId" v-model="open" :title="title" variant="surface" class="must-do-card" :data-kind="item.kind">
    <template #trigger>
      <span class="card-trigger">
        <span class="card-title">{{ title }}</span>
        <span class="card-line">
          <template v-if="item.kind === 'malware'">先檢查是否裝到受影響版本，再更新</template>
          <template v-else>更新到 <Badge v-for="v in versions" :key="v" variant="soft" color="warning" class="mono">{{ v }}</Badge></template>
        </span>
        <span class="card-line">
          <Badge v-for="who in item.audience" :key="who" variant="soft" color="primary">{{ who }}</Badge>
          <Badge v-for="code in item.owasp" :key="code" variant="outline" color="secondary">{{ owaspLabel(code) }}</Badge>
          <Badge v-if="!item.owasp.length" variant="outline" color="secondary">{{ NO_OWASP }}</Badge>
          <span class="muted">涵蓋 {{ item.recordIds.length }} 則</span>
        </span>
      </span>
    </template>

    <div class="card-body">
      <section v-if="item.kind === 'malware'" class="card-block">
        <h4>處理步驟</h4>
        <ol class="steps">
          <li>檢查各專案 lockfile 是否裝到受影響版本（<span class="mono">{{ affected.join('、') || '來源未涵蓋' }}</span>）</li>
          <li>裝到的機器更換其上的金鑰與密碼</li>
          <li>更新到安全版本</li>
        </ol>
      </section>

      <section v-if="quotes.length || patched.length || kevActions.length || item.kind === 'kev'" class="card-block">
        <h4>官方依據</h4>
        <blockquote v-for="[en, zh] in quotes" :key="en" class="quote"><p lang="en">「{{ en }}」</p><p>中譯：{{ zh || '來源未涵蓋' }}</p></blockquote>
        <p v-for="r in patched" :key="r.id">GitHub Advisory 官方修補版本：<span class="mono">{{ r.patchedVersions?.join('、') }}</span>（受影響範圍 <span class="mono">{{ r.affectedVersions?.join('、') || '來源未涵蓋' }}</span>）</p>
        <blockquote v-for="[en, zh] in kevActions" :key="en" class="quote"><p>CISA 要求：<span lang="en">{{ en }}</span></p><p>中譯：{{ zh || '來源未涵蓋' }}</p></blockquote>
        <template v-if="item.kind === 'kev'">
          <p>列入 KEV：{{ kevDates.join('、') || '來源未涵蓋' }}</p>
          <p v-if="advisories.length" class="link-row">
            <Link v-for="(url, i) in advisories" :key="url" :href="url" external size="sm" :suffix-icon="ArrowUpRight">廠商公告{{ advisories.length > 1 ? ` ${i + 1}` : '' }}</Link>
          </p>
          <p v-else class="muted">來源未提供廠商公告連結，請查看下方官方公告。</p>
        </template>
      </section>

      <section class="card-block">
        <h4>弱點類型與處理</h4>
        <p v-if="!cwes.length" class="muted">來源未提供 CWE 編號。</p>
        <div v-for="cwe in cwes" :key="cwe" class="cwe-guide">
          <p class="cwe-name">
            <Link v-if="cweUrl(cwe)" :href="cweUrl(cwe)!" external size="sm" :suffix-icon="ArrowUpRight" class="mono">{{ cwe }}</Link>
            <span v-else class="mono">{{ cwe }}</span>
            <strong v-if="guides[cwe]">{{ guides[cwe].nameZh }}</strong>
          </p>
          <template v-if="guides[cwe]">
            <p><Badge variant="soft" color="secondary" size="sm">風險</Badge> {{ guides[cwe].riskZh }}</p>
            <p><Badge variant="soft" color="secondary" size="sm">處理</Badge> {{ guides[cwe].handlingZh }}</p>
            <p class="muted small">AI 說明，未經人工確認</p>
          </template>
          <p v-else class="muted">AI 未提供說明，請參考 MITRE 定義。</p>
        </div>
      </section>

      <section class="card-block">
        <h4>涵蓋的情報</h4>
        <p v-if="aiCompanyProduct" class="muted small">AI 判定為關注清單中的產品；受影響版本仍待各系統確認。</p>
        <ul class="card-records">
          <li v-for="r in records" :key="r.id">
            <span class="mono">{{ r.id }}</span>
            <span>CVSS {{ r.cvss ?? '來源未涵蓋' }}</span>
            <span>{{ r.cwes.join('、') || 'CWE 來源未涵蓋' }}</span>
            <Link v-if="safeUrl(r.sourceUrl)" :href="safeUrl(r.sourceUrl)!" external size="sm" :suffix-icon="ArrowUpRight">官方公告</Link>
          </li>
        </ul>
      </section>
    </div>
  </Collapsible>
</template>
