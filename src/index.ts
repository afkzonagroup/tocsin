// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Tocsin public API. Pure functions for NIS2 Article 23 deadlines, the IR 2024/2690 significance
 * criteria and report content; an encrypted local store; webhook and import connectors.
 *
 * @packageDocumentation
 */

export { SOURCES, ref, formatRef, type LegalRef, type SourceId } from './legal/refs.js';
export { TocsinError, type TocsinErrorCode } from './util/errors.js';
export type { Tri } from './util/validate.js';

export {
  SERVICE_TYPES,
  SERVICE_TYPE_LABELS,
  STAGES,
  STAGE_LABELS,
  type ServiceType,
  type Stage,
  type Incident,
  type IncidentDetails,
  type AssessmentAnswers,
  type ServiceMetrics,
  type Submission,
  type IntermediateRequest,
  type RecipientCommunication,
  type StoredAssessment,
} from './model/types.js';
export { validateIncident, validateAnswers, validateDetails } from './model/validate.js';
export { validateConfig, type TocsinConfig, type AuthorityConfig, type EntityConfig, type WebhookConfig } from './model/config.js';

export { parseInstant, formatInZone, isValidTimeZone, toIso, toMs } from './time/zone.js';
export { addHours, addCalendarMonths, parseDurationSeconds } from './time/periods.js';

export { assessSignificance, type AssessmentInput, type AssessmentResult, type CriterionResult, type Status } from './assess/assess.js';
export { findRecurringIncidents, type RecurringFinding } from './assess/recurring.js';
export { applyAnswerText } from './assess/answers.js';
export { GENERAL_QUESTIONS, METRIC_QUESTIONS, type Question } from './assess/questions.js';
export { exceedsShareOrCap, financialLossStatus } from './assess/thresholds.js';

export { computeDeadlines, pendingDeadlines, trustServiceDerogationApplies, type Deadline, type DeadlineState } from './stages/deadlines.js';
export { assertCanSubmit, nextStages } from './stages/machine.js';

export { buildReport, ATTRIBUTION, type ReportContent, type ReportElement, type Requirement } from './reports/content.js';
export { renderReport, renderMarkdown, renderHtml, renderJson, escapeMarkdown, REPORT_CSP, type ReportFormat } from './reports/render.js';
export { escapeHtml } from './util/html.js';

export { appendAudit, verifyAudit, type AuditEntry, type ChainCheck } from './audit/chain.js';
export { EncryptedStore, createExportBundle, readExportBundle, emptyData, FORMAT_VERSION, type StoreData, type StoreMeta, type Kdf as StoreKdf } from './store/store.js';
export { rekeyStore, restoreStore, type MaintenanceContext, type RekeyOptions, type RekeyResult, type RestoreOptions, type RestoreResult } from './store/recovery.js';
export { migrateStore, planMigration, STORE_MIGRATIONS, type MigrationStep, type MigrationTools, type MigrationResult } from './store/migrate.js';
export { parseRawKey, type KeySource } from './store/crypto.js';
export * as ops from './registry/ops.js';

export { sendWebhook, verifySignature, signBody, type WebhookMessage } from './connectors/webhook.js';
export { isBlockedAddress, resolveSafeTarget } from './connectors/ssrf.js';
export { planNotifications } from './connectors/notify.js';
export { parseImport, IMPORT_FORMATS, type ImportFormat } from './connectors/importers.js';

export { startUi, type UiOptions, type UiHandle } from './ui/server.js';
