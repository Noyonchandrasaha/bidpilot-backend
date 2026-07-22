# BidPilot Backend Database Model

BidPilot uses MongoDB with `ObjectId` for document `_id` values and relationship fields. Monetary values should use MongoDB `Decimal128`, not floats.

## Collections

- `projects`: root project list/header data, owner, client, platform, service type, budget, status, context summary counters, and next action.
- `project_contexts`: current AI-understood state for one project.
- `project_context_versions`: historical snapshots of context changes.
- `project_messages`: inbound, outbound, AI, and internal project messages.
- `project_message_versions`: regeneration and manual edit history for messages.
- `project_documents`: logical generated documents.
- `project_document_versions`: structured editable document content and generation metadata.
- `project_files`: uploaded/generated file metadata and private object-storage keys.
- `templates`: backend-controlled document template definitions.
- `platform_template_settings`: owner-specific branding/settings per platform.
- `project_credentials`: secret metadata and external secret references or encrypted payloads.
- `project_activities`: project timeline, status history, and entity events.
- `sequence_counters`: atomic counters for project codes such as `UP-2026-00042`.

## Relationship Summary

- `projects.owner_id -> users._id`
- `project_contexts.project_id -> projects._id`
- `project_context_versions.project_id -> projects._id`
- `project_messages.project_id -> projects._id`
- `project_messages.reply_to_message_id -> project_messages._id`
- `project_message_versions.message_id -> project_messages._id`
- `project_documents.project_id -> projects._id`
- `project_documents.template_id -> templates._id`
- `project_document_versions.document_id -> project_documents._id`
- `project_document_versions.template_id -> templates._id`
- `project_files.project_id -> projects._id`
- `platform_template_settings.owner_id -> users._id`
- `project_credentials.project_id -> projects._id`
- `project_activities.project_id -> projects._id`

## Notes

- Store current context in `project_contexts`, and history in `project_context_versions`.
- Store message/document revisions in version collections instead of large arrays.
- Store file content outside normal MongoDB documents; keep only private storage metadata in `project_files`.
- Store secret values in an external secret manager when possible. If unavailable, store encrypted payloads and keep encryption keys outside MongoDB.
- Use multi-document transactions only when creating a project, initial context, and initial activity must succeed atomically.
