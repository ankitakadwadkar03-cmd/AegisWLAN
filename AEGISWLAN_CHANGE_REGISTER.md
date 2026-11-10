# AegisWLAN – Engineering Change Register

**Document ID:** `AEGISWLAN_CHANGE_REGISTER`
**Date:** November 10, 2026
**Baseline Git Commit:** `16a3518` (Branch: `ml-testing-transfer`)
**Project:** Wi-Fi Real-Time Security and Signal Analysis (AegisWLAN / NetShield)
**Governance:** Strict Audit-First Authorization (Phase 0)

---

## 1. Governance & Change Control Principles

1. **Audit-Only Phase 0:** All entries in this register currently reflect the baseline audit state. No source code modifications, branch switches, or dependency installations are authorized during Phase 0.
2. **Model Immutability:** Any proposed change that modifies, retrains, or reorders features for `random_forest_awid3_v3_expanded.joblib` or `wifi_network_recommendation.joblib` is strictly **REJECTED**.
3. **Approval Gate:** Implementation of any registered item requires explicit user authorization phase by phase.

---

## 2. Change Register Log

| Change ID | Req ID | Target Module | Change Description | Change Type | Current Status | Files Affected | Test Status | Approval Status |
|---|---|---|---|---|---|---|---|---|
| **CR-001** | REQ-24 | Frontend / Navigation | Add accessible toggle button for AI Security Advisor in `Header.jsx`, `Sidebar.jsx`, and `AdminDashboardView.jsx` with keyboard escape & auto-focus. | Bug Fix / UX | **IMPLEMENTED** | `frontend/src/components/Header.jsx`<br>`frontend/src/components/Sidebar.jsx`<br>`frontend/src/views/AdminDashboardView.jsx`<br>`frontend/src/components/AdvisorDrawer.jsx`<br>`frontend/src/App.jsx`<br>`frontend/src/App.css` | Verified: `npm run build` pass, visual inspection | Phase 1 Completed & Verified |
| **CR-002** | REQ-25 | Backend / Database | Implement `PATCH /api/incidents/<int:id>` endpoint to persist incident triage status (`New`, `Investigating`, `Resolved`) directly into SQLite with strict type validation and test isolation. | Defect / API Expansion | **IMPLEMENTED** | `backend/app.py`<br>`backend/data/incident_store.py` | Verified: 20 passed pytest unit & integration tests with temporary DB isolation | Phase 1 Completed & Verified |
| **CR-003** | REQ-25 | Frontend / Incidents | Wire `handleUpdateIncidentStatus` in `App.jsx` to call `PATCH /api/incidents/<id>` with saving indicator and error banner so updates persist. | Defect / Data Flow | **IMPLEMENTED** | `frontend/src/App.jsx`<br>`frontend/src/components/IncidentDrawer.jsx`<br>`frontend/src/App.css` | Verified: E2E build pass, optimistic UI & rollback | Phase 1 Completed & Verified |
| **CR-004** | REQ-27 | Backend / Dependencies | Add `reportlab>=4.0.0` to `backend/requirements.txt` to resolve missing dependency for PDF reports. | Dependency Fix | **IMPLEMENTED** | `backend/requirements.txt` | Verified: `generate_pdf_report()` generates valid 5.2KB PDF | Phase 1 Completed & Verified |
| **CR-005** | REQ-26 | Frontend / CSS | Complete Aqua & Coral Phase 3 component styling in `App.css`: high-contrast primary buttons, pale aqua cards, refined headers, and AI Advisor panel. | Design System / UI | **IMPLEMENTED** | `frontend/src/App.css`<br>`frontend/src/views/AdminDashboardView.jsx` | Verified: `npm run build` pass, 0 oxlint errors | Phase 1 Completed & Verified |
| **CR-006** | REQ-04 | Database / Scope B | Execute idempotent schema migration script creating `managed_networks`, `managed_clients`, `prevention_policies`, `prevention_actions`, `notification_contacts`, and `notification_logs`. | Architecture / Schema | Specification Completed | `backend/data/incident_store.py`<br>`backend/data/migrations/001_scope_b_expansion.py` | Planned: SQLite schema validation | Authorized in Phase 2 Roadmap |
| **CR-007** | REQ-04 | Backend / API | Implement CRUD REST endpoints for Scope B managed network registration (`/api/managed-networks`). | API Expansion | Specification Completed | `backend/app.py`<br>`backend/data/incident_store.py` | Planned: Curl / Pytest unit tests | Authorized in Phase 2 Roadmap |
| **CR-008** | REQ-05 | Backend / Router Integration | Create `backend/router_management/` connector modules for OpenWrt (ubus) and UniFi Controller API to query live connected client IP/MAC inventory. | New Subsystem | Specification Completed | `backend/router_management/router_base.py`<br>`backend/router_management/openwrt_connector.py`<br>`backend/router_management/unifi_connector.py` | Planned: Mock router integration test | Authorized in Phase 3 Roadmap |
| **CR-009** | REQ-05 | Frontend / UI | Add Scope B Managed Networks and Verified Connected-Client inventory views to `WifiScanView` and `AdminDashboardView`. | Feature / UI | Specification Completed | `frontend/src/views/WifiScanView.jsx`<br>`frontend/src/views/AdminDashboardView.jsx`<br>`frontend/src/components/RegisterNetworkModal.jsx` | Planned: Component render test | Authorized in Phase 3 Roadmap |
| **CR-010** | REQ-07 | Backend / WIPS | Implement `backend/wips/containment_service.py` to execute client quarantine and MAC blacklisting via authorized router APIs. | Security Engine / WIPS | Specification Completed | `backend/wips/containment_service.py`<br>`backend/app.py` | Planned: Mock containment test | Authorized in Phase 4 Roadmap |
| **CR-011** | REQ-08 | Frontend / Triage | Add administrator approval modal and WIPS execution confirmation workflow into `IncidentDrawer.jsx`. | Security / UX | Specification Completed | `frontend/src/components/IncidentDrawer.jsx` | Planned: UI approval gate test | Authorized in Phase 4 Roadmap |
| **CR-012** | REQ-09 | Backend / Alerting | Implement multi-channel notification gateway supporting SMS (Twilio/AWS SNS) and Email (SMTP/SendGrid) with 15-minute alert flood deduplication. | Subsystem | Specification Completed | `backend/notifications/email_service.py`<br>`backend/notifications/sms_service.py`<br>`backend/notifications/rate_limiter.py` | Planned: Mock delivery test | Authorized in Phase 5 Roadmap |
| **CR-013** | REQ-10 | Backend & Frontend | Implement owner contact verification challenge (6-digit code) and explicit consent management in `SettingsView.jsx`. | Feature / Compliance | Specification Completed | `backend/app.py`<br>`frontend/src/views/SettingsView.jsx` | Planned: Challenge-response test | Authorized in Phase 5 Roadmap |
| **CR-014** | REQ-11 | Machine Learning | Frozen AWID3 31-feature Random Forest model preservation. | Protection / Policy | **ACTIVE & PRESERVED** | `backend/ml/models/random_forest_awid3_v3_expanded.joblib`<br>`backend/ml/v3_feature_schema.py` | Verified: 10/10 pytest passing | Immutable Constraint |
| **CR-015** | REQ-14 | Machine Learning | Frozen Wi-Fi Recommendation 12-feature Random Forest model preservation. | Protection / Policy | **ACTIVE & PRESERVED** | `backend/ml/wifi_recommendation/models/wifi_network_recommendation.joblib`<br>`backend/ml/wifi_recommendation/recommendation_schema.py` | Verified: Metadata JSON match | Immutable Constraint |

---

## 3. Approval Sign-Off Block

- **Phase 0 Audit Deliverables Generated:**
  - `AEGISWLAN_COMPLETE_CODEBASE_AUDIT.md` (Created)
  - `AEGISWLAN_REQUIREMENT_TRACEABILITY_MATRIX.md` (Created)
  - `AEGISWLAN_TARGET_ARCHITECTURE.md` (Created)
  - `AEGISWLAN_IMPLEMENTATION_ROADMAP.md` (Created)
  - `AEGISWLAN_CHANGE_REGISTER.md` (Created)
- **Phase 1 Implementation:** **COMPLETED & FULLY VERIFIED**
  - CR-001 (AI Advisor UI Accessibility & Keyboard Control): COMPLETED
  - CR-002 (Backend PATCH /api/incidents/<id> Persistence): COMPLETED
  - CR-003 (IncidentDrawer Status State & Feedback): COMPLETED
  - CR-004 (ReportLab Dependency in requirements.txt): COMPLETED
  - CR-005 (Aqua & Coral Refined Component Styling): COMPLETED
- **Next Authorized Step:** Await explicit user review and authorization before beginning Phase 2.
