Memory Forensics API — Phase 1 MVP
==================================

Base URL: http://localhost:8000 (default). Override in frontend with window.API_BASE if needed.

Health
- GET /api/health → { status, timestamp }

Cases
- POST /api/cases/upload (multipart/form-data, field: file) → { case_id, message }
	- Stores the upload under backend/uploads/{case_id}_<filename>
	- Stub only: does not run MemoryAnalyzer yet.
- GET /api/cases → list of cases [{ case_id, filename, uploaded_at, status, threat_cards, process_tree }]
- GET /api/cases/{case_id} → metadata for a case

Dashboard
- GET /api/cases/{case_id}/dashboard → { case_id, threat_cards, uploaded_at }
	- threat_cards is stubbed with sample Critical/High/Medium entries until analyzer integration.

Process Tree
- GET /api/cases/{case_id}/process-tree → { case_id, tree }
	- tree is a stubbed System-rooted hierarchy until analyzer integration.

Report Export
- GET /api/cases/{case_id}/report.pdf → inline PDF summary (stubbed, minimal text)

Notes
- CORS is enabled for all origins to simplify frontend dev.
- MemoryAnalyzer import is wired but unused; hook it after upload to populate threat_cards and process_tree.
- Upload size limits and auth are not enforced in MVP—add before production.