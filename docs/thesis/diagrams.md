# Aegis Node — Thesis Architecture & Workflow Diagrams

This document contains official Mermaid diagrams illustrating the system architecture, data flow, detection pipeline, LLM security boundary, remediation workflow, database ER schema, and benchmark evaluation methodology for the Aegis Node M.Tech thesis.

---

## 1. System Architecture Diagram

```mermaid
graph TD
    User["User / Integrator"] -->|Upload File| Frontend["React 18 + Vite Frontend UI"]
    Frontend -->|POST /upload| FastAPI["FastAPI Backend Server"]
    FastAPI --> FileService["File Service (UUID / SHA-256)"]
    FileService -->|Store Sample| SamplesDir["data/samples/ (Immutable)"]
    FastAPI --> ScanEngine["Multi-Stage Scan Engine"]
    
    subgraph Scanning Pipeline
        ScanEngine --> Stage1["Stage 1: ClamAV TCP 3310 (INSTREAM)"]
        ScanEngine --> Stage2["Stage 2: Content Rules Engine (Regex)"]
    end
    
    ScanEngine --> RiskCalc["Risk Score & Verdict Model"]
    ScanEngine -->|Compact Findings| LLMService["Stage 3: Gemini 3.6 Flash LLM"]
    FastAPI --> Sanitizer["Stage 4: Deterministic Sanitizer"]
    Sanitizer -->|Sanitized File| SanitizedDir["data/sanitized/"]
    Sanitizer --> ReScan["Stage 5: Verification Re-Scan"]
    FastAPI --> DB[("SQLite Database")]
```

---

## 2. Data Flow Diagram

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant UI as React Frontend
    participant API as FastAPI Backend
    participant FS as File Service
    participant Engine as Scan Engine
    participant LLM as Gemini 3.6 Flash
    participant San as Sanitizer Engine
    participant DB as SQLite DB

    User->>UI: Upload dataset (CSV/JSON/Parquet)
    UI->>API: POST /api/v1/datasets/upload
    API->>FS: Save file under UUID, compute SHA-256
    FS-->>API: Return file_id & stored_filename
    API-->>UI: Upload Success (dataset_id)
    
    UI->>API: POST /api/v1/datasets/{id}/scan
    API->>Engine: run_scan(stored_filename)
    Engine->>Engine: Stage 1: ClamAV TCP scan
    Engine->>Engine: Stage 2: Content rule inspection
    Engine-->>API: Return ScanEngineResult (verdict, risk_score, findings)
    API->>DB: Persist ScanReportRecord
    API-->>UI: Scan Results JSON
    
    UI->>API: POST /api/v1/datasets/{id}/analyze
    API->>LLM: analyse(compact_findings_only)
    LLM-->>API: Return structured Pydantic response
    API-->>UI: AI Threat Summary
    
    UI->>API: POST /api/v1/datasets/{id}/remediate
    API->>San: sanitize_file(stored_filename)
    San->>FS: Save to data/sanitized/
    API->>Engine: run_scan(sanitized_filename) [Re-Scan]
    API->>DB: Persist RemediationRecord
    API-->>UI: Remediation & Re-Scan Report
```

---

## 3. Threat Detection Pipeline

```mermaid
flowchart LR
    Input["Input Dataset File"] --> ClamAVCheck{"ClamAV Active?"}
    ClamAVCheck -- Yes --> ClamAVScan["Stream bytes to clamd (TCP 3310)"]
    ClamAVCheck -- No --> RuleScan["Skip ClamAV (Fallback)"]
    ClamAVScan --> ClamResult["Status: Clean / Infected"]
    ClamResult --> RuleScan
    
    RuleScan --> FormRule["Formula Rules (FORM-001..003)"]
    RuleScan --> ScriptRule["Script Rules (SCRP-001..003)"]
    RuleScan --> SqlRule["SQL Rules (SQLI-001..002)"]
    RuleScan --> BinRule["Binary Null Byte Rule (BIN-001)"]
    
    FormRule & ScriptRule & SqlRule & BinRule --> Aggregate["Aggregate Findings"]
    Aggregate --> RiskCalc["Calculate Composite Risk Score R in [0, 10]"]
    RiskCalc --> Verdict{"Verdict Decision"}
    Verdict -- R >= 7.0 or Critical/Infected --> Malicious["Verdict: Malicious"]
    Verdict -- 0 < R < 7.0 --> Suspicious["Verdict: Suspicious"]
    Verdict -- R = 0.0 --> Clean["Verdict: Clean"]
```

---

## 4. LLM Security Boundary & Evidence Minimization

```mermaid
flowchart TD
    subgraph Application Boundary
        Dataset["Untrusted Dataset (CSV/JSON)"]
        RawContent["Raw Cell Values / Passwords / Data Bytes"]
        Dataset -.->|ISOLATED - NEVER SENT| ExternalAPI["Cloud LLM API"]
        
        Scanner["Scan Engine"] -->|Extracts| Findings["Compact Finding Dictionaries"]
        Findings --> CompactEvidence["Evidence Payload: rule_id, severity, category, line location"]
    end
    
    subgraph External AI Boundary
        CompactEvidence -->|Transmitted| Gemini["Gemini 3.6 Flash API"]
        Gemini -->|System Prompt Injection Defense| LLMReasoning["Structured AI Threat Reasoning"]
        LLMReasoning -->|Pydantic Schema Validation| Response["LlmAnalysisOutput JSON"]
    end
    
    Response --> UI["React UI Dashboard"]
```

---

## 5. Remediation Pipeline

```mermaid
flowchart TD
    Start["Remediation Request"] --> ReadFile["Read Original Dataset (samples/ or quarantine/)"]
    ReadFile --> CheckFormat{"Format Type"}
    
    CheckFormat -- CSV --> TransCSV["Apply pandas / csv rules"]
    CheckFormat -- JSON --> TransJSON["Apply JSON string cell rules"]
    CheckFormat -- Parquet --> TransParquet["Apply DataFrame string column rules"]
    
    TransCSV & TransJSON & TransParquet --> Rule1["Formula Escaping: '=CMD() -> ''=CMD()"]
    Rule1 --> Rule2["Script Removal: <script> -> [script_removed]"]
    Rule2 --> Rule3["SQL Neutralization: ' OR '1'='1 -> [sql_payload_neutralized]"]
    Rule3 --> WriteSan["Save to data/sanitized/{uuid}_sanitized.{ext}"]
    WriteSan --> Immutability["Verify Original in data/samples/ UNTOUCHED"]
```

---

## 6. Re-Scan Verification Pipeline

```mermaid
flowchart LR
    SanArtifact["Sanitized Dataset Artifact"] --> VerificationScan["run_scan(sanitized_artifact)"]
    VerificationScan --> RescanFindings["Count Remaining Findings & Risk"]
    RescanFindings --> CalcReduction["Calculate Threat Reduction %"]
    CalcReduction --> StatusCheck{"Remaining Findings == 0?"}
    StatusCheck -- Yes --> StatusCompleted["Remediation Status: COMPLETED"]
    StatusCheck -- No --> StatusPartial["Remediation Status: PARTIAL"]
    StatusCompleted & StatusPartial --> PersistRecord["Persist RemediationRecord in DB"]
```

---

## 7. Database Entity Relationship (ER Diagram)

```mermaid
erDiagram
    DatasetRecord ||--o{ ScanReportRecord : "has scan reports"
    DatasetRecord ||--o{ RemediationRecord : "has remediations"

    DatasetRecord {
        int id PK
        string original_filename
        string stored_filename
        int file_size_bytes
        string sha256_hash
        string mime_type
        string file_format
        string status
        datetime uploaded_at
    }

    ScanReportRecord {
        int id PK
        int dataset_id FK
        string sha256_hash
        bool clamav_scanned
        string clamav_status
        string clamav_virus_name
        int threats_found_count
        float risk_score
        int scan_duration_ms
        string verdict
        string findings_json
        datetime scanned_at
    }

    RemediationRecord {
        int id PK
        int dataset_id FK
        string original_sha256
        string sanitized_sha256
        string stored_sanitized_filename
        string remediation_status
        float original_risk_score
        float sanitized_risk_score
        int original_findings_count
        int remaining_findings_count
        int resolved_findings_count
        float threat_reduction_percent
        int changes_count
        string remediation_actions_json
        datetime remediated_at
    }
```

---

## 8. Benchmark Evaluation Methodology

```mermaid
flowchart TD
    Generator["dataset_generator.py"] -->|Generates 100 Files| Corpus["100 Synthetic Datasets"]
    Generator -->|Generates Labels| GroundTruth["data/benchmarks/metadata/ground_truth.json"]
    
    Corpus --> Runner["benchmark_runner.py"]
    GroundTruth --> Runner
    
    subgraph Benchmark Runner Modes
        Runner --> Mode1["rule_only Mode"]
        Runner --> Mode2["clamav_only Mode"]
        Runner --> Mode3["combined Mode"]
        Runner --> Mode4["combined_llm Mode"]
        Runner --> RemMode["Remediation Engine"]
    end
    
    Mode1 & Mode2 & Mode3 & Mode4 & RemMode --> ReportGen["report_generator.py"]
    ReportGen --> CSV["benchmark_results.csv"]
    ReportGen --> JSON["benchmark_results.json"]
    ReportGen --> ReportMD["docs/phase-6-evaluation-report.md"]
```

---

## 9. Deployment Architecture Diagram

```mermaid
graph LR
    subgraph Host OS (Windows 11 / Linux)
        subgraph Docker Engine
            ClamAVContainer["Docker Container: clamav/clamav:stable (Port 127.0.0.1:3310)"]
        end
        
        subgraph Python 3.12 Virtual Environment
            FastAPIApp["Uvicorn / FastAPI Backend Server (Port 8000)"]
        end
        
        subgraph Node.js Runtime
            ViteDev["Vite / React 18 Frontend Dashboard (Port 5173)"]
        end
        
        subgraph Local File System Storage
            SQLiteDB[("aegis_node.db")]
            SamplesDir["data/samples/"]
            QuarantineDir["data/quarantine/"]
            SanitizedDir["data/sanitized/"]
        end
    end

    ViteDev -->|REST API Requests| FastAPIApp
    FastAPIApp -->|TCP INSTREAM Socket| ClamAVContainer
    FastAPIApp --> SQLiteDB
    FastAPIApp --> SamplesDir & QuarantineDir & SanitizedDir
```
