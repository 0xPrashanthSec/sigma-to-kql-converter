
# Sigma → KQL Converter
**Production-ready detection-engineering toolkit for the Elastic Stack**
***
## ⚡ What It Does
Sigma → KQL Converter ingests any Sigma rule (YAML) and instantly produces a clean Kibana Query Language (KQL) query that is:

* **ECS-compliant** – 100 + Elastic Common Schema mappings, including full PowerShell, PE, network, file, registry, cloud and container field support.
* **Production-ready** – no HTML artefacts, no `[object Object]` errors, and syntax-validated output that drops straight into Discover, Detection Rules or Security Dashboards.
* **Rule-aware** – understands complex constructs (`all of selection_*`, `1 of selection_*`, `contains|all`, nested arrays) and preserves logical intent.
* **Visibility-rich** – generates a field-mapping report, conversion statistics, and highlights any unmapped fields for follow-up tuning.
***

## ✨ Key Features

| Category | Highlights |
| :-- | :-- |
| **Mappings** | 100 + ECS fields out-of-the-box; Payload → `powershell.command.script_block_text`, OriginalFileName → `process.pe.original_file_name`, and more. |
| **Executables** | Detects all PowerShell variants (`powershell.exe`, `pwsh.exe`, `powershell_ise.exe`, `ServerRemoteHost.exe`, `wsmprovhost.exe`). |
| **UI/UX** | Responsive dark/light theme, live YAML validation, copy-to-clipboard, .kql download, ECS reference side-panel, conversion dashboard. |
| **Developer Friendly** | Single-page app (HTML + CSS + Vanilla JS) – zero build step, host from any static web server or GitHub Pages. |
| **Stats \& Reporting** | See total, mapped and unmapped fields, mapping rate %, and query length at a glance. |

***
## 🚀 Quick Start

```bash
# Clone and run locally
git clone https://github.com/<your-org>/sigma-to-kql-converter.git
cd sigma-to-kql-converter
python3 -m http.server 8000
# Open http://localhost:8000
```
Or deploy to GitHub Pages:
1. Fork this repo.
2. GitHub → Settings → Pages → Source: **main** ⟶ **/ (root)**.
3. Wait 1-2 minutes – your tool is live at
`https://<your-github-id>.github.io/sigma-to-kql-converter/`.
***
## 🛠️ How to Use

1. Paste a Sigma rule, upload a `.yml`, or select a built-in sample.
2. The converter validates YAML, maps fields, resolves conditions, and displays a ready-to-paste KQL query.
3. Copy or download the query. Review the mapping stats to spot optimisation opportunities.
4. Drop the KQL into Kibana Discover, create a Detection Rule, or embed in dashboards.
***
## 🔍 Under the Hood
* **AdvancedSigmaParser** – recursive descent parser that tokenises selection blocks, resolves modifiers, expands arrays, and assembles boolean logic.
* **FieldMappingEngine** – JSON dictionary of Sigma → ECS translations with fast look-ups and fallbacks.
* **UIManager** – debounced real-time conversion, toast notifications, theme persistence, and dynamic panels (ECS Reference \& Stats).
* **Zero Dependencies** – pure ES 2020; 3 files (<150 kB) for minimal attack surface and instant loading.

***
## 🗺️ Roadmap
1. **Bulk Conversion** – drag-and-drop a folder of rules, zip of ATT\&CK technique packs, or an entire Sigma repo.
2. **REST API Mode** – Docker image exposing `/convert` for CI pipelines (GitHub Actions, GitLab, Jenkins).
3. **Other Back-ends** – output to:
    * Elastic **ES|QL**
    * Microsoft Sentinel **Kusto/KQL**
    * Splunk **SPL** with ECS macros
    * CrowdStrike Humio **HQL**
4. **Correlation Builder** – visual join designer for cross-data-set detections (process + network + DNS).
5. **Auto-Tuning** – query cost estimator that suggests filters to minimise shard hits.
6. **IDE Extension** – VS Code plugin: right-click → “Convert Sigma to KQL”.

***
## 📦 Contributing
Pull requests are welcome for:
* New field mappings
* Optimised parsing algorithms
* Additional sample rules
* UI/UX polish
* Internationalisation (i18n)

Please open an issue first to discuss major changes.
***
## 📝 License
MIT – free to use, modify, distribute.
***

Created by **@prashanthblogs**

