# Vibe Guard — React UI Blueprint (Review 1)

## 1. Purpose

Build **only the React frontend prototype** for Review 1 of:

**Vibe Guard — AI-Powered Secure Code Auditor for AI-Generated Applications**

The UI must visually communicate the complete intended product flow:

**Upload Code → Scan → Detect Vulnerabilities → AI Analysis → Recommended Fix → Security Report**

Use **mock/static data only**. Do not implement the backend, Semgrep, Bandit, database, authentication, real AI APIs, Docker, or AWS yet.

---

## 2. Product Goal

Vibe Guard helps developers identify security vulnerabilities in AI-generated/AI-assisted code and understand how to fix them.

The UI should make three things obvious:

1. **What is vulnerable?**
2. **Why is it vulnerable?**
3. **How should I fix it?**

---

## 3. Visual Direction

Create a polished cybersecurity/developer-tool interface.

### Style
- Dark modern developer dashboard
- Professional and minimal
- Strong visual hierarchy
- Subtle borders and depth
- Clean typography
- Good spacing
- Responsive
- Avoid excessive gradients, neon effects, or gaming aesthetics
- The result should look like a real SaaS security product

### Suggested visual language
- Dark background
- Neutral cards/panels
- Red/orange/yellow severity indicators
- Green for successful/fixed/safe states
- Monospace font for source code
- Simple security/scan icons

---

# 4. Application Structure

Create these frontend routes/pages:

```text
/
├── Dashboard
├── /scan
│   ├── New Scan
│   └── Scan Progress
├── /reports
│   └── Security Report
├── /history
└── /settings
```

Use React Router or an equivalent routing approach.

---

# 5. Global Layout

Use a persistent sidebar.

### Sidebar

Brand:

**Vibe Guard**

Subtitle:

**AI Code Security**

Navigation:

- Dashboard
- New Scan
- Reports
- Scan History
- Settings

Bottom:
- Review 1 Prototype
- Version 0.1

Main content should appear to the right of the sidebar.

---

# 6. Dashboard Page

## Header

Title:

**Security Overview**

Subtitle:

**AI-powered security analysis for your application code.**

Primary button:

**+ New Scan**

## Summary Cards

Show four cards:

### Security Score
**82/100**

Status:
**Good**

### Vulnerabilities
**7**

### High Severity
**2**

### Medium Severity
**3**

Optional:
Low Severity = **2**

## Vulnerability Distribution

Show a clean visual breakdown:

```text
Critical    0
High        2
Medium      3
Low         2
```

Use a chart/donut/bar visualization if it improves the UI.

## Vulnerability Categories

Show cards/list items for:

- SQL Injection — 2
- Cross-Site Scripting — 1
- Hardcoded Credentials — 2
- Command Injection — 1
- Path Traversal — 1

## Recent Scan

Project:
**AI-Web-App**

Status:
**Completed**

Security Score:
**82/100**

Vulnerabilities:
**7**

Button:
**View Report**

---

# 7. New Scan Page

Title:

**Start a Security Scan**

Subtitle:

**Upload your source code and identify security vulnerabilities before deployment.**

## Upload Area

Large drag-and-drop component:

**Drop your project here**

Text:

**Upload a ZIP file or supported source files**

Button:

**Browse Files**

After selecting a file, display:

```text
AI-Web-App.zip
24.6 KB
✓ Ready to scan
```

## Project Name

Input:

**Project Name**

Example:

`AI-Web-App`

## Scan Options

For prototype purposes show:

- Security Rules
- AI Contextual Analysis

Both can appear enabled/selected.

## Security Notice

Display:

**Your source code is analyzed statically and is not executed during scanning.**

## Primary Button

**Start Security Scan**

Clicking it should move to the mock scan-progress page.

---

# 8. Scan Progress Page

Title:

**Analyzing AI-Web-App**

Subtitle:

**Running security checks and preparing AI recommendations...**

Create a vertical or horizontal pipeline:

```text
✓ Code Uploaded
      ↓
✓ Static Analysis
      ↓
✓ Vulnerability Detection
      ↓
✓ AI Contextual Analysis
      ↓
● Generating Security Report
```

Show a progress indicator.

Example status messages:

- Reading source files...
- Running security rules...
- Checking for vulnerable patterns...
- Analyzing detected findings...
- Generating remediation recommendations...

After mock completion:

Button:

**View Security Report**

---

# 9. Security Report Page

This is the **most important Review 1 screen**.

Header:

**Security Report**

Project:

**AI-Web-App**

Status:

**Scan Completed**

## Security Score

Large:

**82/100**

Show a short interpretation:

**7 vulnerabilities detected**

Breakdown:

```text
Critical  0
High      2
Medium    3
Low       2
```

---

# 10. Vulnerability List

Display findings as cards or rows.

Example:

### SQL Injection
Badge:
**HIGH**

```text
backend/database.py : Line 42

query = "SELECT * FROM users WHERE id=" + user_id
```

Button:

**View Analysis**

Other mock findings:

### Cross-Site Scripting
**MEDIUM**

`frontend/components/Profile.jsx : Line 28`

### Hardcoded API Key
**HIGH**

`config/settings.py : Line 8`

### Command Injection
**HIGH**

`backend/utils.py : Line 64`

### Path Traversal
**MEDIUM**

`backend/files.py : Line 31`

---

# 11. Vulnerability Detail View

When the user selects a finding, show a detailed panel/page.

For the SQL Injection example:

## Vulnerability

**SQL Injection**

Severity:

**HIGH**

File:

`backend/database.py`

Line:

`42`

---

## Vulnerable Code

Use a syntax-highlighted code viewer.

```python
query = "SELECT * FROM users WHERE id=" + user_id
```

Highlight the vulnerable line.

---

## AI Analysis

### Why is this vulnerable?

User-controlled input is directly concatenated into an SQL query. An attacker may manipulate the input so that it changes the intended SQL statement.

### Potential Impact

An attacker may gain unauthorized access to database information or manipulate database operations.

---

## Recommended Solution

**Use parameterized queries/prepared statements instead of directly concatenating user input.**

---

## Suggested Secure Code

```python
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))
```

---

## AI Remediation Steps

Display numbered steps:

**1. Identify the user-controlled input.**

**2. Remove direct string concatenation from the SQL query.**

**3. Create a parameterized SQL statement.**

**4. Pass the user input separately as a query parameter.**

**5. Test the application using both normal and malicious inputs.**

---

# 12. AI Recommendation Component

Create a reusable component called:

**AI Security Recommendation**

It should visually communicate:

```text
Scanner Finding
      ↓
Relevant Code Context
      ↓
AI Analysis
      ↓
Secure Recommendation
      ↓
Corrected Code
```

Add a small label:

**AI-assisted remediation**

Do not make this look like a generic chatbot. It should look like a structured security-analysis result.

---

# 13. Code Comparison

Create a component allowing the user to switch between:

**Vulnerable Code | Suggested Fix**

Vulnerable:

```python
query = "SELECT * FROM users WHERE id=" + user_id
```

Secure:

```python
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))
```

Use clear labels.

---

# 14. Reports Page

Show previous reports as cards/table.

Columns:

```text
Project
Date
Score
Vulnerabilities
Status
Action
```

Example:

```text
AI-Web-App     Sep 8     82/100     7     Completed
Demo-API       Sep 7     91/100     3     Completed
Test-App       Sep 5     68/100     11    Completed
```

Button:

**View Report**

---

# 15. Scan History Page

Show historical scans with:

- Project name
- Date/time
- Security score
- Vulnerability count
- Highest severity
- Status

Allow selecting a previous scan to view its report.

---

# 16. Settings Page

For Review 1, keep this simple.

Sections:

### Scanner Settings
- Static analysis enabled
- Security rules enabled

### AI Analysis
- AI analysis enabled
- Model: `Demo AI Model`

### Appearance
- Theme: Dark

These are UI-only controls for now.

---

# 17. Mock Data

Create centralized mock data rather than hardcoding information throughout components.

Example data structure:

```js
{
  project: "AI-Web-App",
  score: 82,
  vulnerabilities: [
    {
      type: "SQL Injection",
      severity: "High",
      file: "backend/database.py",
      line: 42,
      code: "...",
      explanation: "...",
      impact: "...",
      recommendation: "...",
      fixedCode: "...",
      steps: [...]
    }
  ]
}
```

This should make future FastAPI integration easier.

---

# 18. Components

Prefer reusable components such as:

```text
Layout
Sidebar
Topbar
StatCard
SecurityScore
SeverityBadge
VulnerabilityCard
VulnerabilityList
CodeViewer
CodeComparison
AIRecommendation
ScanPipeline
UploadZone
ProgressIndicator
ReportSummary
```

Keep components modular so the mock data can later be replaced with API responses.

---

# 19. Review 1 Demo Flow

The supervisor demonstration should work like this:

```text
Dashboard
   ↓
Click "New Scan"
   ↓
Upload mock project
   ↓
Click "Start Security Scan"
   ↓
Scanning Progress
   ↓
Click "View Security Report"
   ↓
Show Security Score
   ↓
Show Vulnerabilities
   ↓
Open SQL Injection
   ↓
Show Vulnerable Code
   ↓
Show AI Explanation
   ↓
Show Recommended Solution
   ↓
Show Corrected Code
   ↓
Show Step-by-Step Remediation
```

This flow is the primary objective of Review 1.

---

# 20. What NOT to Build Yet

Do NOT implement:

- FastAPI backend
- Semgrep integration
- Bandit integration
- OpenAI API
- Gemini API
- PostgreSQL/SQLite
- Authentication
- User accounts
- Real code execution
- Docker
- AWS deployment
- Real vulnerability scanning

Everything should work using **frontend mock data**.

---

# 21. Technical Quality Requirements

- Use React
- Use clean component architecture
- Use responsive layouts
- Use reusable components
- Keep mock data centralized
- Use realistic security findings
- Add hover/focus states
- Add loading states
- Add empty states where appropriate
- Ensure navigation works
- Ensure buttons and demo flow work
- Avoid placeholder lorem ipsum
- Do not leave unfinished-looking screens

The final prototype should be presentation-ready for **Review 1**.

---

# 22. Definition of Done

Review 1 is successful if the supervisor can see:

1. A professional Vibe Guard dashboard.
2. A working mock code-upload flow.
3. A scanning/progress screen.
4. A security score.
5. Multiple vulnerability findings.
6. Severity for each vulnerability.
7. Vulnerable file and line.
8. Vulnerable code.
9. AI explanation.
10. Security impact.
11. Recommended solution.
12. Corrected code.
13. Step-by-step AI remediation.
14. Scan/report history.

The UI should make the future architecture obvious even though the backend and AI are not implemented yet.
