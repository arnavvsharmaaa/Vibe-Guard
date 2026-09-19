export const currentUser = {
  name: "Arnav Sharma",
  role: "SecOps Lead",
  initials: "AV",
};

export const workspace = {
  org: "Review Workspace",
  project: "AI-Web-App",
};

function countBySeverity(vulnerabilities) {
  return vulnerabilities.reduce(
    (acc, item) => {
      const key = item.severity.toLowerCase();
      acc[key] = (acc[key] || 0) + 1;
      return acc;
    },
    { critical: 0, high: 0, medium: 0, low: 0 }
  );
}

function countByCategory(vulnerabilities) {
  return vulnerabilities.reduce((acc, item) => {
    acc[item.type] = (acc[item.type] || 0) + 1;
    return acc;
  }, {});
}

export const vulnerabilities = [
  {
    id: "vg-001",
    type: "SQL Injection",
    severity: "High",
    file: "backend/database.py",
    line: 42,
    cwe: "CWE-89",
    scanner: "Static analysis rule python.sql.injection — unsanitized string concatenation in SQL query.",
    code: `def get_user(user_id):
    connection = get_db()
    cursor = connection.cursor()
    query = "SELECT * FROM users WHERE id=" + user_id
    cursor.execute(query)
    return cursor.fetchone()`,
    highlightLines: [42],
    startLine: 39,
    language: "python",
    explanation:
      "User-controlled input is directly concatenated into an SQL query. An attacker may manipulate the input so that it changes the intended SQL statement, allowing them to read, modify, or delete records that the application did not intend to expose.",
    impact:
      "An attacker may gain unauthorized access to database information or manipulate database operations. In an AI-generated web app this often appears when a model writes a query builder using string addition instead of a parameterized API.",
    recommendation:
      "Use parameterized queries or prepared statements instead of directly concatenating user input into SQL.",
    fixedCode: `def get_user(user_id):
    connection = get_db()
    cursor = connection.cursor()
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    return cursor.fetchone()`,
    fixedHighlightLines: [42, 43],
    remediationSteps: [
      "Identify the user-controlled input.",
      "Remove direct string concatenation from the SQL query.",
      "Create a parameterized SQL statement.",
      "Pass the user input separately as a query parameter.",
      "Test the application using both normal and malicious inputs.",
    ],
  },
  {
    id: "vg-002",
    type: "Cross-Site Scripting",
    severity: "Medium",
    file: "frontend/components/Profile.jsx",
    line: 28,
    cwe: "CWE-79",
    scanner: "Static analysis rule javascript.react.xss — unescaped HTML rendering of user content.",
    code: `export function Profile({ user }) {
  return (
    <section className="profile">
      <h2>{user.name}</h2>
      <div dangerouslySetInnerHTML={{ __html: user.bio }} />
    </section>
  )
}`,
    highlightLines: [28],
    startLine: 24,
    language: "javascript",
    explanation:
      "The profile biography is injected into the DOM as raw HTML. If that field contains script or event-handler markup from a user or from an AI-generated sample payload, the browser will execute it in the victim's session.",
    impact:
      "An attacker can steal session tokens, impersonate the signed-in user, or deface the application from any page that renders this profile component.",
    recommendation:
      "Render user-controlled text as plain React children, or sanitize HTML with a strict allow-list if rich text is required.",
    fixedCode: `export function Profile({ user }) {
  return (
    <section className="profile">
      <h2>{user.name}</h2>
      <p>{user.bio}</p>
    </section>
  )
}`,
    fixedHighlightLines: [28],
    remediationSteps: [
      "Treat profile biography as untrusted input.",
      "Remove dangerouslySetInnerHTML for this field.",
      "Render the biography as text, not HTML.",
      "If HTML is required, sanitize it with a vetted library and a tight allow-list.",
      "Verify that script tags and event attributes no longer execute in the profile view.",
    ],
  },
  {
    id: "vg-003",
    type: "Hardcoded Credentials",
    severity: "High",
    file: "config/settings.py",
    line: 8,
    cwe: "CWE-798",
    scanner: "Static analysis rule python.secrets.hardcoded — live API key assigned in source.",
    code: `import os

DEBUG = True
DATABASE_URL = "postgres://app:app@localhost/app"

OPENAI_API_KEY = "sk-live-4f9c2e81b7a04d1e9c88"
STRIPE_SECRET = os.getenv("STRIPE_SECRET")`,
    highlightLines: [8],
    startLine: 3,
    language: "python",
    explanation:
      "A production-style API key is committed in application settings. Anyone with repository access, CI logs, or a copied AI-generated snippet can reuse that credential against the provider account.",
    impact:
      "Exposed keys can lead to unauthorized model usage, data exfiltration from connected services, unexpected billing, and persistence after the repository is made public.",
    recommendation:
      "Remove secrets from source control and load them from environment variables or a secret manager. Rotate the leaked key immediately.",
    fixedCode: `import os

DEBUG = False
DATABASE_URL = os.getenv("DATABASE_URL")

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
STRIPE_SECRET = os.getenv("STRIPE_SECRET")`,
    fixedHighlightLines: [8],
    remediationSteps: [
      "Revoke and rotate the hardcoded API key.",
      "Delete the secret from the repository and git history if it was committed.",
      "Load the key from an environment variable or secret manager.",
      "Add secret scanning to the project so new keys are caught before merge.",
      "Confirm local and CI environments receive the secret through a secure channel.",
    ],
  },
  {
    id: "vg-004",
    type: "Command Injection",
    severity: "Medium",
    file: "backend/utils.py",
    line: 64,
    cwe: "CWE-78",
    scanner: "Static analysis rule python.os.command-injection — shell=True with interpolated user input.",
    code: `import os

def preview_log(filename):
    base = "/var/app/logs"
    command = f"head -n 40 {base}/{filename}"
    return os.popen(command).read()`,
    highlightLines: [64],
    startLine: 61,
    language: "python",
    explanation:
      "The filename argument is interpolated into a shell command. Metacharacters such as `;`, `&&`, or `|` can cause the operating system to run additional commands with the application's privileges.",
    impact:
      "An attacker may execute arbitrary system commands, read files outside the log directory, or pivot from the application host.",
    recommendation:
      "Avoid the shell. Call process APIs with an argument list, and validate that the filename is a simple relative path inside the intended directory.",
    fixedCode: `import subprocess
from pathlib import Path

def preview_log(filename):
    base = Path("/var/app/logs")
    target = (base / filename).resolve()
    if not str(target).startswith(str(base.resolve())):
        raise ValueError("Invalid log file")
    result = subprocess.run(
        ["head", "-n", "40", str(target)],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout`,
    fixedHighlightLines: [64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74],
    remediationSteps: [
      "Stop interpolating user input into a shell string.",
      "Replace os.popen with subprocess.run and a fixed argument list.",
      "Resolve the path and confirm it stays inside the log directory.",
      "Reject unexpected characters in the filename.",
      "Test with payloads such as `; cat /etc/passwd` and confirm they are rejected.",
    ],
  },
  {
    id: "vg-005",
    type: "Path Traversal",
    severity: "Medium",
    file: "backend/files.py",
    line: 31,
    cwe: "CWE-22",
    scanner: "Static analysis rule python.path.traversal — user path joined without canonicalization.",
    code: `from flask import send_file

def download_artifact(name):
    storage = "/data/uploads"
    path = storage + "/" + name
    return send_file(path)`,
    highlightLines: [31],
    startLine: 28,
    language: "python",
    explanation:
      "The download handler concatenates a user-supplied name onto a storage directory. Sequences such as `../` can walk out of `/data/uploads` and read arbitrary files the process can access.",
    impact:
      "Sensitive files such as source, environment files, or SSH keys may be disclosed if they are readable by the application user.",
    recommendation:
      "Resolve the combined path and verify it remains inside the upload root before serving the file.",
    fixedCode: `from flask import send_file, abort
from pathlib import Path

def download_artifact(name):
    storage = Path("/data/uploads").resolve()
    path = (storage / name).resolve()
    if not str(path).startswith(str(storage)):
        abort(400)
    return send_file(path)`,
    fixedHighlightLines: [31, 32, 33, 34],
    remediationSteps: [
      "Treat the file name as untrusted path input.",
      "Build the path with a pathlib join, then resolve it.",
      "Reject any resolved path that does not start with the upload root.",
      "Prefer serving files by opaque IDs instead of raw names.",
      "Test with `../../config/settings.py` and confirm the request is blocked.",
    ],
  },
  {
    id: "vg-006",
    type: "SQL Injection",
    severity: "Low",
    file: "backend/search.py",
    line: 19,
    cwe: "CWE-89",
    scanner: "Static analysis rule python.sql.like-injection — LIKE clause built with string formatting.",
    code: `def search_products(term):
    sql = "SELECT name, price FROM products WHERE name LIKE '%{}%'".format(term)
    return db.query(sql)`,
    highlightLines: [19],
    startLine: 18,
    language: "python",
    explanation:
      "Search terms are interpolated into a LIKE clause. Even in a read-only helper, crafted input can alter the WHERE condition or append additional SQL if the driver allows multiple statements.",
    impact:
      "An attacker may dump product tables, infer schema details, or degrade performance with expensive predicates.",
    recommendation:
      "Keep the LIKE pattern in a bound parameter and escape wildcard characters in the user term.",
    fixedCode: `def search_products(term):
    pattern = "%" + term.replace("%", "\\%").replace("_", "\\_") + "%"
    sql = "SELECT name, price FROM products WHERE name LIKE ?"
    return db.query(sql, (pattern,))`,
    fixedHighlightLines: [19, 20, 21],
    remediationSteps: [
      "Remove `.format()` from the SQL string.",
      "Bind the search pattern as a query parameter.",
      "Escape LIKE wildcards in the user term.",
      "Limit result size to reduce denial-of-service risk.",
      "Re-run static rules to confirm the concatenation finding is gone.",
    ],
  },
  {
    id: "vg-007",
    type: "Hardcoded Credentials",
    severity: "Low",
    file: "config/db.py",
    line: 12,
    cwe: "CWE-259",
    scanner: "Static analysis rule python.secrets.password — default database password in source.",
    code: `DB_CONFIG = {
    "host": "localhost",
    "user": "app_user",
    "password": "admin123",
    "name": "vibeapp",
}`,
    highlightLines: [12],
    startLine: 9,
    language: "python",
    explanation:
      "A default database password is stored in configuration that AI assistants frequently copy into generated apps. Shared defaults are easy to guess and often survive into staging environments.",
    impact:
      "Local or poorly firewalled databases can be accessed by anyone who knows the default, enabling data tampering even when the high-severity API key is rotated.",
    recommendation:
      "Read database credentials from the environment and refuse to start if they are missing in non-development modes.",
    fixedCode: `import os

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "name": os.getenv("DB_NAME", "vibeapp"),
}`,
    fixedHighlightLines: [12, 13, 14],
    remediationSteps: [
      "Remove the plaintext password from source.",
      "Supply DB_PASSWORD through the environment.",
      "Fail closed if the password is absent outside local development.",
      "Use a unique password per environment.",
      "Confirm no other generated config files still contain admin123.",
    ],
  },
];

const primarySeverity = countBySeverity(vulnerabilities);
const primaryCategories = countByCategory(vulnerabilities);

export const primaryReport = {
  id: "rep-ai-web-app",
  project: "AI-Web-App",
  date: "Sep 8",
  datetime: "Sep 8, 2026 · 13:12",
  score: 82,
  scoreLabel: "Good",
  status: "Completed",
  findings: 7,
  highestSeverity: "High",
  engine: "Static rules + Demo AI Model",
  filesAnalyzed: 38,
  vulnerabilities,
  severity: primarySeverity,
  categories: primaryCategories,
};

export const reports = [
  primaryReport,
  {
    id: "rep-demo-api",
    project: "Demo-API",
    date: "Sep 7",
    datetime: "Sep 7, 2026 · 18:44",
    score: 91,
    scoreLabel: "Strong",
    status: "Completed",
    findings: 3,
    highestSeverity: "Medium",
    engine: "Static rules + Demo AI Model",
    filesAnalyzed: 12,
    severity: { critical: 0, high: 0, medium: 2, low: 1 },
    categories: {
      "Cross-Site Scripting": 1,
      "Missing Rate Limiting": 1,
      "Verbose Error Message": 1,
    },
    vulnerabilities: [
      {
        id: "demo-001",
        type: "Cross-Site Scripting",
        severity: "Medium",
        file: "src/views/error.js",
        line: 14,
        cwe: "CWE-79",
        scanner: "Static analysis rule javascript.express.xss — response writes unsanitized error text.",
        code: `app.use((err, req, res, next) => {
  res.status(500).send("<pre>" + err.message + "</pre>")
})`,
        highlightLines: [14],
        startLine: 13,
        language: "javascript",
        explanation:
          "Error messages are written into HTML without encoding. If an attacker can trigger an error that echoes request data, the message can carry a script payload.",
        impact:
          "Reflected script execution in the API explorer or any HTML error page sharing this handler.",
        recommendation: "Return JSON errors or encode HTML entities before rendering.",
        fixedCode: `app.use((err, req, res, next) => {
  res.status(500).json({ error: "Internal error" })
})`,
        fixedHighlightLines: [14],
        remediationSteps: [
          "Stop sending raw err.message as HTML.",
          "Use a JSON error contract for the API.",
          "Log the detailed message server-side only.",
          "Confirm the explorer no longer renders HTML from errors.",
          "Re-scan the error middleware.",
        ],
      },
      {
        id: "demo-002",
        type: "Missing Rate Limiting",
        severity: "Medium",
        file: "src/routes/auth.js",
        line: 22,
        cwe: "CWE-307",
        scanner: "Static analysis rule api.auth.no-rate-limit — login route has no throttle.",
        code: `router.post("/login", async (req, res) => {
  const user = await users.findByEmail(req.body.email)
  if (user && user.password === req.body.password) {
    return res.json({ token: sign(user) })
  }
  return res.status(401).json({ error: "invalid" })
})`,
        highlightLines: [22],
        startLine: 22,
        language: "javascript",
        explanation:
          "The login endpoint accepts unlimited attempts. Automated guessing can recover weak credentials generated into demo users.",
        impact:
          "Account takeover of seeded users and increased load on the authentication service.",
        recommendation: "Apply a per-IP and per-account rate limit on authentication routes.",
        fixedCode: `router.post("/login", loginLimiter, async (req, res) => {
  const user = await users.findByEmail(req.body.email)
  if (user && await verifyPassword(req.body.password, user.hash)) {
    return res.json({ token: sign(user) })
  }
  return res.status(401).json({ error: "invalid" })
})`,
        fixedHighlightLines: [22],
        remediationSteps: [
          "Add a rate limiter to /login.",
          "Lock or delay after repeated failures.",
          "Store password hashes, not plaintext.",
          "Monitor authentication failure spikes.",
          "Verify limiter behavior with a burst of requests in a test environment.",
        ],
      },
      {
        id: "demo-003",
        type: "Verbose Error Message",
        severity: "Low",
        file: "src/db.js",
        line: 40,
        cwe: "CWE-209",
        scanner: "Static analysis rule node.errors.stack-leak — stack traces returned to clients.",
        code: `catch (error) {
  res.status(500).send(error.stack)
}`,
        highlightLines: [40],
        startLine: 39,
        language: "javascript",
        explanation:
          "Stack traces reveal file paths and library versions. Attackers use that layout information to target known issues.",
        impact:
          "Information disclosure that makes follow-on attacks against Demo-API easier.",
        recommendation: "Return a generic error identifier and keep stacks in server logs.",
        fixedCode: `catch (error) {
  logger.error(error)
  res.status(500).json({ errorId: "db_query_failed" })
}`,
        fixedHighlightLines: [40, 41],
        remediationSteps: [
          "Remove error.stack from the HTTP response.",
          "Log the stack internally.",
          "Return a stable error identifier.",
          "Disable detailed errors in production configuration.",
          "Confirm clients no longer receive filesystem paths.",
        ],
      },
    ],
  },
  {
    id: "rep-test-app",
    project: "Test-App",
    date: "Sep 5",
    datetime: "Sep 5, 2026 · 09:03",
    score: 68,
    scoreLabel: "Needs work",
    status: "Completed",
    findings: 11,
    highestSeverity: "High",
    engine: "Static rules + Demo AI Model",
    filesAnalyzed: 54,
    severity: { critical: 0, high: 4, medium: 4, low: 3 },
    categories: {
      "SQL Injection": 2,
      "Cross-Site Scripting": 2,
      "Hardcoded Credentials": 2,
      "Command Injection": 1,
      "Path Traversal": 2,
      "Insecure Cookie": 2,
    },
    vulnerabilities: [
      {
        id: "test-001",
        type: "SQL Injection",
        severity: "High",
        file: "server/models.py",
        line: 88,
        cwe: "CWE-89",
        scanner: "Static analysis rule python.sql.injection — f-string query construction.",
        code: `def find_order(order_id):
    return db.execute(f"SELECT * FROM orders WHERE id = {order_id}")`,
        highlightLines: [88],
        startLine: 87,
        language: "python",
        explanation:
          "Order identifiers are interpolated into SQL with an f-string. Numeric-looking fields are still injectable if the driver concatenates them as text.",
        impact:
          "Unauthorized reads of other customers' orders and potential modification of fulfillment records.",
        recommendation: "Use bound parameters for every dynamic value in SQL.",
        fixedCode: `def find_order(order_id):
    return db.execute("SELECT * FROM orders WHERE id = ?", (order_id,))`,
        fixedHighlightLines: [88],
        remediationSteps: [
          "Replace the f-string with a parameter placeholder.",
          "Pass order_id in the execute argument tuple.",
          "Validate that order_id is the expected type.",
          "Add tests for unexpected SQL metacharacters.",
          "Re-scan models.py.",
        ],
      },
    ],
  },
];

export const scanHistory = [
  {
    id: "hist-1",
    reportId: "rep-ai-web-app",
    project: "AI-Web-App",
    datetime: "Sep 8, 2026 · 13:12",
    score: 82,
    findings: 7,
    highestSeverity: "High",
    status: "Completed",
  },
  {
    id: "hist-2",
    reportId: "rep-demo-api",
    project: "Demo-API",
    datetime: "Sep 7, 2026 · 18:44",
    score: 91,
    findings: 3,
    highestSeverity: "Medium",
    status: "Completed",
  },
  {
    id: "hist-3",
    reportId: "rep-test-app",
    project: "Test-App",
    datetime: "Sep 5, 2026 · 09:03",
    score: 68,
    findings: 11,
    highestSeverity: "High",
    status: "Completed",
  },
];

export const dashboardSummary = {
  score: primaryReport.score,
  scoreLabel: primaryReport.scoreLabel,
  total: primaryReport.findings,
  severity: primaryReport.severity,
  categories: primaryReport.categories,
  recentScan: {
    project: primaryReport.project,
    status: primaryReport.status,
    score: primaryReport.score,
    findings: primaryReport.findings,
    reportId: primaryReport.id,
  },
};

export const mockUpload = {
  name: "AI-Web-App.zip",
  size: "24.6 KB",
  status: "Ready to scan",
};

export const scanStages = [
  {
    id: "upload",
    title: "Code Uploaded",
    message: "Reading source files...",
  },
  {
    id: "static",
    title: "Static Analysis",
    message: "Running security rules...",
  },
  {
    id: "detect",
    title: "Vulnerability Detection",
    message: "Checking for vulnerable patterns...",
  },
  {
    id: "ai",
    title: "AI Contextual Analysis",
    message: "Analyzing detected findings...",
  },
  {
    id: "report",
    title: "Generating Security Report",
    message: "Generating remediation recommendations...",
  },
];

export function getReportById(id) {
  return reports.find((report) => report.id === id) || primaryReport;
}

export function getFinding(reportId, findingId) {
  const report = getReportById(reportId);
  return report.vulnerabilities.find((item) => item.id === findingId) || report.vulnerabilities[0];
}
