export const currentUser = {
  name: "Arnav Sharma",
  role: "SecOps Lead",
  initials: "AV",
};

export const workspace = {
  org: "Review Workspace",
  project: "AI-Web-App",
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
