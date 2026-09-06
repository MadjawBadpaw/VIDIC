export const dashboardStats = [
  {
    title: "Total Emails",
    value: 324,
    change: "+12%",
    color: "blue",
  },
  {
    title: "High Risk Emails",
    value: 42,
    change: "+6 today",
    color: "red",
  },
  {
    title: "Safe Emails",
    value: 282,
    change: "87%",
    color: "green",
  },
  {
    title: "Threat Score",
    value: "82%",
    change: "Critical",
    color: "amber",
  },
];

export const threatTimeline = [
  { day: "Mon", threats: 5 },
  { day: "Tue", threats: 11 },
  { day: "Wed", threats: 7 },
  { day: "Thu", threats: 16 },
  { day: "Fri", threats: 10 },
  { day: "Sat", threats: 18 },
  { day: "Sun", threats: 13 },
];

export const recentInvestigations = [
  {
    id: "INV-1001",
    sender: "paypal-security.com",
    severity: "High",
    status: "Blocked",
  },
  {
    id: "INV-1002",
    sender: "microsoft-login.net",
    severity: "Critical",
    status: "Flagged",
  },
  {
    id: "INV-1003",
    sender: "amazon-support.io",
    severity: "Medium",
    status: "Review",
  },
  {
    id: "INV-1004",
    sender: "github-alert.org",
    severity: "High",
    status: "Blocked",
  },
];