const metric = document.querySelector("#blocked-bot-attempts");
const status = document.querySelector("#metric-status");
let requestInFlight = false;

async function refreshMetric() {
  if (requestInFlight) return;
  requestInFlight = true;
  try {
    const response = await fetch("/api/metrics/blocked-bot-attempts", { cache: "no-store" });
    if (!response.ok) throw new Error("Metric request failed");
    const result = await response.json();
    if (typeof result.blocked_bot_attempts !== "number") throw new Error("Metric unavailable");
    metric.textContent = String(result.blocked_bot_attempts);
    metric.classList.remove("activity-unavailable");
    status.textContent = "Live";
  } catch {
    metric.textContent = "Unavailable";
    metric.classList.add("activity-unavailable");
    status.textContent = "Counter unavailable";
  } finally {
    requestInFlight = false;
  }
}

window.setInterval(refreshMetric, 2000);
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) refreshMetric();
});