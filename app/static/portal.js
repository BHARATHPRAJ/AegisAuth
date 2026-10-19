const metric = document.querySelector("#blocked-bot-attempts");
const historyNode = document.querySelector("#initial-history");
const chartStatus = document.querySelector("#chart-status");
const chart = document.querySelector("#attempts-chart");
const simulationForm = document.querySelector("#simulation-form");
const batchForm = document.querySelector("#batch-form");
const traceOutput = document.querySelector("#request-trace");
const traceStatus = document.querySelector("#trace-status");
let requestInFlight = false;

function appendTrace(message, status = "info") {
  const entry = document.createElement("li");
  entry.className = "trace-entry";
  entry.dataset.status = status;

  const time = document.createElement("time");
  time.textContent = new Date().toLocaleTimeString([], { hour12: false });
  const marker = document.createElement("span");
  marker.className = "trace-marker";
  marker.setAttribute("aria-hidden", "true");
  marker.textContent = status === "blocked" || status === "error" ? "!" : "›";
  const text = document.createElement("span");
  text.textContent = message;

  entry.append(time, marker, text);
  traceOutput.append(entry);
  traceOutput.scrollTop = traceOutput.scrollHeight;
}

function beginTrace(endpoint, details) {
  traceOutput.replaceChildren();
  traceStatus.textContent = "Processing";
  traceStatus.dataset.state = "running";
  appendTrace(`POST ${endpoint}`, "running");
  appendTrace(details);
}

function appendBackendTrace(trace) {
  if (!Array.isArray(trace)) {
    appendTrace("Backend response did not include processing trace data.", "error");
    return;
  }
  for (const item of trace) {
    appendTrace(`[backend/${item.stage}] ${item.message}`, item.status);
  }
}

function finishTrace(state, label) {
  traceStatus.textContent = label;
  traceStatus.dataset.state = state;
}

const scenarios = {
  human: { webdriver: false, fast_submit: false, no_interaction: false, no_plugins: false, unusual_viewport: false, honeypot_filled: false },
  headless: { webdriver: true, fast_submit: true, no_interaction: true, no_plugins: true, unusual_viewport: true, honeypot_filled: false },
  "form-filler": { webdriver: false, fast_submit: true, no_interaction: true, no_plugins: false, unusual_viewport: false, honeypot_filled: true },
};

function applyScenario(name) {
  document.querySelectorAll(".scenario-button").forEach((button) => {
    button.classList.toggle("active", button.dataset.scenario === name);
  });
  if (name === "custom") return;
  for (const [signal, enabled] of Object.entries(scenarios[name])) {
    simulationForm.elements.namedItem(signal).checked = enabled;
  }
}

document.querySelectorAll(".scenario-button").forEach((button) => {
  button.addEventListener("click", () => applyScenario(button.dataset.scenario));
});

function simulationTelemetry() {
  const form = new FormData(simulationForm);
  return {
    webdriver: form.has("webdriver"),
    interaction_ms: form.has("fast_submit") ? 20 : 800,
    interaction_events: form.has("no_interaction") ? 0 : 2,
    plugin_count: form.has("no_plugins") ? 0 : 3,
    viewport_width: form.has("unusual_viewport") ? 0 : 1365,
    viewport_height: form.has("unusual_viewport") ? 0 : 768,
    honeypot_filled: form.has("honeypot_filled"),
  };
}

simulationForm.addEventListener("change", () => {
  document.querySelectorAll(".scenario-button").forEach((button) => {
    button.classList.toggle("active", button.dataset.scenario === "custom");
  });
});

simulationForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = simulationForm.querySelector("button[type=submit]");
  const telemetry = simulationTelemetry();
  button.disabled = true;
  beginTrace("/api/simulate/browser-risk", `Sending telemetry payload (${Object.keys(telemetry).length} fields).`);
  try {
    const response = await fetch("/api/simulate/browser-risk", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(telemetry),
    });
    const result = await response.json();
    appendTrace(`HTTP ${response.status} ${response.statusText}`, response.ok ? "ok" : "error");
    appendBackendTrace(result.trace);
    if (!response.ok) throw new Error(`Simulation failed with HTTP ${response.status}.`);
    document.querySelector("#simulation-score").innerHTML = `${result.score}<span>/100</span>`;
    document.querySelector("#simulation-level").textContent = `${result.level[0].toUpperCase()}${result.level.slice(1)} risk`;
    document.querySelector("#result-heading").textContent = result.decision;
    document.querySelector("#risk-fill").style.width = `${result.score}%`;
    document.querySelector(".risk-track").setAttribute("aria-valuenow", result.score);
    document.querySelector("#simulation-reasons").replaceChildren(
      ...result.signals.map((signal) => {
        const item = document.createElement("li");
        item.textContent = signal;
        return item;
      }),
    );
    const policyStatus = result.trace?.find((item) => item.stage === "policy")?.status;
    const blocked = policyStatus === "blocked";
    finishTrace(blocked ? "blocked" : "complete", blocked ? "Blocked" : "Complete");
  } catch (error) {
    appendTrace(error instanceof Error ? error.message : "Simulation request failed.", "error");
    finishTrace("error", "Failed");
    document.querySelector("#result-heading").textContent = "Simulation unavailable";
  } finally {
    button.disabled = false;
  }
});

function drawChart(history, simulated = false) {
  const prefix = simulated ? "#simulation-chart-" : "#chart-";
  const grid = document.querySelector(`${prefix}grid`);
  const area = document.querySelector(`${prefix}area`);
  const line = document.querySelector(`${prefix}line`);
  const points = document.querySelector(`${prefix}points`);
  const labels = document.querySelector(`${prefix}labels`);
  const chartElement = simulated ? document.querySelector("#simulation-chart") : chart;
  const statusElement = document.querySelector(simulated ? "#simulation-chart-status" : "#chart-status");
  const namespace = "http://www.w3.org/2000/svg";
  const width = 720;
  const height = 250;
  const left = 38;
  const right = 12;
  const top = 16;
  const bottom = 34;
  const plotWidth = width - left - right;
  const plotHeight = height - top - bottom;
  const values = history.map((item) => item.count);
  const maximum = Math.max(4, Math.ceil(Math.max(0, ...values) / 4) * 4);
  const path = history.map((item, index) => {
    const x = left + (index / Math.max(1, history.length - 1)) * plotWidth;
    const y = top + plotHeight - (item.count / maximum) * plotHeight;
    return [x, y];
  });
  const create = (name, attributes, text) => {
    const element = document.createElementNS(namespace, name);
    for (const [key, value] of Object.entries(attributes)) element.setAttribute(key, value);
    if (text !== undefined) element.textContent = text;
    return element;
  };

  grid.replaceChildren();
  area.replaceChildren();
  line.replaceChildren();
  points.replaceChildren();
  labels.replaceChildren();

  for (let tick = 0; tick <= 4; tick += 1) {
    const y = top + (tick / 4) * plotHeight;
    const value = maximum * (1 - tick / 4);
    grid.append(create("line", { x1: left, x2: width - right, y1: y, y2: y }));
    labels.append(create("text", { x: left - 10, y: y + 4, "text-anchor": "end" }, String(value)));
  }

  const linePath = path.map(([x, y], index) => `${index === 0 ? "M" : "L"}${x},${y}`).join(" ");
  line.setAttribute("d", linePath);
  area.setAttribute(
    "d",
    `${linePath} L${path.at(-1)[0]},${top + plotHeight} L${path[0][0]},${top + plotHeight} Z`,
  );

  for (const index of [0, 6, 12, 18, history.length - 1]) {
    const item = history[index];
    const x = path[index][0];
    const hour = new Date(item.timestamp * 1000).toLocaleTimeString([], { hour: "numeric" });
    labels.append(create("text", { x, y: height - 8, "text-anchor": index === 0 ? "start" : "middle" }, hour));
  }

  path.forEach(([x, y], index) => {
    if (history[index].count > 0) {
      const point = create("circle", { cx: x, cy: y, r: 3.5 });
      const hour = new Date(history[index].timestamp * 1000).toLocaleString();
      point.append(create("title", {}, `${hour}: ${history[index].count} blocked`));
      points.append(point);
    }
  });
  const chartLabel = simulated ? "Simulated requests" : "Blocked bot attempts";
  chartElement.setAttribute("aria-label", `${chartLabel} by hour. Total in the chart: ${values.reduce((sum, value) => sum + value, 0)}.`);
  statusElement.textContent = "Updated just now";
}

function showUnavailable() {
  metric.textContent = "Unavailable";
  metric.classList.add("activity-unavailable");
  chartStatus.textContent = "Activity unavailable";
}

async function refreshDashboard() {
  if (requestInFlight) return;
  requestInFlight = true;
  try {
    const response = await fetch("/api/metrics/blocked-bot-attempts/history", { cache: "no-store" });
    if (!response.ok) throw new Error("Metric request failed");
    const result = await response.json();
    if (!Array.isArray(result.history)) throw new Error("Metric unavailable");
    const totalResponse = await fetch("/api/metrics/blocked-bot-attempts", { cache: "no-store" });
    if (!totalResponse.ok) throw new Error("Total request failed");
    const totalResult = await totalResponse.json();
    if (typeof totalResult.blocked_bot_attempts !== "number") throw new Error("Total unavailable");
    const simulationTotalResponse = await fetch("/api/metrics/simulated-requests", { cache: "no-store" });
    if (!simulationTotalResponse.ok) throw new Error("Simulation total request failed");
    const simulationTotalResult = await simulationTotalResponse.json();
    const simulationMetric = document.querySelector("#simulated-requests");
    if (typeof simulationTotalResult.simulated_requests !== "number") {
      simulationMetric.textContent = "Unavailable";
      simulationMetric.classList.add("activity-unavailable");
    } else {
      simulationMetric.textContent = String(simulationTotalResult.simulated_requests);
      simulationMetric.classList.remove("activity-unavailable");
    }
    metric.textContent = String(totalResult.blocked_bot_attempts);
    metric.classList.remove("activity-unavailable");
    drawChart(result.history);
    drawChart(result.simulation_history, true);
  } catch {
    showUnavailable();
  } finally {
    requestInFlight = false;
  }
}

function renderBatchResults(results) {
  const list = document.querySelector("#batch-results");
  list.replaceChildren();
  for (const result of results) {
    const row = document.createElement("li");
    row.className = "batch-result";

    const index = document.createElement("span");
    index.className = "batch-result-index";
    index.textContent = `#${result.request}`;

    const profile = document.createElement("span");
    profile.className = "batch-result-profile";
    profile.textContent = result.profile.replaceAll("_", " ");

    const score = document.createElement("span");
    score.className = "batch-result-score";
    score.textContent = `${result.score}/100`;

    const state = document.createElement("span");
    state.className = `batch-result-state${result.blocked ? " blocked" : ""}`;
    state.textContent = result.blocked ? "Blocked" : "Allowed";

    const signals = document.createElement("span");
    signals.className = "batch-result-signals";
    signals.textContent = result.signals.join(" ");

    row.append(index, profile, score, state, signals);
    list.append(row);
  }
}

batchForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const submitButton = batchForm.querySelector("button[type=submit]");
  const status = document.querySelector("#batch-status");
  const resultsList = document.querySelector("#batch-results");
  const profile = batchForm.elements.namedItem("profile").value;
  const count = Number(batchForm.elements.namedItem("count").value);
  submitButton.disabled = true;
  status.textContent = "Firing simulated requests…";
  resultsList.replaceChildren();
  beginTrace("/api/simulate/batch", `Submitting profile=${profile}, requests=${count}.`);
  try {
    const response = await fetch("/api/simulate/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        count,
        profile,
        custom_signals: profile === "custom" ? simulationTelemetry() : null,
      }),
    });
    const result = await response.json();
    appendTrace(`HTTP ${response.status} ${response.statusText}`, response.ok ? "ok" : "error");
    appendBackendTrace(result.trace);
    if (!response.ok) throw new Error(response.status === 429 ? "Rate limit reached. Try again shortly." : `Batch failed with HTTP ${response.status}.`);
    status.textContent = `Handled ${result.request_count} requests · ${result.blocked_count} blocked · ${result.allowed_count} allowed`;
    renderBatchResults(result.results);
    finishTrace(result.blocked_count > 0 ? "blocked" : "complete", "Complete");
    await refreshDashboard();
  } catch (error) {
    status.textContent = error instanceof Error ? error.message : "Batch failed";
    appendTrace(error instanceof Error ? error.message : "Batch request failed.", "error");
    finishTrace("error", "Failed");
  } finally {
    submitButton.disabled = false;
  }
});

try {
  const initialHistory = JSON.parse(historyNode.textContent);
  const initialSimulationHistory = JSON.parse(document.querySelector("#initial-simulation-history").textContent);
  if (Array.isArray(initialHistory)) drawChart(initialHistory);
  else showUnavailable();
  if (Array.isArray(initialSimulationHistory)) drawChart(initialSimulationHistory, true);
} catch {
  showUnavailable();
}

window.setInterval(refreshDashboard, 2000);
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) refreshDashboard();
});