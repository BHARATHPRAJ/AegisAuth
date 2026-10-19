const form = document.querySelector("#login-form");
const startedAt = performance.now();
const csrfToken = form?.elements.namedItem("csrf_token")?.value;

if (form && csrfToken) {
  const telemetry = {
    webdriver: navigator.webdriver === true,
    plugin_count: navigator.plugins?.length ?? 0,
    interaction_ms: null,
    interaction_events: 0,
    viewport_width: window.innerWidth,
    viewport_height: window.innerHeight,
  };
  let interacted = false;
  const markInteraction = () => {
    if (!interacted) {
      telemetry.interaction_ms = Math.round(performance.now() - startedAt);
      telemetry.interaction_events += 1;
      interacted = true;
    }
  };

  document.addEventListener("pointerdown", markInteraction, { once: true });
  document.addEventListener("keydown", markInteraction, { once: true });
  form.addEventListener("input", markInteraction, { once: true });
  form.addEventListener("change", markInteraction, { once: true });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    markInteraction();
    try {
      await fetch("/auth/telemetry", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
        body: JSON.stringify(telemetry),
      });
    } finally {
      form.submit();
    }
  });
}