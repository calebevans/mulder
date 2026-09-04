"use strict";

const eventState = document.getElementById("event-state");
const eventList = document.getElementById("run-events");
const eventUrl = document.body.dataset.eventUrl;
const eventKinds = [
  "investigation_started", "investigation_finished", "phase_changed",
  "extraction_progress", "task_registered", "task_state", "tasks_cleared",
  "tool_observed", "finding_observed", "session_metrics", "phase_result",
  "gate_result", "info"
];

if (eventState && eventList && eventUrl) {
  const source = new EventSource(eventUrl);
  for (const kind of eventKinds) {
    source.addEventListener(kind, (message) => {
      let event;
      try { event = JSON.parse(message.data); } catch (_error) { return; }
      const item = document.createElement("li");
      const detail = event.message || event.title || event.tool || event.phase || event.status || "";
      item.textContent = `#${event.sequence} ${event.kind}${detail ? ` — ${detail}` : ""}`;
      eventList.append(item);
      while (eventList.children.length > 100) { eventList.firstElementChild.remove(); }
      eventState.textContent = `Live · last durable event #${event.sequence}`;
    });
  }
  source.addEventListener("open", () => { eventState.textContent = "Live · audit event stream connected"; });
  source.addEventListener("error", () => { eventState.textContent = "Reconnecting from Last-Event-ID…"; });
}
