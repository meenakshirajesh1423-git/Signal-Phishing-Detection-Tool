const samples = {
  invoice: {
    message: "From: Accounts Payable <billing@acme-invoice-check.example>\nSubject: Final notice: invoice payment overdue\n\nYour account will be suspended today unless the attached invoice is paid immediately. Verify your company login and confirm your password and one-time code to avoid a late fee.\n\nReview invoice: http://acme-invoice-check.example/account/verify",
    url: "http://acme-invoice-check.example/account/verify",
    clues: { senderName: "Accounts Payable", senderDomain: "billing@acme-invoice-check.example", displayedLink: "Review invoice", visualClue: "Unexpected payment request" }
  },
  delivery: {
    message: "Parcel Service: We could not deliver your package. A small redelivery fee is required today. Confirm your address and card details to reschedule: http://parcel-redelivery.example/fee",
    url: "http://parcel-redelivery.example/fee",
    clues: { senderName: "Parcel Service", senderDomain: "not provided", displayedLink: "Confirm your address", visualClue: "Unexpected fee request" }
  },
  normal: {
    message: "From: Library <updates@library.example>\nSubject: Your reserved book is ready\n\nThe book you reserved is ready for pickup at the main desk through Friday. No payment or account action is needed.",
    url: "",
    clues: { senderName: "Library", senderDomain: "updates@library.example", displayedLink: "", visualClue: "" }
  }
};

const scenarios = [
  {
    sender: "Northstar Delivery", address: "dispatch@northstar-delivery.example",
    subject: "Action needed: confirm your delivery",
    body: "Hello,\n\nWe couldn't complete delivery because your address needs confirmation. Use the link below within 12 hours to avoid returning your parcel.\n\nThank you,\nNorthstar Delivery",
    url: "northstar-delivery.example/confirm",
    lesson: "A deadline and delivery pressure try to hurry you. The sender and link are fictional, but in real life, open the carrier's official app or type its known address yourself. Don't use an unexpected message link."
  },
  {
    sender: "Workspace Support", address: "security@workspace-reset.example",
    subject: "Your mailbox will be deactivated",
    body: "Your mailbox has exceeded its storage limit. Sign in today to keep receiving messages. Do not reply to this automated notice.",
    url: "workspace-reset.example/keep-mail",
    lesson: "A threat to cut off an important service and a push to sign in are common pressure tactics. Visit your organization's help portal using a bookmark or ask IT through a known channel."
  },
  {
    sender: "Benefits Desk", address: "rewards@benefits-update.example",
    subject: "Your annual benefit is waiting",
    body: "A benefit is ready for you. Confirm your identity and payment details before the end of the day to claim it. This offer is available for a limited time.",
    url: "benefits-update.example/claim",
    lesson: "An unexpected reward, a deadline, and a request for payment details are warning signs. Never provide passwords, payment details, or one-time codes from a message link."
  }
];

const quizQuestions = [
  {
    sender: "Library Updates · updates@library.example",
    subject: "Your reserved book is ready",
    body: "The book you reserved is ready for pickup at the main desk through Friday. No payment or account action is needed.",
    answer: "legitimate",
    indicators: "Expected context, no demand for sensitive information, and no link asking you to sign in.",
    explanation: "This looks routine based on the details shown. Still, a familiar-looking sender alone is not proof; be alert if the context changes."
  },
  {
    sender: "Payroll Desk · payroll-review@staff-payroll.example",
    subject: "Urgent: salary deposit on hold",
    body: "Your salary deposit will be stopped today. Reply with your account password and one-time code so we can restore payroll.",
    answer: "phishing",
    indicators: "Urgency, threat of financial loss, and a request for a password and one-time code.",
    explanation: "A legitimate payroll team should not ask for your password or one-time code. Contact payroll through a directory or channel you already trust."
  },
  {
    sender: "Cloud Documents · share@document-notice.example",
    subject: "A document was shared with you",
    body: "A colleague shared “Quarterly plan” with you. Sign in to view it: https://document-notice.example/open",
    answer: "suspicious",
    indicators: "Unexpected sign-in request and a sender domain that is not established by the message.",
    explanation: "The message could be real or fake from this text alone. Check with the colleague or open your organization's document service directly rather than using the message link."
  },
  {
    sender: "Community Center · events@community.example",
    subject: "Saturday garden meetup",
    body: "The garden meetup starts at 10 a.m. Saturday. Bring gloves if you have them. Reply to this message if you'd like to volunteer.",
    answer: "legitimate",
    indicators: "No payment, password, urgent deadline, or unexpected sign-in request is present in the sample.",
    explanation: "The visible content appears low risk, but these checks cannot prove a sender's identity. Confirm unexpected changes independently."
  },
  {
    sender: "Account Security · alerts@account-verify.example",
    subject: "Unusual sign-in detected",
    body: "We blocked a sign-in. Confirm your identity in the next 15 minutes or your account will be deleted: http://account-verify.example/secure",
    answer: "phishing",
    indicators: "A short deadline, account threat, and sign-in link on a domain that does not verify the claimed organization.",
    explanation: "Do not follow the link. Visit the service using its official app or a saved bookmark, and check security notifications there."
  }
];

const $ = (selector) => document.querySelector(selector);
const views = ["analyze", "training"];
let activeScenario = 0;
let scenarioAnswered = false;
let toastTimeout;
let insightsRequest = 0;
let screenshotObjectUrl = null;
let analysisMode = "email";
let quizPhase = "pre";
let quizIndex = 0;
let quizScore = 0;
let quizMissed = [];
let quizAnswered = false;
let quizPhaseComplete = false;

async function apiRequest(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { "Content-Type": "application/json", ...options.headers },
    cache: "no-store"
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `The local API returned ${response.status}.`);
  return data;
}

apiRequest("/api/health")
  .then((health) => {
    document.body.classList.add("api-ready");
    updateAIStatus(health.ollama);
  })
  .catch(() => showToast("Local backend unavailable. Start it with: python server.py"));

function updateAIStatus(status) {
  const badge = $("#ai-status");
  if (!status || !status.available) {
    badge.textContent = status?.reason || "LOCAL AI OFF · OLLAMA NOT RUNNING";
    badge.className = "ai-status missing";
    return;
  }
  if (!status.model_installed) {
    badge.textContent = `LOCAL AI OFF · RUN ollama pull ${status.model}`;
    badge.className = "ai-status missing";
    return;
  }
  badge.textContent = `LOCAL AI READY · ${status.model}`;
  badge.className = "ai-status ready";
}

document.querySelectorAll(".nav-item").forEach((button) => {
  button.addEventListener("click", () => switchView(button.dataset.view));
});

function switchView(name) {
  views.forEach((view) => {
    $(`#view-${view}`).classList.toggle("active", view === name);
    document.querySelector(`[data-view="${view}"]`).classList.toggle("active", view === name);
  });
  $("#crumb-title").textContent = { analyze: "Message analysis", training: "Training lab" }[name];
  if (name === "training") renderInsights();
}

function showTrainingInsights() {
  switchView("training");
  $("#training-insights").scrollIntoView({ behavior: "smooth", block: "start" });
}

$("#training-insights-link").addEventListener("click", showTrainingInsights);

$(".disclosure").addEventListener("click", () => {
  const button = $(".disclosure");
  const fields = $("#visual-fields");
  const expanded = button.getAttribute("aria-expanded") === "true";
  button.setAttribute("aria-expanded", String(!expanded));
  button.textContent = expanded ? "＋" : "−";
  fields.hidden = expanded;
});

document.querySelectorAll(".sample-chip").forEach((button) => {
  button.addEventListener("click", () => {
    setAnalysisMode("email");
    const sample = samples[button.dataset.sample];
    $("#message-input").value = sample.message;
    $("#url-input").value = sample.url;
    $("#sender-name").value = sample.clues.senderName;
    $("#sender-domain").value = sample.clues.senderDomain;
    $("#displayed-link").value = sample.clues.displayedLink;
    $("#visual-clue").value = sample.clues.visualClue;
    $("#analysis-results").hidden = true;
  });
});

document.querySelectorAll(".analysis-mode").forEach((button) => {
  button.addEventListener("click", () => setAnalysisMode(button.dataset.mode));
});

function setAnalysisMode(mode) {
  analysisMode = mode;
  document.querySelectorAll(".analysis-mode").forEach((button) => {
    const selected = button.dataset.mode === mode;
    button.classList.toggle("active", selected);
    button.setAttribute("aria-pressed", String(selected));
  });

  const isLink = mode === "link";
  const isPhone = mode === "phone";
  $("#sample-row").hidden = isLink || isPhone;
  $("#message-field").hidden = isLink;
  $("#phone-field").hidden = !isPhone;
  $("#url-field").hidden = isPhone;
  $("#sender-name-field").hidden = isLink || isPhone;
  $("#sender-domain-field").hidden = isLink || isPhone;
  $("#message-field-label").textContent = isPhone
    ? "OPTIONAL MESSAGE OR CALL CONTEXT"
    : mode === "message" ? "TEXT MESSAGE CONTENT" : "EMAIL CONTENT";
  $("#message-field-hint").textContent = isPhone
    ? "WHAT THEY SAID · OPTIONAL"
    : mode === "message" ? "SMS · CHAT · DM" : "EMAIL · SENDER · REQUEST";
  $("#message-input").placeholder = isPhone
    ? "What did the caller or message claim? Leave out personal or financial details."
    : mode === "message"
      ? "Paste the SMS, chat, or direct message here. Include any link or sender details if available…"
      : "Paste the email text here, including its subject and sender if available…";
  $("#url-field-label").textContent = isLink ? "LINK TO CHECK" : "LINK IN THE MESSAGE";
  $("#url-field-hint").textContent = isLink ? "NOT OPENED" : "OPTIONAL · NOT OPENED";
  $("#url-input").placeholder = isLink
    ? "Paste the suspicious link — it will not be opened"
    : "Paste a URL — it will not be opened";
  $("#sender-name-label").textContent = isPhone
    ? "Name or organization they claimed"
    : mode === "message" ? "Displayed sender name or handle" : "Displayed sender name";
  $("#sender-domain-label").textContent = mode === "message"
    ? "Sender number or handle"
    : isPhone ? "Other caller details (optional)" : "Sender email or domain";
  $("#analysis-results").hidden = true;
}

$("#analyze-button").addEventListener("click", analyzeMessage);

$("#screenshot-input").addEventListener("change", () => {
  const file = $("#screenshot-input").files[0];
  if (!file) return;
  if (!["image/png", "image/jpeg", "image/webp"].includes(file.type)) {
    clearScreenshot();
    showToast("Choose a PNG, JPEG, or WebP screenshot.");
    return;
  }
  if (file.size === 0 || file.size > 5 * 1024 * 1024) {
    clearScreenshot();
    showToast("The screenshot must be larger than 0 bytes and no more than 5 MB.");
    return;
  }
  if (screenshotObjectUrl) URL.revokeObjectURL(screenshotObjectUrl);
  screenshotObjectUrl = URL.createObjectURL(file);
  $("#screenshot-thumbnail").src = screenshotObjectUrl;
  $("#screenshot-filename").textContent = `${file.name} · ${(file.size / 1024 / 1024).toFixed(1)} MB`;
  $("#screenshot-preview").hidden = false;
});

$("#remove-screenshot").addEventListener("click", clearScreenshot);

function clearScreenshot() {
  if (screenshotObjectUrl) URL.revokeObjectURL(screenshotObjectUrl);
  screenshotObjectUrl = null;
  $("#screenshot-input").value = "";
  $("#screenshot-thumbnail").removeAttribute("src");
  $("#screenshot-filename").textContent = "";
  $("#screenshot-preview").hidden = true;
}

function readScreenshot(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.addEventListener("load", () => resolve(reader.result));
    reader.addEventListener("error", () => reject(new Error("The screenshot could not be read.")));
    reader.readAsDataURL(file);
  });
}

async function analyzeMessage() {
  const isMessageMode = analysisMode === "email" || analysisMode === "message";
  const isPhoneMode = analysisMode === "phone";
  const payload = {
    analysis_mode: analysisMode,
    message: analysisMode === "link" ? "" : $("#message-input").value,
    url: isPhoneMode ? "" : $("#url-input").value,
    phone_number: isPhoneMode ? $("#phone-input").value : "",
    sender_name: isMessageMode ? $("#sender-name").value : "",
    sender_domain: isMessageMode ? $("#sender-domain").value : "",
    displayed_link: isPhoneMode ? "" : $("#displayed-link").value,
    visual_clue: $("#visual-clue").value
  };
  const screenshot = $("#screenshot-input").files[0];
  const useLocalAI = $("#local-ai-toggle").checked;
  if (analysisMode === "phone" && !payload.phone_number.trim() && !screenshot) {
    showToast("Enter the phone number or caller ID you want to check.");
    $("#phone-input").focus();
    return;
  }
  if (analysisMode === "link" && !payload.url.trim() && !screenshot) {
    showToast("Paste the link you want to check. It will not be opened.");
    $("#url-input").focus();
    return;
  }
  if (screenshot && !useLocalAI) {
    showToast("Enable local AI before analyzing a screenshot.");
    $("#local-ai-toggle").focus();
    return;
  }
  if (!Object.entries(payload).some(([key, value]) => key !== "analysis_mode" && value.trim()) && !screenshot) {
    showToast("Add something to check, or select a screenshot for local AI analysis.");
    $("#message-input").focus();
    return;
  }
  const button = $("#analyze-button");
  button.disabled = true;
  button.querySelector(".button-spark").textContent = "…";
  try {
    payload.local_ai = useLocalAI;
    if (screenshot) payload.image_data = await readScreenshot(screenshot);
    const result = await apiRequest("/api/analyze", {
      method: "POST",
      body: JSON.stringify(payload)
    });
    updateDashboard(result.stats);
    renderAnalysis(result);
  } catch (error) {
    showToast(`Analysis failed: ${error.message}`);
  } finally {
    button.disabled = false;
    button.querySelector(".button-spark").textContent = "✳";
  }
}

function renderAnalysis(result) {
  const findings = result.findings;
  const results = $("#analysis-results");
  const critical = result.risk_score >= 70;
  const verdictClass = critical ? "verdict-high" : result.risk_score >= 20 ? "verdict-caution" : "verdict-low";
  const symbol = critical ? "!" : result.risk_score >= 20 ? "◌" : "✓";
  const ai = result.ai_assessment;
  const aiCard = ai ? `<section class="ai-assessment"><h3>Local AI assessment · ${escapeHtml(ai.verdict.replaceAll("_", " "))}</h3><p>${escapeHtml(ai.summary || "AI assessment completed.")}</p><p class="ai-meta">${escapeHtml(ai.provider)} · ${escapeHtml(ai.model)} · ${ai.confidence}% model confidence${ai.visual_analyzed ? " · screenshot analyzed" : ""}</p>${ai.recommended_action ? `<p><strong>Safer next step:</strong> ${escapeHtml(ai.recommended_action)}</p>` : ""}<p>Model confidence is not a probability that a message is malicious. Verify independently.</p></section>` : "";
  const submittedItems = analysisMode === "phone" ? "phone number and any optional context" : "submitted content";
  const processedItems = ai?.visual_analyzed
    ? `Your ${submittedItems} and screenshot were`
    : `Your ${submittedItems} ${analysisMode === "phone" ? "were" : "was"}`;
  const warningRows = findings.length
    ? findings.map((finding) => `<article class="finding ${finding.severity === "critical" ? "critical" : finding.severity === "info" ? "info" : ""}"><div class="finding-title-row"><strong>${escapeHtml(finding.title)}</strong><span>${finding.points ? `+${finding.points} pts` : "context"}</span></div><p>${escapeHtml(finding.detail)}</p>${finding.evidence ? `<blockquote class="evidence-quote"><span>Evidence</span><mark>${escapeHtml(finding.evidence)}</mark></blockquote>` : ""}</article>`).join("")
    : `<article class="finding info"><strong>No obvious indicators found</strong><p>Only a small set of local checks ran. Confirm unexpected requests with the organization using contact details you already trust.</p></article>`;
  results.innerHTML = `
    <div class="risk-score-card ${critical ? "risk-high" : result.risk_score >= 20 ? "risk-caution" : "risk-low"}">
      <div class="risk-score-heading"><div class="result-status ${verdictClass}"><span class="result-symbol">${symbol}</span>${escapeHtml(result.risk_level)}</div><strong>${result.risk_score}<span>/100</span></strong></div>
      <p>${escapeHtml(result.intro)}</p>
      <small>${escapeHtml(result.score_note)}</small>
    </div>
    ${aiCard}
    <section class="warning-table" aria-label="Warning signs and evidence"><div class="warning-table-heading"><strong>Warning signs &amp; evidence</strong><span>${findings.length} FOUND</span></div><div class="finding-list">${warningRows}</div></section>
    <section class="next-step-card"><span class="next-step-icon" aria-hidden="true">→</span><div><strong>What to do next</strong><p>${escapeHtml(result.next_step)}</p></div></section>
    <p class="result-footer">${processedItems} processed on this computer and not saved or sent over the internet. These checks can miss attacks or flag legitimate messages.</p>`;
  results.hidden = false;
  results.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[character]);
}

function showToast(message) {
  const toast = $("#toast");
  toast.textContent = message;
  toast.classList.add("show");
  clearTimeout(toastTimeout);
  toastTimeout = setTimeout(() => toast.classList.remove("show"), 2800);
}

$("#authorize-check").addEventListener("change", (event) => {
  $("#begin-training").disabled = !event.target.checked;
});
$("#begin-training").addEventListener("click", async () => {
  if (!$("#authorize-check").checked) return;
  const button = $("#begin-training");
  button.disabled = true;
  try {
    const stats = await apiRequest("/api/training/start", {
      method: "POST",
      body: JSON.stringify({ authorized: true })
    });
    updateDashboard(stats);
    $("#authorization-card").hidden = true;
    startQuiz("pre");
  } catch (error) {
    showToast(`Could not start the fictional campaign: ${error.message}`);
    button.disabled = false;
  }
});

function startQuiz(phase) {
  quizPhase = phase;
  quizIndex = 0;
  quizScore = 0;
  quizMissed = [];
  quizPhaseComplete = false;
  $("#authorization-card").hidden = true;
  $("#scenario-card").hidden = true;
  $("#certificate-panel").hidden = true;
  $("#quiz-card").hidden = false;
  renderQuizQuestion();
  $("#quiz-card").scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderQuizQuestion() {
  const question = quizQuestions[quizIndex];
  quizAnswered = false;
  $("#quiz-next").disabled = false;
  $("#quiz-progress").textContent = `${quizPhase === "pre" ? "BASELINE" : "AFTER TRAINING"} · QUESTION ${quizIndex + 1} / ${quizQuestions.length}`;
  $("#quiz-sender").textContent = question.sender;
  $("#quiz-subject").textContent = question.subject;
  $("#quiz-body").textContent = question.body;
  $("#quiz-feedback").hidden = true;
  $("#quiz-result").hidden = true;
  $("#quiz-next").hidden = true;
  $("#quiz-options").hidden = false;
  $("#quiz-options").innerHTML = ["legitimate", "suspicious", "phishing"].map((answer) =>
    `<button class="quiz-option" type="button" data-answer="${answer}">${answer[0].toUpperCase()}${answer.slice(1)}</button>`
  ).join("");
  $("#quiz-options").querySelectorAll(".quiz-option").forEach((button) => {
    button.addEventListener("click", () => answerQuizQuestion(button.dataset.answer));
  });
}

function answerQuizQuestion(answer) {
  if (quizAnswered) return;
  quizAnswered = true;
  const question = quizQuestions[quizIndex];
  const correct = answer === question.answer;
  if (correct) quizScore += 1;
  else quizMissed.push(question.indicators);
  $("#quiz-options").querySelectorAll(".quiz-option").forEach((button) => {
    button.disabled = true;
    if (button.dataset.answer === question.answer) button.classList.add("correct");
    if (button.dataset.answer === answer && !correct) button.classList.add("incorrect");
  });
  $("#quiz-feedback").innerHTML = `<strong>${correct ? "That’s right." : `The best classification is ${escapeHtml(question.answer)}.`}</strong><p><b>Signals to notice:</b> ${escapeHtml(question.indicators)}</p><p>${escapeHtml(question.explanation)}</p>`;
  $("#quiz-feedback").hidden = false;
  $("#quiz-next").textContent = quizIndex + 1 < quizQuestions.length ? "Next message →" : "See quiz results →";
  $("#quiz-next").hidden = false;
}

$("#quiz-next").addEventListener("click", async () => {
  const button = $("#quiz-next");
  if (quizPhaseComplete) {
    button.disabled = true;
    if (quizPhase === "pre") {
      $("#quiz-card").hidden = true;
      $("#scenario-card").hidden = false;
      renderScenario();
      return;
    }
    try {
      await prepareCertificate();
      $("#quiz-card").hidden = true;
      $("#certificate-panel").hidden = false;
      activeScenario = 0;
      $("#certificate-panel").scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (error) {
      showToast(`Could not prepare your certificate: ${error.message}`);
      button.disabled = false;
    }
    return;
  }
  if (quizIndex + 1 < quizQuestions.length) {
    quizIndex += 1;
    renderQuizQuestion();
    return;
  }
  button.disabled = true;
  try {
    const stats = await apiRequest("/api/training/quiz/complete", {
      method: "POST",
      body: JSON.stringify({
        phase: quizPhase,
        score: quizScore,
        total_questions: quizQuestions.length
      })
    });
    updateDashboard(stats);
    $("#quiz-progress").textContent = `${quizPhase === "pre" ? "BASELINE" : "AFTER TRAINING"} · COMPLETE`;
    $("#quiz-options").hidden = true;
    $("#quiz-feedback").hidden = true;
    const missed = quizMissed.length
      ? `<p><strong>Signals to review:</strong></p><ul>${quizMissed.map((indicator) => `<li>${escapeHtml(indicator)}</li>`).join("")}</ul>`
      : "<p>You noticed the key signals in every message. Keep verifying unexpected requests independently.</p>";
    $("#quiz-result").innerHTML = `<strong>Your score: ${quizScore} / ${quizQuestions.length}</strong><p>Answers are not saved individually; only aggregate quiz totals contribute to the dashboard.</p>${missed}`;
    $("#quiz-result").hidden = false;
    button.textContent = quizPhase === "pre" ? "Continue to fictional inbox →" : "Finish training →";
    button.disabled = false;
    quizPhaseComplete = true;
  } catch (error) {
    showToast(`Could not save aggregate quiz results: ${error.message}`);
    button.disabled = false;
  }
});

function renderScenario() {
  const scenario = scenarios[activeScenario];
  scenarioAnswered = false;
  $("#scenario-count").textContent = `SCENARIO ${String(activeScenario + 1).padStart(2, "0")} / ${String(scenarios.length).padStart(2, "0")}`;
  $("#scenario-sender").textContent = scenario.sender;
  $("#scenario-address").textContent = scenario.address;
  $("#scenario-subject").textContent = scenario.subject;
  $("#scenario-body").textContent = scenario.body;
  $("#scenario-url").textContent = scenario.url;
  $("#lesson-panel").hidden = true;
  $("#next-scenario").hidden = true;
  document.querySelectorAll(".choice-button").forEach((button) => { button.disabled = false; });
  $("#scenario-card").scrollIntoView({ behavior: "smooth", block: "nearest" });
}

document.querySelectorAll(".choice-button").forEach((button) => {
  button.addEventListener("click", async () => {
    if (scenarioAnswered) return;
    scenarioAnswered = true;
    const choice = button.dataset.choice;
    document.querySelectorAll(".choice-button").forEach((candidate) => { candidate.disabled = true; });
    try {
      const stats = await apiRequest("/api/training/record", {
        method: "POST",
        body: JSON.stringify({ choice })
      });
      updateDashboard(stats);
      const panel = $("#lesson-panel");
      const heading = choice === "reported" ? "Good catch." : choice === "ignored" ? "Ignoring can leave others without a warning." : "Simulation interaction complete—nothing was opened.";
      const lesson = choice === "clicked"
        ? "This was a fictional, inert link. No page opened and nothing was collected. In real life, don't follow an unexpected link; visit the official service through a channel you already trust."
        : scenarios[activeScenario].lesson;
      panel.innerHTML = `<strong>${heading}</strong>${escapeHtml(lesson)}`;
      panel.hidden = false;
      const next = $("#next-scenario");
      next.textContent = activeScenario + 1 < scenarios.length ? "Next fictional scenario →" : "Take the follow-up quiz →";
      next.hidden = false;
    } catch (error) {
      scenarioAnswered = false;
      document.querySelectorAll(".choice-button").forEach((candidate) => { candidate.disabled = false; });
      showToast(`Could not record this anonymous practice count: ${error.message}`);
    }
  });
});

$("#next-scenario").addEventListener("click", async () => {
  if (activeScenario + 1 < scenarios.length) {
    activeScenario += 1;
    renderScenario();
  } else {
    const button = $("#next-scenario");
    button.disabled = true;
    try {
      $("#scenario-card").hidden = true;
      startQuiz("post");
    } catch (error) {
      showToast(`Could not start the follow-up quiz: ${error.message}`);
    } finally {
      button.disabled = false;
    }
  }
});

async function prepareCertificate() {
  const certificate = await apiRequest("/api/training/certificate", {
    method: "POST",
    body: JSON.stringify({ name: $("#certificate-name").value })
  });
  $("#certificate-date").textContent = certificate.completed_on;
  $("#certificate-recipient").textContent = certificate.recipient;
}

function updateCertificateName() {
  const name = $("#certificate-name").value.trim();
  $("#certificate-recipient").textContent = name || "Training participant";
}

$("#certificate-name").addEventListener("input", updateCertificateName);
$("#download-certificate").addEventListener("click", async () => {
  const button = $("#download-certificate");
  button.disabled = true;
  try {
    const response = await fetch("/api/training/certificate/download", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      cache: "no-store",
      body: JSON.stringify({ name: $("#certificate-name").value })
    });
    const contentType = response.headers.get("Content-Type") || "";
    if (!response.ok) {
      const error = contentType.includes("application/json") ? await response.json() : null;
      throw new Error(error?.error || `The local API returned ${response.status}.`);
    }
    if (!contentType.includes("application/pdf")) {
      throw new Error("The backend did not return a PDF file.");
    }
    const filenameHeader = response.headers.get("Content-Disposition") || "";
    const filenameMatch = filenameHeader.match(/filename="([A-Za-z0-9_-]+\.pdf)"/i);
    const filename = filenameMatch ? filenameMatch[1] : "Signal-Certificate.pdf";
    const file = await response.blob();
    const downloadUrl = URL.createObjectURL(file);
    const link = document.createElement("a");
    link.href = downloadUrl;
    link.download = filename;
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(downloadUrl), 1000);
    showToast(`${filename} downloaded. Check your browser's Downloads folder.`);
  } catch (error) {
    showToast(`Could not download certificate: ${error.message}`);
  } finally {
    button.disabled = false;
  }
});
$("#certificate-insights").addEventListener("click", showTrainingInsights);

async function renderInsights() {
  const requestId = ++insightsRequest;
  try {
    const stats = await apiRequest("/api/training/stats");
    if (requestId !== insightsRequest) return;
    updateDashboard(stats);
  } catch (error) {
    if (requestId === insightsRequest) showToast(`Could not load practice insights: ${error.message}`);
  }
}

function updateDashboard(stats) {
  if (!stats) return;
  $("#metric-analyzed").textContent = String(stats.messages_analyzed);
  $("#metric-clicked").textContent = String(stats.simulated_clicked);
  $("#metric-reported").textContent = String(stats.reported);
  $("#metric-completion").textContent = stats.completion_rate === null ? "—" : `${stats.completion_rate}%`;
  $("#metric-completion-note").textContent = stats.campaigns_started
    ? `${stats.training_completed} of ${stats.campaigns_started} campaigns completed`
    : "No campaign started yet";

  const preScore = stats.pre_quiz_average;
  const postScore = stats.post_quiz_average;
  $("#chart-pre-value").textContent = preScore === null ? "—" : `${preScore.toFixed(1)} / 5 · n=${stats.pre_quiz_count}`;
  $("#chart-post-value").textContent = postScore === null ? "—" : `${postScore.toFixed(1)} / 5 · n=${stats.post_quiz_count}`;
  $("#chart-pre-bar").style.width = `${preScore === null ? 0 : preScore * 20}%`;
  $("#chart-post-bar").style.width = `${postScore === null ? 0 : postScore * 20}%`;
  $(".snapshot-chart").setAttribute(
    "aria-label",
    `Initial quiz average: ${preScore === null ? "no results" : `${preScore} out of 5 from ${stats.pre_quiz_count} quizzes`}. After training average: ${postScore === null ? "no results" : `${postScore} out of 5 from ${stats.post_quiz_count} quizzes`}.`
  );
  if (preScore !== null && postScore !== null) {
    const difference = Number((postScore - preScore).toFixed(1));
    $("#snapshot-change").textContent = `${difference > 0 ? "+" : ""}${difference}`;
    $("#snapshot-message").textContent = `${stats.pre_quiz_count} baseline and ${stats.post_quiz_count} follow-up quiz results. This is a local aggregate comparison, not proof that training alone caused any change.`;
  } else {
    $("#snapshot-change").textContent = "—";
    $("#snapshot-message").textContent = "No complete before-and-after quiz pair yet. Start a campaign to collect baseline and follow-up scores. No sample results are being shown.";
  }
}

$("#reset-insights").addEventListener("click", async () => {
  const button = $("#reset-insights");
  button.disabled = true;
  try {
    const stats = await apiRequest("/api/training/stats", { method: "DELETE" });
    updateDashboard(stats);
    showToast("Local practice counts cleared.");
  } catch (error) {
    showToast(`Could not clear practice counts: ${error.message}`);
  } finally {
    button.disabled = false;
  }
});

$(".help-button").addEventListener("click", () => showToast("Signal uses a backend running only on this computer. Messages aren't saved or sent over the internet."));
