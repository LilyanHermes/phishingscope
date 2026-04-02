const samples = [
  {
    id: "bank-freeze",
    title: "Frozen Bank Account Alert",
    category: "Banking Spoof",
    text:
      "URGENT: Your Chase account has been restricted due to suspicious activity. Verify your login immediately or your debit card will be permanently suspended. Reply with your username and secure passcode to avoid account closure.",
    url: "https://chase-secure-login-alerts.co/verify"
  },
  {
    id: "delivery-failure",
    title: "Package Delivery Failure",
    category: "Delivery Scam",
    text:
      "FedEx notice: We were unable to deliver your parcel today. A $2.99 redelivery fee is required in the next 30 minutes or the package will be returned. Confirm your address and card details now.",
    url: "https://fedex-tracking-redelivery.help/package"
  },
  {
    id: "paypal-demo",
    title: "PayPaI Account Verification Demo",
    category: "Live Demo Sample",
    text:
      "From: PayPaI Security <security-alert@paypaI-account-verify.com>\nSubject: Urgent: Your account has been limited\n\nDear Customer,\n\nWe detected unusual activity on your account. Your access will be suspended within 24 hours unless you verify your identity immediately.\n\nPlease confirm your login and billing information here:\nhttp://paypal-account-verify-login-security.com/reset\n\nFailure to act now may result in permanent account suspension.\n\nThank you,\nSecurity Team",
    url: "http://paypal-account-verify-login-security.com/reset"
  },
  {
    id: "gift-card-boss",
    title: "Executive Gift Card Request",
    category: "Business Email Compromise",
    text:
      "Hi, I need you to handle an urgent task before the board meeting. Buy six Apple gift cards for our client appreciation event and send me the codes right away. Keep this between us. I am unavailable by phone.",
    url: ""
  },
  {
    id: "safe-calendar",
    title: "Legitimate Calendar Update",
    category: "Low Risk Example",
    text:
      "Hi Lilyan,\n\nYour design review for Friday has been moved to 2:30 PM in the usual Zoom room. The agenda and notes are already in the shared team calendar.\n\nThanks,\nMaya",
    url: "https://calendar.google.com"
  }
];

const tips = [
  "Pause before clicking. Real organizations rarely demand immediate action by text or email.",
  "Never send passwords, verification codes, or gift card numbers in reply to a message.",
  "Open official websites manually instead of using links from unexpected messages.",
  "Double-check brand names, domains, and sender context for subtle misspellings or spoofing.",
  "If money or account access is involved, confirm through a trusted phone number or app."
];

const trustSignals = [
  "Phishing campaigns often create urgency so you act before verifying the request.",
  "Spoofed brands and lookalike domains are common tactics used to steal trust quickly.",
  "Credential and billing requests sent by email or text deserve extra scrutiny.",
  "A message can look polished and still be malicious if the request or link is off."
];

const rules = [
  {
    id: "urgent-language",
    label: "Urgent or threatening language",
    severity: "high",
    weight: 18,
    test(input) {
      const urgentPattern =
        /\b(urgent|immediately|act now|within \d+\s?(minutes?|hours?)|final warning|suspended|locked|last chance|expire|deadline)\b/i;
      const threatPattern =
        /\b(legal action|account closure|permanently suspended|penalty|fraud alert|security breach|terminated)\b/i;

      if (urgentPattern.test(input) || threatPattern.test(input)) {
        return "The message creates pressure with urgency, deadlines, or consequences.";
      }

      return null;
    }
  },
  {
    id: "credentials-request",
    label: "Credential request",
    severity: "high",
    weight: 20,
    test(input) {
      const pattern =
        /\b(password|passcode|login|verify your account|verification code|otp|security code|username)\b/i;
      return pattern.test(input)
        ? "The sender asks for login credentials, passcodes, or account verification details."
        : null;
    }
  },
  {
    id: "personal-info",
    label: "Sensitive personal information request",
    severity: "high",
    weight: 15,
    test(input) {
      const pattern =
        /\b(ssn|social security|date of birth|personal info|address confirmation|driver'?s license)\b/i;
      return pattern.test(input)
        ? "The message asks for sensitive identity details that reputable services should not request this way."
        : null;
    }
  },
  {
    id: "payment-request",
    label: "Payment or gift card request",
    severity: "high",
    weight: 18,
    test(input) {
      const pattern =
        /\b(payment|invoice|wire transfer|bank transfer|gift card|gift cards|crypto|bitcoin|wallet|card details|credit card|billing information)\b/i;
      return pattern.test(input)
        ? "The message asks for payment details, billing information, or gift card codes."
        : null;
    }
  },
  {
    id: "pressure-wording",
    label: "Pressure wording",
    severity: "medium",
    weight: 10,
    test(input) {
      const pattern =
        /\b(don't tell anyone|keep this between us|confidential|right away|asap|today only)\b/i;
      return pattern.test(input)
        ? "The sender discourages verification or pushes for a rushed response."
        : null;
    }
  },
  {
    id: "impersonation",
    label: "Brand impersonation",
    severity: "medium",
    weight: 10,
    test(input) {
      const pattern =
        /\b(bank|paypal|microsoft|apple|amazon|netflix|fedex|ups|dhl|irs|google|icloud|office 365|chase|wells fargo|account team)\b/i;
      return pattern.test(input)
        ? "The message claims to be from a bank, delivery service, or account provider."
        : null;
    }
  },
  {
    id: "account-verification",
    label: "Account verification pressure",
    severity: "medium",
    weight: 12,
    test(input) {
      const pattern =
        /\b(verify your identity|confirm your account|account has been limited|restore access|unlock your account|confirm your login|validate your account)\b/i;
      return pattern.test(input)
        ? "The sender pressures you to verify or restore account access through the message."
        : null;
    }
  },
  {
    id: "misspelled-brand",
    label: "Misspelled brand name",
    severity: "high",
    weight: 12,
    test(input) {
      const misspelledBrands = [
        /paypa[l1i]/i,
        /micros[o0]ft/i,
        /rnicrosoft/i,
        /app[1l]e/i,
        /arnazon/i,
        /fedexx/i,
        /chsae/i,
        /wells?\s?farg0/i,
        /netfl[1i]x/i
      ];

      return misspelledBrands.some((pattern) => pattern.test(input))
        ? "The message contains a lookalike brand spelling, which is a common spoofing signal."
        : null;
    }
  },
  {
    id: "generic-greeting",
    label: "Generic greeting",
    severity: "low",
    weight: 7,
    test(input) {
      const pattern =
        /\b(dear customer|dear user|valued customer|account holder|sir\/madam|dear member|hello customer)\b/i;
      return pattern.test(input)
        ? "The message uses a generic greeting instead of identifying the recipient directly."
        : null;
    }
  },
  {
    id: "delivery-scam",
    label: "Delivery scam language",
    severity: "medium",
    weight: 10,
    test(input) {
      const pattern =
        /\b(deliver|delivery|parcel|shipment|tracking|redelivery|courier|package)\b/i;
      return pattern.test(input)
        ? "The message uses delivery language commonly seen in package and redelivery scams."
        : null;
    }
  },
  {
    id: "excessive-punctuation",
    label: "Excessive punctuation or formatting pressure",
    severity: "medium",
    weight: 8,
    test(input) {
      return /!{2,}|\?{2,}|(?:\b[A-Z]{4,}\b.*){2,}/.test(input)
        ? "The message uses exaggerated punctuation or shouting to trigger a reaction."
        : null;
    }
  },
  {
    id: "suspicious-url",
    label: "Suspicious link pattern",
    severity: "high",
    weight: 18,
    test(_, url) {
      return detectSuspiciousUrl(url);
    }
  },
  {
    id: "non-https",
    label: "Non-HTTPS link",
    severity: "medium",
    weight: 10,
    test(_, url) {
      const parsed = parseUrl(url);

      if (url && parsed && parsed.protocol !== "https:") {
        return "The link does not use HTTPS, which is unusual for legitimate account and payment pages.";
      }

      return null;
    }
  },
  {
    id: "brand-spoof",
    label: "Possible domain spoofing",
    severity: "high",
    weight: 16,
    test(input, url) {
      return detectBrandSpoof(input, url);
    }
  },
  {
    id: "sender-spoof-clue",
    label: "Suspicious sender or spoofing clue",
    severity: "medium",
    weight: 10,
    test(input) {
      const pattern =
        /\b(from:\s?.+@.+-|from:\s?.+verify\.com|security-alert@|noreply@.+(verify|secure|alert)|team@.+(billing|login|security))\b/i;
      return pattern.test(input)
        ? "The message includes sender details or naming patterns that look like spoofing clues."
        : null;
    }
  }
];

const elements = {
  messageInput: document.getElementById("message-input"),
  urlInput: document.getElementById("url-input"),
  analyzeButton: document.getElementById("analyze-button"),
  resetButton: document.getElementById("reset-button"),
  copyButton: document.getElementById("copy-button"),
  exportButton: document.getElementById("export-button"),
  demoButton: document.getElementById("demo-button"),
  heroDemoButton: document.getElementById("hero-demo-button"),
  indicatorList: document.getElementById("indicator-list"),
  indicatorHeading: document.getElementById("indicator-heading"),
  indicatorCountText: document.getElementById("indicator-count-text"),
  signalSummaryText: document.getElementById("signal-summary-text"),
  threatBanner: document.getElementById("threat-banner"),
  confidenceText: document.getElementById("confidence-text"),
  scoreValue: document.getElementById("score-value"),
  verdictText: document.getElementById("verdict-text"),
  explanationText: document.getElementById("explanation-text"),
  nextActionText: document.getElementById("next-action-text"),
  explanationPanel: document.getElementById("explanation-panel"),
  confidenceSummaryText: document.getElementById("confidence-summary-text"),
  confidencePanelCard: document.getElementById("confidence-panel-card"),
  loadingShell: document.getElementById("loading-shell"),
  gaugeNeedle: document.getElementById("gauge-needle"),
  sampleList: document.getElementById("sample-list"),
  tipsList: document.getElementById("tips-list"),
  trustList: document.getElementById("trust-list")
};

let currentResult = null;
let activeAnalysisTimer = null;

function parseUrl(rawUrl) {
  if (!rawUrl) {
    return null;
  }

  try {
    const prefixed = /^https?:\/\//i.test(rawUrl) ? rawUrl : `https://${rawUrl}`;
    return new URL(prefixed);
  } catch {
    return null;
  }
}

function detectSuspiciousUrl(rawUrl) {
  const parsed = parseUrl(rawUrl);

  if (!rawUrl) {
    return null;
  }

  if (!parsed) {
    return "The URL format is malformed or intentionally obfuscated.";
  }

  const hostname = parsed.hostname.toLowerCase();

  if (hostname.includes("xn--")) {
    return "The URL contains punycode, which can hide lookalike domains.";
  }

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    return "The URL uses a raw IP address instead of a recognizable domain.";
  }

  if (hostname.split("-").length > 3) {
    return "The domain uses multiple hyphens, a common phishing tactic.";
  }

  if (/(bit\.ly|tinyurl\.com|t\.co|rb\.gy|is\.gd)/i.test(hostname)) {
    return "The URL uses a link shortener that hides the real destination.";
  }

  if (/@/.test(rawUrl)) {
    return "The URL includes an @ symbol, which can disguise where it actually goes.";
  }

  if (/\b(login|verify|secure|update|wallet|signin|reset)\b/i.test(parsed.pathname)) {
    return "The URL path uses account-action keywords often seen in phishing pages.";
  }

  if (/\.(top|click|xyz|help|ru|cn|shop|info)$/i.test(hostname)) {
    return "The URL uses a high-risk or unusual top-level domain.";
  }

  return null;
}

function detectBrandSpoof(input, rawUrl) {
  const parsed = parseUrl(rawUrl);
  const text = input.toLowerCase();
  const hostname = parsed ? parsed.hostname.toLowerCase() : "";
  const brands = ["chase", "paypal", "amazon", "apple", "microsoft", "fedex", "ups", "netflix", "google"];

  for (const brand of brands) {
    if (text.includes(brand) && hostname && !hostname.includes(brand)) {
      return `The message mentions ${brand}, but the URL does not match that brand's expected domain.`;
    }
  }

  return null;
}

function scoreToVerdict(score) {
  if (score >= 60) {
    return "High Risk";
  }

  if (score >= 30) {
    return "Medium Risk";
  }

  return "Low Risk";
}

function getConfidenceLevel(indicators) {
  const weightedStrength = indicators.reduce((sum, indicator) => sum + indicator.weight, 0);
  const strongSignals = indicators.filter((indicator) => indicator.weight >= 15).length;

  if (indicators.length >= 5 || weightedStrength >= 55 || strongSignals >= 3) {
    return "High";
  }

  if (indicators.length >= 3 || weightedStrength >= 28) {
    return "Medium";
  }

  return "Low";
}

function buildConfidenceSummary(confidence, indicators) {
  if (!indicators.length) {
    return "Confidence stays low when very few phishing indicators are present in the message or link.";
  }

  if (confidence === "High") {
    return "Multiple strong indicators point in the same direction, so confidence in this assessment is high.";
  }

  if (confidence === "Medium") {
    return "Several indicators are present, but the signal mix is less overwhelming than a high-confidence phishing case.";
  }

  return "Only a small number of weaker indicators were triggered, so this result should be treated as an early warning rather than a final verdict.";
}

function buildExplanation(indicators, score, verdict) {
  if (!indicators.length) {
    return "No strong phishing indicators were detected. The message appears consistent with legitimate communication patterns.";
  }

  const topSignals = indicators.slice(0, 3).map((indicator) => indicator.label.toLowerCase());

  if (verdict === "High Risk") {
    return `This message is highly likely to be a phishing attempt based on multiple high-confidence indicators, including ${topSignals.join(", ")}.`;
  }

  if (verdict === "Medium Risk") {
    return `This message shows several suspicious patterns, including ${topSignals.join(", ")}, so it should be treated with caution before any reply or click.`;
  }

  return `This message shows limited warning signs, but ${topSignals.join(", ")} still suggest you should verify the request before taking action.`;
}

function buildNextAction(score, indicators) {
  const asksForCredentials = indicators.some((indicator) => indicator.id === "credentials-request");
  const hasUrlIssue = indicators.some(
    (indicator) =>
      indicator.id === "suspicious-url" ||
      indicator.id === "brand-spoof" ||
      indicator.id === "non-https"
  );

  if (score >= 60 || asksForCredentials) {
    return "Do not click links, reply, or share any information. Verify the request through the organization's official website or phone number, then report or delete the message.";
  }

  if (hasUrlIssue || score >= 30) {
    return "Treat this message cautiously. Avoid using the included link, confirm the request through a trusted channel, and only proceed if the sender can be independently verified.";
  }

  return "No major phishing signal was detected, but you should still confirm unexpected requests through a trusted source before taking action.";
}

function analyzeThreat(content, url) {
  const normalizedContent = content.trim();
  const normalizedUrl = url.trim();
  const combined = `${normalizedContent} ${normalizedUrl}`.trim();

  const indicators = rules
    .map((rule) => {
      const detail = rule.test(combined, normalizedUrl);

      if (!detail) {
        return null;
      }

      return {
        id: rule.id,
        label: rule.label,
        detail,
        severity: rule.severity,
        weight: rule.weight
      };
    })
    .filter(Boolean);

  const score = Math.min(
    100,
    indicators.reduce((sum, indicator) => sum + indicator.weight, 0)
  );
  const verdict = scoreToVerdict(score);

  return {
    score,
    verdict,
    indicators,
    confidence: getConfidenceLevel(indicators),
    redFlags: indicators.map((indicator) => indicator.detail),
    explanation: buildExplanation(indicators, score, verdict),
    nextAction: buildNextAction(score, indicators)
  };
}

function getVerdictClasses(verdict) {
  if (verdict === "High Risk") {
    return {
      verdictClass: "verdict verdict--high",
      confidenceClass: "confidence-pill confidence-pill--high",
      bannerClass: "threat-banner threat-banner--high",
      signalClass: "signal-summary signal-summary--high"
    };
  }

  if (verdict === "Medium Risk") {
    return {
      verdictClass: "verdict verdict--medium",
      confidenceClass: "confidence-pill confidence-pill--medium",
      bannerClass: "threat-banner threat-banner--medium",
      signalClass: "signal-summary signal-summary--medium"
    };
  }

  return {
    verdictClass: "verdict verdict--low",
    confidenceClass: "confidence-pill confidence-pill--low",
    bannerClass: "threat-banner threat-banner--low",
    signalClass: "signal-summary signal-summary--low"
  };
}

function buildSignalSummary(result) {
  if (result.verdict === "High Risk") {
    return "Multiple high-risk signals detected";
  }

  if (result.verdict === "Medium Risk") {
    return "Several suspicious patterns detected";
  }

  return "No strong phishing indicators detected";
}

function animateGauge(targetScore) {
  const start = performance.now();
  const duration = 900;
  const currentScore = Number.parseInt(elements.scoreValue.textContent || "0", 10);
  const startScore = Number.isNaN(currentScore) ? 0 : currentScore;

  function step(timestamp) {
    const progress = Math.min(1, (timestamp - start) / duration);
    const eased = 1 - Math.pow(1 - progress, 4);
    const nextScore = Math.round(startScore + (targetScore - startScore) * eased);
    const degrees = Math.round((nextScore / 100) * 180) - 90;

    elements.scoreValue.textContent = String(nextScore);
    elements.gaugeNeedle.style.transform = `translateX(-50%) rotate(${degrees}deg)`;

    if (progress < 1) {
      window.requestAnimationFrame(step);
    }
  }

  window.requestAnimationFrame(step);
}

function setLoadingState(isLoading) {
  elements.loadingShell.hidden = !isLoading;
  elements.analyzeButton.disabled = isLoading;
  elements.analyzeButton.textContent = isLoading ? "Analyzing..." : "Analyze Threat";
}

function renderSamples() {
  elements.sampleList.innerHTML = "";

  samples.forEach((sample) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "sample-item";
    const helperText =
      sample.id === "safe-calendar"
        ? "Load a legitimate-looking example to showcase a low-risk result."
        : "Load a realistic example and inspect how the score is built.";
    button.innerHTML = `
      <div class="sample-item__head">
        <h3>${sample.title}</h3>
        <span class="sample-tag">${sample.category}</span>
      </div>
      <p>${helperText}</p>
    `;

    button.addEventListener("click", () => {
      elements.messageInput.value = sample.text;
      elements.urlInput.value = sample.url;
      runAnalysis();
      document.getElementById("analyzer").scrollIntoView({ behavior: "smooth", block: "start" });
    });

    elements.sampleList.appendChild(button);
  });
}

function renderTips() {
  elements.tipsList.innerHTML = "";

  tips.forEach((tip) => {
    const item = document.createElement("article");
    item.className = "tip-item";
    item.innerHTML = `<p>${tip}</p>`;
    elements.tipsList.appendChild(item);
  });
}

function renderTrustSignals() {
  elements.trustList.innerHTML = "";

  trustSignals.forEach((signal) => {
    const item = document.createElement("article");
    item.className = "tip-item";
    item.innerHTML = `<p>${signal}</p>`;
    elements.trustList.appendChild(item);
  });
}

function loadDemoSample() {
  const demo = samples.find((sample) => sample.id === "paypal-demo");

  if (!demo) {
    return;
  }

  elements.messageInput.value = demo.text;
  elements.urlInput.value = demo.url;
  document.getElementById("analyzer").scrollIntoView({ behavior: "smooth", block: "start" });
  runAnalysis();
}

function renderResult(result) {
  const { verdictClass, confidenceClass, bannerClass, signalClass } = getVerdictClasses(result.verdict);

  elements.verdictText.textContent = result.verdict;
  elements.verdictText.className = verdictClass;
  elements.threatBanner.textContent = `THREAT LEVEL: ${result.verdict.toUpperCase()}`;
  elements.threatBanner.className = bannerClass;
  elements.indicatorCountText.textContent = `Analysis complete — ${result.indicators.length} indicators detected`;
  elements.confidenceText.textContent = result.confidence;
  elements.confidenceText.className = confidenceClass;
  elements.signalSummaryText.textContent = buildSignalSummary(result);
  elements.signalSummaryText.className = signalClass;
  elements.explanationText.textContent = result.explanation;
  elements.nextActionText.textContent = result.nextAction;
  elements.confidenceSummaryText.textContent = buildConfidenceSummary(result.confidence, result.indicators);
  elements.explanationPanel.classList.remove("is-visible");
  elements.confidencePanelCard.classList.remove("is-visible");
  void elements.explanationPanel.offsetWidth;
  elements.explanationPanel.classList.add("is-visible");
  void elements.confidencePanelCard.offsetWidth;
  elements.confidencePanelCard.classList.add("is-visible");
  animateGauge(result.score);

  if (result.indicators.length) {
    elements.indicatorHeading.textContent = `${result.indicators.length} phishing indicators found`;
    elements.indicatorList.innerHTML = "";

    result.indicators.forEach((indicator) => {
      const card = document.createElement("article");
      card.className = `indicator-card indicator-card--${indicator.severity}`;
      card.style.animationDelay = `${Math.min(220, result.indicators.indexOf(indicator) * 70)}ms`;
      card.innerHTML = `
        <div class="indicator-card__copy">
          <h4>${indicator.label}</h4>
          <p>${indicator.detail}</p>
        </div>
        <span class="indicator-card__score">+${indicator.weight}</span>
      `;
      elements.indicatorList.appendChild(card);
    });
  } else {
    elements.indicatorHeading.textContent = "0 phishing indicators found";
    elements.indicatorList.innerHTML = `
      <div class="empty-state">
        No strong phishing indicators were detected in the current content. Stay cautious if the
        message is unexpected or asks you to take account or payment actions anyway.
      </div>
    `;
  }
}

function setActionState(enabled) {
  elements.copyButton.disabled = !enabled;
  elements.exportButton.disabled = !enabled;
}

function runAnalysis() {
  const message = elements.messageInput.value;
  const url = elements.urlInput.value;

  if (activeAnalysisTimer) {
    window.clearTimeout(activeAnalysisTimer);
  }

  currentResult = null;
  setActionState(false);
  setLoadingState(true);
  activeAnalysisTimer = window.setTimeout(() => {
    currentResult = analyzeThreat(message, url);
    renderResult(currentResult);
    setActionState(true);
    setLoadingState(false);
  }, 700);
}

function resetAnalyzer() {
  if (activeAnalysisTimer) {
    window.clearTimeout(activeAnalysisTimer);
  }

  elements.messageInput.value = "";
  elements.urlInput.value = "";
  currentResult = null;
  elements.scoreValue.textContent = "0";
  elements.verdictText.textContent = "Low Risk";
  elements.verdictText.className = "verdict verdict--low";
  elements.threatBanner.textContent = "THREAT LEVEL: LOW RISK";
  elements.threatBanner.className = "threat-banner threat-banner--low";
  elements.indicatorCountText.textContent = "Analysis complete — 0 indicators detected";
  elements.confidenceText.textContent = "Low";
  elements.confidenceText.className = "confidence-pill confidence-pill--low";
  elements.signalSummaryText.textContent = "No strong phishing indicators detected";
  elements.signalSummaryText.className = "signal-summary signal-summary--low";
  elements.explanationText.textContent =
    "Run an analysis to see whether the message looks risky and why.";
  elements.nextActionText.textContent =
    "PhishingScope will recommend the safest next step based on the detected risk.";
  elements.confidenceSummaryText.textContent =
    "Confidence increases when multiple strong indicators point to the same phishing pattern.";
  elements.explanationPanel.classList.remove("is-visible");
  elements.confidencePanelCard.classList.remove("is-visible");
  elements.gaugeNeedle.style.transform = "translateX(-50%) rotate(-90deg)";
  elements.indicatorHeading.textContent = "Run an analysis to see findings";
  elements.indicatorList.innerHTML = `
    <div class="empty-state">
      PhishingScope checks for urgency, credential requests, payment pressure, suspicious links,
      brand spoofing, impersonation patterns, and other common scam behavior.
    </div>
  `;
  setActionState(false);
  setLoadingState(false);
}

async function copyResult() {
  if (!currentResult) {
    return;
  }

  const payload = [
    `Risk score: ${currentResult.score}/100`,
    `Verdict: ${currentResult.verdict}`,
    "Red flags:",
    ...currentResult.redFlags.map((flag) => `- ${flag}`),
    "",
    `Explanation: ${currentResult.explanation}`,
    `Recommended next action: ${currentResult.nextAction}`
  ].join("\n");

  try {
    await navigator.clipboard.writeText(payload);
    const originalText = elements.copyButton.textContent;
    elements.copyButton.textContent = "Copied";
    window.setTimeout(() => {
      elements.copyButton.textContent = originalText;
    }, 1400);
  } catch {
    window.alert("Copy failed on this browser. You can still export the result as JSON.");
  }
}

function exportResult() {
  if (!currentResult) {
    return;
  }

  const payload = {
    message: elements.messageInput.value,
    url: elements.urlInput.value,
    ...currentResult
  };

  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const href = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = href;
  anchor.download = "phishingscope-analysis.json";
  anchor.click();
  URL.revokeObjectURL(href);
}

elements.analyzeButton.addEventListener("click", runAnalysis);
elements.demoButton.addEventListener("click", loadDemoSample);
elements.heroDemoButton.addEventListener("click", loadDemoSample);
elements.resetButton.addEventListener("click", resetAnalyzer);
elements.copyButton.addEventListener("click", copyResult);
elements.exportButton.addEventListener("click", exportResult);

renderSamples();
renderTips();
renderTrustSignals();
resetAnalyzer();
