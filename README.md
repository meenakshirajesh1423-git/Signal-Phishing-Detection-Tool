# Signal - local phishing-awareness demo

Signal is a web app with a Python backend. It can analyze messages with explainable local rules, or optionally use a vision-capable Ollama model running on the same computer. It never saves message or screenshot content. It stores only anonymous, combined training totals in a local SQLite database.

Signal currently has no accounts, sign-in, or Google login. It opens directly in guest mode on this device; the “Guest session” label is only a status indicator, not a user profile. Google sign-in is intentionally not included because the app has no hosted account service and does not need personal identity for local analysis or practice.

## Run locally

1. Make sure Python 3 is installed.
2. Open PowerShell in this folder:

   ```powershell
   cd C:\Users\meena\Downloads\PhishAware
   ```

3. Start the page and backend together:

   ```powershell
   python server.py
   ```

4. Open <http://127.0.0.1:8765>.
5. To stop the backend, return to PowerShell and press **Ctrl+C**.

Keep the server running while using the app. Do not expose or port-forward this demo server to the internet.

## Optional local AI and screenshot analysis

Rule-based analysis works without an AI installation. To enable the **Use local AI for this analysis** option and screenshot inspection:

1. Install Ollama for Windows from <https://ollama.com/download>.
2. In PowerShell, download the default vision-capable model:

   ```powershell
   ollama pull qwen2.5vl:3b
   ```

3. Keep Ollama running, then start Signal with `python server.py` and refresh the page.
4. Open **Visual & sender clues**, enable local AI, and optionally select a PNG, JPEG, or WebP screenshot up to 5 MB.

The page shows whether Ollama and the configured model are ready. If they are unavailable, rule-only analysis remains available and an explicit error explains what needs attention. To choose another compatible model before starting Signal, set `SIGNAL_OLLAMA_MODEL` in PowerShell; that model must support image input for screenshot analysis. Signal contacts only the Ollama service on the same computer (`127.0.0.1:11434` by default); non-loopback Ollama URLs are rejected. The model may produce inaccurate or invented findings, so its assessment and confidence are advisory, not a guarantee. Review screenshots first because they may contain sensitive information.

## What the backend does

The browser sends requests to a small local JSON API. The analyzer has separate Email, Text message, Link, and Phone number modes. It checks submitted text, URLs, sender details, number formatting, and manually described visual clues, then returns a clear verdict, a 0–100 illustrative risk score, warning explanations, supporting evidence excerpts, and a recommended next step. Phone analysis only checks basic formatting; it cannot establish a number's owner, identity, reputation, or safety. If explicitly enabled, the app sends the submitted content and optional screenshot to Ollama on this computer and combines its advisory findings with the rule checks. Link addresses are inspected as text only; the server never visits them. Analysis inputs are not written to the database or server logs.

The score is deterministic and rule-based: each distinct warning uses its documented weight in `RISK_WEIGHTS` in `server.py` (5–30 points, based on the severity of the behavior), the points are added and capped at 100. Bands are 0–19 low signal, 20–44 caution, 45–69 elevated risk, and 70–100 high risk. The score is not a probability and local-AI opinions do not add points. Unit tests cover the weights' determinism, score cap, evidence, and low-signal caveat. This is a transparent demo rubric, not a validated production risk model.

Available endpoints:

- `GET /api/health` — check that the local backend is running and report local Ollama/model readiness.
- `POST /api/analyze` — run rule checks or optional local AI analysis. Optional screenshot data is accepted only when local AI is enabled.
- `GET /api/training/stats` — read aggregate practice totals.
- `POST /api/training/start` — record an authorized local campaign session (the checkbox is a demo gate, not authenticated admin access).
- `POST /api/training/record` — add an anonymous fictional-inbox choice, including inert simulated link interactions.
- `POST /api/training/quiz/complete` — add one aggregate five-question baseline or follow-up quiz score; individual answers are never sent or stored.
- `POST /api/training/certificate` — send an optional certificate name to the local backend and receive certificate details. The name is returned for display but never stored.
- `POST /api/training/certificate/download` — generate a PDF on the local backend and return it as a download. The browser saves it to the user's configured Downloads location; the backend does not save the PDF or name.
- `DELETE /api/training/stats` — clear those totals.

The training flow starts with a five-message baseline quiz, then presents three fictional `.example` inbox scenarios with report, ignore, or interact choices; the simulated link is inert and shows a lesson instead of navigating. A five-message follow-up quiz and completion certificate finish the flow. The authorization checkbox gates practice but is not a sign-in or verified administrator permission system. The app does not send emails, open external links, collect credentials, or record participant identities, individual answers, or response histories.

Aggregate totals are stored at `data/training.sqlite3`, shown in **Practice insights** below the Training Lab, and can be cleared there. The dashboard displays email/text analyses, simulated interactions, reports, completion rate, and aggregate average quiz scores before/after training. These counts apply to this device only. Before completed quizzes exist, the chart shows an empty state—not invented sample data. The before/after averages are aggregate, not individually paired, and do not prove training caused a score change.

The Practice insights section also links to practical phishing advice from CISA and NIST guidance for designing and evaluating cybersecurity awareness programs.

After all three scenarios, participants receive a completion certificate. The optional name is sent only to the backend on this computer so it can generate the PDF; it is not saved. The demo certificate defaults to Alice. Select **Download certificate PDF** and the browser saves the PDF to its configured download location. This is completion recognition, not a professional accreditation.

## Limitations

The analyzer does not use live threat-intelligence feeds. Rule checks can miss attacks or flag legitimate messages; local AI can also be wrong or invent evidence. Confirm unexpected requests through a known, trusted channel. Training totals are stored on this computer and are not shared across a team or devices. The server intentionally binds to loopback only; organization-wide reporting needs a separately secured, authenticated deployment and is not included.

## Run tests

```powershell
python -m unittest -v
```
