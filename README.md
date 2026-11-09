# Signal – AI-Powered Phishing Detection & Awareness Platform

**Signal** is a locally running phishing detection and cybersecurity awareness application. It helps users identify suspicious messages, inspect links, understand potential phishing indicators, and practise recognising phishing attempts through safe, fictional training scenarios.

The application combines explainable rule-based detection with optional local AI analysis using Ollama.

## Features

### 1. Phishing Detection
- Analyse emails and text messages.
- Inspect suspicious URLs without opening them.
- Check phone-number formatting.
- Identify warning signs such as urgency, suspicious domains, requests for sensitive information, and mismatched links.
- Display an illustrative risk score, findings, supporting evidence, and recommended next steps.

### 2. Optional Local AI Analysis
- Integrates with Ollama for local AI-powered analysis.
- Supports optional screenshot analysis using a vision-capable model.
- Combines AI observations with rule-based findings.
- AI results are advisory and may not always be accurate.

### 3. Phishing Awareness Training Lab
- Includes fictional phishing scenarios.
- Provides a baseline quiz and a follow-up quiz.
- Lets participants practise reporting, ignoring, or interacting with simulated messages.
- Simulated links do not navigate to real websites.
- Provides lessons explaining the warning signs in each scenario.
- Generates a training completion certificate.

### 4. Training Insights
- Displays combined training statistics.
- Tracks simulated interactions, reports, quiz averages, and completion metrics.
- Stores aggregate training totals locally using SQLite.
- Does not store individual quiz answers or participant identities.

### 5. Privacy-Focused Design
- Runs on the local computer.
- Does not send messages or screenshots to a cloud AI service.
- Does not open submitted links.
- Does not collect passwords or credentials.
- Does not save message or screenshot content.
- Optional AI analysis sends content only to the local Ollama service.

## Technologies Used

- **Frontend:** HTML, CSS, JavaScript
- **Backend:** Python
- **Database:** SQLite
- **Optional AI:** Ollama with a vision-capable model
- **Testing:** Python unittest

## Project Structure

```text
Signal/
│
├── index.html          # Main application interface
├── styles.css          # Application styling
├── app.js              # Frontend interactions and API requests
├── server.py           # Local Python server and backend API
├── test_server.py      # Backend unit tests
├── README.md           # Project documentation
└── data/               # Local SQLite training database (created at runtime)
```

## Getting Started

### Prerequisites

- Python 3 installed on your computer.
- A modern web browser.

Optional:
- Ollama installed if you want to use local AI and screenshot analysis.

### Installation

**1. Clone the repository**

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
```

**2. Open the project folder**

```bash
cd Signal
```

**3. Start the application**

```bash
python server.py
```

**4. Open the application**

Visit the following address in your browser:

```text
http://127.0.0.1:8765
```

Keep the Python server running while using the application.

To stop the server, return to the terminal and press `Ctrl + C`.

## Optional: Enable Local AI

Rule-based detection works without installing Ollama.

To enable optional local AI analysis:

1. Install Ollama from https://ollama.com/download.
2. Open PowerShell or a terminal.
3. Download the default model:

```bash
ollama pull qwen2.5vl:3b
```

4. Keep Ollama running.
5. Start Signal using `python server.py`.
6. In the application, open **Visual & sender clues** and enable **Use local AI for this analysis**.

The application checks whether Ollama and the configured model are available. If they are unavailable, rule-based analysis can still be used.

## Running the Tests

Run the backend unit tests from the project folder:

```bash
python -m unittest -v
```

The tests cover phishing indicators, risk scoring, URL inspection, screenshot validation, local AI response handling, and training statistics.

## Important Limitations

- Detection results are based on heuristic rules and optional local AI analysis.
- A low risk score does not guarantee that a message or link is safe.
- The risk score is an illustrative rule-based score, not a probability.
- The application does not use live threat-intelligence feeds.
- Phone-number analysis checks formatting only; it cannot verify ownership or reputation.
- Training statistics are local to the device and are not shared across multiple users.
- The training authorization checkbox is a demo safeguard, not authenticated administrator access.
- This is an educational demonstration, not a production security solution.



## Project Purpose

Signal aims to make phishing awareness more practical by combining explainable detection, safe simulated scenarios, and training insights in one application.

The goal is not only to identify suspicious messages, but also to help users understand *why* they may be suspicious and how to respond safely.

