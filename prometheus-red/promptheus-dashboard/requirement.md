# PROMPTHEUS - User Guide

## 1. Introduction

**PROMPTHEUS** is an automated Red-Teaming platform for Large Language Models (LLMs). This tool is designed to help security engineers and developers test AI resilience against attacks such as Jailbreak, Prompt Injection, and Personally Identifiable Information (PII) leakage.

---

## 2. Key Features

### 2.1. Target Management

The system supports testing on various types of endpoints:

- **Gemini 3.1 Pro/Flash**: Directly test Google's latest AI models.
- **Slack Integration**: Simulate attacks on bots integrated within enterprise environments.
- **Local Endpoint**: Connect to locally running models or custom APIs.

### 2.2. Attack Skill Library

Provides pre-designed attack templates:

- **Jailbreak**: Attempts to bypass the model's ethical safeguards.
- **Prompt Injection**: Injects hidden commands to alter AI behavior.
- **PII Leakage**: Checks if the model inadvertently reveals personal information.
- **System Prompt Reveal**: Techniques to force the model to display its original system instructions.

### 2.3. Probing & Attacking Mechanism

- **Automation**: Sends batches of payload variations to the target.
- **Custom Objectives**: Users can define specific objectives for each attack run.
- **Attempt Configuration**: Adjust the number of payloads sent in a single session.

### 2.4. AI Judge

Uses an independent AI model to evaluate results:

- **Vulnerability Analysis**: Determines if the attack was successful.
- **Risk Score**: Provides a score from 0-100 based on severity.
- **Classification**: Automatically categorizes the type of vulnerability detected.
- **Mitigation Advice**: Offers technical advice to patch the vulnerability.

### 2.5. Real-time Dashboard

- **Timeline**: Monitor the attack process in real-time.
- **Payload Details**: View details of each command sent and the response received.
- **System Status**: Monitor latency and success rates of probes.

### 2.6. History & Settings

- **Session Management**: Store and review previous Red-Teaming results.
- **Data Deletion**: Supports deleting individual sessions or the entire history.
- **API Configuration**: Securely manage API keys (Gemini, Slack).

---

## 3. Interface & Workflow Guide (UI/UX Guide)

### 3.1. Dashboard Layout

The interface is divided into 3 main columns to optimize the workflow:

- **Left Column (Sidebar)**: Where you manage **Targets** and **Skills**.
- **Middle Column (Workstation)**: The area for configuration and real-time attack monitoring.
- **Right Column (History)**: A list of past work sessions (Sessions).

### 3.2. Execution Process & Click Actions

1. **Select Target & Skill**:
   - Click on a **Target** in the left column (e.g., "Gemini 3.1 Pro").
   - Click on a **Skill** right below it (e.g., "Jailbreak").
2. **Configure Objective**:
   - In the center area, enter the content you want to attack in the **"Attack Objective"** box.
   - Adjust the number of attempts by clicking the number buttons (1, 3, 5, 10) in the **"Attempts"** section.
3. **Activate Attack**:
   - Click the **"Launch Probe"** button (neon blue) at the bottom right corner to start.
   - The system will automatically switch to "Attacking" mode, disabling buttons to focus on processing.

### 3.3. Data Display After Completion

After the probing process ends, data will appear in the following locations:

#### A. Timeline (Center Area)

- Results will appear as cards in chronological order.
- **Color**: Red cards with a warning icon mean a vulnerability was found (**Vulnerable**). Gray cards mean the target is safe (**Secure**).
- **Quick Info**: Displays the Payload used and a summary of the AI Judge's reasoning.

#### B. Detailed Analysis

- **How to view**: Click directly on any card in the Timeline.
- **Display content**: A panel will slide out (or overlay) showing:
  - **Payload**: The full command sent.
  - **Raw Response**: The original response from the target model.
  - **Judge Verdict**: Detailed evaluation from the AI Judge (Risk Score, Category, Mitigation).

#### C. History Column (Right Column)

- The session that just finished will be saved in the **History** list.
- You can click on any past session to review the entire Timeline and the results of that attack run.

---

## 4. Quick Start

1. **Click Target** -> **Click Skill**.
2. **Enter Objective** (Attack goal).
3. **Click Launch Probe**.
4. **Wait for Timeline to complete**.
5. **Click on red cards** to view detailed vulnerability reports.

---

## 5. Technical Architecture

- **Frontend**: React, Tailwind CSS, Lucide Icons, Framer Motion.
- **Backend**: Node.js Express server.
- **Database**: SQLite (Stores sessions and results).
- **AI Engine**: Google Gemini API (Used for both payload generation and security judging).

---

_This document was compiled to help users understand the functions of the PROMPTHEUS system._
