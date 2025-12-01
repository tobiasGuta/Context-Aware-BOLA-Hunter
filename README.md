# Context-Aware BOLA Hunter

**A Burp Suite Extension for detecting Broken Object Level Authorization (BOLA/IDOR) in complex APIs.**

![Java](https://img.shields.io/badge/Java-ED8B00?style=for-the-badge&logo=java&logoColor=white) ![Burp Suite](https://img.shields.io/badge/Burp_Suite-FF6633?style=for-the-badge&logo=burpsuite&logoColor=white) ![Security](https://img.shields.io/badge/Cybersecurity-Bug_Bounty-red?style=for-the-badge)

## The Problem
Standard vulnerability scanners operate on a "Replay" basis. They take a request and replay it with a different cookie.
* **The Flaw:** Modern APIs often require specific, dynamic IDs (e.g., UUIDs) to function. If you try to access `GET /api/document/123` as an attacker, but valid documents use UUIDs like `550e8400-e29b...`, standard tools fail to guess the ID.

## The Solution
**Context-Aware BOLA Hunter** solves this by maintaining a dynamic "Global Pool" of valid object IDs harvested from high-privileged accounts. It then injects these known valid IDs into the requests of a low-privileged attacker.

---

## Key Features

* **Context-Aware Harvesting:** Automatically scrapes UUIDs, Emails, and Integer IDs from HTTP response bodies and URL paths.
* **Smart Injection:** Supports both **Parameter Injection** (`?id=...`) and **REST Path Injection** (`/api/user/UUID/data`).
* **Surgical Control:** A "Live Hunt" dashboard allows you to specify **which** harvested IDs to inject (e.g., "Only attack using the Admin's UUID").
* **Dynamic Configuration:** Add, edit, and toggle Regex rules on the fly without reloading the extension.
* **Persistence:** Your custom Regex rules and settings are saved automatically between Burp restarts.
* **Safety Rails:**
    * **Attack Mode Toggle:** A master "Kill Switch" to prevent accidental testing.
    * **Repeater Safe:** Automatically ignores traffic from Burp Repeater so it doesn't interfere with manual debugging.
    * **Self-Injection Protection:** Prevents swapping an ID with itself.

---

## Installation

### Prerequisites
* **Burp Suite Professional or Community**
* **Java JDK 17+** (Required for the Montoya API)

### Building from Source
1.  Clone this repository.
2.  Build the JAR file using Gradle:
    ```bash
    ./gradlew jar
    ```
    *(The output file will be in `build/libs/BolaHunter-1.0.jar`)*

### Loading into Burp
1.  Open Burp Suite.
2.  Go to **Extensions** -> **Installed**.
3.  Click **Add**.
4.  Select **Extension type: Java**.
5.  Select the `.jar` file you just built.

---

## Usage Guide

### 1. The Harvest (Phase A)
* Log into your target application as a **High-Privileged User** (e.g., Admin).
* Browse the application. The extension will passively scan response bodies and URLs.
* Check the **"BOLA Hunter"** tab. You will see captured IDs appearing in the "Live Hunt" table.

### 2. Selection (The Setup)
* Look at the "Live Hunt" table.
* **Check the box** next to the specific ID you want to test (e.g., the Victim's UUID).
* Uncheck any "noise" IDs (like generic image IDs).

### 3. The Attack (Phase B)
* Log out and log back in as a **Low-Privileged User** (Attacker).
* Toggle the **"ATTACK MODE"** button to **ON** (Green).
* Browse the application normally (e.g., view your own profile).
* The extension will automatically intercept your requests and swap your ID with the Victim's ID.
* **Check the Logs/Logger:** If the server responds with `200 OK` and sensitive data, you have found a BOLA vulnerability.

---

## Configuration (Settings Tab)

You can define custom Regex patterns to match any API structure.

| Rule Name | Default Pattern | Description |
| :--- | :--- | :--- |
| **UUID** | `[0-9a-f]{8}-...` | Matches standard v4 UUIDs. |
| **Email** | `...+@.+\..+` | Matches email addresses. |
| **Int ID** | `\b[0-9]{4,10}\b` | Matches integers (4-10 digits) to avoid false positives. |
| **User Ref** | `usr_[a-zA-Z0-9]+` | Matches custom IDs like Stripe (`usr_123`). |

* *Note: Uncheck a rule in the settings table to temporarily disable it.*

https://github.com/user-attachments/assets/5e5bba9c-881c-4c89-8641-dcd9e9377c9f

---

## Tech Stack

* **Language:** Java 17 / 21
* **Framework:** Burp Suite Montoya API (v2023.12.1)
* **UI:** Java Swing (GridBagLayout, JTables)
* **Build System:** Gradle

---

## Disclaimer
This tool is for educational purposes and authorized security testing only. Using this tool on networks or systems without permission is illegal. The author assumes no responsibility for misuse.
