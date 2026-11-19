
# CloudGuard AI

**Cloud Security Posture and Attack Path Analyzer**
CloudGuard AI is a Python-based cybersecurity project designed to assess cloud configuration risks, identify IAM security weaknesses, detect potential attack paths, prioritize security findings, and generate remediation recommendations.

The project demonstrates an integrated cloud security assessment workflow using FastAPI, Python, and automated security analysis modules.

## Project Overview

CloudGuard AI combines multiple security assessment components into one API-driven platform.

Its objective is to help security analysts identify misconfigurations, excessive privileges, insecure resource exposure, and potential paths to sensitive data.

## Key Features

- Cloud configuration security scanning.
- IAM privilege and account security analysis.
- Attack path detection using explicit identity-resource relationships.
- Security risk prioritization.
- Automated remediation recommendations.
- Full security assessment through a single API endpoint.
- Automatic JSON security report generation.
- Automated testing with Pytest.

## Architecture

```text
                 CloudGuard AI
                       |
                       v
                 FastAPI Application
                       |
          +------------+------------+
          |            |            |
          v            v            v
      Cloud Scan   IAM Analyzer   Attack Path
          |            |            |
          +------------+------------+
                       |
                       v
               Risk Prioritization
                       |
                       v
              Recommendation Engine
                       |
                       v
                Report Generator
                       |
                       v
                 JSON Reports
```

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core application |
| FastAPI | REST API |
| Pydantic | Request validation |
| Uvicorn | API server |
| Pytest | Automated testing |
| JSON | Assessment data and reports |
| Linux / Kali Linux | Development environment |

## Project Structure

```text
CloudGuard-AI/
|
├── app/
│   ├── analyzers/
│   │   ├── attack_path.py
│   │   ├── iam_analyzer.py
│   │   ├── recommendation_engine.py
│   │   └── risk_prioritizer.py
│   │
│   ├── scanners/
│   │   └── cloud_config.py
│   │
│   ├── reports/
│   │   └── report_generator.py
│   │
│   └── main.py
│
├── data/
├── docs/
├── reports/
├── tests/
│
├── requirements.txt
├── README.md
└── .gitignore
```

## Security Assessment Modules

### 1. Cloud Configuration Scanner

Checks cloud resource configurations for:

- Publicly accessible storage.
- Disabled encryption.
- Disabled security logging.

### 2. IAM Security Analyzer

Identifies:

- Excessive administrator privileges.
- Disabled multi-factor authentication.
- Inactive user accounts.

### 3. Attack Path Analyzer

Identifies potential paths between explicitly associated identities and sensitive resources.

It considers:

- Administrator privileges.
- MFA configuration.
- Public resource exposure.
- Sensitive data classification.

### 4. Risk Prioritization Engine

Assigns severity-based risk scores:

| Severity | Score | Priority |
|---|---:|---|
| CRITICAL | 100 | IMMEDIATE |
| HIGH | 75 | URGENT |
| MEDIUM | 50 | MODERATE |
| LOW | 25 | LOW |

These are prioritization scores, not probabilities of exploitation.

### 5. Recommendation Engine

Generates remediation recommendations for detected security findings.

### 6. Report Generator

Automatically generates timestamped JSON reports containing:

- Assessment summary.
- Cloud configuration findings.
- IAM analysis.
- Attack path results.
- Risk prioritization.
- Remediation recommendations.

## Installation

Clone the repository or download the project.

Navigate into the project directory:

```bash
cd CloudGuard-AI
```

Create a virtual environment:

```bash
python3 -m venv venv
```

Activate it:

```bash
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Running the Application

Start the FastAPI server:

```bash
uvicorn app.main:app --reload --port 8001
```

Open the API documentation:

http://127.0.0.1:8001/docs

Health endpoint:

http://127.0.0.1:8001/health

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | / | Project information |
| GET | /health | Health check |
| POST | /scan/config | Cloud configuration scan |
| POST | /analyze/iam | IAM analysis |
| POST | /analyze/attack-path | Attack path analysis |
| POST | /prioritize/risks | Risk prioritization |
| POST | /recommendations/generate | Generate recommendations |
| POST | /reports/generate | Generate security report |
| POST | /assess/full | Complete assessment |

## Running Tests

Run the complete test suite:

```bash
python -m pytest -v
```

### Current Test Results

The development test run completed successfully:

- 30 tests passed.
- 0 tests failed.
- Full assessment integration test passed.

## Example Use Case

A simulated cloud environment contains:

- An administrator identity with excessive privileges.
- MFA disabled for the administrator.
- Publicly accessible storage.
- Sensitive data stored in that resource.

CloudGuard AI analyzes the supplied configuration and identity-resource relationships, detects potential security risks, prioritizes findings, and generates remediation recommendations.

## Security Limitations

This project currently operates using supplied assessment data and local simulated environments.

It does not yet perform live AWS or Azure security assessments, automatically retrieve effective IAM permissions, or independently verify real-world attack paths.

Risk scores are rule-based severity values rather than calibrated exploitation probabilities.

Only use the platform against systems and environments for which you have authorization.

## Future Development Roadmap

- AWS security assessment integration using boto3.
- Azure cloud security integration.
- Cloud IAM policy analysis.
- Advanced attack graph modeling.
- CVSS-informed risk scoring.
- Dashboard for security findings.
- PDF assessment reports.
- SIEM and SOC workflow integration.
- AI-assisted security finding analysis.

## Project Purpose

CloudGuard AI is a practical cybersecurity portfolio project demonstrating Python development, API engineering, cloud security concepts, IAM analysis, attack-path modeling, automated security testing, and security reporting.

**Project Status:** Active Development

**Version:** 1.1.0
