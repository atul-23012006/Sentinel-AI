# SentinelAI --- AI-Powered Adaptive Access Control & Insider Threat Detection

> An intelligent enterprise security platform that combines hybrid
> access-control policies with machine-learning-based behavioral anomaly
> detection to identify suspicious activity from authorized or
> compromised users and trigger adaptive security responses.

------------------------------------------------------------------------

## 1. Overview

Modern enterprise applications commonly rely on static authorization
mechanisms such as role-based access control (RBAC). These mechanisms
answer an important question:

> **"Is this user authorized to access this resource?"**

However, authorization alone does not necessarily establish that the
current activity is safe.

A legitimate employee account may be compromised. An authorized employee
may abuse their privileges. A user may suddenly access an unusually
large number of sensitive files or download data at an abnormal time.

**SentinelAI** addresses this gap by combining:

1.  **Authentication and identity management**
2.  **Hybrid access control**
3.  **Security policy enforcement**
4.  **Behavioral monitoring**
5.  **Machine-learning anomaly detection**
6.  **Risk scoring**
7.  **Adaptive security responses**
8.  **Centralized security auditing**
9.  **AI-assisted security-event explanation**

The central design principle is:

> **Authorization determines whether access is permitted by policy;
> behavioral risk determines whether the current activity requires
> additional security controls.**

AI is therefore used as a supporting security layer rather than as an
unrestricted authority that independently grants access.

------------------------------------------------------------------------

## 2. Real-World Problem

Traditional access-control systems primarily rely on predefined roles,
permissions, and attributes.

For example:

``` text
Employee
   |
   +--> Finance Role
           |
           +--> Read Financial Reports
```

If the employee's credentials are compromised, an attacker can
potentially inherit those permissions.

Consider:

``` text
02:13 AM  -> Login
02:14 AM  -> Access 35 confidential files
02:16 AM  -> Download 18 files
02:18 AM  -> Attempt restricted HR access
02:20 AM  -> Attempt database access
```

A static authorization system may continue to allow requests because the
account has valid credentials and permissions.

SentinelAI introduces a behavioral security layer:

``` text
Identity
   +
Access Policy
   +
Context
   +
Historical Behavior
        |
        v
   Risk Analysis
        |
        v
   Adaptive Decision
```

The system can identify patterns associated with:

-   Compromised accounts
-   Insider threats
-   Privilege abuse
-   Unusual access
-   Excessive resource access
-   Potential data exfiltration
-   Repeated authentication failures
-   Policy violations

------------------------------------------------------------------------

## 3. Project Objectives

### Primary objectives

-   Implement a secure authentication and authorization framework.
-   Implement multiple access-control models.
-   Combine access-control decisions through a hybrid policy engine.
-   Record security-relevant events in a centralized audit system.
-   Model normal user behavior.
-   Detect anomalous behavior using machine learning.
-   Convert behavioral anomalies into a security risk score.
-   Dynamically respond to high-risk activity.
-   Provide administrators with understandable security-event
    explanations.

### Secondary objectives

-   Demonstrate practical information-security concepts.
-   Provide measurable ML performance.
-   Create realistic security attack scenarios for testing.
-   Produce an extensible architecture suitable for future security
    features.

------------------------------------------------------------------------

## 4. Key Features

### 4.1 Authentication

The system provides user authentication and account management.

User attributes can include:

-   User ID
-   Username
-   Password hash
-   Role
-   Department
-   Security clearance
-   Device trust status
-   Account status

Passwords should never be stored in plaintext.

------------------------------------------------------------------------

### 4.2 Hybrid Access Control

SentinelAI supports multiple policy dimensions:

#### RBAC --- Role-Based Access Control

Access depends on the user's assigned role.

Example:

``` text
Finance Employee -> Financial Reports
HR Employee      -> HR Records
Administrator    -> Administrative Resources
```

#### MAC --- Mandatory Access Control

Resources have security classifications and users have clearance levels.

Example:

``` text
PUBLIC
CONFIDENTIAL
SECRET
TOP_SECRET
```

A user cannot access a resource whose classification exceeds the user's
permitted clearance.

#### ABAC --- Attribute-Based Access Control

Access is determined using attributes such as:

-   Department
-   Role
-   Device
-   Location
-   Resource type
-   Clearance
-   Employment status

Example:

``` text
IF
    user.department == resource.department
AND
    user.device == TRUSTED
AND
    user.clearance >= resource.classification

THEN
    ALLOW
```

#### TBAC --- Time-Based Access Control

Access depends on temporal conditions.

Example:

``` text
09:00–18:00 -> Allowed
Outside hours -> Additional verification / Denied
```

------------------------------------------------------------------------

## 5. Hybrid Policy Engine

The core authorization component is the **Hybrid Policy Engine**.

Instead of depending on one access-control model, SentinelAI evaluates
several policies.

Example:

``` text
Access Request
      |
      +--> RBAC -> PASS
      |
      +--> MAC  -> PASS
      |
      +--> ABAC -> PASS
      |
      +--> TBAC -> FAIL
      |
      v
Final Policy Decision -> DENY
```

Policy composition can use strategies such as:

### AND

Every required policy must pass.

``` text
RBAC AND MAC AND ABAC AND TBAC
```

### OR

At least one applicable policy may grant access.

``` text
RBAC OR ABAC
```

### Priority

A security-critical denial can override an allow decision.

``` text
MAC DENY
   |
   +--> overrides RBAC ALLOW
```

The exact policy-combination rules should be explicitly documented and
tested rather than hidden inside application code.

------------------------------------------------------------------------

## 6. Behavioral Monitoring

Every security-relevant action generates an event.

Example:

``` json
{
  "userId": "U102",
  "action": "DOWNLOAD",
  "resource": "financial_report.pdf",
  "resourceClassification": "CONFIDENTIAL",
  "timestamp": "02:17:31",
  "location": "Unknown",
  "device": "D904",
  "result": "ALLOWED"
}
```

Potential behavioral features include:

-   Login hour
-   Failed login count
-   Number of resources accessed
-   Number of downloads
-   Request frequency
-   Resource sensitivity
-   Location
-   Device familiarity
-   Access outside normal hours
-   Number of denied requests
-   Historical access patterns

------------------------------------------------------------------------

## 7. AI / Machine Learning Component

### 7.1 Why machine learning?

Security rules are effective for known conditions, but they do not
necessarily describe every possible abnormal user behavior.

Machine learning can identify deviations from learned patterns.

Example:

``` text
Normal behavior:
5–10 files/day
0–2 downloads/day
09:00–18:00 activity

Observed behavior:
47 files in 8 minutes
18 downloads
02:17 login
Unknown device
```

The system can classify this activity as anomalous.

------------------------------------------------------------------------

### 7.2 Initial ML Approach

The recommended first model is:

**Isolation Forest**

Reason:

-   Suitable for anomaly detection
-   Does not require a large set of labeled attack examples
-   Appropriate for behavioral outlier detection
-   Relatively straightforward to evaluate
-   Can be extended with other models later

Possible future models:

-   One-Class SVM
-   Autoencoders
-   Random Forest for supervised classification
-   Gradient boosting models

The project should start with one well-evaluated model rather than
attempting several models without meaningful comparison.

------------------------------------------------------------------------

## 8. Risk Scoring

The anomaly detector produces an anomaly signal that is converted into a
normalized security risk score.

Example:

``` text
Risk Score: 0–100
```

Possible risk factors:

``` text
Login anomaly             -> 20 points
Access-frequency anomaly  -> 30 points
Download anomaly          -> 25 points
Location anomaly          -> 10 points
Device anomaly            -> 15 points
```

The final risk score should be based on a documented scoring strategy.

Example response policy:

    Risk Score Response
  ------------ -----------------------------------
         0--30 Allow and log
        31--60 Allow and increase monitoring
        61--80 Require additional authentication
       81--100 Block and generate security alert

These thresholds are project parameters and should be experimentally
evaluated rather than presented as universal security standards.

------------------------------------------------------------------------

## 9. Adaptive Security

This is one of the project's key features.

A user may have valid authorization but still trigger an adaptive
response.

Example:

``` text
RBAC       -> PASS
MAC        -> PASS
ABAC       -> PASS
TBAC       -> PASS

ML Risk    -> 91/100

                    |
                    v

            Adaptive Decision
                    |
              +-----+-----+
              |           |
            MFA         BLOCK
```

The project therefore separates:

### Authorization

> Is the user permitted to perform this action?

from:

### Behavioral risk

> Does the current activity look suspicious?

This separation makes the architecture easier to reason about and
reduces the risk of using an opaque AI model as the sole security
authority.

------------------------------------------------------------------------

## 10. Audit and Security Logging

All security-sensitive events should be recorded.

Example:

``` text
------------------------------------------------
ACCESS EVENT
------------------------------------------------
User          : U102
Resource      : ResearchData.pdf
Action        : READ
Timestamp     : 14:42:21

RBAC          : PASS
MAC           : PASS
ABAC          : FAIL
TBAC          : PASS

Policy        : DENIED
Risk Score    : 67
Reason        : Department mismatch
------------------------------------------------
```

The audit system should support:

-   Authentication events
-   Failed authentication attempts
-   Access requests
-   Policy decisions
-   Denied requests
-   Risk-score changes
-   Security alerts
-   Adaptive responses
-   Administrative actions

------------------------------------------------------------------------

## 11. AI Security Analyst

An optional LLM layer can transform technical security events into
administrator-friendly explanations.

Example input:

``` text
Risk Score: 93
Files Accessed: 31
Downloads: 15
Login Time: 02:17
Device: Unknown
```

Possible generated explanation:

``` text
HIGH-RISK SECURITY EVENT

The account accessed 31 confidential resources within a short
period outside its typical working hours. The request originated
from an unfamiliar device and included multiple downloads.

Possible concerns:
- Credential compromise
- Privilege misuse
- Potential data exfiltration

Recommended actions:
1. Require additional authentication.
2. Review recent account activity.
3. Investigate the unfamiliar device.
4. Review downloaded resources.
```

The LLM should explain and summarize evidence produced by the security
system. It should not independently override deterministic
access-control policies.

------------------------------------------------------------------------

## 12. System Architecture

``` text
                        +----------------+
                        |     Client     |
                        +-------+--------+
                                |
                                v
                        +----------------+
                        | Authentication |
                        +-------+--------+
                                |
                                v
                        +----------------+
                        | Access Request |
                        +-------+--------+
                                |
                  +-------------+-------------+
                  |                           |
                  v                           v
          +---------------+           +---------------+
          | Policy Engine |           |  Risk Engine  |
          |               |           |               |
          | RBAC          |           | Behavioral    |
          | MAC           |           | Features      |
          | ABAC          |           |      |        |
          | TBAC          |           |      v        |
          +-------+-------+           | ML Anomaly    |
                  |                   | Detection     |
                  |                   +-------+-------+
                  |                           |
                  +-------------+-------------+
                                |
                                v
                       +------------------+
                       | Decision Engine  |
                       +--------+---------+
                                |
                +---------------+---------------+
                |               |               |
                v               v               v
              ALLOW           MFA             BLOCK
                |               |               |
                +---------------+---------------+
                                |
                                v
                       +------------------+
                       |  Audit Service   |
                       +--------+---------+
                                |
                                v
                         +-------------+
                         | PostgreSQL  |
                         +-------------+
                                |
                                v
                       +------------------+
                       | Admin Dashboard |
                       +------------------+
                                |
                                v
                       +------------------+
                       |  AI Analyst      |
                       +------------------+
```

------------------------------------------------------------------------

## 13. Suggested Technology Stack

### Backend

-   Python
-   FastAPI

### Database

-   PostgreSQL

### Machine Learning

-   Python
-   Pandas
-   NumPy
-   Scikit-learn
-   Isolation Forest

### AI

-   LLM API or suitable local LLM
-   Used primarily for incident explanation and security summaries

### Frontend

-   React
-   HTML/CSS/JavaScript

### Development / Deployment

-   Git
-   GitHub
-   Docker
-   Docker Compose

------------------------------------------------------------------------

## 14. Proposed Database Design

### Users

``` text
users
--------------------------------
user_id
username
password_hash
role
department
clearance_level
device_trust
account_status
created_at
```

### Resources

``` text
resources
--------------------------------
resource_id
resource_name
owner_id
classification
department
required_role
created_at
```

### Policies

``` text
policies
--------------------------------
policy_id
policy_type
policy_name
rule_definition
priority
enabled
created_at
```

### Access Events

``` text
access_events
--------------------------------
event_id
user_id
resource_id
action
timestamp
location
device_id
policy_decision
risk_score
final_decision
reason
```

### Security Alerts

``` text
security_alerts
--------------------------------
alert_id
user_id
event_id
alert_type
risk_score
severity
description
status
created_at
```

------------------------------------------------------------------------

## 15. Example End-to-End Scenario

### Scenario A --- Normal access

``` text
User:
Finance Employee

Request:
READ -> Financial_Report.pdf

RBAC -> PASS
MAC  -> PASS
ABAC -> PASS
TBAC -> PASS

AI Risk -> 12/100

FINAL -> ALLOW
```

------------------------------------------------------------------------

### Scenario B --- Suspicious behavior

``` text
User:
Finance Employee

02:17 AM -> Login
02:18 AM -> 35 confidential files accessed
02:19 AM -> 18 downloads
02:20 AM -> Unknown device
```

ML result:

``` text
Anomaly Score -> HIGH
Risk Score     -> 91/100
```

Response:

``` text
FINAL -> BLOCK
ACTION -> Security Alert
ACTION -> Audit Event
```

------------------------------------------------------------------------

### Scenario C --- Moderate risk

``` text
Policy -> ALLOW
AI Risk -> 72/100
```

Response:

``` text
FINAL -> ADDITIONAL AUTHENTICATION REQUIRED
```

After successful additional authentication:

``` text
ACCESS -> ALLOWED
EVENT -> LOGGED
```

------------------------------------------------------------------------

## 16. Attack / Test Scenarios

The project should include controlled test scenarios.

### Test 1 --- Brute-force-like authentication activity

``` text
Multiple failed login attempts
        |
        v
Anomalous authentication pattern
        |
        v
Risk increase
```

### Test 2 --- Credential compromise simulation

``` text
Normal user
        |
        v
Unusual login time
        |
        v
Unknown device
        |
        v
Unusual resource access
```

### Test 3 --- Potential data exfiltration

``` text
Normal download rate
        |
        v
Sudden large number of downloads
        |
        v
Anomaly detected
        |
        v
High risk
        |
        v
Block / MFA
```

### Test 4 --- Privilege abuse

``` text
Authorized user
        |
        v
Attempts unusual sensitive-resource access
        |
        v
Policy + behavioral evaluation
```

### Test 5 --- Policy violation

``` text
User clearance < Resource classification
        |
        v
MAC DENY
        |
        v
Access blocked
```

------------------------------------------------------------------------

## 17. Machine Learning Evaluation

A resume-worthy implementation should measure model performance.

Possible metrics:

-   Precision
-   Recall
-   F1-score
-   False Positive Rate
-   False Negative Rate
-   ROC-AUC where applicable
-   Confusion Matrix

Example result format:

``` text
Model: Isolation Forest

Precision:        XX%
Recall:           XX%
F1 Score:         XX%
False Positive:   XX%
```

The actual values must come from experiments and should never be
fabricated.

------------------------------------------------------------------------

## 18. Project Development Roadmap

### Phase 1 --- Foundation

-   Project architecture
-   PostgreSQL setup
-   Authentication
-   User management
-   Resource management

### Phase 2 --- Access Control

-   RBAC
-   MAC
-   ABAC
-   TBAC
-   Hybrid policy engine

### Phase 3 --- Security Monitoring

-   Audit logging
-   Security-event model
-   Security dashboard
-   Controlled attack scenarios

### Phase 4 --- Machine Learning

-   Behavioral feature engineering
-   Dataset creation
-   Isolation Forest
-   Anomaly scoring
-   Model evaluation

### Phase 5 --- Adaptive Security

-   Risk scoring
-   MFA/challenge workflow
-   Automatic blocking
-   Security alerts

### Phase 6 --- AI Analyst

-   LLM integration
-   Incident summaries
-   Security explanations
-   Recommended investigation actions

### Phase 7 --- Finalization

-   Unit testing
-   Integration testing
-   Security testing
-   ML evaluation
-   Dockerization
-   Documentation
-   Demo preparation

------------------------------------------------------------------------

## 19. Recommended Project Scope

### Minimum Viable Product

``` text
Authentication
     +
RBAC
     +
Audit Logging
     +
Basic Anomaly Detection
     +
Risk Score
```

### Strong College Project

``` text
Authentication
     +
RBAC + MAC + ABAC + TBAC
     +
Hybrid Policy Engine
     +
Audit Logging
     +
ML Anomaly Detection
     +
Risk Scoring
     +
Adaptive Responses
```

### Resume-Ready Version

``` text
Everything above
     +
Realistic behavioral dataset
     +
Model evaluation
     +
Security attack simulations
     +
Admin dashboard
     +
AI incident explanations
     +
Automated testing
     +
Docker deployment
     +
Complete technical documentation
```

The recommended target is the **Resume-Ready Version**.

------------------------------------------------------------------------

## 20. Project Structure

A possible structure is:

``` text
SentinelAI/
│
├── backend/
│   ├── app/
│   │   ├── auth/
│   │   ├── users/
│   │   ├── resources/
│   │   ├── policies/
│   │   ├── audit/
│   │   ├── alerts/
│   │   ├── risk/
│   │   └── ai/
│   │
│   ├── tests/
│   └── requirements.txt
│
├── ml/
│   ├── data/
│   ├── preprocessing/
│   ├── training/
│   ├── evaluation/
│   └── models/
│
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── services/
│   │   └── dashboard/
│   └── package.json
│
├── database/
│   ├── schema.sql
│   └── seed.sql
│
├── docker/
│
├── docs/
│   ├── architecture.md
│   ├── security-model.md
│   ├── ml-evaluation.md
│   └── threat-model.md
│
├── docker-compose.yml
└── README.md
```

------------------------------------------------------------------------

## 21. Security Considerations

SentinelAI itself must be designed securely.

Important considerations include:

-   Never store plaintext passwords.
-   Validate and sanitize input.
-   Use parameterized database queries.
-   Protect authentication tokens.
-   Apply least privilege.
-   Separate administrative privileges.
-   Protect audit logs from unauthorized modification.
-   Avoid exposing sensitive information in error messages.
-   Secure API endpoints.
-   Validate resource ownership.
-   Protect ML/AI endpoints from abuse.
-   Treat LLM-generated recommendations as advisory.
-   Maintain deterministic policy enforcement for authorization.
-   Test for privilege escalation and policy bypass.

------------------------------------------------------------------------

## 22. Threat Model

Potential threats to the system include:

  -----------------------------------------------------------------------
  Threat                  Example                 Mitigation
  ----------------------- ----------------------- -----------------------
  Credential compromise   Stolen password         Behavioral analysis +
                                                  additional
                                                  authentication

  Insider misuse          Excessive sensitive     Risk scoring + audit
                          access                  

  Privilege abuse         Unauthorized sensitive  Hybrid policies
                          activity                

  Data exfiltration       Mass downloads          Behavioral anomaly
                                                  detection

  Brute force             Repeated failed logins  Rate limiting + alerts

  Policy bypass           Manipulated request     Server-side policy
                                                  enforcement

  Audit tampering         Modified logs           Restricted privileges +
                                                  integrity controls

  AI misuse               Malicious prompt/input  Input validation +
                                                  constrained AI role
  -----------------------------------------------------------------------

------------------------------------------------------------------------

## 23. Alignment with CBS3002 Information Security

The project directly maps to the course topics.

  -----------------------------------------------------------------------
  CBS3002 Topic                       SentinelAI Component
  ----------------------------------- -----------------------------------
  Confidentiality, Integrity,         Security objectives and controls
  Availability                        

  Security violations and threats     Threat scenarios

  Security policies                   Policy engine

  Access control models               RBAC, MAC, ABAC, TBAC

  Hybrid policies                     Hybrid Policy Engine

  Policy composition                  Policy decision logic

  Identity                            User identity and attributes

  Control of access                   Authorization engine

  Information flow                    Resource classification and flow
                                      rules

  Vulnerability analysis              Security testing

  Auditing                            Central audit system

  Intrusion detection                 Behavioral anomaly detection

  User security                       Authentication and risk analysis

  Program security                    Secure application design

  Data privacy                        Protection of sensitive resources

  Enterprise security                 Enterprise-oriented architecture

  Database security                   PostgreSQL security and auditing
  -----------------------------------------------------------------------

The CBS3002 syllabus specifically covers access-control models, hybrid
policies, policy composition, system design, information flow,
vulnerability analysis, auditing, intrusion detection, data privacy, OS
security, and database auditing/security. The project's architecture is
intentionally built around these areas.

------------------------------------------------------------------------

## 24. Why This Project Is Resume-Worthy

SentinelAI combines several technically relevant areas:

``` text
Cybersecurity
     +
Backend Engineering
     +
Database Engineering
     +
Machine Learning
     +
AI
     +
Security Architecture
```

It is stronger than a project where AI is simply placed on top of a
conventional CRUD application because the AI component addresses a
concrete security problem: detecting behavioral deviations that static
authorization may not capture.

A strong implementation should emphasize **measured results, security
architecture, and realistic attack simulations**, not merely the number
of technologies used.

------------------------------------------------------------------------

## 25. Resume Description

### SentinelAI --- AI-Powered Adaptive Access Control & Insider Threat Detection

**Technology:** Python, FastAPI, PostgreSQL, Scikit-learn, React, Docker

Possible resume bullets:

-   Developed a hybrid authorization engine integrating **RBAC, MAC,
    ABAC and temporal access policies** for context-aware protection of
    sensitive resources.
-   Implemented **ML-based behavioral anomaly detection** to identify
    suspicious authentication, resource-access and data-transfer
    patterns and generate dynamic security risk scores.
-   Built adaptive security workflows, centralized audit logging and
    AI-assisted incident explanations for potential **credential
    compromise, privilege abuse and data exfiltration**.

Only include metrics such as detection accuracy, F1-score, latency, or
dataset size after actually measuring them.

------------------------------------------------------------------------

## 26. Future Enhancements

Possible future work:

-   Continuous authentication
-   Device fingerprinting
-   Graph-based user-resource analysis
-   Federated identity integration
-   Advanced UEBA
-   Graph neural networks for attack-path analysis
-   Automated SIEM integration
-   Threat-intelligence feeds
-   Explainable ML
-   Privacy-preserving behavioral analytics
-   Kubernetes deployment
-   Distributed audit logging

These should be treated as future enhancements rather than required
components of the initial project.

------------------------------------------------------------------------

## 27. Final Project Vision

SentinelAI is designed around a simple principle:

> **A user having permission does not necessarily mean that their
> current behavior is safe.**

The system combines:

``` text
Identity
   +
Policy
   +
Context
   +
Behavior
   +
Machine Learning
   +
Risk Analysis
   +
Adaptive Response
```

to create a security platform capable of moving beyond static
authorization toward **context-aware and behavior-aware security**.

The goal is not to replace traditional access control with AI.

The goal is to **augment deterministic security policies with behavioral
intelligence** so that organizations can react when legitimate or
compromised accounts exhibit suspicious behavior.
