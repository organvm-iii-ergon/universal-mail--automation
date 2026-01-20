# Process Definition: Mail Automation Enhancement

## Objective
Harmonize the Gmail labeling automation (`gmail_labeler.py`) with the comprehensive rules defined in the iCloud Filtering Guide.

## 1. Steps

### Phase 1: Analysis & Design
1.  **Gap Analysis**: Compare `LABEL_RULES` in `gmail_labeler.py` against categories in the iCloud Guide.
    *   *Identified Gap*: "Travel & Bookings" category is present in the Guide but missing in the Python script.
    *   *Identified Gap*: "Research & Learning" in the Guide maps to "Professional/Jobs" or "Marketing" in the script, but deserves a distinct `Education/Research` category.
2.  **Rule Translation**: Convert specific email addresses and subject keywords from the Guide into Python `re` patterns.

### Phase 2: Implementation
1.  **Refactor `gmail_labeler.py`**:
    *   **Add** `Travel` category with patterns from the Guide (Airlines, Hotels, Booking sites).
    *   **Add** `Education/Research` category (Universities, MOOCs, ResearchGate).
    *   **Enhance** `Finance` and `Shopping` with specific sender domains to improve precision.
2.  **Validation**: Verify Python syntax and regex validity.

### Phase 3: Execution & Monitoring
1.  **Execution**: Run the updated labeler against the inbox.
2.  **Monitoring**: Review `gmail_labeler.log` for categorization distribution and errors.

## 2. Inputs & Outputs

### Inputs
*   **Source Code**: `/Users/4jp/Workspace/mail_automation/gmail_labeler.py`
*   **Reference Data**: `/Users/4jp/Workspace/mail_automation/iCloud Mail Filtering Rules - Complete Guide.md`
*   **Data Source**: Live Gmail Inbox (via API)

### Outputs
*   **Code Artifact**: Updated `gmail_labeler.py` (v2.0)
*   **Operational State**: Emails in Gmail organized into labels.
*   **Logs**: Execution logs detailing the number of emails processed per category.

## 3. Metrics (KPIs)

| Metric | Definition | Target |
| :--- | :--- | :--- |
| **Uncategorized Reduction** | Decrease in the volume of "Uncategorized" emails | -15% relative to baseline |
| **Rule Specificity** | Count of distinct regex patterns in `LABEL_RULES` | Increase by ~20 patterns |
| **Processing Efficiency** | Time to process a batch of 500 emails | Maintain < 60s |
| **New Category Volume** | Number of emails caught by new `Travel` & `Education` rules | > 0 |
