#!/usr/bin/env python3

"""
cvss_nist_mapping.py

A Python script to:
1. Help the user build a CVSS v3.1 vector via interactive prompts.
2. Parse and calculate CVSS v3.1 Base, Temporal, and Environmental scores.
3. Provide expanded NIST SP 800-53 control recommendations based on key metrics.

NOTE: The nist_800_53_mappings dictionary has been updated to include
WAY MORE references to NIST 800-53 controls for demonstration purposes.
Use and tailor these references based on your environment and risk model.
"""

import re
import math

# ------------------------------------------------------------------------------
# SIGNIFICANTLY EXPANDED Mappings from CVSS metrics to recommended
# NIST SP 800-53 (Rev. 5) controls (NOT OFFICIAL OR EXHAUSTIVE)
# ------------------------------------------------------------------------------

    #!/usr/bin/env python3

"""
cvss_nist_mapping.py

A Python script to:
1. Help the user build a CVSS v3.1 vector via interactive prompts.
2. Parse and calculate CVSS v3.1 Base, Temporal, and Environmental scores.
3. Provide expanded NIST SP 800-53 control recommendations based on key metrics.

NOTE: The nist_800_53_mappings dictionary has been updated to include
WAY MORE references to NIST 800-53 controls for demonstration purposes.
Use and tailor these references based on your environment and risk model.
"""

import re
import math

# ------------------------------------------------------------------------------
# SIGNIFICANTLY EXPANDED Mappings from CVSS metrics to recommended
# NIST SP 800-53 (Rev. 5) controls (NOT OFFICIAL OR EXHAUSTIVE)
# ------------------------------------------------------------------------------
nist_800_53_mappings = {
    "AV": {
        # Network
        "N": [
            "AC-4 Information Flow Enforcement",
            "AC-17 Remote Access",
            "AC-17(1) Automated Monitoring / Control",
            "AC-17(2) Protection of Confidentiality / Integrity",
            "AC-19 Access Control for Mobile Devices",
            "SC-7 Boundary Protection",
            "SC-7(1) Physical / Logical Separation of System Components",
            "SC-7(3) Access Points",
            "SC-7(12) Isolation of Security Tools / Mechanisms",
            "SI-4 Information System Monitoring",
            "SI-4(4) Monitoring of External / Internal Communications"
        ],
        # Adjacent
        "A": [
            "AC-3 Access Enforcement",
            "AC-18 Wireless Access",
            "AC-18(1) Authentication and Encryption for Wireless Access",
            "AC-18(2) Monitoring Unauthorized Wireless Connections",
            "SC-7 Boundary Protection",
            "SC-7(2) Network Segregation / Segmentation",
            "CM-7 Least Functionality",
            "CM-7(1) Configuration for Least Functionality"
        ],
        # Local
        "L": [
            "PE-2 Physical Access Authorizations",
            "PE-3 Physical Access Control",
            "PE-3(1) Access Control for Transmission / Display Devices",
            "PE-5 Access Control for Output Devices",
            "SC-8 Transmission Confidentiality and Integrity",
            "MP-2 Media Access",
            "MP-5 Media Transport",
            "SI-4(5) System Monitoring | System-Generated Alerts"
        ],
        # Physical
        "P": [
            "PE-3 Physical Access Control",
            "PE-6 Monitoring Physical Access",
            "PE-6(1) Intrusion Alarms / Surveillance Equipment",
            "PE-8 Visitor Access Records",
            "PE-18 Location of Information System Components",
            "MP-2 Media Access",
            "MP-3 Media Marking",
            "MP-4 Media Storage"
        ]
    },
    "AC": {
        # Low Attack Complexity
        "L": [
            "CM-2 Baseline Configuration",
            "CM-3 Configuration Change Control",
            "CM-7 Least Functionality",
            "AC-3 Access Enforcement",
            "AC-6 Least Privilege",
            "SA-15 Developer Configuration Management"
        ],
        # High Attack Complexity
        "H": [
            "CM-6 Configuration Settings",
            "SA-3 System Development Life Cycle",
            "SA-10 Developer Configuration Management",
            "SA-11 Developer Testing and Evaluation",
            "SR-3 Supply Chain Controls",
            "SR-3(1) Supply Chain Controls | Organizational Approaches",
            "SC-39 Process Isolation"
        ]
    },
    "PR": {
        # No Privileges Required
        "N": [
            "AC-3 Access Enforcement",
            "AC-2 Account Management",
            "AC-2(3) Disable Inactive Accounts",
            "IA-2 Identification and Authentication (Organizational Users)",
            "IA-8 Identification and Authentication (Non-Organizational Users)",
            "SC-23 Session Authenticity"
        ],
        # Low Privileges Required
        "L": [
            "IA-5 Authenticator Management",
            "AC-6(2) Least Privilege | Non-privileged Accounts / Roles",
            "AC-14 Permitted Actions without Identification or Authentication",
            "AC-2(5) Inactivity Logout",
            "IA-11 Re-authentication"
        ],
        # High Privileges Required
        "H": [
            "AC-6 Least Privilege",
            "AC-2(2) Automated System Account Management",
            "IA-4 Identifier Management",
            "IA-5 Authenticator Management",
            "CM-5 Access Restrictions for Change",
            "CM-5(1) Automated Access Restrictions / Authorizations"
        ]
    },
    "UI": {
        # No user interaction
        "N": [
            "SI-10 Information Input Validation",
            "SI-3 Malicious Code Protection",
            "SI-3(1) Central Management of Malicious Code Protection",
            "SC-18 Mobile Code",
            "AC-25 Reference Monitor",
            "AU-2(4) System-generated Alerts (for automated exploit attempts)"
        ],
        # Requires user interaction
        "R": [
            "SI-10 Information Input Validation",
            "AT-2 Security Awareness Training",
            "AT-3 Role-Based Training",
            "AT-4 Training Records",
            "SC-18 Mobile Code (User-Driven)",
            "SC-26 Honeypots (Optional / for advanced threat detection)",
            "PM-13 Information Security Workforce"
        ]
    },
    "S": {
        # Unchanged scope
        "U": [
            "SC-5 Denial of Service Protection",
            "RA-5 Vulnerability Monitoring and Scanning",
            "RA-5(1) Update Vulnerabilities to be Scanned",
            "PM-15 Information Security Measures of Performance",
            "CA-7 Continuous Monitoring",
            "SI-4(14) System Monitoring | Insider Threats"
        ],
        # Changed scope
        "C": [
            "SC-5 Denial of Service Protection",
            "SI-4(5) System Monitoring | System-Generated Alerts",
            "RA-3 Risk Assessment",
            "RA-3(1) Risk Assessment | Supply Chain Vulnerabilities",
            "PM-9 Risk Management Strategy",
            "CA-2 Security Assessments"
        ]
    },
    "C": {
        # Confidentiality: None
        "N": [
            "PL-8 Information Security Architecture",
            "SC-8(2) Transmission of Information | Protection of Information Outside System",
            "MP-2 Media Access (Basic, minimal for confidentiality)",
            "AC-3(3) Access Enforcement | Security-relevant Access Controls"
        ],
        # Confidentiality: Low
        "L": [
            "SC-28 Protection of Information at Rest",
            "SC-8 Transmission Confidentiality and Integrity",
            "AC-21 User-based Collaboration and Information Sharing",
            "MP-5 Media Transport",
            "SC-17 Public Key Infrastructure Certificates",
            "SC-12 Cryptographic Key Establishment and Management"
        ],
        # Confidentiality: High
        "H": [
            "SC-28 Protection of Information at Rest",
            "SC-28(1) Cryptographic Protection",
            "SC-31 Covert Channel Analysis",
            "SC-8 Transmission Confidentiality and Integrity",
            "SC-8(1) Cryptographic Protection",
            "MP-5 Media Transport",
            "MP-5(4) Cryptographic Protection of Information",
            "SC-12(2) Key Management by Organizational Personnel"
        ]
    },
    "I": {
        # Integrity: None
        "N": [
            "SI-1 System and Information Integrity Policy and Procedures",
            "SI-4 Information System Monitoring",
            "CM-2(2) Baseline Configuration | Automation Support",
            "SA-5 Information System Documentation"
        ],
        # Integrity: Low
        "L": [
            "SC-8 Transmission Confidentiality and Integrity",
            "SI-7 Software, Firmware, and Information Integrity",
            "CM-3 Configuration Change Control",
            "CM-3(1) Automated Change Implementation",
            "SI-7(5) Automated Notifications of Integrity Violations",
            "AU-9 Protection of Audit Information"
        ],
        # Integrity: High
        "H": [
            "SC-8 Transmission Confidentiality and Integrity",
            "SI-7(1) Integrity Checks",
            "CM-3(2) Access Restrictions for Change",
            "SA-10 Developer Configuration Management",
            "SI-7(8) Cryptographic Protection",
            "SC-44 Detonation Chambers / Sandboxing for Malicious Content",
            "SA-11(8) Static Code Analysis"
        ]
    },
    "A": {
        # Availability: None
        "N": [
            "CP-1 Contingency Planning Policy and Procedures",
            "IR-4 Incident Handling",
            "IR-4(1) Automated Incident Handling Processes",
            "CP-4 Contingency Plan Testing",
            "CP-4(1) Coordinate with Related Plans"
        ],
        # Availability: Low
        "L": [
            "CP-7 Alternate Processing Site",
            "CP-8 Telecommunications Services",
            "CP-8(2) Single Points of Failure",
            "CP-9 System Backup",
            "CP-9(3) Separation of Backup Information",
            "CP-10 Information System Recovery and Reconstitution"
        ],
        # Availability: High
        "H": [
            "CP-7 Alternate Processing Site",
            "CP-7(1) Accessibility",
            "CP-10 Information System Recovery and Reconstitution",
            "CP-10(2) Automated Recovery",
            "SC-36 Distributed Processing and Storage",
            "CP-13 Alternative Security Mechanisms",
            "CP-6 Emergency Power",
            "CP-6(1) Uninterruptible Power Supply"
        ]
    }
}

# ------------------------------------------------------------------------------
# 1. Helper Function: Build CVSS Vector via Interactive Prompts
# (UNCHANGED)
# ------------------------------------------------------------------------------
def build_cvss_vector() -> str:
    """
    Guides the user to build a CVSS v3.1 Base Vector via prompts.
    Returns a properly formatted CVSS:3.1 vector string.
    """
    valid_options = {
        "AV": ["N", "A", "L", "P"],
        "AC": ["L", "H"],
        "PR": ["N", "L", "H"],
        "UI": ["N", "R"],
        "S":  ["U", "C"],
        "C":  ["N", "L", "H"],
        "I":  ["N", "L", "H"],
        "A":  ["N", "L", "H"],
    }
    
    descriptions = {
        "AV": "Attack Vector (N=Network, A=Adjacent, L=Local, P=Physical)",
        "AC": "Attack Complexity (L=Low, H=High)",
        "PR": "Privileges Required (N=None, L=Low, H=High)",
        "UI": "User Interaction (N=None, R=Required)",
        "S":  "Scope (U=Unchanged, C=Changed)",
        "C":  "Confidentiality (N=None, L=Low, H=High)",
        "I":  "Integrity (N=None, L=Low, H=High)",
        "A":  "Availability (N=None, L=Low, H=High)"
    }
    
    chosen_metrics = {}
    for metric, valid_vals in valid_options.items():
        while True:
            user_input = input(f"{descriptions[metric]} [{'/'.join(valid_vals)}]: ").strip().upper()
            if user_input in valid_vals:
                chosen_metrics[metric] = user_input
                break
            else:
                print(f"Invalid choice. Please select from {valid_vals}")
    
    vector_parts = [f"{k}:{v}" for k, v in chosen_metrics.items()]
    cvss_vector = "CVSS:3.1/" + "/".join(vector_parts)
    
    print(f"\nConstructed CVSS Vector: {cvss_vector}\n")
    return cvss_vector

# ------------------------------------------------------------------------------
# 2. Parse CVSS Vector (UNCHANGED)
# ------------------------------------------------------------------------------
def parse_cvss_vector(cvss_vector: str) -> dict:
    pattern = r"CVSS:3\.1/(.*)"
    match = re.match(pattern, cvss_vector)
    
    if match:
        vector_body = match.group(1)
    else:
        vector_body = cvss_vector
    
    metrics = {}
    metric_pairs = vector_body.split('/')
    for pair in metric_pairs:
        if ':' in pair:
            k, v = pair.split(':')
            metrics[k] = v
    return metrics

# ------------------------------------------------------------------------------
# 3. CVSS v3.1 Base Score Calculation (UNCHANGED)
# ------------------------------------------------------------------------------
def cvss_score_base(metrics: dict) -> float:
    av_dict = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2}
    ac_dict = {'L': 0.77, 'H': 0.44}
    pr_dict = {
        'N': {'U': 0.85, 'C': 0.85},
        'L': {'U': 0.62, 'C': 0.68},
        'H': {'U': 0.27, 'C': 0.50}
    }
    ui_dict = {'N': 0.85, 'R': 0.62}
    c_dict  = {'N': 0.0,  'L': 0.22, 'H': 0.56}
    i_dict  = {'N': 0.0,  'L': 0.22, 'H': 0.56}
    a_dict  = {'N': 0.0,  'L': 0.22, 'H': 0.56}
    
    scope = metrics.get('S', 'U')
    av = av_dict.get(metrics.get('AV', 'N'), 0.85)
    ac = ac_dict.get(metrics.get('AC', 'L'), 0.77)
    pr = pr_dict.get(metrics.get('PR', 'N'), {'U': 0.85})[scope]
    ui = ui_dict.get(metrics.get('UI', 'N'), 0.85)
    c  = c_dict.get(metrics.get('C', 'N'), 0.0)
    i  = i_dict.get(metrics.get('I', 'N'), 0.0)
    a  = a_dict.get(metrics.get('A', 'N'), 0.0)
    
    exploitability = 8.22 * av * ac * pr * ui
    impact_subscore = 1 - ((1 - c) * (1 - i) * (1 - a))
    
    if scope == 'U':
        impact = 6.42 * impact_subscore
    else:  # scope == 'C'
        impact = 7.52 * (impact_subscore - 0.029) - 3.25 * pow((impact_subscore - 0.02), 15)
    
    if impact <= 0:
        base_score = 0.0
    else:
        if scope == 'U':
            base_score = min((impact + exploitability), 10)
        else:
            base_score = min(1.08 * (impact + exploitability), 10)
    
    return round(base_score, 1)

# ------------------------------------------------------------------------------
# 4. Temporal Score Calculation (UNCHANGED)
# ------------------------------------------------------------------------------
def cvss_score_temporal(base_score: float, e: str = "X", rl: str = "X", rc: str = "X") -> float:
    e_dict  = {'X': 1.0, 'U': 0.91, 'P': 0.94, 'F': 0.97, 'H': 1.0}
    rl_dict = {'X': 1.0, 'O': 0.87, 'T': 0.90, 'W': 0.95, 'U': 1.0}
    rc_dict = {'X': 1.0, 'U': 0.92, 'R': 0.96, 'C': 1.0}
    
    temporal_score = base_score * e_dict.get(e, 1.0) \
                                 * rl_dict.get(rl, 1.0) \
                                 * rc_dict.get(rc, 1.0)
    return round(temporal_score, 1)

# ------------------------------------------------------------------------------
# 5. Environmental Score Calculation (UNCHANGED)
# ------------------------------------------------------------------------------
def cvss_score_environmental(temporal_score: float,
                            cr: str = "X", ir: str = "X", ar: str = "X") -> float:
    req_dict = {'X': 1.0, 'L': 0.5, 'M': 1.0, 'H': 1.5}
    
    env_multiplier = (req_dict.get(cr, 1.0) +
                      req_dict.get(ir, 1.0) +
                      req_dict.get(ar, 1.0)) / 3.0
    
    environmental_score = temporal_score * env_multiplier
    
    if environmental_score > 10:
        environmental_score = 10
    
    return round(environmental_score, 1)

# ------------------------------------------------------------------------------
# 6. NIST SP 800-53 Control Mapping (UNCHANGED)
# ------------------------------------------------------------------------------
def map_nist_controls(metrics: dict) -> set:
    recommended_controls = set()
    
    for metric_key, metric_value in metrics.items():
        if metric_key in nist_800_53_mappings:
            possible_controls = nist_800_53_mappings[metric_key].get(metric_value, [])
            for control in possible_controls:
                recommended_controls.add(control)
    
    return recommended_controls

# ------------------------------------------------------------------------------
# 7. Main Program Logic (UNCHANGED)
# ------------------------------------------------------------------------------
def main():
    print("=== CVSS v3.1 Calculator & NIST 800-53 Control Mapper (EXPANDED) ===\n")
    
    choice = input("Would you like to build a CVSS vector interactively? (y/n): ").strip().lower()
    
    if choice == 'y':
        cvss_vector = build_cvss_vector()
    else:
        user_vector = input("Enter existing CVSS vector (or press Enter for default example): ").strip()
        if not user_vector:
            user_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        cvss_vector = user_vector
    
    metrics = parse_cvss_vector(cvss_vector)
    if not metrics:
        print("Error: Could not parse CVSS vector.")
        return
    
    base_score = cvss_score_base(metrics)
    print(f"\n[*] Base Score: {base_score}")
    
    print("\n--- Temporal Score (Optional) ---")
    e  = input("Exploit Code Maturity (E) [X, U, P, F, H] (default X): ").strip().upper() or "X"
    rl = input("Remediation Level (RL) [X, O, T, W, U] (default X): ").strip().upper() or "X"
    rc = input("Report Confidence (RC) [X, U, R, C] (default X): ").strip().upper() or "X"
    temporal_score = cvss_score_temporal(base_score, e=e, rl=rl, rc=rc)
    print(f"[*] Temporal Score: {temporal_score}")
    
    print("\n--- Environmental Score (Optional) ---")
    cr = input("Confidentiality Requirement (CR) [X, L, M, H] (default X): ").strip().upper() or "X"
    ir = input("Integrity Requirement (IR) [X, L, M, H] (default X): ").strip().upper() or "X"
    ar = input("Availability Requirement (AR) [X, L, M, H] (default X): ").strip().upper() or "X"
    environmental_score = cvss_score_environmental(temporal_score, cr=cr, ir=ir, ar=ar)
    print(f"[*] Environmental Score: {environmental_score}")
    
    recommended_controls = map_nist_controls(metrics)
    if recommended_controls:
        print("\nRecommended NIST SP 800-53 Controls based on Base Metrics:")
        for control in sorted(recommended_controls):
            print(f"  - {control}")
    else:
        print("\nNo specific NIST 800-53 control recommendations found for these metrics (in this demo).")
    
    print("\n=== End of Analysis ===")

if __name__ == "__main__":
    main()

# ------------------------------------------------------------------------------
# 1. Helper Function: Build CVSS Vector via Interactive Prompts
# (UNCHANGED)
# ------------------------------------------------------------------------------
def build_cvss_vector() -> str:
    """
    Guides the user to build a CVSS v3.1 Base Vector via prompts.
    Returns a properly formatted CVSS:3.1 vector string.
    """
    valid_options = {
        "AV": ["N", "A", "L", "P"],
        "AC": ["L", "H"],
        "PR": ["N", "L", "H"],
        "UI": ["N", "R"],
        "S":  ["U", "C"],
        "C":  ["N", "L", "H"],
        "I":  ["N", "L", "H"],
        "A":  ["N", "L", "H"],
    }
    
    descriptions = {
        "AV": "Attack Vector (N=Network, A=Adjacent, L=Local, P=Physical)",
        "AC": "Attack Complexity (L=Low, H=High)",
        "PR": "Privileges Required (N=None, L=Low, H=High)",
        "UI": "User Interaction (N=None, R=Required)",
        "S":  "Scope (U=Unchanged, C=Changed)",
        "C":  "Confidentiality (N=None, L=Low, H=High)",
        "I":  "Integrity (N=None, L=Low, H=High)",
        "A":  "Availability (N=None, L=Low, H=High)"
    }
    
    chosen_metrics = {}
    for metric, valid_vals in valid_options.items():
        while True:
            user_input = input(f"{descriptions[metric]} [{'/'.join(valid_vals)}]: ").strip().upper()
            if user_input in valid_vals:
                chosen_metrics[metric] = user_input
                break
            else:
                print(f"Invalid choice. Please select from {valid_vals}")
    
    vector_parts = [f"{k}:{v}" for k, v in chosen_metrics.items()]
    cvss_vector = "CVSS:3.1/" + "/".join(vector_parts)
    
    print(f"\nConstructed CVSS Vector: {cvss_vector}\n")
    return cvss_vector

# ------------------------------------------------------------------------------
# 2. Parse CVSS Vector (UNCHANGED)
# ------------------------------------------------------------------------------
def parse_cvss_vector(cvss_vector: str) -> dict:
    pattern = r"CVSS:3\.1/(.*)"
    match = re.match(pattern, cvss_vector)
    
    if match:
        vector_body = match.group(1)
    else:
        vector_body = cvss_vector
    
    metrics = {}
    metric_pairs = vector_body.split('/')
    for pair in metric_pairs:
        if ':' in pair:
            k, v = pair.split(':')
            metrics[k] = v
    return metrics

# ------------------------------------------------------------------------------
# 3. CVSS v3.1 Base Score Calculation (UNCHANGED)
# ------------------------------------------------------------------------------
def cvss_score_base(metrics: dict) -> float:
    av_dict = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2}
    ac_dict = {'L': 0.77, 'H': 0.44}
    pr_dict = {
        'N': {'U': 0.85, 'C': 0.85},
        'L': {'U': 0.62, 'C': 0.68},
        'H': {'U': 0.27, 'C': 0.50}
    }
    ui_dict = {'N': 0.85, 'R': 0.62}
    c_dict  = {'N': 0.0,  'L': 0.22, 'H': 0.56}
    i_dict  = {'N': 0.0,  'L': 0.22, 'H': 0.56}
    a_dict  = {'N': 0.0,  'L': 0.22, 'H': 0.56}
    
    scope = metrics.get('S', 'U')
    av = av_dict.get(metrics.get('AV', 'N'), 0.85)
    ac = ac_dict.get(metrics.get('AC', 'L'), 0.77)
    pr = pr_dict.get(metrics.get('PR', 'N'), {'U': 0.85})[scope]
    ui = ui_dict.get(metrics.get('UI', 'N'), 0.85)
    c  = c_dict.get(metrics.get('C', 'N'), 0.0)
    i  = i_dict.get(metrics.get('I', 'N'), 0.0)
    a  = a_dict.get(metrics.get('A', 'N'), 0.0)
    
    exploitability = 8.22 * av * ac * pr * ui
    impact_subscore = 1 - ((1 - c) * (1 - i) * (1 - a))
    
    if scope == 'U':
        impact = 6.42 * impact_subscore
    else:  # scope == 'C'
        impact = 7.52 * (impact_subscore - 0.029) - 3.25 * pow((impact_subscore - 0.02), 15)
    
    if impact <= 0:
        base_score = 0.0
    else:
        if scope == 'U':
            base_score = min((impact + exploitability), 10)
        else:
            base_score = min(1.08 * (impact + exploitability), 10)
    
    return round(base_score, 1)

# ------------------------------------------------------------------------------
# 4. Temporal Score Calculation (UNCHANGED)
# ------------------------------------------------------------------------------
def cvss_score_temporal(base_score: float, e: str = "X", rl: str = "X", rc: str = "X") -> float:
    e_dict  = {'X': 1.0, 'U': 0.91, 'P': 0.94, 'F': 0.97, 'H': 1.0}
    rl_dict = {'X': 1.0, 'O': 0.87, 'T': 0.90, 'W': 0.95, 'U': 1.0}
    rc_dict = {'X': 1.0, 'U': 0.92, 'R': 0.96, 'C': 1.0}
    
    temporal_score = base_score * e_dict.get(e, 1.0) \
                                 * rl_dict.get(rl, 1.0) \
                                 * rc_dict.get(rc, 1.0)
    return round(temporal_score, 1)

# ------------------------------------------------------------------------------
# 5. Environmental Score Calculation (UNCHANGED)
# ------------------------------------------------------------------------------
def cvss_score_environmental(temporal_score: float,
                            cr: str = "X", ir: str = "X", ar: str = "X") -> float:
    req_dict = {'X': 1.0, 'L': 0.5, 'M': 1.0, 'H': 1.5}
    
    env_multiplier = (req_dict.get(cr, 1.0) +
                      req_dict.get(ir, 1.0) +
                      req_dict.get(ar, 1.0)) / 3.0
    
    environmental_score = temporal_score * env_multiplier
    
    if environmental_score > 10:
        environmental_score = 10
    
    return round(environmental_score, 1)

# ------------------------------------------------------------------------------
# 6. NIST SP 800-53 Control Mapping (UNCHANGED)
# ------------------------------------------------------------------------------
def map_nist_controls(metrics: dict) -> set:
    recommended_controls = set()
    
    for metric_key, metric_value in metrics.items():
        if metric_key in nist_800_53_mappings:
            possible_controls = nist_800_53_mappings[metric_key].get(metric_value, [])
            for control in possible_controls:
                recommended_controls.add(control)
    
    return recommended_controls

# ------------------------------------------------------------------------------
# 7. Main Program Logic (UNCHANGED)
# ------------------------------------------------------------------------------
def main():
    print("=== CVSS v3.1 Calculator & NIST 800-53 Control Mapper (EXPANDED) ===\n")
    
    choice = input("Would you like to build a CVSS vector interactively? (y/n): ").strip().lower()
    
    if choice == 'y':
        cvss_vector = build_cvss_vector()
    else:
        user_vector = input("Enter existing CVSS vector (or press Enter for default example): ").strip()
        if not user_vector:
            user_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        cvss_vector = user_vector
    
    metrics = parse_cvss_vector(cvss_vector)
    if not metrics:
        print("Error: Could not parse CVSS vector.")
        return
    
    base_score = cvss_score_base(metrics)
    print(f"\n[*] Base Score: {base_score}")
    
    print("\n--- Temporal Score (Optional) ---")
    e  = input("Exploit Code Maturity (E) [X, U, P, F, H] (default X): ").strip().upper() or "X"
    rl = input("Remediation Level (RL) [X, O, T, W, U] (default X): ").strip().upper() or "X"
    rc = input("Report Confidence (RC) [X, U, R, C] (default X): ").strip().upper() or "X"
    temporal_score = cvss_score_temporal(base_score, e=e, rl=rl, rc=rc)
    print(f"[*] Temporal Score: {temporal_score}")
    
    print("\n--- Environmental Score (Optional) ---")
    cr = input("Confidentiality Requirement (CR) [X, L, M, H] (default X): ").strip().upper() or "X"
    ir = input("Integrity Requirement (IR) [X, L, M, H] (default X): ").strip().upper() or "X"
    ar = input("Availability Requirement (AR) [X, L, M, H] (default X): ").strip().upper() or "X"
    environmental_score = cvss_score_environmental(temporal_score, cr=cr, ir=ir, ar=ar)
    print(f"[*] Environmental Score: {environmental_score}")
    
    recommended_controls = map_nist_controls(metrics)
    if recommended_controls:
        print("\nRecommended NIST SP 800-53 Controls based on Base Metrics:")
        for control in sorted(recommended_controls):
            print(f"  - {control}")
    else:
        print("\nNo specific NIST 800-53 control recommendations found for these metrics (in this demo).")
    
    print("\n=== End of Analysis ===")

if __name__ == "__main__":
    main()