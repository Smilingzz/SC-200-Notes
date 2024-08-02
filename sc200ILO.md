# SC-200 Intended Learning Outcomes (from <https://learn.microsoft.com/en-us/credentials/certifications/resources/study-guides/sc-200>)

## Manage a Security Operations Environment (20–25%)

### Configure Settings in Microsoft Defender XDR

- Configure a connection from Defender XDR to a Sentinel workspace
  - <https://learn.microsoft.com/en-us/azure/sentinel/connect-microsoft-365-defender?tabs=MDE>
  - **TLDR**
    - Prerequisites: XDR License, Global/Security Administrator role, r/w permission in Sentinel, install XDR in Sentinel Content Hub.
    - Can either connect XDR to Sentinel (Azure Portal), or both to a separate portal (Defender Portal).
    - Do setup in Sentinel for Azure Portal.
      - **Connect Incidents and Alerts**
      - **Connect entitites**
      - **Connect Events**
- Configure alert and vulnerability notification rules
  - <https://learn.microsoft.com/en-us/defender-xdr/configure-email-notifications>
  - **TLDR**
    - Only users with **Manage security settings** can configure email notifications.
    - As Global/Security Administrator, Goto **Settings > Endpoints > General > Email notification > Add item**
    - Specify rule name, org. name etc, incl. device name y/n?.
    - Enter recipients and save rule.
- Configure Microsoft Defender for Endpoint advanced features
  - <https://learn.microsoft.com/en-us/defender-endpoint/advanced-features>
  - **TLDR**
    - Edit in **Defender > Settings > Endpoint > Advanced features**
- Configure endpoint rules settings, including indicators and web content filtering
  - <https://learn.microsoft.com/en-us/defender-endpoint/web-content-filtering>
  - <https://learn.microsoft.com/en-us/defender-endpoint/indicator-manage>
  - **TLDR**
    - Goto **Settings > Endpoints > Rules**
    - Web content filtering.
      - As Global/Security Administrator, Goto **Settings > Endpoints > General > Advanced Features**
      - Block websites for device groups with policies.
      - Blocks with Defender SmartScreen (Edge) or network protection (the rest).
    - Indicators.
      - As Global/Security Administrator, Goto **Settings > Endpoints > Indicators**
    - Security policies.
      - As Global/Security Administrator, Goto **Endpoints > Configuration management > Endpoint security policies > Create new Policy**
- Manage automated investigation and response capabilities in Microsoft Defender XDR
  - <https://learn.microsoft.com/en-us/defender-xdr/m365d-configure-auto-investigation-response>
  - **TLDR**
    - As Global/Secrutiy Administrator, Goto **Settings > Endpoints > Device groups under Permissions** to review device group policies.
- Configure automatic attack disruption in Microsoft Defender XDR
  - <https://learn.microsoft.com/en-us/defender-xdr/configure-attack-disruption>
  - **TLDR**
    - As Global/Secrutiy Administrator, Goto **Settings > Endpoints > Device groups under Permission** to review device group policies.
    - Check Automation levels.

### Manage Assets and Environments

- Configure and manage device groups, permissions, and automation levels in Microsoft Defender for Endpoint
  - <https://learn.microsoft.com/en-us/defender-endpoint/machine-groups>
  - <https://learn.microsoft.com/en-us/defender-endpoint/configure-automated-investigations-remediation>
  - **TLDR**
    - Goto **Settings > Permissions > Device Groups > Add device group**.
    - Specify name, automation list, include members section (what devices to add).
- Identify and remediate unmanaged devices in Microsoft Defender for Endpoint
  - <https://learn.microsoft.com/en-us/defender-endpoint/device-discovery>
  - **TLDR**
    - Only discovers devices connected to the corporate network.
    - Onboarded device use either Basic (passive) or Standard (active) device discovery.
    - Network devices are not managed by a sensor, we use onboarded device to scan network ranges instead.
    - Basically, detect devices and onboard them!
- Manage resources by using Azure Arc
  - <https://learn.microsoft.com/en-us/azure/azure-arc/overview>
  - **TLDR**
    - Basically, Azure Arc enables centralized control of non-Azure and on-prem. resources into the Azure Resource Manager.
      - Servers, Kubernetes, SQL and virtual machines.
- Connect environments to Microsoft Defender for Cloud (by using multi-cloud management)
  - <https://learn.microsoft.com/en-us/azure/defender-for-cloud/concept-cloud-security-posture-management?source=recommendations>
  - **TLDR**
    - Asset Inventory provides an overview of vulnerabilities in cloud assets.
      - Can also perform asset discovery through Asset management options.
    - Use Asset Inventory:
      - Goto **Inventory > Filter > relevant options > Search**.
    - Auto Provisioning: Auto-install feature.
      - Enable in Log Analytics agent.
        - Goto **Environment settings > relevant sub. > Auto provisioning page, On.**
- Discover and remediate unprotected resources by using Defender for Cloud
  - **TODO: Read up on this!**
- Identify and remediate devices at risk by using Microsoft Defender Vulnerability Management
  - <https://learn.microsoft.com/en-us/training/modules/use-threat-vulnerability-management-microsoft-defender-for-endpoint/>
  - **TLDR**
    - Microsoft Defender Vulnerability Management is for Endpoint.
    - Remediate software vulnerabilities:
      - Goto **Vulnerability Mangement > Recommendations > Click software > Request remedaition > Go through Wizard**.
    - In **Vulnerability Mangement > Inventories** We can see software etc. related to tenant. And request remediation through the Wizard.

### Design and Configure a Microsoft Sentinel Workspace

- Plan a Microsoft Sentinel workspace
  - <https://learn.microsoft.com/en-us/training/modules/create-manage-azure-sentinel-workspaces/>
  - **TLDR**
    - Single tenant with single or regional workspaces OR multi-tenant?
    - Configure Log Analytics.
      - Then add Sentinel to the Log Analytics workspace.
- Configure Microsoft Sentinel roles
  - <https://learn.microsoft.com/en-us/training/modules/create-manage-azure-sentinel-workspaces/5-understand-azure-sentinel-permissions-roles>
  - **TLDR**
    - Uses RBAC.
    - Roles, Microsoft Sentinel.. Reader/Responder/Contributor/Automation Contributor.
    - To work with Playbooks:
      - Must have Logic App Contributor role.
    - Give Sentinel permission to run Playbooks:
      - Sentinel has special service account to run playbooks.
      - Requires explicit permissions to the resource group of the playbook.
    - Connect data sources to Sentinel:
    - Must have User Write permissions.
  - Guest users assign incidents:
    - Needs Sentinel Responder and Directory Reader role.
  - Create and delete Workbooks:
    - Sentinel Contributor role OR (lesser role AND Azure Monitor role of Workbook Contributor).
- Specify Azure RBAC roles for Microsoft Sentinel configuration
  - <https://learn.microsoft.com/en-us/training/modules/create-manage-azure-sentinel-workspaces/5-understand-azure-sentinel-permissions-roles>
  - **TLDR**
    - Entire roles for Azure exist:
      - Azure.. Owner/Contributor/Reader.
      - Log Analytics... Contributor/Reader.
- Design and configure Microsoft Sentinel data storage, including log types and log retention
  - <https://learn.microsoft.com/en-us/training/modules/create-manage-azure-sentinel-workspaces/6-manage-azure-sentinel-settings>
  - <https://learn.microsoft.com/en-us/training/modules/create-manage-azure-sentinel-workspaces/7-configure-logs>
  - **TLDR**
    - Log retention from 30-730 days.
    - Three primary log types:
      - Analytics logs: Can perform KQL on them. Alerts supported.
      - Basic logs: Specific data types, simple KQL, alerts not supported.
      - Archive logs: Store up to 7 years, cannot query.
    - Can configure logs: Goto **Sentinel Settings > Log Analytics portal > Tables > Manage table > do stuff > save**.
- Manage multiple workspaces by using workspace manager and Azure Lighthouse
  - <https://learn.microsoft.com/en-us/training/modules/create-manage-azure-sentinel-workspaces/4-manage-workspaces-across-tenants-using-azure-lighthouse>
  - **TLDR**
    - Sentinel Workspace manager = manage multiple workspaces within one or more Azure tenants.
    - Azure Lighthouse = Basically OAuth, can manage mutliple tenants with one account.

### Ingest Data Sources in Microsoft Sentinel

- Identify data sources to be ingested for Microsoft Sentinel
- Implement and use Content hub solutions
- Configure and use Microsoft connectors for Azure resources, including Azure Policy and diagnostic settings
- Configure bidirectional synchronization between Microsoft Sentinel and Microsoft Defender XDR
- Plan and configure Syslog and Common Event Format (CEF) event collections
- Plan and configure collection of Windows Security events by using data collection rules, including Windows Event Forwarding (WEF)
- Configure threat intelligence connectors, including platform, TAXII, upload indicators API, and MISP
- Create custom log tables in the workspace to store ingested data

## Configure Protections and Detections (15–20%)

### Configure Protections in Microsoft Defender Security Technologies

- Configure policies for Microsoft Defender for Cloud Apps
- Configure policies for Microsoft Defender for Office 365
- Configure security policies for Microsoft Defender for Endpoints, including attack surface reduction (ASR) rules
- Configure cloud workload protections in Microsoft Defender for Cloud

### Configure Detection in Microsoft Defender XDR

- Configure and manage custom detections
- Configure alert tuning
- Configure deception rules in Microsoft Defender XDR

### Configure Detections in Microsoft Sentinel

- Classify and analyze data by using entities
- Configure scheduled query rules, including KQL
- Configure near-real-time (NRT) query rules, including KQL
- Manage analytics rules from Content hub
- Configure anomaly detection analytics rules
- Configure the Fusion rule
- Query Microsoft Sentinel data by using ASIM parsers
- Manage and use threat indicators

## Manage Incident Response (35–40%)

### Respond to Alerts and Incidents in Microsoft Defender XDR

- Investigate and remediate threats to Microsoft Teams, SharePoint Online, and OneDrive
- Investigate and remediate threats in email by using Microsoft Defender for Office 365
- Investigate and remediate ransomware and business email compromise incidents identified by automatic attack disruption
- Investigate and remediate compromised entities identified by Microsoft Purview data loss prevention (DLP) policies
- Investigate and remediate threats identified by Microsoft Purview insider risk policies
- Investigate and remediate alerts and incidents identified by Microsoft Defender for Cloud
- Investigate and remediate security risks identified by Microsoft Defender for Cloud Apps
- Investigate and remediate compromised identities in Microsoft Entra ID
- Investigate and remediate security alerts from Microsoft Defender for Identity
- Manage actions and submissions in the Microsoft Defender portal

### Respond to Alerts and Incidents Identified by Microsoft Defender for Endpoint

- Investigate timeline of compromised devices
- Perform actions on the device, including live response and collecting investigation packages
- Perform evidence and entity investigation
- Enrich investigations by using other Microsoft tools
- Investigate threats by using unified audit log
- Investigate threats by using Content Search
- Perform threat hunting by using Microsoft Graph activity logs

### Manage Incidents in Microsoft Sentinel

- Triage incidents in Microsoft Sentinel
- Investigate incidents in Microsoft Sentinel
- Respond to incidents in Microsoft Sentinel

### Configure Security Orchestration, Automation, and Response (SOAR) in Microsoft Sentinel

- Create and configure automation rules
- Create and configure Microsoft Sentinel playbooks
- Configure analytic rules to trigger automation
- Trigger playbooks manually from alerts and incidents
- Run playbooks on on-premises resources

## Perform Threat Hunting (15–20%)

### Hunt for Threats by Using KQL

- Identify threats by using Kusto Query Language (KQL)
- Interpret threat analytics in the Microsoft Defender portal
- Create custom hunting queries by using KQL

### Hunt for Threats by Using Microsoft Sentinel

- Analyze attack vector coverage by using the MITRE ATT&CK in Microsoft Sentinel
- Customize content gallery hunting queries
- Use hunting bookmarks for data investigations
- Monitor hunting queries by using livestream
- Retrieve and manage archived log data
- Create and manage search jobs

### Analyze and Interpret Data by Using Workbooks

- Activate and customize Microsoft Sentinel workbook templates
- Create custom workbooks that include KQL
- Configure visualizations


## Other useful links:
- <https://github.com/OneEqualsOne/Azure-Learning-Materials/blob/main/SC-200/SC-200%20Notes.md>
