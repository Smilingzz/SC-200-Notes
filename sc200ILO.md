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
  - <https://learn.microsoft.com/en-us/training/modules/connect-data-to-azure-sentinel-with-data-connectors/2-ingest-log-data-with-data-connectors>
  - **TLDR**
    - Connect to Sentinel Data Connectors.
      - Included in Content Hub Solutions in Sentinel.
    - Data sources:
      - XDR (Identity/Endpoint/Office 365/Cloud Apps)
      - Azure Services (Entra ID/Activity/Entra ID Protection/DDoS etc.)
      - Custom connectors through Log Analytics Data Collector API.
      - Send any logs through Sentinel Logstash plugin.
      - Common Event Format (CEF) (Industry-standard).
      - Syslog connector (Linux).
    - Syslog and CEF requires host to be deployed in dedicated Azure VM.
- Implement and use Content hub solutions
  - <https://learn.microsoft.com/en-us/azure/sentinel/sentinel-solutions-deploy?tabs=azure-portal>
  - **TLDR**
    - All included in the **Sentinel > Content management > Content hub**
    - Has many pre-defines contents that can be installed using auto-provisioning.
- Configure and use Microsoft connectors for Azure resources, including Azure Policy and diagnostic settings
  - <https://learn.microsoft.com/en-us/training/modules/connect-microsoft-services-to-azure-sentinel/>
  - **TLDR**
    - Done through Data Connectors.
    - Activate Azure Activity (which uses Azure Policy):
      - Goto **Sentinel > Content Management > Content Hub > Type Azure Activity > Select Azure Activity > Select Install > Select Azure Activity Data connector > Open connector page > In Instructions/Configuration > Connect your subscriptions.. Launch Azure Policy Assignment Wizard > In Basics select your Azure Sub. > In Parameters chose workspace > in Remediation > Create a remediation task > Finish**.
- Configure bidirectional synchronization between Microsoft Sentinel and Microsoft Defender XDR
  - <https://learn.microsoft.com/en-us/defender-xdr/microsoft-365-defender-integration-with-azure-sentinel>
  - **TLDR**
    - Add XDR Connector in Content Hub. This will make a bi-directional synchronization between Defender and XDR.
- Plan and configure Syslog and Common Event Format (CEF) event collections
  - <https://learn.microsoft.com/en-us/training/modules/connect-common-event-format-logs-to-azure-sentinel/>
  - **TDLR**
    - Need Log Analytics agent on either host or Azure VM connected to host.
    - Goto **Sentinel > Configuration > Data Connectors > Select CEF > Copy "sudo wget ..." command > run on Linux VM**.
  - <https://learn.microsoft.com/en-us/training/modules/connect-syslog-data-sources-to-azure-sentinel/>
  - **TLDR**
    - Need Log Analytics agent on either host or Azure VM connected to host.
    - Different steps to setup Syslog if its a Azure Linux VM or not.
    - Configure Data Collection Rule (DCR):
      - Goto **Data collection rule > Data Sources > Add data source > Config + Data sources + Linux syslog > Minimum log level > Save**.
- Plan and configure collection of Windows Security events by using data collection rules, including Windows Event Forwarding (WEF)
  - <https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/data-collection-rule-overview>
  - <https://learn.microsoft.com/en-us/training/modules/connect-syslog-data-sources-to-azure-sentinel/>
  - **TLDR**
    - Uses the Azure Monitor pipeline.
    - DCR is used in Azure Monitor to filter the ingested data.
      - What data to collect, how to transform it (KQL) and where to send it.
- Configure threat intelligence connectors, including platform, TAXII, upload indicators API, and MISP
  - <https://learn.microsoft.com/en-us/training/modules/connect-threat-indicators-to-azure-sentinel/>
  - **TLDR**
    - TAXII threat connector (2.0/2.1)
      - Goto **Data connectors > Threat intelligence - TAXII > Open connector >  Specify requirements > Add**.
    - Threat Intelligence Connector
      - Done through MS Graph Security API.
      - We connect Sentinel to other TI platform.
        - Register an app in Entra ID to get credentials.
    - TI data can be accessed in ThreatIntelligenceIndicator.
- Create custom log tables in the workspace to store ingested data
  - <https://learn.microsoft.com/en-us/azure/sentinel/data-transformation>
  - **TLDR**
    - Log Analytics stores all data.
    - With DCR we can create customized tables.

## Configure Protections and Detections (15–20%)

### Configure Protections in Microsoft Defender Security Technologies

- Configure policies for Microsoft Defender for Cloud Apps
  - <https://learn.microsoft.com/en-us/training/modules/microsoft-cloud-app-security/>
  - **TLDR**
    - We can configure AC through the Conditional Access App Control.
    - Entra ID AC integrated if used already.
- Configure policies for Microsoft Defender for Office 365
  - <https://learn.microsoft.com/en-us/training/modules/m365-threat-remediate/>
  - **TLDR**
    - Configure policies in the Defender portal.
    - Safe Attachments exist, protects against malware.
    - Safe Links exists.
    - Anti-phishing policies exist as well.
- Configure security policies for Microsoft Defender for Endpoints, including attack surface reduction (ASR) rules
  - <https://learn.microsoft.com/en-us/training/modules/implement-windows-10-security-enhancements-with-microsoft-defender-for-endpoint/3-enable-attack-surface-reduction-rules?ns-enrollment-type=learningpath&ns-enrollment-id=learn.wwl.sc-200-mitigate-threats-using-microsoft-defender-for-endpoint>
  - <https://learn.microsoft.com/en-us/training/modules/deploy-microsoft-defender-for-endpoints-environment/6-create-manage-roles-for-role-based-access-control>
  - <https://learn.microsoft.com/en-us/training/modules/deploy-microsoft-defender-for-endpoints-environment/7-configure-device-groups>
  - <https://learn.microsoft.com/en-us/training/modules/configure-manage-automation-microsoft-defender-for-endpoint/4-configure-automated-investigation-remediation-capabilities?ns-enrollment-type=learningpath&ns-enrollment-id=learn.wwl.sc-200-mitigate-threats-using-microsoft-defender-for-endpoint>
  - **TLDR**
    - ASR
      - Available for Windows OS machines.
      - Config in Endpoint, Goto **Settings > Endpoint Security > ASR > config/create ASR**.
      - Works well with group policies as well.
    - RBAC
      - As Sec/Global Admin Goto **Defender Portal > Settings > Endpoints > Permissions > Roles > Turn on roles > add items > add permissions to role > assign role to Entra Sec. group**.
    - Device Groups
      - As Sec/Global Admin Goto **Defender Portal > Settings > Endpoints > Permissions > Device Groups > Add device group > Config automation settings and rules to match devices to group > config users that can access device group (must be user assigned to RBAC group)**.
    - Automated investigation and remediation exists.
      - To turn on Goto **Settings > Endpoints > Advanced features > Turn on auto. investigation and remediation**.
- Configure cloud workload protections in Microsoft Defender for Cloud
  - <https://learn.microsoft.com/en-us/azure/defender-for-cloud/workload-protections-dashboard>
  - <https://learn.microsoft.com/en-us/training/paths/sc-200-mitigate-threats-using-azure-defender/>
  - **TLDR**
    - Workload protections dashboard exists in Defender for Cloud.
    - Basically, it logs data from cloud/hybrid/on-prem resources and makes it secure through the service.
    - Has tons of different subscriptions for servers/DNS/SQL etc.

### Configure Detection in Microsoft Defender XDR

- Configure and manage custom detections
  - <https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules>
  - **TLDR**
    - Custom detections can be made with KQL.
      - Query must return Timestamp and ReportId, and one other ID for device or similar etc.
      - Select **Create detection rule** and configure it.
        - Configure frequency on how often it should run.
        - Choose which entity is the impacted one, i.e. if rule hits, what is the impacted entity?
        - Specify actions (device = run AV, isolate etc.) (files = block / quarantine) (users = isolate etc.)
        - Set rule scope. (All devices / device groups).
    - We can mage existing ones in **Hunting > Custom detection rules**.
- Configure alert tuning
  - <https://learn.microsoft.com/en-us/defender-xdr/investigate-alerts?tabs=settings>
  - **TLDR**
    - Goto **Settings > Defender XDR > Alert Tuning > Add new rule > specify which service (Enpoint/Office 365 etc) > add conditions that should supress the alert > Select either Hide/Resolve alert**.
- Configure deception rules in Microsoft Defender XDR
  - <https://learn.microsoft.com/en-us/defender-xdr/configure-deception>
  - **TLDR**
    - Deception basically adds decoy accounts and hosts in the tenant.
    - Turn on deception Goto **Settings > Endpoints > Advanced Features under General > Toggle on Deception capabilities**.
    - To create/modify deception rules:
      - Goto **Settings > Endpoints > Add deception rule > Config name, lure types > Add devices lure should belong to**.

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
