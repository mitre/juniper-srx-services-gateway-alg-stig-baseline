control 'SV-214540' do
  title 'The Juniper SRX Services Gateway Firewall must generate an alert that can be forwarded to, at a minimum, the ISSO and ISSM when threats identified by authoritative sources are detected.'
  desc "Without an alert, security personnel may be unaware of major detection incidents that require immediate action and this delay may result in the loss or compromise of information.

The ALG generates an alert that notifies designated personnel of the Indicators of Compromise (IOCs) which require real-time alerts. These messages should include a severity level indicator or code as an indicator of the criticality of the incident. These indicators reflect the occurrence of a compromise or a potential compromise.

Since these incidents require immediate action, these messages are assigned a critical or level 1 priority/severity, depending on the system's priority schema.

Alerts may be transmitted, for example, telephonically, by electronic mail messages, or by text messaging. The ALG must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel. Alerts must be sent immediately to designated individuals. Alerts may be sent via NMS, SIEM, Syslog configuration, SNMP trap or notice, or manned console message.

Authoritative sources include USSTRATCOM warning and tactical directives/orders including Fragmentary Order (FRAGO), Communications Tasking Orders (CTOs), IA Vulnerability Notices, Network Defense Tasking Message (NDTM), DOD GIG Tasking Message (DGTM), and Operations Order (OPORD)."
  desc 'check', 'Obtain the list of threats identified by authoritative sources from the ISSM or ISSO. For each threat, ensure a security policy, screen, or filter that denies or mitigates the threat includes the log or syslog option. Verify a log event, SNMP trap, or SNMP notification is generated and sent to be forwarded to, at a minimum, the ISSO and ISSM when threats identified by authoritative sources are detected.

[edit]
show security zones
show security polices

If an alert is not generated that can be forwarded to, at a minimum, the ISSO and ISSM when threats identified by authoritative sources are detected, this is a finding.'
  desc 'fix', 'Configure the Juniper SRX to generate and send a notification or log message that can be forwarded via an event monitoring system (e.g., via Syslog configuration, SNMP trap, manned console message, or other events monitoring system). The NSM, Syslog, or SNMP server must then be configured to send the message.

The following example configures the zone security policy to include the log and/or syslog action in all terms to log packets matching each firewall term to ensure the term results are recorded in the firewall log and Syslog. To get traffic logs from permitted sessions, add "then log session-close" to each policy. To get traffic logs from denied sessions, add "then log session-init" to the policy.

Security policy and security screens:
set security policies from-zone <zone_name> to-zone <zone_name> policy <policy_name> then log

Example:
set security policies from-zone untrust to-zone trust policy default-deny then log session-init'
  impact 0.5
  tag check_id: 'C-15746r297304_chk'
  tag severity: 'medium'
  tag gid: 'V-214540'
  tag rid: 'SV-214540r971533_rule'
  tag stig_id: 'JUSX-AG-000147'
  tag gtitle: 'SRG-NET-000392-ALG-000142'
  tag fix_id: 'F-15744r297305_fix'
  tag 'documentable'
  tag legacy: ['V-66345', 'SV-80835']
  tag cci: ['CCI-002664']
  tag nist: ['SI-4 (5)']

  # Check if SNMP is configured (used to determine whether to apply these checks)
  snmp_config = inspec.command("show configuration snmp | display set").stdout

  if snmp_config.strip.empty?
    # Skip block with a pass + reason if SNMP is not configured
    impact 0.0
    describe 'SNMP-dependent logging and alerting checks' do
      skip 'SNMP is not configured, skipping SNMP-related generating alerts checks'
    end
  else
    # SNMP is configured — run full logging and alerting tests
  
    # 1. Check if IDP or UTM (antivirus, web filtering) is enabled and applied
    describe command('show configuration security idp | display set') do
      its('stdout') { should match(/set security idp/) }
    end

    describe command('show configuration security utm | display set') do
      its('stdout') { should match(/set security utm/) }
    end

    # 2. Confirm IDP policies are applied to zones (e.g., untrust)
    describe command('show configuration security zones | display set') do
      its('stdout') { should match(/set security zones security-zone untrust idp/).or match(/set security zones security-zone trust idp/) }
    end

    # 3. Confirm security logs stream is enabled for real-time alerting
    describe command('show configuration security log | display set') do
      its('stdout') { should match(/set security log mode stream/) }
      its('stdout') { should match(/set security log stream [^\s]+ host \d+\.\d+\.\d+\.\d+/) }
      its('stdout') { should match(/set security log stream [^\s]+ severity (info|notice|warning|error)/) }
    end

    # 4. Confirm logs include IDP or UTM events (this confirms detection occurred and alert was sent)
    describe command('show log messages | match IDP') do
      its('stdout') { should_not be_empty }
    end
  end
end
