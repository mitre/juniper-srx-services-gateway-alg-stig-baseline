control 'SV-214541' do
  title 'The Juniper SRX Services Gateway Firewall must generate an alert that can be forwarded to, at a minimum, the ISSO and ISSM when DoS incidents are detected.'
  desc %q(Without an alert, security personnel may be unaware of major detection incidents that require immediate action and this delay may result in the loss or compromise of information.

The ALG generates an alert that notifies designated personnel of the Indicators of Compromise (IOCs) which require real-time alerts. These messages should include a severity level indicator or code as an indicator of the criticality of the incident. These indicators reflect the occurrence of a compromise or a potential compromise.

Since these incidents require immediate action, these messages are assigned a critical or level 1 priority/severity, depending on the system's priority schema.

CJCSM 6510.01B, "Cyber Incident Handling Program", lists nine Cyber Incident and Reportable Event Categories. DoD has determined that categories identified by CJCSM 6510.01B Major Indicators (category 1, 2, 4, or 7 detection events) will require an alert when an event is detected.

Alerts may be transmitted, for example, telephonically, by electronic mail messages, or by text messaging. The ALG must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel.)
  desc 'check', 'Verify a security policy with an associated screen that denies or mitigates the threat of DoS attacks includes the log or syslog option. Verify a log event, SNMP trap, or SNMP notification is generated and sent to be forwarded to, at a minimum, the ISSO and ISSM when threats identified by authoritative sources are detected.

[edit]
show security zones
show security polices

If an alert is not generated that can be forwarded to, at a minimum, the ISSO and ISSM when DoS incidents are detected, this is a finding.'
  desc 'fix', 'Configure the Juniper SRX to generate for DoS attacks detected in CCI-002385. DoS attacks are detected using screens. The alert sends a notification or log message that can be forwarded via an event monitoring system (e.g., via Syslog configuration, SNMP trap, manned console message, or other events monitoring system). The NSM, Syslog, or SNMP server must then be configured to send the message.

The following example configures the zone security policy to include the log and/or syslog action in all terms to log packets matching each firewall term to ensure the term results are recorded in the firewall log and Syslog. To get traffic logs from permitted sessions, add "then log session-close" to each policy. To get traffic logs from denied sessions, add "then log session-init" to the policy.

Apply policy or screen to a zone example:

set security zones security-zone trust interfaces ge-0/0/2.0
set security zones security-zone untrust screen untrust-screen
set security policies from-zone untrust to-zone trust policy default-deny then log session-init'
  impact 0.5
  tag check_id: 'C-15747r297307_chk'
  tag severity: 'medium'
  tag gid: 'V-214541'
  tag rid: 'SV-214541r971533_rule'
  tag stig_id: 'JUSX-AG-000150'
  tag gtitle: 'SRG-NET-000392-ALG-000148'
  tag fix_id: 'F-15745r297308_fix'
  tag 'documentable'
  tag legacy: ['SV-80837', 'V-66347']
  tag cci: ['CCI-002664']
  tag nist: ['SI-4 (5)']
  
  # Check if SNMP is configured (used to determine whether to apply these checks)
  snmp_config = inspec.command("show configuration snmp | display set").stdout

  if snmp_config.strip.empty?
    # Skip block with a pass + reason if SNMP is not configured
    impact 0.0
    describe 'SNMP-dependent logging and alerting checks' do
      skip 'SNMP is not configured, skipping SNMP-related generation of alerts checks'
    end
  else
    # 1. Check if security screens are configured (DoS protection)
    describe command('show configuration security screen | display set') do
      its('stdout') { should match(/set security screen ids-option [^\s]+/i) }
      its('stdout') { should match(/(syn-flood|icmp-flood|port-scan|udp-flood)/i) }
    end

    # 2. Check if security screens are applied to zones (e.g., untrust or trust)
    describe command('show configuration security zones | display set') do
      its('stdout') { should match(/set security zones security-zone [^\s]+ screen [^\s]+/) }
    end

    # 3. Check if security logging is configured to stream alerts
    describe command('show configuration security log | display set') do
      its('stdout') { should match(/set security log mode stream/) }
      its('stdout') { should match(/set security log stream [^\s]+ host \d+\.\d+\.\d+\.\d+/) }
      its('stdout') { should match(/set security log stream [^\s]+ severity (info|notice|warning|error)/) }
    end

    # 4. Verify logs are being generated for SCREEN/DoS events
    describe command('show log messages | match SCREEN') do
      its('stdout') { should_not be_empty }
    end
  end
end
