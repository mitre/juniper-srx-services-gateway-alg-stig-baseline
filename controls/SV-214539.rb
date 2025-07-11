control 'SV-214539' do
  title 'The Juniper SRX Services Gateway Firewall must generate an alert to, at a minimum, the ISSO and ISSM when unusual/unauthorized activities or conditions are detected during continuous monitoring of communications traffic as it traverses inbound or outbound  across internal security boundaries.'
  desc "Without an alert, security personnel may be unaware of major detection incidents that require immediate action and this delay may result in the loss or compromise of information.

Since these incidents require immediate action, these messages are assigned a critical or level 1 priority/severity, depending on the system's priority schema.

In accordance with CCI-001242, the ALG which provides content inspection services is a real-time intrusion detection system. These systems must generate an alert when detection events from real-time monitoring occur as required by CCI-2262 and CCI-2261. Alerts may be transmitted, for example, telephonically, by electronic mail messages, or by text messaging. The ALG must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel. Alerts must be sent immediately to designated individuals. Alerts may be sent via NMS, SIEM, Syslog configuration, SNMP trap or notice, or manned console message.

Unusual/unauthorized activities or conditions may include large file transfers, long-time persistent connections, unusual protocols and ports in use, and attempted communications with suspected malicious external addresses."
  desc 'check', 'For each zone, verify a log event, SNMP trap, or SNMP notification is generated and sent to be forwarded to, at a minimum, the ISSO and ISSM when unusual/unauthorized activities or conditions are detected during continuous monitoring of communications traffic as it traverses inbound or outbound across internal security boundaries. 

[edit]
show security zones
show security polices

If each inbound and outbound zone policy does not generate an alert that can be forwarded to, at a minimum, the ISSO and ISSM when unusual/unauthorized activities or conditions are detected during continuous monitoring of communications traffic as it traverses inbound or outbound across internal security boundaries, this is a finding.'
  desc 'fix', 'Configure the Juniper SRX to generate and send a notification or log message immediately that can be forwarded via an event monitoring system (e.g., via Syslog configuration, SNMP trap, manned console message, or other events monitoring system). The NSM, Syslog, or SNMP server must then be configured to send the message.

The following example configures the zone security policy to include the log and/or syslog action in all terms to log packets matching each firewall term to ensure the term results are recorded in the firewall log and Syslog. To get traffic logs from permitted sessions, add "then log session-close" to each policy. To get traffic logs from denied sessions, add "then log session-init" to the policy.

Security policy and security screens:
set security policies from-zone <zone_name> to-zone <zone_name> policy <policy_name> then log

Example:
set security policies from-zone untrust to-zone trust policy default-deny then log session-init'
  impact 0.5
  tag check_id: 'C-15745r297301_chk'
  tag severity: 'medium'
  tag gid: 'V-214539'
  tag rid: 'SV-214539r971533_rule'
  tag stig_id: 'JUSX-AG-000146'
  tag gtitle: 'SRG-NET-000392-ALG-000141'
  tag fix_id: 'F-15743r297302_fix'
  tag 'documentable'
  tag legacy: ['V-66343', 'SV-80833']
  tag cci: ['CCI-002664']
  tag nist: ['SI-4 (5)']

  # Check if SNMP is configured (used to determine whether to apply these checks)
  snmp_config = inspec.command("show configuration snmp | display set").stdout

  if snmp_config.strip.empty?
    # Skip block with a pass + reason if SNMP is not configured
    impact 0.0
    describe 'SNMP-dependent logging and alerting checks' do
      skip 'SNMP is not configured, skipping SNMP-related logging and alerting checks'
    end
  else
    # SNMP is configured — run full logging and alerting tests

    # 1. Check that logs are generated for permitted policies (inbound and outbound)
    describe command('show configuration security policies | display set') do
      let(:stdout) { subject.stdout }

      it 'should log session starts for inbound and outbound allow policies' do
        expect(stdout).to match(/set security policies from-zone trust to-zone untrust policy .* then permit log session-init/)
        expect(stdout).to match(/set security policies from-zone untrust to-zone trust policy .* then permit log session-init/)
      end
    end

    # 2. Ensure a security log stream is defined to forward alerts
    describe command('show configuration security log | display set') do
      let(:stdout) { subject.stdout }

      it 'should have stream mode enabled for real-time alerting' do
        expect(stdout).to match(/set security log mode stream/)
      end

      it 'should specify at least one log stream destination (e.g. SIEM monitored by ISSO/ISSM)' do
        expect(stdout).to match(/set security log stream [^\s]+ host \d+\.\d+\.\d+\.\d+/)
      end

      it 'should use an appropriate severity level (info or higher)' do
        expect(stdout).to match(/set security log stream [^\s]+ severity (info|notice|warning|error)/)
      end
    end

    # 3. Validate SNMP trap targets (if used as alerting mechanism)
    describe command('show configuration snmp | display set') do
      its('stdout') { should match(/set snmp trap-group [^\s]+ targets \d+\.\d+\.\d+\.\d+/) }
    end
  end

end
