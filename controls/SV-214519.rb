control 'SV-214519' do
  title 'The Juniper SRX Services Gateway must generate log records when firewall filters, security screens and security policies are invoked and the traffic is denied or restricted.'
  desc 'Without generating log records that log usage of objects by subjects and other objects, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

Security objects are data objects which are controlled by security policy and bound to security attributes.

By default, the Juniper SRX will not forward traffic unless it is explicitly permitted via security policy. Logging for Firewall security-related sources such as screens and security policies must be configured separately. To ensure firewall filters, security screens and security policies send events to a Syslog server and local logs, security logging must be configured one each firewall term.'
  desc 'check', 'To verify what is logged in the Syslog, view the Syslog server (Syslog server configuration is out of scope for this STIG); however, the reviewer must also verify that packets are being logged to the local log using the following commands.

From operational mode, enter the following command.

show firewall log

View the Action column; the configured action of the term matches the action taken on the packet: A (accept), D (discard).

If events in the log do not reflect the action taken on the packet, this is a finding.'
  desc 'fix', 'Include the log and/or syslog action in all term to log packets matching each firewall term to ensure the term results are recorded in the firewall log and Syslog. To get traffic logs from permitted sessions, add "then log session-close" to each policy. To get traffic logs from denied sessions, add "then log session-init" to the policy.

Firewall filter:
[edit]
set firewall family <family name> filter <filter_name> term <term_name> then log

Examples: 
set firewall family inet filter protect_re term tcp-connection then syslog
set firewall family inet filter protect_re term tcp-connection then log
set firewall family inet filter ingress-filter-v4 term deny-dscp then log
set firewall family inet filter ingress-filter-v4 term deny-dscp then syslog

Security policy and security screens:
set security policies from-zone <zone_name> to-zone <zone_name> policy <policy_name> then log

Example:
set security policies from-zone untrust to-zone trust policy default-deny then log'
  impact 0.5
  tag check_id: 'C-15725r297241_chk'
  tag severity: 'medium'
  tag gid: 'V-214519'
  tag rid: 'SV-214519r557389_rule'
  tag stig_id: 'JUSX-AG-000036'
  tag gtitle: 'SRG-NET-000492-ALG-000027'
  tag fix_id: 'F-15723r297242_fix'
  tag 'documentable'
  tag legacy: ['SV-80793', 'V-66303']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  # Run command to get the configured syslog servers
  syslog_cmd = command('show configuration system syslog | display set | match "host"')
  syslog_output = syslog_cmd.stdout.strip

  # Always check that firewall logging is configured for local logs
  syslog_file_cmd = command('show configuration system syslog | display set | match "file"')
  syslog_file_output = syslog_file_cmd.stdout.strip

  # Check if local logging is configured
  describe 'Local syslog logging configuration' do
    it 'should have local log configured' do
      # Ensure that local file logging is configured
      expect(syslog_file_output).to match(/^set system syslog file/)
    end
  end

  # Check syslog server configuration only if syslog server is configured
  # otherwise skip the test and skip the syslog-related checks
  if syslog_output.empty?
    # If no syslog server is configured, skip syslog-related checks
    describe 'Syslog server check' do
      it 'should skip syslog-related checks because no syslog server is configured' do
        skip 'No syslog server configured. Skipping syslog-related checks.'
      end
    end
  else
    # If syslog is configured, verify that at least one syslog host is configured
    describe 'Syslog server configuration' do
      it 'should have at least one syslog host configured' do
        expect(syslog_output).to match(/^set system syslog host/)
      end
    end

    # Retrieve firewall filter configurations
    filter_cmd = command('show configuration firewall | display set')
    filter_output = filter_cmd.stdout.strip

    # Filter out all terms with 'then' clauses that should include 'log'
    term_lines = filter_output.split("\n").select { |line| line =~ /then/ }

    # Verify that each firewall term is configured to log matched packets
    describe 'Firewall term logging actions (syslog)' do
      it 'should log matching packets in each firewall term with a "then log" action' do
        missing_logs = term_lines.reject { |line| line.include?('then log') }

        expect(missing_logs).to be_empty, "Some firewall terms do not include 'then log':\n#{missing_logs.join("\n")}"
      end
    end
  end
end
