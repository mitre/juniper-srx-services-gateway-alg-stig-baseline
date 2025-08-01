control 'SV-214520' do
  title 'The Juniper SRX Services Gateway Firewall must generate audit records when unsuccessful attempts to access security zones occur.'
  desc 'Without generating log records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

Access for different security levels maintains separation between resources (particularly stored data) of different security domains.

The Juniper SRX Firewall implements security zones which are configured with different security policies based on risk and trust levels.'
  desc 'check', 'To verify what is logged in the Syslog, view the Syslog server (Syslog server configuration is out of scope for this STIG); however, the reviewer must also verify that packets are being logged to the local log using the following commands.

From operational mode, enter the following command.

show firewall log

View the Action column; the configured action of the term matches the action taken on the packet: A (accept), D (discard).

If events in the log do not reflect the action taken on the packet, this is a finding.'
  desc 'fix', 'Include the log and/or syslog action in all zone configurations to log attempts to access zones. To get traffic logs from permitted sessions, add "then log session-close" to the policy. To get traffic logs from denied sessions, add "then log session-init" to the policy.

set security policies from-zone <zone_name> to-zone <zone_name> policy <policy_name> then log

Example:
set security policies from-zone untrust to-zone trust policy default-deny then log'
  impact 0.5
  tag check_id: 'C-15726r297244_chk'
  tag severity: 'medium'
  tag gid: 'V-214520'
  tag rid: 'SV-214520r557389_rule'
  tag stig_id: 'JUSX-AG-000037'
  tag gtitle: 'SRG-NET-000493-ALG-000028'
  tag fix_id: 'F-15724r297245_fix'
  tag 'documentable'
  tag legacy: ['SV-80795', 'V-66305']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  # STEP 1: Verify local syslog logging to a file is configured
  syslog_file_cmd = command('show configuration system syslog | display set | match "file"')
  syslog_file_output = syslog_file_cmd.stdout.strip

  describe 'Local syslog file configuration' do
    it 'should include at least one configured file log target' do
      expect(syslog_file_output).to match(/^set system syslog file/), "No local syslog file configured. At least one file log target should be defined to capture logs."
    end
  end

  # STEP 2: Check that firewall log entries are being generated
  firewall_log_cmd = command('show firewall log')
  firewall_log_output = firewall_log_cmd.stdout.strip

  describe 'Firewall log presence' do
    it 'should not be empty' do
      expect(firewall_log_output).not_to be_empty, "Firewall log is empty. Ensure that the firewall is configured to log events."
    end
  end

  # STEP 3: Check that discarded packet actions (D) are being logged
  describe 'Unsuccessful access attempts (discarded packets)' do
    it 'should appear in the firewall log' do
      discard_matches = firewall_log_output.lines.select { |line| line.include?(' D ') || line.strip.end_with?('D') }

      expect(discard_matches).not_to be_empty, "No discarded (D) packet actions found in firewall log. Unsuccessful access attempts may not be logged."
    end
  end
end

