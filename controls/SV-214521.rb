control 'SV-214521' do
  title 'The Juniper SRX Services Gateway Firewall must be configured to support centralized management and configuration of the audit log.'
  desc 'Without the ability to centrally manage the content captured in the audit records, identification, troubleshooting, and correlation of suspicious behavior would be difficult and could lead to a delayed or incomplete analysis of an ongoing attack.

The DOD requires centralized management of all network component audit record content. Network components requiring centralized audit log management must have the capability to support centralized management. The content captured in audit records must be managed from a central location (necessitating automation). Centralized management of audit records and logs provides for efficiency in maintenance and management of records, as well as the backup and archiving of those records. Ensure at least one Syslog server and local files are configured to support requirements. However, the Syslog itself must also be configured to filter event records so it is not overwhelmed. A best practice when configuring the external Syslog server is to add similar log-prefixes to the log file names to help and researching of central Syslog server. Another best practice is to add a match condition to limit the recorded events to those containing the regular expression (REGEX). This requirement does not apply to audit logs generated on behalf of the device itself (management).

While the Juniper SRX inherently has the capability to generate log records, by default only the high facility levels are captured and only to local files.'
  desc 'check', 'To verify that traffic logs are being sent to the syslog server, check the syslog server files. 

If traffic logs are not being sent to the syslog server, this is a finding.'
  desc 'fix', %q(Logging for security-related sources such as screens and security policies must be configured separately. 

The following example specifies that security log messages in structured-data format (syslog format) are sent from the source <MGT IP address> (e.g., the SRX's loopback or other interface IP address) to an external syslog server.

[edit]
set security log cache
set security log format syslog
set security log source-address <MGT IP Address>
set security log stream <stream name> host <syslog server IP Address>

To get traffic logs from permitted sessions, add "then log session-close" to the policy.
To get traffic logs from denied sessions, add "then log session-init" to the policy. Enable Logging on Security Policies:

[edit]
set security policies from-zone <zone-name> to-zone <zone-name> policy <policy-name> then log <event>

Example to log session init and session close events:
set security policies from-zone trust to-zone untrust policy default-permit then log session-init
set security policies from-zone trust to-zone untrust policy default-permit then log session-close)
  impact 0.5
  tag check_id: 'C-15727r297247_chk'
  tag severity: 'medium'
  tag gid: 'V-214521'
  tag rid: 'SV-214521r997542_rule'
  tag stig_id: 'JUSX-AG-000057'
  tag gtitle: 'SRG-NET-000333-ALG-000049'
  tag fix_id: 'F-15725r297248_fix'
  tag 'documentable'
  tag legacy: ['SV-80797', 'V-66307']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']

  #-----------------------------------------------------------------
  # Use this code if Syslog server is not required (test is skipped)
  #-----------------------------------------------------------------
  # syslog_config = command('show configuration system syslog | display set | match "host "').stdout.strip

  # if syslog_config.empty?
  #   impact 0.0
  #   describe 'Syslog configuration' do
  #     skip 'Syslog is not enabled on the device — skipping syslog tests.'
  #   end
  # else
  #   # Check if syslog configuration contains expected fields
  #   describe command('show configuration system syslog') do
  #     its('stdout') { should match(/host/) }           # Ensure a syslog host is configured
  #     its('stdout') { should match(/log-prefix/) }     # Ensure log-prefix is set for identification
  #     its('stdout') { should match(/any/) }            # Ensure "any" facility is being logged
  #     its('stdout') { should match(/authorization/) }  # Ensure authorization logs are included
  #   end

  #   syslog_server_ip = input('syslog_server_ip')

  #   # Check if the syslog server is reachable
  #   describe command("ping #{syslog_server_ip}") do
  #     its('stdout') { should match(/bytes from/) }       # Ensure the syslog server is reachable
  #   end

  #   # Check if audit logs are being sent to the syslog server
  #   describe command("show log messages | match #{syslog_server_ip}") do
  #     its('stdout') { should_not be_empty }              # Ensure logs are being sent to the syslog server
  #   end
  # end  

  # Check if any remote syslog host is configured
  syslog_host_config = command('show configuration system syslog | display set | match "host "').stdout.strip

  describe 'Remote syslog host configuration check' do
    it 'should have at least one remote syslog host configured' do
      expect(syslog_host_config).not_to be_empty, 
        'No remote syslog hosts are configured — Ensure at least one Syslog server is configured.'
    end
  end

  # Proceed with deeper tests only if syslog is configured
  unless syslog_host_config.empty?
    describe command('show configuration system syslog') do
      its('stdout') { should match(/host/) }           # Remote host exists
      its('stdout') { should match(/log-prefix/) }     # Log prefix set
      its('stdout') { should match(/any/) }            # 'any' facility used
      its('stdout') { should match(/authorization/) }  # Auth logs enabled
    end

    syslog_server_ip = input('syslog_server_ip')

    describe command("ping #{syslog_server_ip}") do
      its('stdout') { should match(/bytes from/) }     # Server reachable
    end

    describe command("show log messages | match #{syslog_server_ip}") do
      its('stdout') { should_not be_empty }            # Logs reaching server
    end
  end  
end
