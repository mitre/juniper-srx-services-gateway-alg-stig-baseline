control 'SV-214522' do
  title 'In the event that communications with the Syslog server is lost, the Juniper SRX Services Gateway must continue to queue traffic log records locally.'
  desc 'It is critical that when the network element is at risk of failing to process audit logs as required, it take action to mitigate the failure. Audit processing failures include: software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded. Responses to audit failure depend upon the nature of the failure mode.

Since availability is an overriding concern given the role of the Juniper SRX in the enterprise, the system must not be configured to shut down in the event of a log processing failure. The system will be configured to log events to local files which will provide a log backup. If communication with the syslog server is lost or the server fails, the network device must continue to queue log records locally. Upon restoration of the connection to the centralized collection server, action should be taken to synchronize the local log data with the collection server.

By default, both traffic log and system log events are sent to a local log file named messages. You can create a separate log file that contains only traffic log messages so that you do not need to filter for traffic log messages. This makes it easier to track usage patterns or troubleshoot issues for a specific policy. 

A best practice is to add log-prefixes to the log file names to help in researching the events and filters to prevent log overload. Another best practice is to add a match condition to limit the recorded events to those containing the regular expression (REGEX).'
  desc 'check', 'Verify logging has been enabled and configured.

[edit] 
show log <LOG-NAME> match "RT_FLOW_SESSION"

If a local log file or files is not configured to capture "RT_FLOW_SESSION" events, this is a finding.'
  desc 'fix', 'The following example commands configure local backup files to capture DoD-defined auditable events. 

[edit]
set system syslog file <LOG-NAME> any info
set system syslog file <LOG-NAME> match "RT_FLOW_SESSION "

Example:
set system syslog file<LOG-NAME> match "RT_FLOW_SESSION "'
  impact 0.5
  tag check_id: 'C-15728r297250_chk'
  tag severity: 'medium'
  tag gid: 'V-214522'
  tag rid: 'SV-214522r1038960_rule'
  tag stig_id: 'JUSX-AG-000063'
  tag gtitle: 'SRG-NET-000089-ALG-000055'
  tag fix_id: 'F-15726r297251_fix'
  tag 'documentable'
  tag legacy: ['SV-80799', 'V-66309']
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']

  # Run the Junos command to show syslog configuration in "set" format
  describe command('show configuration system syslog | display set') do
    let(:output) { subject.stdout }

    # --- Check for at least one local log file destination ---
    # This verifies that a log file is configured and a severity level is defined.
    it 'should define at least one file destination with severity' do
      expect(output).to match(/set system syslog file \S+ any \S+/)
    end

    # --- Check for logging of interactive commands ---
    # Important for auditing administrator activity on the system.
    it 'should define logging for interactive commands' do
      expect(output).to match(/set system syslog file interactive-commands interactive-commands any/)
    end
  end
end
