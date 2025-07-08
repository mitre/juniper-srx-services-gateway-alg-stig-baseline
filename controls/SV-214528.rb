control 'SV-214528' do
  title 'The Juniper SRX Services Gateway Firewall must terminate all communications sessions associated with user traffic after 15 minutes or less of inactivity.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element.

This control does not imply that the device terminates all sessions or network access; it only ends the inactive session.

Since many of the inactivity timeouts pre-defined by Junos OS are set to 1800 seconds, an explicit custom setting of 900 must be set for each application used by the DoD implementation. Since a timeout cannot be set directly on the predefined applications, the timeout must be set on the any firewall rule that uses a pre-defined application (i.e., an application that begins with junos-), otherwise the default pre-defined timeout will be used.'
  desc 'check', 'Check both the applications and protocols to ensure session inactivity timeout for communications sessions is set to 900 seconds or less.

First get a list of security policies, then enter the show details command for each policy-name found.

[edit]
show security policies
show security policy <policy-name> details

Example:
Application: any
 IP protocol: 0, ALG: 0, Inactivity timeout: 0

Verify an activity timeout is configured for either "any" application or, at a minimum, the pre-defined applications (i.e., application names starting with junos-).

To verify locally created applications, first get a list of security policies, then enter the show details command for each policy-name found.

[edit]
Show applications 
show applications application <application-name>

If an inactivity timeout value of 900 seconds or less is not set for each locally created application and pre-defined applications, this is a finding.'
  desc 'fix', 'Add or update the session inactivity timeout for communications sessions to 900 seconds or less.

Examples: 
[edit]
set applications application <application-name> term 1 protocol udp inactivity-timeout 900
set applications application junos-http inactivity-timeout 900

Or

Create a service that matches any TCP/UDP:
[edit]
set applications application TCP-ALL source-port 1-65535 destination-port 1-65535 protocol tcp inactivity-timeout 900

Note: When pre-defined applications are used in firewall policies, the timeout value must be set in the policy stanza.'
  impact 0.5
  tag check_id: 'C-15734r297268_chk'
  tag severity: 'medium'
  tag gid: 'V-214528'
  tag rid: 'SV-214528r971530_rule'
  tag stig_id: 'JUSX-AG-000105'
  tag gtitle: 'SRG-NET-000213-ALG-000107'
  tag fix_id: 'F-15732r297269_fix'
  tag 'documentable'
  tag legacy: ['V-66321', 'SV-80811']
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
  
  # 15 minutes = 900 seconds
  MAX_TIMEOUT = input('max_timeout', value: 900)

  # TCP Protocol-Level Timeout
  tcp_session_cmd = command('show configuration security flow tcp-session | display set')

  describe 'TCP protocol-level session timeouts' do
    it "tcp-initial-timeout should be #{MAX_TIMEOUT} seconds or less" do
      if tcp_session_cmd.stdout =~ /tcp-initial-timeout (\d+)/
        timeout = Regexp.last_match(1).to_i
        expect(timeout).to be <= MAX_TIMEOUT
      else
        skip 'tcp-initial-timeout not configured'
      end
    end

    it "time-wait-state should be #{MAX_TIMEOUT} seconds or less" do
      if tcp_session_cmd.stdout =~ /time-wait-state session-timeout (\d+)/
        timeout = Regexp.last_match(1).to_i
        expect(timeout).to be <= MAX_TIMEOUT
      else
        skip 'TCP session timeout (time-wait-state session-timeout) not configured.'
      end
    end
  end

  # Application-Level Inactivity Timeouts (TCP & UDP)
  app_timeout_cmd = command('show configuration applications | display set | match inactivity-timeout')

  if app_timeout_cmd.stdout.strip.empty?
    describe 'Application-defined session timeouts (TCP/UDP)' do
      skip 'No application inactivity-timeouts configured.'
    end
  else
    describe 'Application-defined session timeouts (TCP/UDP)' do
      it "should be #{MAX_TIMEOUT} seconds or less when configured" do
        timeouts = app_timeout_cmd.stdout.lines.map do |line|
          match = line.match(/inactivity-timeout (\d+)/)
          match ? match[1].to_i : nil
        end.compact

        expect(timeouts).not_to be_empty
        timeouts.each do |timeout|
          expect(timeout).to be <= MAX_TIMEOUT
        end
      end
    end
  end
end

