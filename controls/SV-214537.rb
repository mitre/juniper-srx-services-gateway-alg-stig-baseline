control 'SV-214537' do
  title 'The Juniper SRX Services Gateway Firewall must continuously monitor all inbound communications traffic for unusual/unauthorized activities or conditions.'
  desc 'If inbound communications traffic is not continuously monitored, hostile activity may not be detected and prevented. Output from application and traffic monitoring serves as input to continuous monitoring and incident response programs.

The Juniper SRX is a highly scalable system which, by default, provides stateful or stateless continuous monitoring when placed in the architecture at either the perimeter or internal boundaries. 

Unusual/unauthorized activities or conditions may include unusual use of unusual protocols or ports and attempted communications from trusted zones to external addresses. 

Interfaces with identical security requirements can be grouped together into a single security zone. By default, once a security policy is applied to a zone, the Juniper SRX continuously monitors the associated zone for unusual/unauthorized activities or conditions based on the firewall filter or screen associated with that zone.'
  desc 'check', 'For each inbound zone, verify a firewall screen or security policy is configured.

[edit]
show security zone
show security policies

If communications traffic for each inbound zone is not configured with a firewall screen and/or security policy, this is a finding.'
  desc 'fix', 'Configure a security policy or screen to each inbound zone to implement continuous monitoring. The following commands configure a security zone called “untrust” that can be used to apply security policy for inbound interfaces that are connected to untrusted networks. This example assumes that interfaces ge-0/0/1 and ge-0/0/2 are connected to untrusted and trusted network segments.

Apply policy or screen to a zone example:

set security zones security-zone untrust interfaces ge-0/0/1.0
set security zones security-zone trust interfaces ge-0/0/2.0
set security zones security-zone untrust screen untrust-screen
set security policies from-zone untrust to-zone trust policy default-deny match destination-address any
set security policies from-zone untrust to-zone trust policy default-deny then deny'
  impact 0.7
  tag check_id: 'C-15743r1018646_chk'
  tag severity: 'high'
  tag gid: 'V-214537'
  tag rid: 'SV-214537r1018647_rule'
  tag stig_id: 'JUSX-AG-000144'
  tag gtitle: 'SRG-NET-000390-ALG-000139'
  tag fix_id: 'F-15741r297296_fix'
  tag 'documentable'
  tag legacy: ['SV-80829', 'V-66339']
  tag cci: ['CCI-002661']
  tag nist: ['SI-4 (4) (b)']

  # Check that flow trace options are enabled to monitor sessions
  describe command('show configuration security flow') do
    its('stdout') { should match(/traceoptions/) }
  end

  # Per-zone inbound checks
  monitored_zones = input('monitored_zones', value: ['DMZ-zone']) # Set a default 'DMZ-zone'
  monitored_zones.each do |zone|
    # Check that there are policies monitoring inbound traffic from zone
    describe "Inbound security policy from #{zone}" do
      subject { command("show configuration security policies | display set | match 'from-zone #{zone}'") }

      it "should have policies from #{zone} to any zone" do
        expect(subject.stdout).to match(/from-zone #{zone}/)
      end
    end

    # Check that logs are configured for sessions initiated on inbound policies
    describe "Inbound session logging for #{zone}" do
      subject { command("show configuration security policies | display set | match 'from-zone #{zone}' | match 'then log session-init'") }

      it "should log session-init for #{zone} policies" do
        expect(subject.stdout).to match(/then log session-init/)
      end
    end

    # Confirm that host-inbound system services are restricted or monitored on zone
    describe "Host-inbound traffic settings for #{zone}" do
      subject { command("show configuration security zones | display set | match '#{zone}'") }

      it "should not allow all system-services" do
        expect(subject.stdout).not_to match(/system-services all/)
      end

      it "should restrict or monitor system-services" do
        expect(subject.stdout).to match(/host-inbound-traffic system-services/)
      end
    end
  end

  # Optionally confirm IDP or threat detection is active (if licensed)
  # describe command('show configuration security idp') do
  #   its('stdout') { should match(/security idp/) }
  # end
end
