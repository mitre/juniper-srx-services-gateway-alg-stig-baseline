control 'SV-214533' do
  title 'The Juniper SRX Services Gateway Firewall must only allow inbound communications from organization-defined authorized sources routed to organization-defined authorized destinations.'
  desc 'Unrestricted traffic may contain malicious traffic which poses a threat to an enclave or to other connected networks. Additionally, unrestricted traffic may transit a network, which uses bandwidth and other resources.

Traffic enters the Juniper SRX by way of interfaces. Security zones are configured for one or more interfaces with the same security requirements for filtering data packets. A security zone implements a security policy for one or multiple network segments. These policies must be applied to inbound traffic as it crosses the network perimeter and as it crosses internal security domain boundaries.'
  desc 'check', 'Obtain and review the list of authorized sources and destinations. This is usually part of the System Design Specification or Accreditation Package.

Review each of the configured security policies in turn.

[edit]
show security policies <security-policy-name>

If any existing policies allow traffic that is not part of the authorized sources and destinations list, this is a finding.'
  desc 'fix', 'Configure a security policy or screen to each outbound zone to implement continuous monitoring. The following commands configure a security zone called “untrust” that can be used to apply security policy for inbound interfaces that are connected to untrusted networks. This example assumes that interfaces ge-0/0/1 and ge-0/0/2 are connected to untrusted and trusted network segments.

Apply security policy a zone example:

set security zones security-zone untrust interfaces ge-0/0/1.0
set security zones security-zone trust interfaces ge-0/0/2.0
set security policies from-zone trust to-zone untrust policy default-deny match destination-address any
set security policies from-zone trust to-zone untrust policy default-deny then deny'
  impact 0.5
  tag check_id: 'C-15739r297283_chk'
  tag severity: 'medium'
  tag gid: 'V-214533'
  tag rid: 'SV-214533r997550_rule'
  tag stig_id: 'JUSX-AG-000126'
  tag gtitle: 'SRG-NET-000364-ALG-000122'
  tag fix_id: 'F-15737r297284_fix'
  tag 'documentable'
  tag legacy: ['SV-80821', 'V-66331']
  tag cci: ['CCI-002403', 'CCI-004891']
  tag nist: ['SC-7 (11)', 'SC-7 (29)']

  describe command('show configuration security policies | display set') do
    let(:policy_output) { subject.stdout }

    # Trust to Trust
    it 'allows all traffic within trust zone' do
      expect(policy_output).to match(
        %r{set security policies from-zone trust to-zone trust policy default-permit match source-address any}
      )
      expect(policy_output).to match(
        %r{set security policies from-zone trust to-zone trust policy default-permit match destination-address any}
      )
      expect(policy_output).to match(
        %r{set security policies from-zone trust to-zone trust policy default-permit match application any}
      )
      expect(policy_output).to match(
        %r{set security policies from-zone trust to-zone trust policy default-permit then permit}
      )
    end

    # Trust to Untrust
    it 'allows all traffic from trust to untrust' do
      expect(policy_output).to match(
        %r{set security policies from-zone trust to-zone untrust policy default-permit match source-address any}
      )
      expect(policy_output).to match(
        %r{set security policies from-zone trust to-zone untrust policy default-permit match destination-address any}
      )
      expect(policy_output).to match(
        %r{set security policies from-zone trust to-zone untrust policy default-permit match application any}
      )
      expect(policy_output).to match(
        %r{set security policies from-zone trust to-zone untrust policy default-permit then permit}
      )
    end

    # Default policy fallback
    it 'has default permit-all policy set' do
      expect(policy_output).to match(
        %r{set security policies default-policy permit-all}
      )
    end
  end

  # ---------------------------------------------------------------------------
  # To validate using specific authorized sources and destinations, use this code
  # ---------------------------------------------------------------------------
  
  # Define inputs for authorized sources and destinations
  # authorized_sources = input('authorized_sources', value: [])
  # authorized_destinations = input('authorized_destinations', value: [])

  #  # Check if security policies are configured to allow only authorized sources to authorized destinations
  # describe command('show configuration security policies') do
  #   authorized_sources.each do |source|
  #     its('stdout') { should include("source-address #{source}") }
  #   end

  #   authorized_destinations.each do |destination|
  #     its('stdout') { should include("destination-address #{destination}") }
  #   end

  #   its('stdout') { should include('then permit') } # Ensure the policy explicitly permits traffic
  # end

  # # Ensure there is a default-deny policy for all other traffic
  # describe command('show configuration security policies') do
  #   its('stdout') { should include('policy default-deny') }
  #   its('stdout') { should include('match destination-address any') }
  #   its('stdout') { should include('then deny') }
  # end

  
  # ---------------------------------------------------------------------------
  # To validate that the policy from trust to untrust allows traffic only from
  # defined source subnet to specific destination IP using HTTPS use this code
  # ---------------------------------------------------------------------------

  # describe command('show configuration security policies | display set') do
  #   let(:output) { subject.stdout }

  #   it 'does not use overly broad source-address (e.g., any)' do
  #     expect(output).not_to match(
  #       /set security policies from-zone trust to-zone untrust policy .* match source-address any/
  #     )
  #   end

  #   it 'does not use overly broad destination-address (e.g., any)' do
  #     expect(output).not_to match(
  #       /set security policies from-zone trust to-zone untrust policy .* match destination-address any/
  #     )
  #   end

  #   it 'does not use overly broad application match (e.g., any)' do
  #     expect(output).not_to match(
  #       /set security policies from-zone trust to-zone untrust policy .* match application any/
  #     )
  #   end

  #   it 'contains the specific source-address TRUST-SUBNET' do
  #     expect(output).to match(
  #       /set security policies from-zone trust to-zone untrust policy allow-web match source-address TRUST-SUBNET/
  #     )
  #   end

  #   it 'contains the specific destination-address WEB-SERVER' do
  #     expect(output).to match(
  #       /set security policies from-zone trust to-zone untrust policy allow-web match destination-address WEB-SERVER/
  #     )
  #   end

  #   it 'contains the specific application https' do
  #     expect(output).to match(
  #       /set security policies from-zone trust to-zone untrust policy allow-web match application https/
  #     )
  #   end

  #   it 'permits traffic for allow-web policy' do
  #     expect(output).to match(
  #       /set security policies from-zone trust to-zone untrust policy allow-web then permit/
  #     )
  #   end
  # end
end
