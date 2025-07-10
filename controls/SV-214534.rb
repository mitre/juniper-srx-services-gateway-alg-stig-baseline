control 'SV-214534' do
  title 'The Juniper SRX Services Gateway Firewall must be configured to fail securely in the event of an operational failure of the firewall filtering or boundary protection function.'
  desc 'If a boundary protection device fails in an unsecure manner (open), information external to the boundary protection device may enter, or the device may permit unauthorized information release.

Secure failure ensures when a boundary control device fails, all traffic will be subsequently denied.

Fail secure is a condition achieved by employing information system mechanisms to ensure in the event of operational failures of boundary protection devices at managed interfaces (e.g., routers, firewalls, guards, and application gateways residing on protected subnetworks commonly referred to as demilitarized zones), information systems do not enter into unsecure states where intended security properties no longer hold.'
  desc 'check', 'Request documentation of the architecture and Juniper SRX configuration. Verify the site has configured the SRX to fail closed, thus preventing traffic from flowing through without filtering and inspection.

If the site has not configured the SRX to fail closed, this is a finding.'
  desc 'fix', 'Implement and configure the Juniper SRX to fail closed, thus preventing traffic from flowing through without filtering and inspection. In case of failure, document a process for the Juniper SRX to be configured to fail closed. Redundancy should be implemented if failing closed has a mission impact.'
  impact 0.5
  tag check_id: 'C-15740r297286_chk'
  tag severity: 'medium'
  tag gid: 'V-214534'
  tag rid: 'SV-214534r557389_rule'
  tag stig_id: 'JUSX-AG-000127'
  tag gtitle: 'SRG-NET-000365-ALG-000123'
  tag fix_id: 'F-15738r297287_fix'
  tag 'documentable'
  tag legacy: ['V-66333', 'SV-80823']
  tag cci: ['CCI-001126']
  tag nist: ['SC-7 (18)']

  #----------------------------------------------------------------------------
  # Tests verifies that the Juniper SRX firewall "fails closed"
  # (i.e., blocks traffic by default if it fails or loses configuration).
  # The following are being checked:
  #  - No traffic is allowed by default, unless explicitly permitted
  #  - Global default-deny policies are in place
  #  - Unconfigured interfaces/zones do not forward traffic
  #----------------------------------------------------------------------------
  
  # Check security policies between trust and untrust zones
  # Look for a default deny policy between key zones
  describe command('show security policies from-zone trust to-zone untrust') do
    # Output must show "Default policy: deny all"
    its('stdout') { should match (/Default policy: deny all/) }
  end

  # Check global security policy defaults
  # Ensures that a default deny-all global policy is in place for unspecified zone combinations
  describe command('show security policies global') do
    its('stdout') { should match (/Default policy: deny all/) }
  end

  # Ensure no interfaces are configured to accept all inbound traffic by default
  # This prevents unmanaged services from being exposed
  describe command('show security zones') do
    # check that no zone is allowing "host-inbound-traffic system-services all" implicitly
    its('stdout') { should_not match (/interfaces.*trust.*host-inbound-traffic.*system-services.*all/) }
  end

  # Verify that a global deny-all policy is actually configured
  # This is usually a catch-all rule at the bottom of the policy list
  describe command('show configuration security policies') do
    # Match a policy named "deny-all" or similar
    its('stdout') { should match (/deny-all/) }
  end

  # #----------------------------------------------------------------------------
  # # To check if Default policies are set to deny all traffic use this block
  # #----------------------------------------------------------------------------

  # # Ensure the SRX fails closed by default
  # describe command('show configuration security policies | display set') do
  #   let(:policy_output) { subject.stdout }

  #   # Default policies should deny all traffic
  #   it 'has default deny-all policy for untrust zone' do
  #     expect(policy_output).to match(
  #       %r{set security policies from-zone untrust to-zone trust policy default-deny match source-address any}
  #     )
  #     expect(policy_output).to match(
  #       %r{set security policies from-zone untrust to-zone trust policy default-deny match destination-address any}
  #     )
  #     expect(policy_output).to match(
  #       %r{set security policies from-zone untrust to-zone trust policy default-deny then deny}
  #     )
  #   end
  # end
end
