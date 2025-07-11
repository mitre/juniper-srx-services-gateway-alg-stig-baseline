control 'SV-214535' do
  title 'The Juniper SRX Services Gateway Firewall must deny network communications traffic by default and allow network communications traffic by exception (i.e., deny all, permit by exception).'
  desc "A deny-all, permit-by-exception network communications traffic policy ensures that only those connections which are essential and approved are allowed.

As a managed interface, the ALG must block all inbound and outbound network communications traffic to the application being managed and controlled unless a policy filter is installed to explicitly allow the traffic. The allow policy filters must comply with the site's security policy. A deny all, permit by exception network communications traffic policy ensures that only those connections which are essential and approved, are allowed.

By default, Junos denies all traffic through an SRX Series device using an implicit default security policy exists that denies all packets. Organizations must configure security policies that permits or redirects traffic in compliance with DoD policies and best practices. Sites must not change the factory-default security policies."
  desc 'check', 'Verify the default-policy has not been changed and is set to deny all traffic.

[edit]
show security policies default-policy

If the default-policy is not set to deny-all, this is a finding.'
  desc 'fix', 'By default, the SRX device will not forward traffic unless it is explicitly permitted via security policy. If the default-policy has been changed, then this must be corrected using the set security policies default-policy command.'
  impact 0.5
  tag check_id: 'C-15741r297289_chk'
  tag severity: 'medium'
  tag gid: 'V-214535'
  tag rid: 'SV-214535r557389_rule'
  tag stig_id: 'JUSX-AG-000128'
  tag gtitle: 'SRG-NET-000202-ALG-000124'
  tag fix_id: 'F-15739r297290_fix'
  tag 'documentable'
  tag legacy: ['SV-80825', 'V-66335']
  tag cci: ['CCI-001109']
  tag nist: ['SC-7 (5)']

  
  describe command('show configuration security policies | display set') do
    let(:stdout) { subject.stdout }
    
    # Test 1: Check for a default deny-all policy
    it 'should contain a default deny-all policy' do
      expect(stdout).to match(/set security policies default-policy deny-all/)
    end

    # Test 2: Ensure no allow-all policies exist
    it 'should not contain an allow-all default policy' do
      expect(stdout).not_to match(/set security policies default-policy allow-all/)
    end

    # Test 3: Ensure that at least one explicit policy exists
    it 'should contain at least one explicit policy permitting traffic' do
      expect(stdout).to match(/set security policies from-zone .+ to-zone .+ policy .+ match/)
      expect(stdout).to match(/set security policies from-zone .+ to-zone .+ policy .+ then permit/)
    end
  end
end
