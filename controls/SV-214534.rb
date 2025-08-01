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

  # --------------------------------------------------------------------------
  # OVERALL CONTROL PURPOSE:
  # This control verifies that the Juniper SRX firewall is configured to fail
  # securely (fail closed) if its filtering functions fail. This ensures that
  # no traffic is allowed by default unless explicitly permitted, reducing the
  # risk of unauthorized access during an outage or misconfiguration.
  # 
  # TESTS:
  # 1. Default deny between trust and untrust zones
  # 2. Default global deny policy
  # 3. Interfaces/zones are not open to all system services
  # 4. Explicit deny-all policy exists in configuration (optional)
  # -------------------------------------------------------------------------

  #-------------------------------------------------------------------------------
  # Test 1: Check that the default policy between trust and untrust zones is deny
  #-------------------------------------------------------------------------------
  describe command('show configuration security policies from-zone trust to-zone untrust | display set') do
    let(:output) { subject.stdout }

    it 'should include an explicit deny rule in trust-to-untrust policies' do
      expect(output).to match(%r{set security policies from-zone trust to-zone untrust policy .* then deny}),
        <<~FAILMSG
          Expected an explicit 'then deny' rule for traffic from trust to untrust to enforce fail-closed behavior.
        FAILMSG
    end

    it 'should define at least one policy for trust to untrust' do
      expect(output).to match(/policy/),
        <<~FAILMSG
          No policies were found from trust to untrust. Without any policy, traffic is denied implicitly,
          but it's best practice to explicitly define a deny-all catch-all rule.
        FAILMSG
    end
  end

  #-------------------------------------------------------------------------------
  # Test 2: Ensure a global default policy is in place to deny traffic between
  #         unspecified zones (applies when zone pairs aren't explicitly defined)
  #-------------------------------------------------------------------------------
  describe command('show configuration security policies global | display set') do
    let(:output) { subject.stdout }

    it 'should include a global deny-all catch-all policy' do
      expect(output).to match(%r{set security policies global policy .* then deny}),
        <<~FAILMSG
          Expected to find a global 'then deny' rule to enforce default deny behavior when no specific zone-to-zone policy exists.
          You need to define a global security policy on your Juniper SRX that explicitly denies all traffic as a catch-all (fail-closed) rule.
          This ensures that if no specific policies are defined for a zone pair, the default behavior is to deny all traffic.
          This is critical for maintaining a secure posture in the event of misconfigurations or unexpected traffic patterns.
          Without this, the firewall may allow traffic that should be blocked, leading to potential security vulnerabilities.
          Use the following command to set a global deny-all policy:
            set security policies global policy deny-all match source-address any
            set security policies global policy deny-all match destination-address any
            set security policies global policy deny-all match application any
            set security policies global policy deny-all then deny
        FAILMSG
    end
  end

  #-------------------------------------------------------------------------------
  # Test 3: Ensure no interface or zone allows all inbound traffic by default
  #-------------------------------------------------------------------------------
  describe command('show configuration security zones | display set') do
    let(:output) { subject.stdout }

    it 'should not allow all system services inbound on any interface' do
      expect(output).not_to match(/host-inbound-traffic.*system-services all/),
        <<~FAILMSG
          Found an interface or zone allowing all system services inbound (system-services all).
          This could allow unauthorized access if not strictly managed.
          For all interfaces that allow inbound traffic, replace system-services all with specify system services.
          For example:
            set security zones security-zone <zone-name> host-inbound-traffic system-services ssh
            set security zones security-zone <zone-name> host-inbound-traffic system-services ssh telnet
        FAILMSG
    end
  end

  #-------------------------------------------------------------------------------
  # Test 4: Look for an explicitly named catch-all deny-all rule
  #         (optional convention check)
  #-------------------------------------------------------------------------------
  describe command('show configuration security policies | display set') do
    let(:output) { subject.stdout }

    it 'should include a policy named deny-all or equivalent' do
      expect(output).to match(/set security policies .* policy deny-all .* then deny/),
        <<~FAILMSG
          Could not find a policy named 'deny-all' or an equivalent policy that denies all traffic.
          Having a clearly named deny-all rule helps make fail-closed behavior obvious to reviewers.
          If you do not have a deny-all policy, consider adding one to ensure that all traffic is denied by default.
          Use the following command to create a deny-all policy:
            set security policies from-zone <zone-name> to-zone <zone-name> policy deny-all match source-address any
            set security policies from-zone <zone-name> to-zone <zone-name> policy deny-all match destination-address any
            set security policies from-zone <zone-name> to-zone <zone-name> policy deny-all match application any
            set security policies from-zone <zone-name> to-zone <zone-name> policy deny-all then deny
          This will ensure that any traffic not explicitly allowed by other policies is denied, maintaining a fail-closed posture.
        FAILMSG
    end
  end
end
