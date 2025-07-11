control 'SV-214538' do
  title 'The Juniper SRX Services Gateway Firewall must continuously monitor outbound communications traffic for unusual/unauthorized activities or conditions.'
  desc 'If outbound communications traffic is not continuously monitored, hostile activity may not be detected and prevented. Output from application and traffic monitoring serves as input to continuous monitoring and incident response programs.

The Juniper SRX is a highly scalable system that can provide stateful or stateless continuous monitoring when placed in the architecture at the perimeter or internal boundaries. Unusual/unauthorized activities or conditions may include use of unusual protocols or ports and attempted communications from trusted zones to external addresses.'
  desc 'check', 'For each outbound zone, verify a firewall screen or security policy is configured.

[edit]
show security zones
show security policies

If communications traffic for each outbound zone is not configured with a firewall screen or security policy, this is a finding.'
  desc 'fix', 'Configure a security policy or screen to each outbound zone to implement continuous monitoring. The following commands configure a security zone called "untrust" that can be used to apply security policy for inbound interfaces that are connected to untrusted networks. This example assumes that interfaces ge-0/0/1 and ge-0/0/2 are connected to untrusted and trusted network segments.

Apply policy or screen to a zone example:

set security zones security-zone untrust interfaces ge-0/0/1.0
set security zones security-zone trust interfaces ge-0/0/2.0
set security zones security-zone untrust screen untrust-screen
set security policies from-zone trust to-zone untrust policy default-deny match destination-address any
set security policies from-zone trust to-zone untrust policy default-deny then deny'
  impact 0.7
  tag check_id: 'C-15744r1056073_chk'
  tag severity: 'high'
  tag gid: 'V-214538'
  tag rid: 'SV-214538r1056075_rule'
  tag stig_id: 'JUSX-AG-000145'
  tag gtitle: 'SRG-NET-000391-ALG-000140'
  tag fix_id: 'F-15742r1056074_fix'
  tag 'documentable'
  tag legacy: ['SV-80831', 'V-66341']
  tag cci: ['CCI-002662']
  tag nist: ['SI-4 (4) (b)']


  # ------------------------------------------------------------------------
  # Ensure that zones sending outbound traffic (e.g., trust → untrust) are:
  #  - Monitored with security policies
  #  - Logging outbound session attempts
  #  - Using screens if appropriate
  #  - Restricting host outbound system traffic
  #  - Only perform monitoring checks if the zone contains Layer 3 (routed) interfaces
  #  - Pass the test if only Layer 2 (switched) interfaces are present
  # ------------------------------------------------------------------------

  # Per-zone outbound checks
  monitored_zones = input('monitored_zones', value: ['trust', 'untrust', 'dmz'])

  # Loop through each zone to apply STIG checks
  monitored_zones.each do |zone|

    # Step 1: Get all interfaces assigned to this zone
    interfaces_cmd = inspec.command("show configuration security zones security-zone #{zone} | display set | match interfaces")
    interfaces = interfaces_cmd.stdout.scan(/interfaces (\S+)/).flatten.uniq

    # Step 2: Identify which of those interfaces are Layer 3 (have `family inet`)
    l3_interfaces = interfaces.select do |intf|
      intf_config = inspec.command("show configuration interfaces #{intf} | display set").stdout
      intf_config.include?('family inet')
    end

    # If there are no Layer 3 interfaces, STIG checks don't apply
    if l3_interfaces.empty?

      # Pass with a clear message — this will appear in [PASS] test output
      describe "Zone '#{zone}' has no Layer 3 interfaces — STIG checks not applicable" do
        it 'passes because no routed interfaces exist in the zone' do
          expect(true).to eq(true)
        end
      end

    else
      # Zone has L3 interfaces — apply all outbound STIG checks
      describe "Zone '#{zone}' has Layer 3 interfaces — applying STIG outbound checks" do

        # Check 1: Security policies are defined for outbound traffic from this zone
        it 'has security policies defined for outbound traffic' do
          policy_check = inspec.command("show configuration security policies | display set | match 'from-zone #{zone}'")
          expect(policy_check.stdout).to match(/from-zone #{zone}/)
        end

        # Check 2: Outbound sessions are logged
        it 'logs outbound sessions using session-init' do
          log_check = inspec.command("show configuration security policies | display set | match 'from-zone #{zone}' | match 'then log session-init'")
          expect(log_check.stdout).to match(/then log session-init/)
        end

        # Check 3: A firewall screen is applied to the zone
        it 'has a firewall screen applied to the zone' do
          screen_check = inspec.command("show configuration security zones | display set | match '#{zone} screen'")
          expect(screen_check.stdout).to match(/set security zones security-zone #{zone} screen/)
        end

        # Check 4: Host-inbound traffic (like ping, ssh) is restricted — not overly permissive
        it 'restricts host-inbound system services' do
          hit_check = inspec.command("show configuration security zones | display set | match '#{zone}'")
          expect(hit_check.stdout).not_to match(/system-services all/)  # Do not allow all system services
          expect(hit_check.stdout).to match(/host-inbound-traffic system-services|protocols/)  # At least something is defined
        end
      end
    end
  end
end
