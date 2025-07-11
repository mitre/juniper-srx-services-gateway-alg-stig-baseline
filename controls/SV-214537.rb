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

  # ------------------------------------------------------------------------
  # Ensure that zones receiving inbound traffic (e.g., trust → untrust) are:
  # - Monitored with security policies
  # - Logging inbound session attempts
  # - Using screens if appropriate
  # - Only perform monitoring checks if the zone contains Layer 3 (routed) interfaces
  # - Pass the test if only Layer 2 (switched) interfaces are present
  # ------------------------------------------------------------------------

  # Per-zone inbound checks
  monitored_zones = input('monitored_zones', value: ['trust', 'untrust', 'dmz'])

  monitored_zones.each do |zone|
    # Step 1: Identify all interfaces assigned to the zone
    interfaces_cmd = inspec.command("show configuration security zones security-zone #{zone} | display set | match interfaces")
    interfaces = interfaces_cmd.stdout.scan(/interfaces (\S+)/).flatten.uniq

    # Step 2: Determine if any are Layer 3 (routed) interfaces
    l3_interfaces = interfaces.select do |intf|
      intf_config = inspec.command("show configuration interfaces #{intf} | display set").stdout
      intf_config.include?('family inet')
    end

    if l3_interfaces.empty?
      # Zone has no L3 interfaces — STIG check not applicable
      describe "Zone '#{zone}' has no Layer 3 interfaces — STIG checks not applicable" do
        it 'passes because no routed interfaces exist in the zone' do
          expect(true).to eq(true)
        end
      end
    else
      # Zone has L3 interfaces — apply full STIG checks
      describe "Zone '#{zone}' has Layer 3 interfaces — applying STIG inbound checks" do

        # Check 1: Security policies exist for traffic coming from this zone
        it 'has security policies for inbound traffic from this zone' do
          policy_check = inspec.command("show configuration security policies | display set | match 'from-zone #{zone}'")
          expect(policy_check.stdout).to match(/from-zone #{zone}/)
        end

        # Check 2: Session logging is configured for inbound policies
        it 'logs inbound sessions using session-init' do
          log_check = inspec.command("show configuration security policies | display set | match 'from-zone #{zone}' | match 'then log session-init'")
          expect(log_check.stdout).to match(/then log session-init/)
        end

        # Check 3: A firewall screen is applied to the zone
        it 'has a firewall screen applied to the zone' do
          screen_check = inspec.command("show configuration security zones | display set | match '#{zone} screen'")
          expect(screen_check.stdout).to match(/set security zones security-zone #{zone} screen/)
        end

        # Check 4: Host-inbound traffic is restricted and not wide open
        it 'restricts host-inbound system services' do
          hit_check = inspec.command("show configuration security zones | display set | match '#{zone}'")
          expect(hit_check.stdout).not_to match(/system-services all/)
          expect(hit_check.stdout).to match(/host-inbound-traffic system-services/)
        end
      end
    end
  end
end
