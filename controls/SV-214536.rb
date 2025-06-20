control 'SV-214536' do
  title 'The Juniper SRX Services Gateway Firewall must configure ICMP to meet DoD requirements.'
  desc 'Providing too much information in error messages risks compromising the data and security of the application and system.

Organizations carefully consider the structure/content of error messages. The required information within error messages will vary based on the protocol and error condition. Information that could be exploited by adversaries includes ICMP messages that reveal the use of firewalls or access-control lists.'
  desc 'check', 'Verify ICMP messages are configured to meet DoD requirements.

[edit]
show firewall family inet

If ICMP messages are not configured in compliance with DoD requirements, this is a finding.'
  desc 'fix', 'Configure ICMP to meet DoD requirements. The following is an example which uses the filter name "protect_re" as the filter name with pre-configured address books (source-prefix-lists).

[edit]
set firewall family inet filter protect_re term permit-icmp from source-prefix-list ssh-addresses
set firewall family inet filter protect_re term permit-icmp from source-prefix-list bgp-addresses
set firewall family inet filter protect_re term permit-icmp from source-prefix-list loopback-addresses
set firewall family inet filter protect_re term permit-icmp from source-prefix-list local-addresses
set firewall family inet filter protect_re term permit-icmp from source-prefix-list ixiav4
set firewall family inet filter protect_re term permit-icmp from icmp-type echo-request
set firewall family inet filter protect_re term permit-icmp from icmp-type echo-reply
set firewall family inet filter protect_re term permit-icmp then log
set firewall family inet filter protect_re term permit-icmp then syslog
set firewall family inet filter protect_re term permit-icmp then accept
set firewall family inet6 filter protect_re-v6 term permit-ar from icmp-type neighboradvertisement
set firewall family inet6 filter protect_re-v6 term permit-ar from icmp-type neighborsolicit
set firewall family inet6 filter ingress-v6 term permit-ar from icmp-type neighboradvertisement
set firewall family inet6 filter ingress-v6 term permit-ar from icmp-type neighborsolicit
set firewall family inet6 filter ingress-v6 term permit-ar from icmp-type 134
set firewall family inet6 filter ingress-v6 term permit-ar then accept
set firewall family inet6 filter egress-v6 term permit-lr from icmp-type neighboradvertisement
set firewall family inet6 filter egress-v6 term permit-lr from icmp-type neighbor-solicit
set firewall family inet6 filter egress-v6 term permit-lr from icmp-type 134
set firewall family inet6 filter egress-v6 term permit-lr then accept'
  impact 0.5
  tag check_id: 'C-15742r297292_chk'
  tag severity: 'medium'
  tag gid: 'V-214536'
  tag rid: 'SV-214536r557389_rule'
  tag stig_id: 'JUSX-AG-000132'
  tag gtitle: 'SRG-NET-000273-ALG-000129'
  tag fix_id: 'F-15740r297293_fix'
  tag 'documentable'
  tag legacy: ['SV-80827', 'V-66337']
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']

  # Block or restrict ICMP from untrust to trust (no inbound pings from internet)
  describe command('show configuration security policies | display set | match "application junos-ping"') do
    its('stdout') { should_not match(/from-zone untrust to-zone trust/) }
  end

  # Check that ICMP is not globally allowed in host-inbound system services
  describe command('show configuration security zones | display set | match system-services') do
    # Ensure ICMP is not allowed globally in host-inbound system services
    # Works if: You’ve explicitly deleted or never configured this system service.
    its('stdout') { should_not match(/set security zones security-zone untrust host-inbound-traffic system-services ping/) }
    # To be more precise, we could tighten the match and use:
    # its('stdout') { should_not match(/security-zone untrust .* ping/) }
  end

  # Optionally check rate-limiting (CoS or policer config — advanced)
  describe command('show configuration firewall | display set | match icmp') do
    #its('stdout') { should match(/term block-icmp/) }
    its('stdout') { should match(/term .*icmp.*/) }
  end

  # (Optional) Ensure diagnostic ICMP is allowed internally
  describe command('show configuration security policies | display set | match junos-ping') do
    its('stdout') { should match(/from-zone trust to-zone trust/) }
  end

  # Ensure ICMP is blocked or denied in the security policies
  describe command('show configuration security policies | display set') do
    its('stdout') { should match(/policy block-icmp .* then deny/) }
  end

end
