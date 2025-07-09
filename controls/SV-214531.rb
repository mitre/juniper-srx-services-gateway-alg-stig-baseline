control 'SV-214531' do
  title 'The Juniper SRX Services Gateway Firewall must protect against known types of denial-of-service (DoS) attacks by implementing signature-based screens.'
  desc 'If the network does not provide safeguards against DoS attacks, network resources will be unavailable to users. Installation of content filtering gateways and application layer firewalls at key boundaries in the architecture mitigates the risk of DoS attacks. These attacks can be detected by match(ing observed communications traffic with patterns of known attacks.

Juniper SRX Firewall DoS protections can be configured by either using a Screen or within the global flow options. Screens, also known as IDS-options, block various layer 3 and 4 attacks. Screen objects are configured with various screen-specific options and then assigned to a zone. The Juniper SRX can be configured with Screens to protect against the following signature-based DoS attacks: ICMP based attacks such as ping of death, IP based attacks such as IP spoofing and teardrop, and TCP based attacks such as TCP headers and land.'
  desc 'check', 'Run the following command to see the screen options currently configured:

[edit]
show security screen ids-option
show security zone match( "screen"

If security screens are not configured or if the security zone is not configured with screen options, this is a finding.'
  desc 'fix', 'The following example commands configure security screens under a profile named untrust-screen. Screen options with configurable thresholds may be customized to minimize/prevent operational impact on traffic performance.

[edit]
set security screen ids-option <zone-name> <screen name> <option name> <value>

Based on 800-53 requirements and vendor recommendations, the following signature-based screens are required, at a minimum, for use in DOD configurations.

set security screen ids-option untrust-screen icmp ping-death
set security screen ids-option untrust-screen ip bad-option
set security screen ids-option untrust-screen ip record-route-option
set security screen ids-option untrust-screen ip timestamp-option
set security screen ids-option untrust-screen ip security-option
set security screen ids-option untrust-screen ip stream-option
set security screen ids-option untrust-screen ip spoofing
set security screen ids-option untrust-screen ip source-route-option
set security screen ids-option untrust-screen ip unknown-protocol
set security screen ids-option untrust-screen ip tear-drop
set security screen ids-option untrust-screen ip ipv6-extension-header hop-by-hop-header
jumbo-payload-option
set security screen ids-option untrust-screen ip ipv6-extension-header hop-by-hop-header
router-alert-option
set security screen ids-option untrust-screen ip ipv6-extension-header hop-by-hop-header
quick-start-option
set security screen ids-option untrust-screen ip ipv6-extension-header routing-header
set security screen ids-option untrust-screen ip ipv6-extension-header fragment-header
set security screen ids-option untrust-screen ip ipv6-extension-header no-next-header
set security screen ids-option untrust-screen ip ipv6-extension-header shim6-header
set security screen ids-option untrust-screen ip ipv6-extension-header mobility-header
set security screen ids-option untrust-screen ip ipv6-malformed-header
set security screen ids-option untrust-screen tcp syn-fin
set security screen ids-option untrust-screen tcp fin-no-ack
set security screen ids-option untrust-screen tcp tcp-no-flag
set security screen ids-option untrust-screen tcp syn-frag
set security screen ids-option untrust-screen tcp land

To enable screen protection, the screen profile must be associated with individual security zones using the following command. Recommend assigning "untrust-screen" profile name to the default zone named "untrust".

[edit]
set security zone security-zone <ZONE NAME> screen <SCREEN PROFILE NAME>
Example: set security zones security-zone untrust screen untrust-screen'
  impact 0.7
  tag check_id: 'C-15737r297277_chk'
  tag severity: 'high'
  tag gid: 'V-214531'
  tag rid: 'SV-214531r997548_rule'
  tag stig_id: 'JUSX-AG-000122'
  tag gtitle: 'SRG-NET-000362-ALG-000126'
  tag fix_id: 'F-15735r997547_fix'
  tag 'documentable'
  tag legacy: ['V-66327', 'SV-80817']
  tag cci: ['CCI-002385', 'CCI-004866']
  tag nist: ['SC-5 a', 'SC-5 b']

  # Check if untrust-screen is properly configured under the security zone
  describe command('show configuration security zones security-zone untrust') do
    its('stdout') { should match(/screen untrust-screen/)}
    its('stderr') { should eq '' }
    its('exit_status') { should eq 0 }
  end

  # Check the specific IDS signature options
  describe command('show configuration security screen ids-option untrust-screen | display set') do
    # ICMP-related checks
    its('stdout') { should match(/icmp ping-death/)}
    
    # IP-related checks
    its('stdout') { should include('icmp ping-death') }
    its('stdout') { should include('ip bad-option') }
    its('stdout') { should include('ip record-route-option') }
    its('stdout') { should include('ip timestamp-option') }
    its('stdout') { should include('ip security-option') }
    its('stdout') { should include('ip stream-option') }
    its('stdout') { should include('ip spoofing') }
    its('stdout') { should include('ip source-route-option') }
    its('stdout') { should include('ip unknown-protocol') }
    its('stdout') { should include('ip tear-drop') }

    # IPv6-related checks
    its('stdout') { should include('ip ipv6-extension-header hop-by-hop-header jumbo-payload-option') }
    its('stdout') { should include('ip ipv6-extension-header hop-by-hop-header router-alert-option') }
    its('stdout') { should include('ip ipv6-extension-header hop-by-hop-header quick-start-option') }
    its('stdout') { should include('ip ipv6-extension-header routing-header') }
    its('stdout') { should include('ip ipv6-extension-header fragment-header') }
    its('stdout') { should include('ip ipv6-extension-header no-next-header') }
    its('stdout') { should include('ip ipv6-extension-header shim6-header') }
    its('stdout') { should include('ip ipv6-extension-header mobility-header') }
    its('stdout') { should include('ip ipv6-malformed-header') }

    # TCP-related checks
    its('stdout') { should include('tcp syn-fin') }
    its('stdout') { should include('tcp fin-no-ack') }
    its('stdout') { should include('tcp tcp-no-flag') }
    its('stdout') { should include('tcp syn-frag') }
    its('stdout') { should include('tcp land') }

    its('stderr') { should eq '' }
    its('exit_status') { should eq 0 }
  end  
end
