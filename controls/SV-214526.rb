control 'SV-214526' do
  title 'The Juniper SRX Services Gateway Firewall must not be configured as a DHCP server since providing this network service is unrelated to the role as a Firewall.'
  desc 'Information systems are capable of providing a wide variety of functions (capabilities or processes) and services. Some of these functions and services are installed and enabled by default. The organization must determine which functions and services are required to perform the content filtering and other necessary core functionality for each component of the SRX. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

The Juniper SRX is a highly configurable platform that can fulfil many roles in the Enterprise or Branch architecture depending on the model installed. Some services are employed for management services; however, these services can often also be provided as a network service on the data plane. Examples of these services are NTP, DNS, and DHCP. Also, as a Next Generation Firewall (NGFW) and Unified Threat Management (UTM) device, the SRX integrate functions which have been traditionally separated. 

The SRX may integrate related content filtering, security services, and analysis services and tools (e.g., IPS, proxy, malware inspection, black/white lists). Depending on licenses purchased, gateways may also include email scanning, decryption, caching, VPN, and DLP services. However, services and capabilities which are unrelated to this primary functionality must not be installed (e.g., DNS, email server, FTP server, or web server).'
  desc 'check', 'Check both the zones and the interface stanza to ensure DHCP proxy server services are not configured.

[edit]
show system services dhcp

If a stanza exists for DHCP (e.g., forwarders option), this is a finding.'
  desc 'fix', 'First, remove the DHCP stanza. Then re-enter the set security zones and interfaces command without the "dhcp" attribute. The exact command entered depends how the zone is configured with the authorized attributes, services, and options.

Examples: 

[edit]
delete system services dhcp
set security zones security-zone <zone-name> interfaces <interface-name> host-inbound-traffic'
  impact 0.5
  tag check_id: 'C-15732r297262_chk'
  tag severity: 'medium'
  tag gid: 'V-214526'
  tag rid: 'SV-214526r557389_rule'
  tag stig_id: 'JUSX-AG-000086'
  tag gtitle: 'SRG-NET-000131-ALG-000086'
  tag fix_id: 'F-15730r297263_fix'
  tag 'documentable'
  tag legacy: ['V-66317', 'SV-80807']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  # Check if DHCP server is configured under system services
  describe command('show configuration system services') do
    it 'should not configure the device as a DHCP server' do
      expect(subject.stdout).not_to match(/^\s*dhcp\s*{/), 
        'DHCP server configuration found under system services'
    end
  end

  # Extra validation: ensure the dhcp block is empty or not present
  describe command('show configuration system services dhcp') do
    it 'should return no DHCP server configuration' do
      expect(subject.stdout.strip).to eq(''),
        'DHCP configuration should not be present on the firewall'
    end
  end
end
