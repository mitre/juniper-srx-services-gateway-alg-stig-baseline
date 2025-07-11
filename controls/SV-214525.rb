control 'SV-214525' do
  title 'The Juniper SRX Services Gateway Firewall must not be configured as a DNS proxy since providing this network service is unrelated to the role as a Firewall.'
  desc 'Information systems are capable of providing a wide variety of functions (capabilities or processes) and services. Some of these functions and services are installed and enabled by default. The organization must determine which functions and services are required to perform the content filtering and other necessary core functionality for each component of the SRX. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

The Juniper SRX is a highly configurable platform that can fulfil many roles in the Enterprise or Branch architecture depending on the model installed. Some services are employed for management services; however, these services can often also be provided as a network service on the data plane. Examples of these services are NTP, DNS, and DHCP. Also, as a Next Generation Firewall (NGFW) and Unified Threat Management (UTM) device, the SRX integrate functions which have been traditionally separated. 

The SRX may integrate related content filtering, security services, and analysis services and tools (e.g., IPS, proxy, malware inspection, black/white lists). Depending on licenses purchased, gateways may also include email scanning, decryption, caching, VPN, and DLP services. However, services and capabilities which are unrelated to this primary functionality must not be installed (e.g., DNS, email server, FTP server, or web server).'
  desc 'check', 'Check both the zones and the interface stanza to ensure DNS proxy server services are not configured.

[edit}
show system services dns

If a stanza exists for DNS (e.g., forwarders option), this is a finding.'
  desc 'fix', 'First, remove the DNS stanza. Then re-enter the set security zones and interfaces command without the "dns" attribute. The exact command entered depends how the zone is configured with the authorized attributes, services, and options.

Examples: 

[edit]
delete system services dns
set security zones security-zone <zone-name> interfaces <interface-name> host-inbound-traffic'
  impact 0.5
  tag check_id: 'C-15731r297259_chk'
  tag severity: 'medium'
  tag gid: 'V-214525'
  tag rid: 'SV-214525r557389_rule'
  tag stig_id: 'JUSX-AG-000085'
  tag gtitle: 'SRG-NET-000131-ALG-000086'
  tag fix_id: 'F-15729r297260_fix'
  tag 'documentable'
  tag legacy: ['V-66315', 'SV-80805']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  # Retrieve full configuration once
  cmd = command('show configuration | display set')
  output = cmd.stdout

  describe 'Configuration retrieval' do
    it 'should succeed' do
      expect(cmd.exit_status).to eq(0)
    end
  end

  # Check security zones for DNS service
  describe 'Security zone service configuration' do
    it 'should not enable DNS as a system service' do
      expect(output).not_to match(/set security zones security-zone .* host-inbound-traffic system-services dns/)
    end
  end

  # Check interfaces for DNS proxy
  describe 'Interface-level DNS proxy' do
    it 'should not configure DNS proxy on interfaces' do
      expect(output).not_to match(/set interfaces .* unit \d+ family inet .* dns-proxy/)
    end
  end

  # Check global forwarding-options for DNS proxy
  describe 'Forwarding options DNS proxy' do
    it 'should not define global DNS proxy options' do
      expect(output).not_to match(/set forwarding-options dns-proxy/)
    end
  end
end
