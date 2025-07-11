control 'SV-214532' do
  title 'The Juniper SRX Services Gateway Firewall must block outbound traffic containing known and unknown denial-of-service (DoS) attacks to protect against the use of internal information systems to launch any DoS attacks against other networks or endpoints.'
  desc 'DoS attacks can take multiple forms but have the common objective of overloading or blocking a network or host to deny or seriously degrade performance. If the network does not provide safeguards against DoS attack, network resources will be unavailable to users. The Juniper SRX must include protection against DoS attacks that originate from inside the enclave, which can affect either internal or external systems. These attacks may use legitimate or rogue endpoints from inside the enclave. These attacks can be simple "floods" of traffic to saturate circuits or devices, malware that consumes CPU and memory on a device or causes it to crash, or a configuration issue that disables or impairs the proper function of a device. For example, an accidental or deliberate misconfiguration of a routing table can misdirect traffic for multiple networks.

The Juniper SRX Firewall uses Screens and Security Policies to detect known DoS attacks with known attack vectors. However, these Screens and policies must be applied to outbound traffic using zones and interface stanzas. 

Traffic exits the Juniper SRX by way of interfaces. Security zones are configured for one or more interfaces with the same security requirements for filtering data packets. A security zone implements a security policy for one or multiple network segments. These policies must be applied to inbound traffic as it crosses both the network perimeter and as it crosses internal security domain boundaries.'
  desc 'check', 'Obtain and review the list of outbound interfaces and zones. This is usually part of the System Design Specification or Accreditation Package.

Review each of the configured outbound interfaces and zones. Verify zones that communicate outbound have been configured with DoS screens.

[edit]
show security zones <security-zone-name>

If the zone for the security screen has not been applied to all outbound interfaces, this is a finding.'
  desc 'fix', 'To enable screen protection, the screen profile must be associated with individual security zones using the following command. Recommend assigning "untrust-screen" profile name.

Apply screen to each outbound interface example:

set security zones security-zone untrust interfaces <OUTBOUND-INTERFACE>
set security zones security-zone trust screen untrust-screen'
  impact 0.5
  tag check_id: 'C-15738r297280_chk'
  tag severity: 'medium'
  tag gid: 'V-214532'
  tag rid: 'SV-214532r997549_rule'
  tag stig_id: 'JUSX-AG-000124'
  tag gtitle: 'SRG-NET-000192-ALG-000121'
  tag fix_id: 'F-15736r297281_fix'
  tag 'documentable'
  tag legacy: ['V-66329', 'SV-80819']
  tag cci: ['CCI-001094', 'CCI-004866']
  tag nist: ['SC-5 (1)', 'SC-5 b']

  # Get list of policies to determine which zones initiate outbound traffic
  policies_output = command('show configuration security policies | display set').stdout

  # Extract all unique outbound zones from "from-zone"
  outbound_zones = policies_output.scan(/set security policies from-zone (\S+) to-zone (\S+)/).map(&:first).uniq

  outbound_zones.each do |zone|
    describe "Security zone #{zone} DoS screen configuration" do
      let(:zone_config) { command("show configuration security zones security-zone #{zone} | display set | match screen").stdout }

      it "should have a DoS screen configured" do
        expect(zone_config).to match(/screen/), "Zone #{zone} is missing a DoS screen"
      end
    end
  end
end
