control 'SV-214527' do
  title 'The Juniper SRX Services Gateway Firewall must be configured to prohibit or restrict the use of unauthorized functions, ports, protocols, and/or services, as defined in the PPSM CAL, vulnerability assessments.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types); organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

DoD continually assesses the ports, protocols, and services that can be used for network communications. Some ports, protocols or services have known exploits or security weaknesses. Network traffic using these ports, protocols, and services must be prohibited or restricted in accordance with DoD policy. The PPSM CAL and vulnerability assessments provide an authoritative source for ports, protocols, and services that are unauthorized or restricted across boundaries on DoD networks.

The Juniper SRX must be configured to prevent or restrict the use of prohibited ports, protocols, and services throughout the network by filtering the network traffic and disallowing or redirecting traffic as necessary. Default and updated policy filters from the vendors will disallow older version of protocols and applications and will address most known non-secure ports, protocols, and/or services.'
  desc 'check', 'Entering the following commands from the configuration level of the hierarchy.

[edit]
show security services

If functions, ports, protocols, and services identified on the PPSM CAL are not disabled, this is a finding.'
  desc 'fix', 'Ensure functions, ports, protocols, and services identified on the PPSM CAL are not used for system services configuration.

[edit]
show security services

Compare the services which are enabled, including the port, services, protocols and functions.

Consult the Juniper knowledge base and configuration guides to determine the commands for disabling each port, protocol, service or function that is not in compliance with the PPSM CAL and vulnerability assessments.'
  impact 0.5
  tag check_id: 'C-15733r297265_chk'
  tag severity: 'medium'
  tag gid: 'V-214527'
  tag rid: 'SV-214527r557389_rule'
  tag stig_id: 'JUSX-AG-000087'
  tag gtitle: 'SRG-NET-000132-ALG-000087'
  tag fix_id: 'F-15731r297266_fix'
  tag 'documentable'
  tag legacy: ['SV-80809', 'V-66319']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']

  # -----------------------------------------------
  # Input: List of approved "set" command prefixes
  # These represent allowed Junos service lines under 'security services'.
  # This list should match the PPSM CAL (or organizational policy).
  # -----------------------------------------------
  approved_services = input('approved_services')
  
  # Get the configuration output from the device
  # We use `match "security services"` to extract only the relevant config lines.
  # The 'display set' format ensures each line starts with `set ...`
  cmd = command('show configuration | display set | match "security services"')
  output = cmd.stdout

  # Basic check: Ensure the command executed successfully
  describe 'Security services configuration' do
    it 'should retrieve the configuration successfully' do
      expect(cmd.exit_status).to eq(0)
    end
  end

  # Clean and extract all lines that begin with `set security services`
  configured_services = output.lines.map(&:strip).select { |line| line.start_with?('set security services') }

  # Compare each configured line to the approved list
  describe 'Configured security services' do
    it 'should only include PPSM-approved services' do
      configured_services.each do |line|
        expect(
          approved_services.any? { |approved| line.start_with?(approved) }
        ).to eq(true), "Unauthorized service found: #{line}"
      end
    end
  end
end
