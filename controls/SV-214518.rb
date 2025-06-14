control 'SV-214518' do
  title 'For User Role Firewalls, the Juniper SRX Services Gateway Firewall must employ user attribute-based security policies to enforce approved authorizations for logical access to information and system resources.'
  desc 'Successful authentication must not automatically give an entity access to an asset or security boundary. The lack of authorization-based access control could result in the immediate compromise and unauthorized access to sensitive information. All DOD systems must be properly configured to incorporate access control methods that do not rely solely on authentication for authorized access.

Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset.

The Juniper Technical Library, Understanding User Role Firewalls, explains this Juniper SRX functionality in detail. This function integrates user-based firewall policies. Administrators can permit or restrict network access of employees, contractors, partners, and other users based on the roles they are assigned. User role firewalls enable greater threat mitigation, provide more informative forensic resources, improve record archiving for regulatory compliance, and enhance routine access provisioning. User role firewalls are more feasible with sites that do not have production workload and are used for employees to access network resources as opposed to large-scale datacenter environments.

User role firewalls trigger two actions, retrieval of user and/or role information associated with the traffic, and determine the action to take based on six match criteria within the context of the zone pair.

The source-identity field distinguishes a user role firewall from other types of firewalls. If the source identity is specified in any policy for a particular zone pair, it is a user role firewall. The user and role information must be retrieved before policy lookup occurs. If the source identity is not specified in any policy, user and role lookup is not required.

To retrieve user and role information, authentication tables are searched for an entry with an IP address corresponding to the traffic. If an entry is found, the user is classified as an authenticated user. If not found, the user is classified as an unauthenticated user.

The username and roles associated with an authenticated user are retrieved for policy matching. Both the authentication classification and the retrieved user and role information are used to match the source-identity field.

Characteristics of the traffic are matched to the policy specifications. Within the zone context, the first policy that matches the user or role and the five standard match criteria determines the action to be applied to the traffic.'
  desc 'check', 'If user-based firewall policies are not used, this is Not Applicable.

To verify the existence of user-based firewall policies, view a summary of all policies configured on the firewall.

[edit]
show security policies

If the source identity is not specified in any policy for a particular zone pair, this is a finding.'
  desc 'fix', "Configure attribute-based security policies to enforce approved authorizations for logical access to information and system resources using the following commands.

To configure redirection from the SRX Series device to the Access Control Service, from configuration mode, configure the UAC profile for the captive portal <acs-device>.

[edit]
set services unified-access-control captive-portal <acs-device-name> redirect-traffic unauthenticated

Configure the redirection URL for the Access Control Service or a default URL for the captive portal.

[edit]
set services unified-access-control captive-portal acs-device redirect-url https://%ic-url%/?target=%dest-url%&enforcer=%enforcer-id%

This policy specifies the default target and enforcer variables to be used by the Access Control Service to direct the user back after authentication. This ensures that changes to system specifications will not affect configuration results.

Configure a user role firewall policy that redirects HTTP traffic from zone trust to zone untrust if the source-identity is unauthenticated-user. The captive portal profile name is specified as the action to be taken for traffic matching this policy. The following is an example only since there the actual policy is dependent on the architecture of the organization's network.

[edit]
set security policies from-zone trust to-zone untrust policy user-role-fw1 match source-address any
set security policies from-zone trust to-zone untrust policy user-role-fw1 match destination-address any
set security policies from-zone trust to-zone untrust policy user-role-fw1 match application http
set security policies from-zone trust to-zone untrust policy user-role-fw1 match source-identity unauthenticated-user
set security policies from-zone trust to-zone untrust policy user-role-fw1 then permit app"
  impact 0.5
  tag check_id: 'C-15724r997540_chk'
  tag severity: 'medium'
  tag gid: 'V-214518'
  tag rid: 'SV-214518r997541_rule'
  tag stig_id: 'JUSX-AG-000019'
  tag gtitle: 'SRG-NET-000015-ALG-000016'
  tag fix_id: 'F-15722r297239_fix'
  tag 'documentable'
  tag legacy: ['V-66003', 'SV-80493']
  tag cci: ['CCI-000213', 'CCI-004891']
  tag nist: ['AC-3', 'SC-7 (29)']


  # Define the commands and keywords to check
  commands = [
    'show configuration security policies',
    'show configuration',
    'show configuration access'
  ]

  keywords = [
    'source-identity',
    'user-name',
    'role',
    'identity',
    'user'
  ]

  # Flag to track if user-based policies are found
  user_based_policies_found = false

  # Check if user-based policies are configured
  commands.each do |command|
    keywords.each do |keyword|
      describe command("#{command} | match #{keyword}") do
        it 'should not return any output if user-based policies are not used' do
          if subject.stdout.strip != ''
            user_based_policies_found = true
          end
          expect(subject.stdout.strip).to eq ''
        end
      end
    end
  end

  # Conditional logic based on whether user-based policies are found
  if user_based_policies_found
    # Check if source-identity is specified for all zone pairs
    describe command('show configuration security policies | match source-identity') do
      it 'should specify source-identity for all user-based policies' do
        expect(subject.stdout.strip).not_to eq ''
      end
    end
  else
    # If no user-based policies are found, this is not a finding
    describe 'User-based firewall policies' do
      it 'are not used, so this is not a finding' do
        expect(user_based_policies_found).to eq false
      end
    end
  end

  #  # First, check for user-based firewall configuration
  # userfw_config = command('show configuration | display set | match "user"')
  # describe userfw_config do
  #   its('exit_status') { should eq 0 }
  # end

  # userfw_keywords = %w[
  #   security userfirewall
  #   access profile
  #   source-identity
  #   destination-identity
  # ]

  # userfw_used = userfw_keywords.any? { |kw| userfw_config.stdout.include?(kw) }

  # if userfw_used
  #   describe 'User-based firewall features' do
  #     it 'are in use, skipping security policy source-identity check' do
  #       expect(userfw_used).to eq true
  #     end
  #   end
  # else
  #   # If user-based firewall not used, check that source-identity is explicitly defined in security policies
  #   from_zone = input('from_zone')
  #   to_zone = input('to_zone')

  #   policy_cmd = command("show configuration security policies from-zone #{from_zone} to-zone #{to_zone}")
  #   describe policy_cmd do
  #     its('exit_status') { should eq 0 }
  #   end

  #   describe "Security policies from #{from_zone} to #{to_zone}" do
  #     it 'must include source-identity if user-based firewall is not used' do
  #       output = policy_cmd.stdout
  #       expect(output).to match(/source-identity/), "Expected 'source-identity' in policy, but none was found:\n#{output}"
  #     end
  #   end
  # end
end
