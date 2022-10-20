control "SV-216015" do
  title "The audit records must provide data for all auditable events defined at the organizational 
level for the organization-defined information system components."
  desc "Without auditing, individual system accesses cannot be tracked, and malicious activity 
cannot be detected and traced back to an individual account.

Without accurate time stamps, 
source, user, and activity information, malicious activity cannot be accurately 
tracked.

Without an audit reduction and reporting capability, users find it difficult to 
identify specific patterns of attack."
  desc "check", "The Audit Configuration profile is required.

This check applies to the global zone only.  
Determine the zone that you are currently securing.

# zonename

If the command output is 
\"global\", this check applies.

Check the status of the audit system. It must be auditing.

# 
pfexec auditconfig -getcond

If this command does not report:

audit condition = 
auditing

this is a finding."
  desc "fix", "The Audit Control profile is required.

This action applies to the global zone only.  
Determine the zone that you are currently securing.

# zonename

If the command output is 
\"global\", this action applies.

If auditing has been disabled, it must be enabled with the 
following command:

# pfexec audit -s"
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-OS-000062"
  tag gid: "V-216015"
  tag rid: "SV-216015r603268_rule"
  tag stig_id: "SOL-11.1-010100"
  tag fix_id: "F-17251r372428_fix"
  tag legacy: ["SV-60665","V-47789"]
  tag cci: ["CCI-000169"]
  tag nist: ["AU-12 a"]

  unless command('zonename').stdout.strip == "global"
    impact 0.0
    describe 'This control is Not Applicable. This control applies to the global zone only.' do
      skip 'This control is Not Applicable. This control applies to the global zone only.' 
    end
  else
    audit_condition_value = command("pfexec auditconfig -getcond").stdout.strip.split("=").collect(&:strip)[1]
    describe audit_condition_value do
      it { should cmp 'auditing'}
    end
  end
end
