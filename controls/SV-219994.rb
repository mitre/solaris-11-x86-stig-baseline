control "SV-219994" do
  title "The audit system must alert the System Administrator (SA) if there is any type of audit 
failure."
  desc "Proper alerts to system administrators and Information Assurance (IA) officials of audit 
failures ensure a timely response to critical system issues."
  desc "check", "This check applies to the global zone only. Determine the zone that you are currently 
securing.

# zonename

If the command output is \"global\", this check applies.

The root 
role is required.

Verify the presence of an audit_warn entry in /etc/mail/aliases.
# 
/usr/lib/sendmail -bv audit_warn
If the response is:
audit_warn... User unknown

this 
is a finding.

Review the output of the command and verify that the audit_warn alias notifies 
the appropriate users in this form:

audit_warn:user1,user2

If an appropriate user is 
not listed, this is a finding."
  desc "fix", "The root role is required. 

This action applies to the global zone only. Determine the zone 
that you are currently securing.

# zonename

If the command output is \"global\", this 
action applies.

Add an audit_warn alias to /etc/mail/aliases that will forward to 
designated system administrator(s).

# pfedit /etc/mail/aliases

Insert a line in the 
form:
audit_warn:user1,user2

Put the updated aliases file into service.
# newaliases"
  impact 0.7
  tag severity: "high"
  tag gtitle: "SRG-OS-000344"
  tag gid: "V-219994"
  tag rid: "SV-219994r603268_rule"
  tag stig_id: "SOL-11.1-010380"
  tag fix_id: "F-21703r372494_fix"
  tag legacy: ["SV-60717","V-47843"]
  tag cci: ["CCI-001858"]
  tag nist: ["AU-5 (2)"]
end