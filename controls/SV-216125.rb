control "SV-216125" do
  title "The operating system, upon successful logon, must display to the user the date and time of the 
last logon (access)."
  desc "Users need to be aware of activity that occurs regarding their account. Providing users with 
information regarding the date and time of their last successful login allows the user to 
determine if any unauthorized activity has occurred and gives them an opportunity to notify 
administrators."
  desc "check", "Determine if last login will be printed for SSH users.

# grep PrintLastLog 
/etc/ssh/sshd_config

If PrintLastLog is found, not preceded with a \"#\" sign, and is set to 
\"no\", this is a finding.

PrintLastLog should either not exist (defaulting to yes) or exist 
and be set to yes."
  desc "fix", "The root role is required for this action.

# pfedit /etc/ssh/sshd_config

Locate the line 
containing:

PrintLastLog no

and place a comment sign (\"# \")at the beginning of the line or 
delete the line

# PrintLastLog no

Restart the ssh service

# pfexec svcadm restart 
svc:/network/ssh"
  impact 0.3
  tag severity: "low"
  tag gtitle: "SRG-OS-000025"
  tag gid: "V-216125"
  tag rid: "SV-216125r603268_rule"
  tag stig_id: "SOL-11.1-040450"
  tag fix_id: "F-17361r372758_fix"
  tag legacy: ["V-48131","SV-61003"]
  tag cci: ["CCI-000052"]
  tag nist: ["AC-9"]
end