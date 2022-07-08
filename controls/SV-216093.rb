control "SV-216093" do
  title "The operating system must enforce password complexity requiring that at least one lowercase 
character is used."
  desc "Complex passwords can reduce the likelihood of success of automated password-guessing 
attacks."
  desc "check", "Check the MINLOWER setting.

# grep ^MINLOWER /etc/default/passwd

If MINLOWER is not set 
to 1 or more, this is a finding."
  desc "fix", "The root role is required.
# pfedit /etc/default/passwd 

Locate the line 
containing:

MINLOWER

Change the line to read:

MINLOWER=1"
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-OS-000070"
  tag gid: "V-216093"
  tag rid: "SV-216093r603268_rule"
  tag stig_id: "SOL-11.1-040080"
  tag fix_id: "F-17329r372662_fix"
  tag legacy: ["SV-60853","V-47981"]
  tag cci: ["CCI-000193"]
  tag nist: ["IA-5 (1) (a)"]
end