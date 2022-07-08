control "SV-216092" do
  title "The system must require passwords to contain at least one uppercase alphabetic character."
  desc "Complex passwords can reduce the likelihood of success of automated password-guessing 
attacks."
  desc "check", "Check the MINUPPER setting.

# grep ^MINUPPER /etc/default/passwd

If MINUPPER is not set 
to 1 or more, this is a finding."
  desc "fix", "The root role is required.
# pfedit /etc/default/passwd 

Locate the line 
containing:

MINUPPER

Change the line to read:

MINUPPER=1"
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-OS-000069"
  tag gid: "V-216092"
  tag rid: "SV-216092r603268_rule"
  tag stig_id: "SOL-11.1-040070"
  tag fix_id: "F-17328r372659_fix"
  tag legacy: ["SV-60843","V-47971"]
  tag cci: ["CCI-000192"]
  tag nist: ["IA-5 (1) (a)"]
end