control "SV-216227" do
  title "The operating system must conduct backups of operating system documentation including 
security-related documentation per organization-defined frequency to conduct backups 
that is consistent with recovery time and recovery point objectives."
  desc "Operating system backup is a critical step in maintaining data assurance and availability. 


System documentation is data generated for/by the host (such as logs) and/or 
administrative users.

Backups shall be consistent with organizational recovery time and 
recovery point objectives."
  desc "check", "The operations staff shall ensure that proper backups are created, tested, and archived. 


Ask the operator for documentation on the backup procedures implemented.

If the backup 
procedures are not documented then this is a finding."
  desc "fix", "The operations staff shall install, configure, test, and verify operating system backup 
software.

Additionally, all backup procedures must be documented."
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-216227"
  tag rid: "SV-216227r603268_rule"
  tag stig_id: "SOL-11.1-090070"
  tag fix_id: "F-17463r373064_fix"
  tag legacy: ["V-47973","SV-60845"]
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b"]
end