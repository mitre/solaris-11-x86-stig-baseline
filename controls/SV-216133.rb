control "SV-216133" do
  title "The system must not respond to ICMP broadcast timestamp requests."
  desc "By accurately determining the system's clock state, an attacker can more effectively attack 
certain time-based pseudorandom number generators (PRNGs) and the authentication systems 
that rely on them."
  desc "check", "Determine if response to ICMP broadcast timestamp requests is disabled.

# ipadm show-prop 
-p _respond_to_timestamp_broadcast -co current ip

If the output of this command is not 
\"0\", this is a finding."
  desc "fix", "The Network Management profile is required.

Disable respond to timestamp broadcasts.

# 
pfexec ipadm set-prop -p _respond_to_timestamp_broadcast=0 ip"
  impact 0.3
  tag severity: "low"
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-216133"
  tag rid: "SV-216133r603268_rule"
  tag stig_id: "SOL-11.1-050030"
  tag fix_id: "F-17369r372782_fix"
  tag legacy: ["SV-61045","V-48173"]
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b"]
end