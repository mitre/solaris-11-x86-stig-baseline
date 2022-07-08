control "SV-216057" do
  title "The telnet service daemon must not be installed unless required."
  desc "Telnet is an insecure protocol."
  desc "check", "Determine if the telnet daemon package in installed.

# pkg list 
service/network/telnet

If an installed package named \"service/network/telnet\" is 
listed and vntsd is not in use for LDoms, this is a finding."
  desc "fix", "The Software Installation Profile is required.

# pfexec pkg uninstall 
service/network/telnet"
  impact 0.7
  tag severity: "high"
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-216057"
  tag rid: "SV-216057r603268_rule"
  tag stig_id: "SOL-11.1-020150"
  tag fix_id: "F-17293r372554_fix"
  tag legacy: ["V-47915","SV-60787"]
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b"]
end