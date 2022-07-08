control "SV-216052" do
  title "The legacy remote network access utilities daemons must not be installed."
  desc "Legacy remote access utilities allow remote control of a system without proper 
authentication."
  desc "check", "Determine if the legacy remote access package is installed.

# pkg list 
service/network/legacy-remote-utilities

If an installed package named 
service/network/legacy-remote-utilities is listed, this is a finding."
  desc "fix", "The Software Installation Profile is required.

# pfexec pkg uninstall 
service/network/legacy-remote-utilities"
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-216052"
  tag rid: "SV-216052r603268_rule"
  tag stig_id: "SOL-11.1-020100"
  tag fix_id: "F-17288r372539_fix"
  tag legacy: ["SV-60773","V-47901"]
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b"]
end