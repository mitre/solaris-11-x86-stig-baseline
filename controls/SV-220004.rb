control "SV-220004" do
  title "The operating system must protect the integrity of transmitted information."
  desc "Ensuring the integrity of transmitted information requires the operating system take 
feasible measures to employ transmission layer security. This requirement applies to 
communications across internal and external networks."
  desc "check", "All remote sessions must be conducted via encrypted services and ports.

Ask the operator to 
document all configured external ports and protocols. If any unencrypted connections are 
used, this is a finding."
  desc "fix", "All remote sessions must be conducted via SSH and IPsec. Ensure that SSH and IPsec are the only 
protocols used."
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-OS-000423"
  tag gid: "V-220004"
  tag rid: "SV-220004r603268_rule"
  tag stig_id: "SOL-11.1-060070"
  tag fix_id: "F-21713r372884_fix"
  tag legacy: ["SV-61051","V-48179"]
  tag cci: ["CCI-002418"]
  tag nist: ["SC-8"]
end