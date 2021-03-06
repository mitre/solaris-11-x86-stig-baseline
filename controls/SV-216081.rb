control "SV-216081" do
  title "Generic Security Services (GSS) must be disabled."
  desc "This service should be disabled if it is not required."
  desc "check", "Determine the status of the Generic Security Services.

# svcs -Ho state 
svc:/network/rpc/gss

If the GSS service is reported as online, this is a finding."
  desc "fix", "The Service Management profile is required:

Disable the GSS service.

# pfexec svcadm 
disable svc:/network/rpc/gss"
  impact 0.3
  tag severity: "low"
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-216081"
  tag rid: "SV-216081r603268_rule"
  tag stig_id: "SOL-11.1-030030"
  tag fix_id: "F-17317r372626_fix"
  tag legacy: ["V-47931","SV-60803"]
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b"]
end