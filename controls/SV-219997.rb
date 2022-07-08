control "SV-219997" do
  title "The system must verify that package updates are digitally signed."
  desc "Digitally signed packages ensure that the source of the package can be identified."
  desc "check", "Determine what the signature policy is for pkg publishers:

# pkg property | grep 
signature-policy

Check that output produces:

signature-policy verify

If the output 
does not confirm that signature-policy verify is active, this is a finding."
  desc "fix", "The Software Installation Profile is required.

Configure the package system to ensure 
that digital signatures are verified.

# pfexec pkg set-property signature-policy verify"
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-OS-000366"
  tag gid: "V-219997"
  tag rid: "SV-219997r603268_rule"
  tag stig_id: "SOL-11.1-020020"
  tag fix_id: "F-21706r372521_fix"
  tag legacy: ["SV-60755","V-47883"]
  tag cci: ["CCI-001749"]
  tag nist: ["CM-5 (3)"]
end