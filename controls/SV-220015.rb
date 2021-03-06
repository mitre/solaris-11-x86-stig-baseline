control "SV-220015" do
  title "The operating system must verify the correct operation of security functions in accordance 
with organization-defined conditions and in accordance with organization-defined 
frequency (if periodic verification)."
  desc "Security functional testing involves testing the operating system for conformance to the 
operating system security function specifications, as well as for the underlying security 
model. The need to verify security functionality applies to all security functions. The 
conformance criteria state the conditions necessary for the operating system to exhibit the 
desired security behavior or satisfy a security property. For example, successful login 
triggers an audit entry."
  desc "check", "Ask the operator if DoD-approved SCAP compliance checking software is installed and run on a 
periodic basis.

If DoD-approved SCAP compliance checking software is not installed 
and/or not run on a periodic basis, this is a finding."
  desc "fix", "Install, configure, and run DoD-approved SCAP compliance checking software on a periodic 
basis. Review the output of the software and document any out-of-compliance issues."
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-OS-000445"
  tag gid: "V-220015"
  tag rid: "SV-220015r603268_rule"
  tag stig_id: "SOL-11.1-090250"
  tag fix_id: "F-21724r373085_fix"
  tag legacy: ["SV-60779","V-47907"]
  tag cci: ["CCI-002696"]
  tag nist: ["SI-6 a"]
end