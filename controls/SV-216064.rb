control "SV-216064" do
  title "All run control scripts must have mode 0755 or less permissive."
  desc "If the startup files are writable by other users, these users could modify the startup files to 
insert malicious commands into the startup files."
  desc "check", "Check run control script modes.

# ls -lL /etc/rc* /etc/init.d /lib/svc/method

If any run 
control script has a mode more permissive than 0755, this is a finding."
  desc "fix", "Ensure all system startup files have mode 0755 or less permissive. Examine the rc files, and 
all files in the rc1.d (rc2.d, and so on) directories, and in the /etc/init.d and 
/lib/svc/method directories to ensure they are not world writable. If they are world 
writable, use the chmod command to correct the vulnerability and to research 
why.

Procedure: 

# chmod go-w &lt;startupfile&gt;"
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-216064"
  tag rid: "SV-216064r603268_rule"
  tag stig_id: "SOL-11.1-020300"
  tag fix_id: "F-17300r372575_fix"
  tag legacy: ["SV-74257","V-59827"]
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b"]
end