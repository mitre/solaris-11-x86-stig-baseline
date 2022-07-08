control "SV-216074" do
  title "All .Xauthority files must have mode 0600 or less permissive."
  desc ".Xauthority files ensure the user is authorized to access the specific X Windows host. 
Excessive permissions may permit unauthorized modification of these files, which could 
lead to Denial of Service to authorized access or allow unauthorized access to be obtained."
  desc "check", "If X Display Manager (XDM) is not used on the system, this is not applicable.

Determine if XDM 
is running. 

Procedure:
# ps -ef | grep xdm

Check the file permissions for the .Xauthority 
files in the home directories of users of X. Procedure:
# cd ~&lt;X user&gt;
# ls -lL 
.Xauthority

If the file mode is more permissive than 0600, this is finding."
  desc "fix", "Change the mode of the .Xauthority files.

Procedure:
# chmod 0600 .Xauthority"
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-216074"
  tag rid: "SV-216074r603268_rule"
  tag stig_id: "SOL-11.1-020510"
  tag fix_id: "F-17310r372605_fix"
  tag legacy: ["SV-75473","V-61005"]
  tag cci: ["CCI-000366","CCI-000225"]
  tag nist: ["CM-6 b","AC-6"]
end