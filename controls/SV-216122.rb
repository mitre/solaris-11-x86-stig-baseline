control "SV-216122" do
  title "The system must not allow autologin capabilities from the GNOME desktop."
  desc "As automatic logins are a known security risk for other than \"kiosk\" types of systems, GNOME 
automatic login should be disabled in pam.conf."
  desc "check", "Determine if autologin is enabled for the GNOME desktop.

# egrep \"auth|account\" 
/etc/pam.d/gdm-autologin | grep -vc ^#

If the command returns other than \"0\", this is a 
finding."
  desc "fix", "The root role is required.

Modify the /etc/pam.d/gdm-autologin file.

# pfedit 
/etc/pam.d/gdm-autologin

Locate the lines:

auth required pam_unix_cred.so.1
auth 
sufficient pam_allow.so.1
account sufficient pam_allow.so.1

Change the lines to 
read:

#auth required pam_unix_cred.so.1
#auth sufficient pam_allow.so.1
#account 
sufficient pam_allow.so.1"
  impact 0.7
  tag severity: "high"
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-216122"
  tag rid: "SV-216122r603268_rule"
  tag stig_id: "SOL-11.1-040410"
  tag fix_id: "F-17358r372749_fix"
  tag legacy: ["V-48121","SV-60993"]
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b"]
end