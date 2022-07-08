control "SV-216182" do
  title "Permissions on user . (hidden) files must be 750 or less permissive."
  desc "Group-writable or world-writable user configuration files may enable malicious users to 
steal or modify other users' data or to gain another user's system privileges."
  desc "check", "The root role is required.

Ensure that the permissions on user \".\" files are 750 or less 
permissive.

# for dir in \\
`logins -ox | awk -F: '($8 == \"PS\") { print $6 }'`; do
find 
${dir}/.[A-Za-z0-9]* \\! -type l \\
\\( -perm -0001 -o -perm -0002 -o -perm -0004 -o -perm -0020 
\\) -ls
done

If output is produced, this is a finding."
  desc "fix", "The root role is required. 

Change the permissions on users' \".\" files to 750 or less 
permissive.

# chmod 750 [file name]"
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-216182"
  tag rid: "SV-216182r793048_rule"
  tag stig_id: "SOL-11.1-070030"
  tag fix_id: "F-17418r372929_fix"
  tag legacy: ["SV-61001","V-48129"]
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b"]
end