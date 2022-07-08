control "SV-216181" do
  title "Permissions on user home directories must be 750 or less permissive."
  desc "Group-writable or world-writable user home directories may enable malicious users to steal 
or modify other users' data or to gain another user's system privileges."
  desc "check", "The root role is required.

Check that the permissions on users' home directories are 750 or 
less permissive.

# for dir in `logins -ox |\\
awk -F: '($8 == \"PS\") { print $6 }'`; do
find 
${dir} -type d -prune \\( -perm -g+w -o \\
-perm -o+r -o -perm -o+w -o -perm -o+x \\) -ls
done

If 
output is created, this is finding."
  desc "fix", "The root role is required. 

Change the permissions on users' directories to 750 or less 
permissive.

# chmod 750 [directory name]"
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-216181"
  tag rid: "SV-216181r603268_rule"
  tag stig_id: "SOL-11.1-070020"
  tag fix_id: "F-17417r372926_fix"
  tag legacy: ["V-48133","SV-61005"]
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b"]
end