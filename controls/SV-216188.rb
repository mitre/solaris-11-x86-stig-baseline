control "SV-216188" do
  title "All home directories must be owned by the respective user assigned to it in /etc/passwd."
  desc "Since the user is accountable for files stored in the user's home directory, the user must be 
the owner of the directory."
  desc "check", "The root role is required.

Check that home directories are owned by the correct user.

# 
export IFS=\":\"; logins -uxo | while read user uid group gid gecos home rest; do result=$(find 
${home} -type d -prune \\! -user $user -print 2&gt;/dev/null); 
if [ ! -z \"${result}\" ]; then 

echo \"User: ${user}\\tOwner: $(ls -ld $home | awk '{ print $3 }')\";
fi;
done

If any output 
is produced, this is a finding."
  desc "fix", "The root role is required.

Correct the owner of any directory that does not match the 
password file entry for that user.

# chown [user] [home directory]"
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-216188"
  tag rid: "SV-216188r603268_rule"
  tag stig_id: "SOL-11.1-070090"
  tag fix_id: "F-17424r372947_fix"
  tag legacy: ["V-48097","SV-60969"]
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b"]
end