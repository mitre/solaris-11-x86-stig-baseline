control "SV-216197" do
  title "World-writable files must not exist."
  desc "Data in world-writable files can be read, modified, and potentially compromised by any user 
on the system. World-writable files may also indicate an incorrectly written script or 
program that could potentially be the cause of a larger compromise to the system's integrity."
  desc "check", "The root role is required.

Check for the existence of world-writable files.

# find / \\( 
-fstype nfs -o -fstype cachefs -o -fstype autofs \\
-o -fstype ctfs -o -fstype mntfs -o -fstype 
objfs \\
-o -fstype proc \\) -prune -o -type f -perm -0002 -print
If output is produced, this is a 
finding."
  desc "fix", "The root role is required.

Change the permissions of the files identified in the check step 
to remove the world-writable permission.

# pfexec chmod o-w [filename]"
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-216197"
  tag rid: "SV-216197r603268_rule"
  tag stig_id: "SOL-11.1-070180"
  tag fix_id: "F-17433r372974_fix"
  tag legacy: ["SV-60935","V-48063"]
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b"]
end