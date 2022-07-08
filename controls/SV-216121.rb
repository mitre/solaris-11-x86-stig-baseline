control "SV-216121" do
  title "The use of FTP must be restricted."
  desc "FTP is an insecure protocol that transfers files and credentials in clear text, and can be 
replaced by using SFTP. However, if FTP is permitted for use in the environment, it is 
important to ensure that the default \"system\" accounts are not permitted to transfer files 
via FTP, especially the root role. Consider also adding the names of other privileged or 
shared accounts that may exist on the system such as user \"oracle\" and the account which the web 
server process runs under."
  desc "check", "The root role is required.

Determine if the FTP server package is installed:

# pkg list 
service/network/ftp

If the output of this command is:

pkg list: no packages matching 
'service/network/ftp' installed

no further action is required.

If the FTP server is 
installed, determine if FTP access is restricted.

# for user in `logins -s | awk '{ print $1 
}'` \\
aiuser noaccess nobody nobody4; do
grep -w \"${user}\" /etc/ftpd/ftpusers 
&gt;/dev/null 2&gt;&amp;1
if [ $? != 0 ]; then
echo \"User '${user}' not in 
/etc/ftpd/ftpusers.\"
fi
done

If output is returned, this is a finding."
  desc "fix", "The root role is required.

Determine if the FTP server package is installed:

# pkg list 
service/network/ftp

If the output of this command is:

pkg list: no packages matching 
'service/network/ftp' installed

no further action is required.

# for user in `logins -s 
| awk '{ print $1 }'` \\
aiuser noaccess nobody nobody4; do
$(echo $user &gt;&gt; 
/etc/ftpd/ftpusers)
done
# sort -u /etc/ftpd/ftpusers &gt; /etc/ftpd/ftpusers.temp
# 
mv /etc/ftpd/ftpusers.temp /etc/ftpd/ftpusers"
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-216121"
  tag rid: "SV-216121r603268_rule"
  tag stig_id: "SOL-11.1-040400"
  tag fix_id: "F-17357r372746_fix"
  tag legacy: ["V-48117","SV-60989"]
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b"]
end