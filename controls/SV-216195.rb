control "SV-216195" do
  title "User .netrc files must not exist."
  desc "The .netrc file presents a significant security risk since it stores passwords in 
unencrypted form."
  desc "check", "The root role is required.

Check for the presence of user .netrc files.

# for dir in 
\\
`logins -ox | awk -F: '($8 == \"PS\") { print $6 }'`; do
ls -l ${dir}/.netrc 
2&gt;/dev/null
done

If output is produced, this is a finding."
  desc "fix", "The root role is required.

Determine if any .netrc files exist, and work with the owners to 
determine the best course of action in accordance with site policy."
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-216195"
  tag rid: "SV-216195r603268_rule"
  tag stig_id: "SOL-11.1-070160"
  tag fix_id: "F-17431r372968_fix"
  tag legacy: ["SV-60939","V-48067"]
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b"]
end