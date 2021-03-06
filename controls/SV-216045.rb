control "SV-216045" do
  title "The System packages must be up to date with the most recent vendor updates and security fixes."
  desc "Failure to install security updates can provide openings for attack."
  desc "check", "The Software Installation Profile is required.

An up-to-date Solaris repository must be 
accessible to the system. Enter the command:

# pkg publisher

to determine the current 
repository publisher. If a repository is not accessible, it may need to be locally installed 
and configured.

Check for Solaris software package updates:

# pfexec pkg update -n

If 
the command does not report \"No updates available for this image,\" this is a finding."
  desc "fix", "The Software Installation Profile is required.

An up-to-date Solaris repository must be 
accessible to the system. Enter the command:

# pkg publisher

to determine the current 
repository publisher. If a repository is not accessible, it may need to be locally installed 
and configured.

Update system packages to the current version.

# pfexec pkg update

A 
reboot may be required for the updates to take effect."
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-216045"
  tag rid: "SV-216045r603268_rule"
  tag stig_id: "SOL-11.1-020010"
  tag fix_id: "F-17281r372518_fix"
  tag legacy: ["V-47881","SV-60753"]
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b"]
end