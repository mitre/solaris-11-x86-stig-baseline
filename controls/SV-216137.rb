control "SV-216137" do
  title "The system must ignore ICMP redirect messages."
  desc "Ignoring ICMP redirect messages reduces the likelihood of denial of service attacks."
  desc "check", "Determine if ICMP redirect messages are ignored.

# ipadm show-prop -p _ignore_redirect 
-co current ipv4
# ipadm show-prop -p _ignore_redirect -co current ipv6

If the output of 
all commands is not \"1\", this is a finding."
  desc "fix", "The Network Management profile is required.

Disable ignore redirects for IPv4 and 
IPv6.

# pfexec ipadm set-prop -p _ignore_redirect=1 ipv4
# pfexec ipadm set-prop -p 
_ignore_redirect=1 ipv6"
  impact 0.3
  tag severity: "low"
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-216137"
  tag rid: "SV-216137r603268_rule"
  tag stig_id: "SOL-11.1-050070"
  tag fix_id: "F-17373r372794_fix"
  tag legacy: ["V-48189","SV-61061"]
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b"]
end