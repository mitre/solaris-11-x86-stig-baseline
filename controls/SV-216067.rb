control "SV-216067" do
  title "Run control scripts library search paths must contain only authorized paths."
  desc "The library search path environment variable(s) contain a list of directories for the 
dynamic linker to search to find libraries. If this path includes the current working 
directory or other relative paths, libraries in these directories may be loaded instead of 
system libraries. This variable is formatted as a colon-separated list of directories. If 
there is an empty entry, such as a leading or trailing colon, two consecutive colons, or a 
single period, this is interpreted as the current working directory. Paths starting with a 
slash (/) are absolute paths."
  desc "check", "Verify run control scripts' library search paths. 

# find /etc/rc* /etc/init.d -type f 
-print | xargs grep LD_LIBRARY_PATH

This variable is formatted as a colon-separated list 
of directories.

If there is an empty entry, such as a leading or trailing colon, or two 
consecutive colons, this is a finding. 

If an entry begins with a character other than a slash 
(/), or has not been documented with the ISSO, this is a finding."
  desc "fix", "Edit the run control script and remove the relative path entries from the library search path 
variables that have not been documented with the ISSO. 

Edit the run control script and 
remove any empty path entries from the file."
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-216067"
  tag rid: "SV-216067r603268_rule"
  tag stig_id: "SOL-11.1-020330"
  tag fix_id: "F-17303r372584_fix"
  tag legacy: ["V-59833","SV-74263"]
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b"]
end