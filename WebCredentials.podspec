Pod::Spec.new do |s|
  s.name = "WebCredentials"
  s.version = "1.2.10"
  s.summary = "A Swift 5 wrapper for Security.SecSharedWebCredentials"
  s.description = <<-DESC
                  This is a micro-framework which aims to make accessing the
                  Security.SecSharedWebCredentials API easy and convenient in Swift 5.
                  Using this API isn't necessary anymore on iOS >= 11 but if you want
                  to offer Safari AutoFill in your App to users running iOS < 11, you
                  might find this useful.
                  DESC
  s.homepage = "https://github.com/resmio/WebCredentials"
  s.license = { 
    :type => "MIT",
    :file => "LICENSE"
  }
  s.authors = {
    "Jan Nash" => "jan@resmio.com" 
  }
  s.platform = :ios, "12.0"
  s.swift_version = '5.8'
  s.source = {
    :git => "https://github.com/resmio/WebCredentials.git",
    :tag => "v#{s.version}"
  }
  s.source_files = "WebCredentials/**/*.swift"
  s.public_header_files = []
end
