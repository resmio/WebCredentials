Pod::Spec.new do |s|
  s.name = "WebCredentials"
  s.version = "0.0.1"
  s.summary = "A Swift 5 wrapper for Security.SecSharedWebCredentials"
  s.description = <<-DESC
                  This is a micro-framework which aims to make accessing the
                  Security.SecSharedWebCredentials API easy and convenient in Swift 5.
                  DESC
  s.homepage = "https://github.com/resmio/WebCredentials"
  s.license = { 
    :type => "MIT",
    :file => "LICENSE"
  }
  s.authors = {
    "Jan Nash" => "jan@resmio.com" 
  }
  s.platform = :ios, "8.0"
  s.swift_version = '5.0'
  s.source = {
    :git => "https://github.com/resmio/WebCredentials.git",
    :tag => "v#{s.version}"
  }
  s.source_files = "WebCredentials/**/*.swift"
  s.public_header_files = []
end
