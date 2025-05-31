# pqcrypto_lai.gemspec

require_relative "lib/laicrypto/version"

Gem::Specification.new do |spec|
  spec.name          = "laicrypto"
  spec.version       = Laicrypto::VERSION
  spec.summary       = "LAI is a promising post-quantum cryptosystem based on isogenies of elliptic curves."
  spec.authors       = ["GALIH RIDHO UTOMO"]
  spec.email         = ["g4lihru@students.unnes.ac.id"]

  spec.description   = <<~DESC
    LAI is a promising post-quantum cryptosystem based on isogenies of elliptic curves over lemniscate lattices, offering resistance against quantum-capable adversaries.
  DESC

  spec.homepage      = "https://github.com/4211421036/laicrypto"
  spec.license       = "MIT"

  spec.files = Dir.chdir(File.expand_path(__dir__)) {
    Dir["lib/**/*.rb", "README.md"]
  }
  spec.require_paths = ["lib"]

  # Supaya bundler/gem push tahu host yang diizinkan
  spec.metadata = {
    "allowed_push_host" => "https://rubygems.pkg.github.com/4211421036"
  }

  # Jika ada dependency lain: spec.add_runtime_dependency "something", "~> 1.0"
end
