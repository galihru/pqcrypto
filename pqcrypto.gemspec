# pqcrypto_lai.gemspec

Gem::Specification.new do |spec|
  spec.name          = "laicrypto"
  spec.version       = Laicrypto::VERSION
  spec.summary       = "LAI is a promising post-quantum cryptosystem based on isogenies of elliptic curves."
  spec.authors       = ["GALIH RIDHO UTOMO"]
  spec.email         = ["g4lihru@students.unnes.ac.id"]

  spec.description   = <<~DESC
    LAI is a promising post-quantum cryptosystem based on isogenies of elliptic curves over lemniscate lattices, offering resistance against quantum-capable adversaries.
  DESC

  spec.homepage      = "https://github.com/4211421036/pqcrypto"
  spec.license       = "MIT"

  # File‐file yang akan di‐pack
  spec.files         = Dir.chdir(File.expand_path(__dir__)) do
    Dir[
      "lib/**/*.rb",
      "README.md"
    ]
  end

  spec.require_paths = ["lib"]

  # Jika perlu dependensi lain (sekarang hanya butuh stdlib Ruby)
  # spec.add_runtime_dependency "some_gem", "~> 1.0"

  # Ukuran Ruby minimal (jika ingin)
  # spec.required_ruby_version = Gem::Requirement.new(">= 2.6.0")
end
