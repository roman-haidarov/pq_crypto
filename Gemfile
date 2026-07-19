# frozen_string_literal: true

source "https://rubygems.org"

gemspec

group :test do
  if Gem::Version.new(RUBY_VERSION) >= Gem::Version.new("3.1")
    gem "async", "~> 2.21.1"
  end
end
