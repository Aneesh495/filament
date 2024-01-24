require "./spec_helper"
require "../src/filament/version"

describe Filament do
  it "reports the correct version string" do
    Filament::VERSION.should eq("0.1.0")
  end
end
