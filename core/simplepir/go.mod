module oob.local/oobpir

go 1.22

require github.com/ahenzinger/simplepir v0.0.0

// Pinned upstream SimplePIR (github.com/ahenzinger/simplepir @ e9020b03, MIT).
// Used unmodified except for the pre-existing removal of -march=native
// (see ../../integration/simplepir/UPSTREAM.md). No patch is applied by this module.
replace github.com/ahenzinger/simplepir => ../../integration/simplepir/upstream
