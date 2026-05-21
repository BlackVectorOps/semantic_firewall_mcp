module github.com/BlackVectorOps/semantic_firewall_mcp

go 1.26.3

replace github.com/BlackVectorOps/semantic_firewall/v4 => ../semantic_firewall

require (
	github.com/BlackVectorOps/semantic_firewall/v4 v4.0.0-00010101000000-000000000000
	github.com/mark3labs/mcp-go v0.54.0
)

require (
	github.com/google/jsonschema-go v0.4.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.2 // indirect
	github.com/spf13/cast v1.7.1 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	golang.org/x/mod v0.32.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/text v0.33.0 // indirect
	golang.org/x/tools v0.41.0 // indirect
)
