module github.com/evancaplan/polytoken-mcp

go 1.26

require github.com/evancaplan/polytoken v0.0.0-20260808174420-d268530fbafb

require (
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/evancaplan/polytoken => ../polytoken
