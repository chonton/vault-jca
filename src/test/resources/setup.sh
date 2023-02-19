echo "I'm here"
export VAULT_ADDR=http://vault:8200
export VAULT_TOKEN=12345
vault audit enable
vault secrets enable transit
echo "done"