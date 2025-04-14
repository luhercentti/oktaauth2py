All test locally:


configure vault:

export VAULT_ADDR='http://localhost:8200'
export VAULT_TOKEN='root' # From docker-compose.yml

# Enable KV secrets engine
vault secrets enable -path=okta kv-v2

# Store Okta secrets
vault kv put okta/flask-app \
  client_id="your-okta-client-id" \
  client_secret="your-okta-client-secret" \
  flask_secret_key="your-flask-secret-key" \
  okta_domain="https://dev-123456.okta.com" \
  redirect_uri="http://okta-flask-service.default.svc.cluster.local:8080/callback" \
  vault_addr="http://host.docker.internal:8200"


# Create a policy
vault policy write okta-policy - <<EOF
path "okta/data/flask-app" {
  capabilities = ["read"]
}
EOF

////////////////////

to obtain "flask_secret_key:

python3 -c 'import secrets; print(secrets.token_hex(32))'
or
openssl rand -hex 32

/////

vault auth enable kubernetes

kubectl get serviceaccount default -o yaml


minikube ssh -- sudo cat /var/lib/minikube/certs/ca.crt > minikube-ca.crt

TOKEN_REVIEW_JWT=$(kubectl create token default --duration=1h)


vault write auth/kubernetes/config \
  kubernetes_host="$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')" \
  kubernetes_ca_cert=@minikube-ca.crt \
  token_reviewer_jwt="$TOKEN_REVIEW_JWT"

////


docker build -t luhercen/okta-flask-app:latest .

test locally:
docker run -p 8080:8080 \
  -e OKTA_DOMAIN="https://dev-xxxxx.okta.com" \
  -e OKTA_CLIENT_ID="xxxxxx" \
  -e OKTA_CLIENT_SECRET="xxxxxx" \
  -e OKTA_REDIRECT_URI="http://192.168.49.2:30000/callback" \
  -e FLASK_SECRET_KEY="xxxxxxx" \
  luhercen/okta-flask-app:latest

docker login
docker push luhercen/okta-flask-app:latest
verify: https://hub.docker.com/repository/docker/luhercen/okta-flask-app


docker run -p 5000:5000 \
  -e VAULT_ADDR='http://host.docker.internal:8200' \
  -e VAULT_TOKEN='root' \
  luhercen/okta-flask-app:latest