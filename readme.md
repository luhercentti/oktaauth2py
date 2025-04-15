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
  vault_addr="http://host.docker.internal:8200"  \
  auth_server="default"


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

///// to connect minikube with vault locally

vault auth enable kubernetes

kubectl get serviceaccount default -o yaml


minikube ssh -- sudo cat /var/lib/minikube/certs/ca.crt > minikube-ca.crt

TOKEN_REVIEW_JWT=$(kubectl create token default --duration=1h)


vault write auth/kubernetes/config \
  kubernetes_host="$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')" \
  kubernetes_ca_cert=@minikube-ca.crt \
  token_reviewer_jwt="$TOKEN_REVIEW_JWT"

///////
the standalone docker file works only locally with docker without minikube

docker build -t standalone-okta-flask-app:latest -f stanadaloneapp.py

test locally before minikube:

docker run -p 5000:5000 \
  -e VAULT_ADDR='http://host.docker.internal:8200' \
  -e VAULT_TOKEN='root' \
  standalone-okta-flask-app:latest


//////

Run in minikube:

docker build -t luhercen/okta-flask-app:latest .

docker login
docker push luhercen/okta-flask-app:latest
verify: https://hub.docker.com/repository/docker/luhercen/okta-flask-app

# Create a secret (run this once)
kubectl create secret generic vault-credentials \
  --from-literal=token=root          # Replace "root" with your token

kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
  
minikube service okta-flask-service --url


gitleaks git -v