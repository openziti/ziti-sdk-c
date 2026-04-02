#!/bin/bash
set -euo pipefail

KC_ADMIN_USER="admin"
KC_ADMIN_PASS="admin"
REALM="ziti-test"
CLIENT_ID="ziti-enrolltocert"
TEST_USER="testuser"
TEST_PASS="testpass"

# install docker CLI if not available (e.g., inside ziti-builder container with socket mounted)
if ! command -v docker &> /dev/null; then
    echo "Docker CLI not found, attempting to install..."
    if command -v apt-get &> /dev/null; then
        apt-get update -qq && apt-get install -y -qq docker.io > /dev/null 2>&1
    elif command -v apk &> /dev/null; then
        apk add --no-cache docker-cli > /dev/null 2>&1
    elif command -v yum &> /dev/null; then
        yum install -y -q docker > /dev/null 2>&1
    fi
    if ! command -v docker &> /dev/null; then
        echo "Failed to install Docker CLI"
        exit 1
    fi
    echo "Docker CLI installed"
fi

# use host networking so Keycloak is reachable at localhost from both
# the host and any sibling container sharing the Docker socket
echo "Starting Keycloak container..."
docker run -d --name ziti-test-keycloak \
  --network host \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=$KC_ADMIN_USER \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=$KC_ADMIN_PASS \
  quay.io/keycloak/keycloak start-dev

KC_URL="http://localhost:8080"

echo "Waiting for Keycloak to be ready (up to 3 minutes)..."
for i in $(seq 1 90); do
  if curl -sf "$KC_URL/realms/master" > /dev/null 2>&1; then
    echo "Keycloak is ready (after ~$((i*2))s)"
    break
  fi
  if [ "$i" -eq 90 ]; then
    echo "Keycloak failed to start within 3 minutes"
    docker logs ziti-test-keycloak 2>&1 | tail -20
    exit 1
  fi
  sleep 2
done

# get admin token
ADMIN_TOKEN=$(curl -sf -X POST "$KC_URL/realms/master/protocol/openid-connect/token" \
  -d "grant_type=password&client_id=admin-cli&username=$KC_ADMIN_USER&password=$KC_ADMIN_PASS" \
  | jq -r '.access_token')

if [ -z "$ADMIN_TOKEN" ] || [ "$ADMIN_TOKEN" = "null" ]; then
  echo "Failed to get admin token"
  exit 1
fi

echo "Creating realm: $REALM"
curl -sf -X POST "$KC_URL/admin/realms" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"realm\": \"$REALM\", \"enabled\": true}"

echo "Creating client: $CLIENT_ID"
curl -sf -X POST "$KC_URL/admin/realms/$REALM/clients" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"clientId\": \"$CLIENT_ID\",
    \"enabled\": true,
    \"publicClient\": true,
    \"standardFlowEnabled\": true,
    \"directAccessGrantsEnabled\": true,
    \"redirectUris\": [\"http://localhost:20314/*\"],
    \"webOrigins\": [\"+\"]
  }"

echo "Creating user: $TEST_USER"
curl -sf -X POST "$KC_URL/admin/realms/$REALM/users" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"username\": \"$TEST_USER\",
    \"enabled\": true,
    \"email\": \"$TEST_USER@test.example.com\",
    \"emailVerified\": true,
    \"firstName\": \"Test\",
    \"lastName\": \"User\",
    \"credentials\": [{
      \"type\": \"password\",
      \"value\": \"$TEST_PASS\",
      \"temporary\": false
    }]
  }"

# get user's sub claim
USER_ID=$(curl -sf "$KC_URL/admin/realms/$REALM/users?username=$TEST_USER" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  | jq -r '.[0].id')

echo "Keycloak setup complete"
echo "  Realm: $REALM"
echo "  Client: $CLIENT_ID"
echo "  User: $TEST_USER (sub=$USER_ID)"
echo "$USER_ID" > "${QUICKSTART_HOME:-/tmp}/keycloak-user-id"
