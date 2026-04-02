#!/bin/bash
set -euo pipefail

KC_ADMIN_USER="admin"
KC_ADMIN_PASS="admin"
REALM="ziti-test"
CLIENT_ID="ziti-enrolltocert"
TEST_USER="testuser"
TEST_PASS="testpass"
KC_CONTAINER="ziti-test-keycloak"

# install required tools if not available (e.g., inside ziti-builder container)
install_pkg() {
    local pkg="$1"
    if command -v apt-get &> /dev/null; then
        apt-get update -qq && apt-get install -y -qq "$pkg" > /dev/null 2>&1
    elif command -v apk &> /dev/null; then
        apk add --no-cache "$pkg" > /dev/null 2>&1
    elif command -v yum &> /dev/null; then
        yum install -y -q "$pkg" > /dev/null 2>&1
    fi
}

if ! command -v docker &> /dev/null; then
    echo "docker not found, attempting to install..."
    install_pkg docker.io || install_pkg docker-cli || install_pkg docker
    if ! command -v docker &> /dev/null; then
        echo "Failed to install docker"
        exit 1
    fi
    echo "docker installed"
fi

if ! command -v jq &> /dev/null; then
    echo "jq not found, attempting to install..."
    install_pkg jq
    if ! command -v jq &> /dev/null; then
        echo "Failed to install jq"
        exit 1
    fi
    echo "jq installed"
fi

# detect if we're running inside a container and find its Docker network
KC_NETWORK_ARGS=""
KC_HOST="localhost"

# try multiple methods to find our container ID
MY_CONTAINER_ID=""
# method 1: cgroups v1
MY_CONTAINER_ID=$(cat /proc/1/cpuset 2>/dev/null | grep -oE '[a-f0-9]{64}' || true)
# method 2: HOSTNAME env (Docker sets this to short container ID)
if [ -z "$MY_CONTAINER_ID" ] && [ -n "${HOSTNAME:-}" ]; then
    # verify HOSTNAME looks like a container ID (hex string)
    if echo "$HOSTNAME" | grep -qE '^[a-f0-9]{12}'; then
        MY_CONTAINER_ID="$HOSTNAME"
    fi
fi
# method 3: mountinfo
if [ -z "$MY_CONTAINER_ID" ]; then
    MY_CONTAINER_ID=$(grep -oE '[a-f0-9]{64}' /proc/self/mountinfo 2>/dev/null | head -1 || true)
fi

if [ -n "$MY_CONTAINER_ID" ]; then
    echo "Detected container ID: $MY_CONTAINER_ID"
    MY_NETWORK=$(docker inspect "$MY_CONTAINER_ID" --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' 2>/dev/null | awk '{print $1}' || true)
    if [ -n "$MY_NETWORK" ] && [ "$MY_NETWORK" != "host" ]; then
        echo "Running inside container on network: $MY_NETWORK"
        KC_NETWORK_ARGS="--network $MY_NETWORK"
        KC_HOST="$KC_CONTAINER"
    fi
else
    echo "Not running inside a container, using localhost"
fi

KC_URL="http://${KC_HOST}:8080"

echo "Starting Keycloak container (host=$KC_HOST)..."
docker run -d --name "$KC_CONTAINER" \
  $KC_NETWORK_ARGS \
  -p 8080:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=$KC_ADMIN_USER \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=$KC_ADMIN_PASS \
  quay.io/keycloak/keycloak start-dev

echo "Waiting for Keycloak to be ready (up to 3 minutes)..."
for i in $(seq 1 90); do
  if curl -sf "$KC_URL/realms/master" > /dev/null 2>&1; then
    echo "Keycloak is ready (after ~$((i*2))s)"
    break
  fi
  if [ "$i" -eq 90 ]; then
    echo "Keycloak failed to start within 3 minutes"
    docker logs "$KC_CONTAINER" 2>&1 | tail -20
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

# write the Keycloak host for tests to use
echo "$KC_HOST" > "${QUICKSTART_HOME:-/tmp}/keycloak-host"

echo "Keycloak setup complete"
echo "  URL: $KC_URL"
echo "  Realm: $REALM"
echo "  Client: $CLIENT_ID"
echo "  User: $TEST_USER (sub=$USER_ID)"
echo "$USER_ID" > "${QUICKSTART_HOME:-/tmp}/keycloak-user-id"
