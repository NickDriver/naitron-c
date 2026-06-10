#!/bin/sh
# Run the streaming AI-chat example under `ntc dev` (foreground + hot-reload).
#
#   examples/ai-chat/run.sh            # serves http://127.0.0.1:3000
#
# Then:  python3 examples/ai-chat/mint_token.py   -> paste the token in the UI.
set -e
cd "$(dirname "$0")/../.."   # repo root

[ -x build/ntc ] || make

chmod +x examples/ai-chat/chat_controller.py

# mount the controller at /api/chat (NTC_CONTROLLER_ROUTE customizes the seeded
# route; default would be GET /api/hello)
export NTC_CONTROLLER_BIN="$PWD/examples/ai-chat/chat_controller.py"
export NTC_CONTROLLER_ROUTE="GET /api/chat"
export NTC_STATIC_DIR="$PWD/examples/ai-chat/web"

# protect /api with JWT; this demo uses an HS256 shared secret (mint_token.py).
# In production, set auth.jwks_url instead and drop the secret.
export NTC_AUTH_MODE=jwt
export NTC_AUTH_SECRET="dev-secret"
export NTC_AUTH_PROTECT=/api

# `ntc dev` hot-reloads on a controller-binary change. For an interpreted
# controller the script *is* the binary, so editing chat_controller.py reloads
# it directly - no --build needed (a C controller would use --build "make ...").
echo "chat UI: http://127.0.0.1:3000/   (mint a token: python3 examples/ai-chat/mint_token.py)"
exec ./build/ntc dev 3000 --no-dashboard
