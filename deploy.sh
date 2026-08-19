#!/usr/bin/env bash
set -e

REMOTE_HOST="10.51.211.13"
REMOTE_USER="linuxadmin"
REMOTE_PASS="Openlabs@2025"
REMOTE_DIR="/docker/crowdsec-dashboard"

echo "[1/4] Criando diretório remoto $REMOTE_DIR..."
sshpass -p "$REMOTE_PASS" ssh -o StrictHostKeyChecking=no "$REMOTE_USER@$REMOTE_HOST" "echo '$REMOTE_PASS' | sudo -S mkdir -p $REMOTE_DIR && echo '$REMOTE_PASS' | sudo -S chown -R $REMOTE_USER:$REMOTE_USER $REMOTE_DIR"

echo "[2/4] Sincronizando arquivos da aplicação..."
sshpass -p "$REMOTE_PASS" scp -r -o StrictHostKeyChecking=no \
  /openlabs/projects/crowdsec/app.py \
  /openlabs/projects/crowdsec/requirements.txt \
  /openlabs/projects/crowdsec/Dockerfile \
  /openlabs/projects/crowdsec/docker-compose.yml \
  /openlabs/projects/crowdsec/static \
  "$REMOTE_USER@$REMOTE_HOST:$REMOTE_DIR/"

echo "[3/4] Construindo e iniciando o contêiner no servidor..."
sshpass -p "$REMOTE_PASS" ssh -o StrictHostKeyChecking=no "$REMOTE_USER@$REMOTE_HOST" "cd $REMOTE_DIR && echo '$REMOTE_PASS' | sudo -S docker compose up -d --build"

echo "[4/4] Validando saúde da aplicação..."
sleep 3
sshpass -p "$REMOTE_PASS" ssh -o StrictHostKeyChecking=no "$REMOTE_USER@$REMOTE_HOST" "curl -s http://localhost:8090/api/health || echo 'Falha ao checar /api/health'"

echo ""
echo "=== DASHBOARD PRONTO ==="
echo "Acesse: http://$REMOTE_HOST:8090"
