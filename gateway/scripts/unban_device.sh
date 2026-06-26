#!/bin/bash
# Script per sbloccare un dispositivo bannato dal Trust Engine
# Può essere eseguito direttamente o all'interno del container Docker

echo "============================================================"
echo "   Smart MicroGrid - Device Recovery Tool"
echo "============================================================"
echo ""

# Determina se siamo in un container o in locale
if [ -f /.dockerenv ] || [ -n "$DOCKER_CONTAINER" ]; then
    # Siamo in un container
    echo "🐳 Esecuzione in ambiente Docker"
    python3 /app/src/scripts/unban_device.py
else
    # Siamo in locale, usa docker exec
    echo "💻 Esecuzione da host locale"
    echo ""
    
    # Trova il container del provisioner o trust engine
    CONTAINER=$(docker ps --filter "name=trust" --format "{{.Names}}" | head -n1)
    
    if [ -z "$CONTAINER" ]; then
        CONTAINER=$(docker ps --filter "name=provision" --format "{{.Names}}" | head -n1)
    fi
    
    if [ -z "$CONTAINER" ]; then
        echo "❌ Nessun container attivo trovato per trust_engine o provisioner"
        echo "   Avvia i container con: cd gateway && docker-compose up -d"
        exit 1
    fi
    
    echo "📦 Usando container: $CONTAINER"
    echo ""
    
    # Verifica che lo script esista nel container
    docker exec "$CONTAINER" test -f /app/src/scripts/unban_device.py
    if [ $? -ne 0 ]; then
        echo "❌ Script non trovato nel container"
        echo "   Assicurati di aver montato correttamente la directory src/scripts/"
        exit 1
    fi
    
    # Esegui lo script nel container
    docker exec -it "$CONTAINER" python3 /app/src/scripts/unban_device.py
fi