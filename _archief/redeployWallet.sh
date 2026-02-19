docker compose build --no-cache wallet
docker compose up -d --force-recreate wallet
docker compose logs -f wallet
