#!/bin/bash
set -e

echo "⏳ Waiting for PostgreSQL and database to be ready..."

until PGPASSWORD=$POSTGRES_PASSWORD psql -h db -U ${POSTGRES_USER:-ncm} -d ${POSTGRES_DB:-ncmdb} -c '\q' 2>/dev/null; do
  echo "  DB not ready yet, retrying in 2s..."
  sleep 2
done

echo "✅ Database is up"

echo "⏳ Running migrations..."
alembic upgrade head
echo "✅ Migrations done"

echo "⏳ Checking if seed needed..."
NEEDS_SEED=$(PGPASSWORD=$POSTGRES_PASSWORD psql -h db -U ${POSTGRES_USER:-ncm} -d ${POSTGRES_DB:-ncmdb} -tAc "SELECT COUNT(*) FROM organizations;" 2>/dev/null || echo "0")

if [ "$NEEDS_SEED" = "0" ]; then
  echo "🌱 Seeding initial data..."
  python seed.py
else
  echo "✅ Seed skipped (data exists)"
fi

echo "🚀 Starting API..."
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
