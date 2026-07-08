.PHONY: help up down build logs migrate seed test lint clean sandbox-env sandbox-up sandbox-down

help:
	@echo "VulnShield Platform - Available Commands"
	@echo "  make up            - Start all services (development)"
	@echo "  make sandbox-env   - Generate .env.sandbox with random secrets"
	@echo "  make sandbox-up    - Start hardened sandbox deployment (includes AI/Ollama profile)"
	@echo "  make sandbox-down  - Stop sandbox deployment"
	@echo "  make down          - Stop all services"
	@echo "  make build    - Build all Docker images"
	@echo "  make logs     - Tail service logs"
	@echo "  make migrate  - Run database migrations"
	@echo "  make seed     - Load development sample data (corp.local demo assets)"
	@echo "  make test     - Run all tests"
	@echo "  make lint     - Run linters"
	@echo "  make clean    - Remove containers and volumes"

up:
	docker compose up -d

sandbox-env:
	./scripts/generate-sandbox-env.sh .env.sandbox

sandbox-up:
	docker compose --env-file .env.sandbox -f docker-compose.yml -f docker-compose.sandbox.yml --profile ai up -d --build

sandbox-down:
	docker compose --env-file .env.sandbox -f docker-compose.yml -f docker-compose.sandbox.yml --profile ai down

down:
	docker compose down

build:
	docker compose build

logs:
	docker compose logs -f

migrate:
	docker compose exec postgres psql -U vulnshield -d vulnshield -f /migrations/003_simulated_flags.sql

seed:
	docker compose exec postgres psql -U vulnshield -d vulnshield -f /seed/dev_sample_data.sql

test:
	docker compose run --rm auth-service pytest /app/tests -v
	docker compose run --rm asset-service pytest /app/tests -v
	cd frontend && npm test -- --passWithNoTests

lint:
	docker compose run --rm auth-service ruff check /app
	cd frontend && npm run lint

clean:
	docker compose down -v --remove-orphans
