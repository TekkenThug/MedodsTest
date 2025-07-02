# Medods testcase

## Run

Copy `.env.example` and rename to `.env`

Use `docker-compose -f docker-compose.yml up -d`

To create test data use code from `seed.sql` in `postgres` container:

```bash
docker exec -it postgres bash
```

then

```bash
psql -U postgres -d test
```

## Swagger

On link http://localhost:8000/swagger/index.htm