# Aegis Node: Release Manifest

## Source Directories (Required)
- `/backend`: Core FastAPI application and security services.
- `/frontend`: React dashboard application.

## Configuration Templates (Required)
- `Dockerfile`: Multi-stage build definition.
- `render.yaml`: Render deployment blueprint.
- `docker-compose.yml`: Local containerization setup.
- `.env.example`: Template for environment variables.

## Documentation (Optional/Informational)
- `README.md`
- `CHANGELOG.md`
- `docs/AEGIS_NODE_FINAL_ARCHITECTURE.md`
- `docs/AEGIS_NODE_SECURITY_ARCHITECTURE.md`
- `docs/AEGIS_NODE_AI_SECURITY.md`
- `docs/AEGIS_NODE_THREAT_INTELLIGENCE.md`
- `docs/AEGIS_NODE_RESEARCH_SUMMARY.md`
- `docs/AEGIS_NODE_VALIDATION_SUMMARY.md`
- `docs/USER_GUIDE.md`
- `docs/DEPLOYMENT_GUIDE.md`
- `docs/DEVELOPER_GUIDE.md`
- `docs/RELEASE_NOTES.md`
- `docs/LIMITATIONS.md`
- `docs/SECURITY.md`
- `docs/RELEASE_MANIFEST.md`

## Tests & Benchmarks (Development Only)
- `/tests`: Pytest regression suite.
- `/research`: Benchmarks, ground truth, and synthetic datasets.
- `/evaluation`: Historical evaluation results.
- `/experiments`: Validation execution records.
