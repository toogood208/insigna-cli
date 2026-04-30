# Insighta CLI

`Insighta CLI` is a standalone-ready command-line client for Insighta Labs+. It lives in this workspace temporarily so it can be developed against the backend, but it is intentionally isolated and can be moved into its own repository later.

## Commands

```powershell
insighta login --api-url https://your-backend.example.com
insighta logout
insighta whoami

insighta profiles list
insighta profiles list --gender male --country NG --age-group adult
insighta profiles list --min-age 25 --max-age 40 --sort-by age --order desc
insighta profiles get <id>
insighta profiles search "young males from nigeria"
insighta profiles create --name "Harriet Tubman"
insighta profiles export --format csv --gender male --country NG
```

## Authentication Flow

The CLI uses the backend's GitHub OAuth + PKCE flow:

1. generates `state`, `code_verifier`, and `code_challenge`
2. starts a temporary local callback server
3. opens the browser to the backend auth endpoint
4. validates the callback state
5. exchanges the callback through the backend
6. stores tokens locally at `~/.insighta/credentials.json`

## Configuration

Set the backend URL with either:

- `--api-url` during login
- `INSIGHTA_API_URL` environment variable

Subsequent commands reuse the stored backend URL from the credential file unless overridden by the environment.

## Installation As A Global Tool

From this folder:

```powershell
dotnet pack
dotnet tool install --global --add-source .\nupkg Insighta.Cli
```

Update an existing installation:

```powershell
dotnet tool update --global --add-source .\nupkg Insighta.Cli
```

## Extraction To Another Repo

This folder is self-contained:

- its own `.csproj`
- its own `README`
- no project reference to the backend
- no shared source files

That means it can be copied to a new repo directly or extracted later with git history tools like `git subtree split`.
