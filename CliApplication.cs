using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Web;

namespace Insighta.Cli;

public sealed class CliApplication
{
    private const string ApiVersionHeaderName = "X-API-Version";
    private const string ApiVersionHeaderValue = "1";
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true
    };

    private readonly CredentialStore _credentialStore = new();

    public async Task<int> RunAsync(string[] args)
    {
        if (args.Length == 0)
        {
            PrintHelp();
            return 1;
        }

        try
        {
            return await DispatchAsync(args);
        }
        catch (CliException ex)
        {
            Console.Error.WriteLine(ex.Message);
            return ex.ExitCode;
        }
    }

    private async Task<int> DispatchAsync(string[] args)
    {
        return args[0].ToLowerInvariant() switch
        {
            "login" => await LoginAsync(args[1..]),
            "logout" => await LogoutAsync(),
            "whoami" => await WhoAmIAsync(),
            "profiles" => await ProfilesAsync(args[1..]),
            "help" or "--help" or "-h" => ShowHelpAndExit(),
            _ => throw new CliException($"Unknown command: {args[0]}.{Environment.NewLine}Run `insighta help` for usage.")
        };
    }

    private async Task<int> LoginAsync(string[] args)
    {
        var options = OptionSet.Parse(args);
        var apiBaseUrl = ResolveApiBaseUrl(options);
        var userState = CreateRandomToken();
        var codeVerifier = CreatePkceVerifier();
        var codeChallenge = CreatePkceChallenge(codeVerifier);
        var port = GetAvailablePort();
        var callbackUri = $"http://127.0.0.1:{port}/callback/";

        using var httpClient = CreateHttpClient(apiBaseUrl);
        using var listener = new HttpListener();
        listener.Prefixes.Add(callbackUri);
        listener.Start();

        var startUrl = BuildUri(
            apiBaseUrl,
            "/auth/github",
            new Dictionary<string, string?>
            {
                ["mode"] = "cli",
                ["client_redirect_uri"] = callbackUri,
                ["state"] = userState,
                ["code_challenge"] = codeChallenge,
                ["code_challenge_method"] = "S256"
            });

        var start = await WithSpinnerAsync(
            "Preparing GitHub login",
            async () => await GetJsonAsync<AuthStartEnvelope>(httpClient, startUrl, includeApiVersion: false));

        if (start?.Data == null || string.IsNullOrWhiteSpace(start.Data.AuthorizeUrl) || string.IsNullOrWhiteSpace(start.Data.State))
        {
            throw new CliException("The backend returned an incomplete OAuth start response.");
        }

        OpenBrowser(start.Data.AuthorizeUrl);
        Console.WriteLine("Waiting for GitHub callback...");

        var callbackResult = await WaitForCallbackAsync(listener);
        if (!string.Equals(callbackResult.State, start.Data.State, StringComparison.Ordinal))
        {
            throw new CliException("OAuth state validation failed.");
        }

        var exchangeUrl = BuildUri(
            apiBaseUrl,
            "/auth/github/callback",
            new Dictionary<string, string?>
            {
                ["code"] = callbackResult.Code,
                ["state"] = callbackResult.State,
                ["code_verifier"] = codeVerifier
            });

        var tokenResponse = await WithSpinnerAsync(
            "Completing login",
            async () => await GetJsonAsync<AuthCallbackResponse>(httpClient, exchangeUrl, includeApiVersion: false));

        if (tokenResponse?.User == null)
        {
            throw new CliException("The backend did not return user information after login.");
        }

        var credentials = Credentials.FromAuthResponse(apiBaseUrl, tokenResponse);
        await _credentialStore.SaveAsync(credentials);
        Console.WriteLine($"Logged in as @{tokenResponse.User.Username}");
        return 0;
    }

    private async Task<int> LogoutAsync()
    {
        var credentials = await _credentialStore.LoadRequiredAsync();
        using var httpClient = CreateAuthorizedHttpClient(credentials);

        await EnsureFreshAccessTokenAsync(httpClient, credentials);

        var body = new RefreshTokenRequest(credentials.RefreshToken);
        await WithSpinnerAsync(
            "Logging out",
            async () => await SendAsync<JsonElement>(httpClient, HttpMethod.Post, "/auth/logout", body, includeApiVersion: false));

        await _credentialStore.DeleteAsync();
        Console.WriteLine("Logged out successfully.");
        return 0;
    }

    private async Task<int> WhoAmIAsync()
    {
        var credentials = await _credentialStore.LoadRequiredAsync();
        using var httpClient = CreateAuthorizedHttpClient(credentials);
        await EnsureFreshAccessTokenAsync(httpClient, credentials);

        var response = await WithSpinnerAsync(
            "Fetching account",
            async () => await SendAsync<UserEnvelope>(httpClient, HttpMethod.Get, "/api/users/me", includeApiVersion: false));

        if (response?.Data == null)
        {
            throw new CliException("Unable to read the current user.");
        }

        PrintKeyValueTable(new Dictionary<string, string?>
        {
            ["id"] = response.Data.Id,
            ["github_id"] = response.Data.GitHubId,
            ["username"] = response.Data.Username,
            ["email"] = response.Data.Email,
            ["role"] = response.Data.Role,
            ["is_active"] = response.Data.IsActive.ToString().ToLowerInvariant(),
            ["created_at"] = response.Data.CreatedAt,
            ["last_login_at"] = response.Data.LastLoginAt
        });

        return 0;
    }

    private async Task<int> ProfilesAsync(string[] args)
    {
        if (args.Length == 0)
        {
            throw new CliException("Missing profiles subcommand. Use list, get, search, create, or export.");
        }

        return args[0].ToLowerInvariant() switch
        {
            "list" => await ProfilesListAsync(args[1..]),
            "get" => await ProfilesGetAsync(args[1..]),
            "search" => await ProfilesSearchAsync(args[1..]),
            "create" => await ProfilesCreateAsync(args[1..]),
            "export" => await ProfilesExportAsync(args[1..]),
            _ => throw new CliException($"Unknown profiles subcommand: {args[0]}.")
        };
    }

    private async Task<int> ProfilesListAsync(string[] args)
    {
        var options = OptionSet.Parse(args);
        var query = BuildProfileQuery(options);

        var response = await ExecuteProfileRequestAsync<PagedProfilesResponse>(
            "Fetching profiles",
            HttpMethod.Get,
            $"/api/profiles{ToQueryString(query)}");

        PrintProfilesTable(response);
        return 0;
    }

    private async Task<int> ProfilesGetAsync(string[] args)
    {
        if (args.Length == 0 || string.IsNullOrWhiteSpace(args[0]))
        {
            throw new CliException("Usage: insighta profiles get <id>");
        }

        var response = await ExecuteProfileRequestAsync<ProfileEnvelope>(
            "Fetching profile",
            HttpMethod.Get,
            $"/api/profiles/{Uri.EscapeDataString(args[0])}");

        if (response.Data == null)
        {
            throw new CliException("Profile response did not include data.");
        }

        PrintKeyValueTable(new Dictionary<string, string?>
        {
            ["id"] = response.Data.Id,
            ["name"] = response.Data.Name,
            ["gender"] = response.Data.Gender,
            ["gender_probability"] = response.Data.GenderProbability.ToString("0.00"),
            ["age"] = response.Data.Age.ToString(),
            ["age_group"] = response.Data.AgeGroup,
            ["country_id"] = response.Data.CountryId,
            ["country_name"] = response.Data.CountryName,
            ["country_probability"] = response.Data.CountryProbability.ToString("0.00"),
            ["created_at"] = response.Data.CreatedAt
        });

        return 0;
    }

    private async Task<int> ProfilesSearchAsync(string[] args)
    {
        if (args.Length == 0)
        {
            throw new CliException("Usage: insighta profiles search \"query\"");
        }

        var options = OptionSet.Parse(args[1..]);
        var query = BuildProfileQuery(options);
        query["q"] = args[0];

        var response = await ExecuteProfileRequestAsync<PagedProfilesResponse>(
            "Searching profiles",
            HttpMethod.Get,
            $"/api/profiles/search{ToQueryString(query)}");

        PrintProfilesTable(response);
        return 0;
    }

    private async Task<int> ProfilesCreateAsync(string[] args)
    {
        var options = OptionSet.Parse(args);
        var name = options.GetSingleValue("--name");
        if (string.IsNullOrWhiteSpace(name))
        {
            throw new CliException("Usage: insighta profiles create --name \"Harriet Tubman\"");
        }

        var response = await ExecuteProfileRequestAsync<ProfileEnvelope>(
            "Creating profile",
            HttpMethod.Post,
            "/api/profiles",
            new CreateProfileRequest(name));

        if (response.Data == null)
        {
            throw new CliException("Profile creation response did not include data.");
        }

        Console.WriteLine("Profile saved.");
        PrintKeyValueTable(new Dictionary<string, string?>
        {
            ["id"] = response.Data.Id,
            ["name"] = response.Data.Name,
            ["gender"] = response.Data.Gender,
            ["gender_probability"] = response.Data.GenderProbability.ToString("0.00"),
            ["age"] = response.Data.Age.ToString(),
            ["age_group"] = response.Data.AgeGroup,
            ["country_id"] = response.Data.CountryId,
            ["country_name"] = response.Data.CountryName,
            ["country_probability"] = response.Data.CountryProbability.ToString("0.00"),
            ["created_at"] = response.Data.CreatedAt
        });

        return 0;
    }

    private async Task<int> ProfilesExportAsync(string[] args)
    {
        var options = OptionSet.Parse(args);
        var format = options.GetSingleValue("--format") ?? "csv";
        if (!string.Equals(format, "csv", StringComparison.OrdinalIgnoreCase))
        {
            throw new CliException("Only --format csv is supported.");
        }

        var query = BuildProfileQuery(options);
        query["format"] = format;

        var credentials = await _credentialStore.LoadRequiredAsync();
        using var httpClient = CreateAuthorizedHttpClient(credentials);
        await EnsureFreshAccessTokenAsync(httpClient, credentials);

        var bytes = await WithSpinnerAsync(
            "Exporting profiles",
            async () => await DownloadBytesAsync(httpClient, $"/api/profiles/export{ToQueryString(query)}"));

        var fileName = $"profiles_{DateTime.UtcNow:yyyyMMddHHmmss}.csv";
        var outputPath = Path.Combine(Environment.CurrentDirectory, fileName);
        await File.WriteAllBytesAsync(outputPath, bytes);
        Console.WriteLine($"Saved CSV to {outputPath}");
        return 0;
    }

    private async Task<T> ExecuteProfileRequestAsync<T>(string label, HttpMethod method, string path, object? body = null)
    {
        var credentials = await _credentialStore.LoadRequiredAsync();
        using var httpClient = CreateAuthorizedHttpClient(credentials);
        await EnsureFreshAccessTokenAsync(httpClient, credentials);

        return await WithSpinnerAsync(
            label,
            async () => await SendAsync<T>(httpClient, method, path, body, includeApiVersion: true));
    }

    private async Task EnsureFreshAccessTokenAsync(HttpClient httpClient, Credentials credentials)
    {
        if (!credentials.AccessTokenExpiresSoon())
        {
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(credentials.TokenType, credentials.AccessToken);
            return;
        }

        if (credentials.RefreshTokenExpired())
        {
            throw new CliException("Your session has expired. Run `insighta login` again.");
        }

        var refreshed = await SendAsync<RefreshResponse>(
            httpClient,
            HttpMethod.Post,
            "/auth/refresh",
            new RefreshTokenRequest(credentials.RefreshToken),
            includeApiVersion: false,
            authorize: false);

        credentials.ApplyRefresh(refreshed);
        await _credentialStore.SaveAsync(credentials);
        httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(credentials.TokenType, credentials.AccessToken);
    }

    private static HttpClient CreateHttpClient(string baseUrl)
    {
        var client = new HttpClient
        {
            BaseAddress = new Uri(NormalizeBaseUrl(baseUrl), UriKind.Absolute),
            Timeout = TimeSpan.FromSeconds(100)
        };

        client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        return client;
    }

    private static HttpClient CreateAuthorizedHttpClient(Credentials credentials)
    {
        var client = CreateHttpClient(credentials.BaseUrl);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(credentials.TokenType, credentials.AccessToken);
        return client;
    }

    private static async Task<byte[]> DownloadBytesAsync(HttpClient httpClient, string path)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.Add(ApiVersionHeaderName, ApiVersionHeaderValue);
        using var response = await httpClient.SendAsync(request);

        if (!response.IsSuccessStatusCode)
        {
            await ThrowForErrorAsync(response);
        }

        return await response.Content.ReadAsByteArrayAsync();
    }

    private static async Task<T> SendAsync<T>(HttpClient httpClient, HttpMethod method, string path, object? body = null, bool includeApiVersion = false, bool authorize = true)
    {
        using var request = new HttpRequestMessage(method, path);
        if (includeApiVersion)
        {
            request.Headers.Add(ApiVersionHeaderName, ApiVersionHeaderValue);
        }

        if (!authorize)
        {
            request.Headers.Authorization = null;
        }

        if (body != null)
        {
            request.Content = new StringContent(JsonSerializer.Serialize(body, JsonOptions), Encoding.UTF8, "application/json");
        }

        using var response = await httpClient.SendAsync(request);
        if (!response.IsSuccessStatusCode)
        {
            await ThrowForErrorAsync(response);
        }

        if (typeof(T) == typeof(JsonElement))
        {
            var document = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
            return (T)(object)document.RootElement.Clone();
        }

        var payload = await response.Content.ReadFromJsonAsync<T>(JsonOptions);
        if (payload == null)
        {
            throw new CliException("The server returned an empty response.");
        }

        return payload;
    }

    private static async Task<T> GetJsonAsync<T>(HttpClient httpClient, string absoluteUrl, bool includeApiVersion)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, absoluteUrl);
        if (includeApiVersion)
        {
            request.Headers.Add(ApiVersionHeaderName, ApiVersionHeaderValue);
        }

        using var response = await httpClient.SendAsync(request);
        if (!response.IsSuccessStatusCode)
        {
            await ThrowForErrorAsync(response);
        }

        var payload = await response.Content.ReadFromJsonAsync<T>(JsonOptions);
        if (payload == null)
        {
            throw new CliException("The server returned an empty response.");
        }

        return payload;
    }

    private static async Task ThrowForErrorAsync(HttpResponseMessage response)
    {
        try
        {
            var error = await response.Content.ReadFromJsonAsync<ErrorEnvelope>(JsonOptions);
            if (error != null && !string.IsNullOrWhiteSpace(error.Message))
            {
                throw new CliException($"Request failed ({(int)response.StatusCode}): {error.Message}");
            }
        }
        catch (JsonException)
        {
        }

        throw new CliException($"Request failed with status {(int)response.StatusCode} {response.ReasonPhrase}.");
    }

    private static async Task<CallbackResult> WaitForCallbackAsync(HttpListener listener)
    {
        var context = await listener.GetContextAsync();
        var query = HttpUtility.ParseQueryString(context.Request.Url?.Query ?? string.Empty);
        var code = query["code"];
        var state = query["state"];
        var error = query["error"];

        var html = string.IsNullOrWhiteSpace(error)
            ? "<html><body><h2>Insighta login complete.</h2><p>You can return to the terminal.</p></body></html>"
            : $"<html><body><h2>Insighta login failed.</h2><p>{WebUtility.HtmlEncode(error)}</p></body></html>";

        var bytes = Encoding.UTF8.GetBytes(html);
        context.Response.StatusCode = string.IsNullOrWhiteSpace(error) ? 200 : 400;
        context.Response.ContentType = "text/html; charset=utf-8";
        context.Response.ContentLength64 = bytes.Length;
        await context.Response.OutputStream.WriteAsync(bytes);
        context.Response.Close();

        if (!string.IsNullOrWhiteSpace(error))
        {
            throw new CliException($"GitHub login failed: {error}");
        }

        if (string.IsNullOrWhiteSpace(code) || string.IsNullOrWhiteSpace(state))
        {
            throw new CliException("GitHub callback did not include the expected code and state.");
        }

        return new CallbackResult(code, state);
    }

    private static async Task<T> WithSpinnerAsync<T>(string label, Func<Task<T>> operation)
    {
        using var spinner = new Spinner(label);
        spinner.Start();
        try
        {
            var result = await operation();
            spinner.Stop(success: true);
            return result;
        }
        catch
        {
            spinner.Stop(success: false);
            throw;
        }
    }

    private static Dictionary<string, string?> BuildProfileQuery(OptionSet options)
    {
        return new Dictionary<string, string?>
        {
            ["gender"] = options.GetSingleValue("--gender"),
            ["country_id"] = options.GetSingleValue("--country") ?? options.GetSingleValue("--country-id"),
            ["age_group"] = options.GetSingleValue("--age-group"),
            ["min_age"] = options.GetSingleValue("--min-age"),
            ["max_age"] = options.GetSingleValue("--max-age"),
            ["sort_by"] = options.GetSingleValue("--sort-by"),
            ["order"] = options.GetSingleValue("--order"),
            ["page"] = options.GetSingleValue("--page"),
            ["limit"] = options.GetSingleValue("--limit")
        };
    }

    private static string ToQueryString(Dictionary<string, string?> values)
    {
        var parts = values
            .Where(kvp => !string.IsNullOrWhiteSpace(kvp.Value))
            .Select(kvp => $"{Uri.EscapeDataString(kvp.Key)}={Uri.EscapeDataString(kvp.Value!)}")
            .ToArray();

        return parts.Length == 0 ? string.Empty : $"?{string.Join("&", parts)}";
    }

    private static string BuildUri(string baseUrl, string path, Dictionary<string, string?> values)
    {
        return $"{NormalizeBaseUrl(baseUrl).TrimEnd('/')}{path}{ToQueryString(values)}";
    }

    private static string ResolveApiBaseUrl(OptionSet? options = null, Credentials? credentials = null)
    {
        var configured = options?.GetSingleValue("--api-url")
            ?? Environment.GetEnvironmentVariable("INSIGHTA_API_URL")
            ?? credentials?.BaseUrl;

        if (string.IsNullOrWhiteSpace(configured))
        {
            throw new CliException("Set INSIGHTA_API_URL or pass --api-url <backend-url>.");
        }

        return NormalizeBaseUrl(configured);
    }

    private static string NormalizeBaseUrl(string baseUrl)
    {
        return baseUrl.Trim().TrimEnd('/');
    }

    private static int GetAvailablePort()
    {
        var listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private static string CreateRandomToken()
    {
        return Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
    }

    private static string CreatePkceVerifier()
    {
        return Base64Url(RandomNumberGenerator.GetBytes(32));
    }

    private static string CreatePkceChallenge(string verifier)
    {
        var bytes = SHA256.HashData(Encoding.ASCII.GetBytes(verifier));
        return Base64Url(bytes);
    }

    private static string Base64Url(byte[] data)
    {
        return Convert.ToBase64String(data)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private static void OpenBrowser(string url)
    {
        Process.Start(new ProcessStartInfo
        {
            FileName = url,
            UseShellExecute = true
        });
    }

    private static void PrintProfilesTable(PagedProfilesResponse response)
    {
        var rows = response.Data.Select(profile => new[]
        {
            profile.Id,
            profile.Name,
            profile.Gender,
            profile.Age.ToString(),
            profile.AgeGroup,
            profile.CountryId,
            profile.CountryName
        }).ToList();

        ConsoleTable.Write(
            ["id", "name", "gender", "age", "age_group", "country_id", "country_name"],
            rows);

        Console.WriteLine();
        Console.WriteLine($"page {response.Page}/{Math.Max(response.TotalPages, 1)} | total {response.Total} | limit {response.Limit}");
        Console.WriteLine($"self: {response.Links.Self}");
        if (!string.IsNullOrWhiteSpace(response.Links.Next))
        {
            Console.WriteLine($"next: {response.Links.Next}");
        }
        if (!string.IsNullOrWhiteSpace(response.Links.Prev))
        {
            Console.WriteLine($"prev: {response.Links.Prev}");
        }
    }

    private static void PrintKeyValueTable(Dictionary<string, string?> values)
    {
        var width = values.Keys.Max(k => k.Length);
        foreach (var pair in values)
        {
            Console.WriteLine($"{pair.Key.PadRight(width)} : {pair.Value}");
        }
    }

    private static int ShowHelpAndExit()
    {
        PrintHelp();
        return 0;
    }

    private static void PrintHelp()
    {
        Console.WriteLine("""
Insighta CLI

Usage:
  insighta login --api-url <backend-url>
  insighta logout
  insighta whoami

  insighta profiles list [--gender male] [--country NG] [--age-group adult] [--min-age 25] [--max-age 40] [--sort-by age] [--order desc] [--page 2] [--limit 20]
  insighta profiles get <id>
  insighta profiles search "young males from nigeria" [--page 1] [--limit 10]
  insighta profiles create --name "Harriet Tubman"
  insighta profiles export --format csv [--gender male] [--country NG]

Configuration:
  Set INSIGHTA_API_URL or pass --api-url during login.

Credentials:
  Stored at ~/.insighta/credentials.json
""");
    }

    private sealed record CallbackResult(string Code, string State);

    private sealed class Spinner : IDisposable
    {
        private readonly string _label;
        private readonly CancellationTokenSource _cts = new();
        private Task? _loopTask;

        public Spinner(string label)
        {
            _label = label;
        }

        public void Start()
        {
            _loopTask = Task.Run(async () =>
            {
                var frames = new[] { '|', '/', '-', '\\' };
                var index = 0;
                while (!_cts.IsCancellationRequested)
                {
                    Console.Write($"\r{_label} {frames[index++ % frames.Length]}");
                    await Task.Delay(100, _cts.Token).ContinueWith(_ => { });
                }
            });
        }

        public void Stop(bool success)
        {
            _cts.Cancel();
            _loopTask?.Wait(TimeSpan.FromSeconds(1));
            Console.Write("\r");
            Console.WriteLine(success ? $"{_label} done." : $"{_label} failed.");
        }

        public void Dispose()
        {
            _cts.Dispose();
        }
    }

    private sealed class OptionSet
    {
        private readonly Dictionary<string, List<string>> _values = new(StringComparer.OrdinalIgnoreCase);

        public static OptionSet Parse(string[] args)
        {
            var options = new OptionSet();
            for (var i = 0; i < args.Length; i++)
            {
                var current = args[i];
                if (!current.StartsWith("--", StringComparison.Ordinal))
                {
                    continue;
                }

                string value;
                if (current.Contains('=', StringComparison.Ordinal))
                {
                    var split = current.Split('=', 2);
                    current = split[0];
                    value = split[1];
                }
                else if (i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal))
                {
                    value = args[++i];
                }
                else
                {
                    value = "true";
                }

                if (!options._values.TryGetValue(current, out var list))
                {
                    list = [];
                    options._values[current] = list;
                }

                list.Add(value);
            }

            return options;
        }

        public string? GetSingleValue(string name)
        {
            return _values.TryGetValue(name, out var list) ? list.LastOrDefault() : null;
        }
    }
}

internal sealed class CliException : Exception
{
    public CliException(string message, int exitCode = 1) : base(message)
    {
        ExitCode = exitCode;
    }

    public int ExitCode { get; }
}

internal sealed class CredentialStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    private readonly string _directoryPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        ".insighta");

    private string FilePath => Path.Combine(_directoryPath, "credentials.json");

    public async Task SaveAsync(Credentials credentials)
    {
        Directory.CreateDirectory(_directoryPath);
        var json = JsonSerializer.Serialize(credentials, JsonOptions);
        await File.WriteAllTextAsync(FilePath, json);
    }

    public async Task<Credentials?> LoadAsync()
    {
        if (!File.Exists(FilePath))
        {
            return null;
        }

        var json = await File.ReadAllTextAsync(FilePath);
        return JsonSerializer.Deserialize<Credentials>(json);
    }

    public async Task<Credentials> LoadRequiredAsync()
    {
        var credentials = await LoadAsync();
        if (credentials == null)
        {
            throw new CliException("You are not logged in. Run `insighta login` first.");
        }

        return credentials;
    }

    public Task DeleteAsync()
    {
        if (File.Exists(FilePath))
        {
            File.Delete(FilePath);
        }

        return Task.CompletedTask;
    }
}

internal sealed class ConsoleTable
{
    public static void Write(string[] headers, List<string[]> rows)
    {
        if (rows.Count == 0)
        {
            Console.WriteLine("No profiles found.");
            return;
        }

        var widths = new int[headers.Length];
        for (var i = 0; i < headers.Length; i++)
        {
            widths[i] = headers[i].Length;
        }

        foreach (var row in rows)
        {
            for (var i = 0; i < row.Length; i++)
            {
                widths[i] = Math.Max(widths[i], row[i].Length);
            }
        }

        Console.WriteLine(string.Join("  ", headers.Select((header, index) => header.PadRight(widths[index]))));
        Console.WriteLine(string.Join("  ", widths.Select(width => new string('-', width))));

        foreach (var row in rows)
        {
            Console.WriteLine(string.Join("  ", row.Select((value, index) => value.PadRight(widths[index]))));
        }
    }
}

public sealed class Credentials
{
    [JsonPropertyName("base_url")]
    public string BaseUrl { get; set; } = string.Empty;

    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; } = string.Empty;

    [JsonPropertyName("refresh_token")]
    public string RefreshToken { get; set; } = string.Empty;

    [JsonPropertyName("token_type")]
    public string TokenType { get; set; } = "Bearer";

    [JsonPropertyName("access_token_expires_at")]
    public DateTimeOffset AccessTokenExpiresAt { get; set; }

    [JsonPropertyName("refresh_token_expires_at")]
    public DateTimeOffset RefreshTokenExpiresAt { get; set; }

    [JsonPropertyName("username")]
    public string Username { get; set; } = string.Empty;

    [JsonPropertyName("role")]
    public string Role { get; set; } = string.Empty;

    public static Credentials FromAuthResponse(string baseUrl, AuthCallbackResponse response)
    {
        return new Credentials
        {
            BaseUrl = baseUrl,
            AccessToken = response.AccessToken,
            RefreshToken = response.RefreshToken,
            TokenType = response.TokenType,
            AccessTokenExpiresAt = DateTimeOffset.UtcNow.AddSeconds(response.ExpiresIn),
            RefreshTokenExpiresAt = DateTimeOffset.UtcNow.AddSeconds(response.RefreshExpiresIn),
            Username = response.User?.Username ?? string.Empty,
            Role = response.User?.Role ?? string.Empty
        };
    }

    public bool AccessTokenExpiresSoon()
    {
        return AccessTokenExpiresAt <= DateTimeOffset.UtcNow.AddSeconds(15);
    }

    public bool RefreshTokenExpired()
    {
        return RefreshTokenExpiresAt <= DateTimeOffset.UtcNow;
    }

    public void ApplyRefresh(RefreshResponse response)
    {
        AccessToken = response.AccessToken;
        RefreshToken = response.RefreshToken;
        AccessTokenExpiresAt = DateTimeOffset.UtcNow.AddMinutes(3);
        RefreshTokenExpiresAt = DateTimeOffset.UtcNow.AddMinutes(5);
    }
}

public sealed record RefreshTokenRequest([property: JsonPropertyName("refresh_token")] string RefreshToken);
public sealed record CreateProfileRequest([property: JsonPropertyName("name")] string Name);

public sealed class ErrorEnvelope
{
    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;

    [JsonPropertyName("message")]
    public string Message { get; set; } = string.Empty;
}

public sealed class AuthStartEnvelope
{
    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;

    [JsonPropertyName("data")]
    public AuthStartData? Data { get; set; }
}

public sealed class AuthStartData
{
    [JsonPropertyName("authorize_url")]
    public string AuthorizeUrl { get; set; } = string.Empty;

    [JsonPropertyName("state")]
    public string State { get; set; } = string.Empty;
}

public sealed class AuthCallbackResponse
{
    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;

    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; } = string.Empty;

    [JsonPropertyName("refresh_token")]
    public string RefreshToken { get; set; } = string.Empty;

    [JsonPropertyName("token_type")]
    public string TokenType { get; set; } = "Bearer";

    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; set; }

    [JsonPropertyName("refresh_expires_in")]
    public int RefreshExpiresIn { get; set; }

    [JsonPropertyName("user")]
    public UserDto? User { get; set; }
}

public sealed class RefreshResponse
{
    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;

    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; } = string.Empty;

    [JsonPropertyName("refresh_token")]
    public string RefreshToken { get; set; } = string.Empty;
}

public sealed class UserEnvelope
{
    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;

    [JsonPropertyName("data")]
    public UserDto? Data { get; set; }
}

public sealed class UserDto
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("github_id")]
    public string GitHubId { get; set; } = string.Empty;

    [JsonPropertyName("username")]
    public string Username { get; set; } = string.Empty;

    [JsonPropertyName("email")]
    public string? Email { get; set; }

    [JsonPropertyName("avatar_url")]
    public string? AvatarUrl { get; set; }

    [JsonPropertyName("role")]
    public string Role { get; set; } = string.Empty;

    [JsonPropertyName("is_active")]
    public bool IsActive { get; set; }

    [JsonPropertyName("last_login_at")]
    public string LastLoginAt { get; set; } = string.Empty;

    [JsonPropertyName("created_at")]
    public string CreatedAt { get; set; } = string.Empty;
}

public sealed class ProfileEnvelope
{
    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;

    [JsonPropertyName("data")]
    public ProfileDto? Data { get; set; }
}

public sealed class PagedProfilesResponse
{
    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;

    [JsonPropertyName("page")]
    public int Page { get; set; }

    [JsonPropertyName("limit")]
    public int Limit { get; set; }

    [JsonPropertyName("total")]
    public int Total { get; set; }

    [JsonPropertyName("total_pages")]
    public int TotalPages { get; set; }

    [JsonPropertyName("links")]
    public PaginationLinks Links { get; set; } = new();

    [JsonPropertyName("data")]
    public List<ProfileDto> Data { get; set; } = [];
}

public sealed class PaginationLinks
{
    [JsonPropertyName("self")]
    public string Self { get; set; } = string.Empty;

    [JsonPropertyName("next")]
    public string? Next { get; set; }

    [JsonPropertyName("prev")]
    public string? Prev { get; set; }
}

public sealed class ProfileDto
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("gender")]
    public string Gender { get; set; } = string.Empty;

    [JsonPropertyName("gender_probability")]
    public double GenderProbability { get; set; }

    [JsonPropertyName("age")]
    public int Age { get; set; }

    [JsonPropertyName("age_group")]
    public string AgeGroup { get; set; } = string.Empty;

    [JsonPropertyName("country_id")]
    public string CountryId { get; set; } = string.Empty;

    [JsonPropertyName("country_name")]
    public string CountryName { get; set; } = string.Empty;

    [JsonPropertyName("country_probability")]
    public double CountryProbability { get; set; }

    [JsonPropertyName("created_at")]
    public string CreatedAt { get; set; } = string.Empty;
}
