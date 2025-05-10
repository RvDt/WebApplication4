using Microsoft.AspNetCore.Mvc;
using System.IO.Compression;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace WebApplication4.Controllers
{
    [ApiController]
    [Route("api/yandex")]
    public class YandexAuthController : ControllerBase
    {
        private readonly HttpClient _client;

        public YandexAuthController(IHttpClientFactory factory)
        {
            _client = factory.CreateClient();
        }

        [HttpPost("auth")]
        public async Task<IActionResult> Auth([FromBody] CookieRequest request)
        {
            var cookies = request.Cookies;

            var csrfToken = await FetchCsrfToken(cookies);
            if (string.IsNullOrEmpty(csrfToken)) return BadRequest("CSRF token failed");

            var xToken = await FetchXToken(cookies, csrfToken);
            if (string.IsNullOrEmpty(xToken)) return BadRequest("x-token failed");

            var userId = await FetchUserId(xToken);
            if (string.IsNullOrEmpty(userId)) return BadRequest("userId failed");

            return Ok(new AuthResponse { UserId = userId, AccessToken = xToken });
        }

        [HttpPost("fetch-csrf-token")]
        public async Task<string> FetchCsrfToken(string cookies)
        {
            var url = "https://mobileproxy.passport.yandex.net/1/bundle/oauth/token_by_sessionid?app_id=ru.yandex.taxi&app_version_name=5.21.1&am_app=ru.yandex.taxi+5.21.1";

            var request = new HttpRequestMessage(HttpMethod.Post, url);

            // Формируем тело запроса
            var requestBody = "client_id=c0ebe342af7d48fbbbfcf2d2eedb8f9e&client_secret=ad0a908f0aa341a182a37ecd75bc319e";
            request.Content = new StringContent(requestBody, Encoding.UTF8, "application/x-www-form-urlencoded");

            // Добавляем заголовки — строго так, как в Android-приложении
            request.Headers.TryAddWithoutValidation("Host", "mobileproxy.passport.yandex.net");
            request.Headers.TryAddWithoutValidation("Connection", "Keep-Alive");
            request.Headers.TryAddWithoutValidation("User-Agent", "com.yandex.mobile.auth.sdk/7.44.3.744033792 (samsung SM-G988N; Android 9)");
            request.Headers.TryAddWithoutValidation("Ya-Client-Host", "passport.yandex.ru");
            request.Headers.TryAddWithoutValidation("Ya-Client-Cookie", cookies);
            request.Headers.TryAddWithoutValidation("Content-Type", "application/x-www-form-urlencoded");
            request.Headers.TryAddWithoutValidation("Accept-Encoding", "gzip");

            // Создаём HttpClient
            using var client = new HttpClient();

            try
            {
                var response = await client.SendAsync(request);

                var responseBytes = await response.Content.ReadAsByteArrayAsync();
                var responseBody = Encoding.UTF8.GetString(responseBytes);

                Console.WriteLine("Raw response: " + responseBody);

                // Парсим JSON-ответ
                using var doc = JsonDocument.Parse(responseBody);
                if (doc.RootElement.TryGetProperty("access_token", out var tokenElement))
                {
                    return tokenElement.GetString();
                }
                else
                {
                    Console.WriteLine("❌ access_token не найден");
                    return string.Empty;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("❌ Ошибка при запросе fetchCsrfToken: " + ex.Message);
                return string.Empty;
            }
        }


        private async Task<string> FetchXToken(string cookies, string accessToken)
        {
            var body = $"grant_type=x-token&access_token={accessToken}&client_id=22d873ed2ea14b93a36a0f5a07026458&client_secret=203b2fbe3a6e4552be141195ee8b1eb9";
            var content = new StringContent(body, Encoding.UTF8, "application/x-www-form-urlencoded");

            var request = new HttpRequestMessage(HttpMethod.Post, "https://mobileproxy.passport.yandex.net/1/token?manufacturer=samsung&model=SM-G988N&app_platform=Android+9+(REL)&am_version_name=7.44.3(744033792)&app_id=ru.yandex.taxi&app_version_name=5.21.1&am_app=ru.yandex.taxi+5.21.1");
            request.Content = content;
            request.Headers.Add("User-Agent", "com.yandex.mobile.auth.sdk/7.44.3.744033792 (samsung SM-G988N; Android 9)");
            request.Headers.Add("Cookie", cookies);

            var response = await _client.SendAsync(request);
            var json = await response.Content.ReadAsStringAsync();

            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.TryGetProperty("access_token", out var token) ? token.GetString() : "";
        }

        private async Task<string> FetchUserId(string accessToken)
        {
            var jsonBody = """
        {
            "accepted": [],
            "allow_full_account": true,
            "known_orders": [],
            "mcc": "250",
            "push_settings": {
                "enabled_by_system": true,
                "excluded_tags": [],
                "included_tags": []
            },
            "supported_features": ["multiorder", "pending_orders_handler"],
            "supported_services": ["eats", "grocery", "pharmacy", "shop", "corp_food", "market", "market_viewer", "taxi"]
        }
        """;

            var content = new StringContent(jsonBody, Encoding.UTF8, "application/json");
            var request = new HttpRequestMessage(HttpMethod.Post, "https://tc.mobile.yandex.net/3.0/launch?block_id=go_ru_hosts_3_TAXI_V4_0&mobcf=yandex%25go_ru_hosts_3%25default&mobpr=go_ru_hosts_3_TAXI_0");
            request.Content = content;
            request.Headers.Add("User-Agent", "yandex-taxi/5.21.1.126550 Android/9 (samsung; SM-G988N)");
            request.Headers.Add("Authorization", $"Bearer {accessToken}");
            request.Headers.Add("X-Oauth-Token", accessToken);

            var response = await _client.SendAsync(request);
            var stream = await response.Content.ReadAsStreamAsync();
            var encoding = response.Content.Headers.ContentEncoding.ToString();

            string json;
            if (encoding.Contains("gzip"))
            {
                using var decompressed = new GZipStream(stream, CompressionMode.Decompress);
                using var reader = new StreamReader(decompressed);
                json = await reader.ReadToEndAsync();
            }
            else
            {
                using var reader = new StreamReader(stream);
                json = await reader.ReadToEndAsync();
            }

            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.TryGetProperty("id", out var idProp) ? idProp.GetString() : "";
        }
    }
}
