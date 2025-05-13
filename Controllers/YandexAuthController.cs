using Microsoft.AspNetCore.Mvc;
using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Reflection;
using System.Text;
using System.Text.Json;
using WebApplication4.WebApplication4.Services;

namespace WebApplication4.Controllers
{
    [ApiController]
    [Route("api/yandex")]
    public class YandexAuthController : ControllerBase
    {
        private readonly HttpClient _client;
        private readonly RequestQueueService _queueService; // добавлено

        public YandexAuthController(IHttpClientFactory factory, RequestQueueService queueService)
        {
            _client = factory.CreateClient();
            _queueService = queueService; // сохраняем
        }

        [HttpPost("auth2")]
        public async Task<IActionResult> Auth([FromBody] CookieRequest request)
        {
            try
            {
                return await _queueService.Enqueue<IActionResult>(async () =>
                {
                    if (string.IsNullOrWhiteSpace(request?.Cookies))
                    {
                        //_logger.LogWarning("Пустые куки в запросе");
                        return BadRequest("Необходимы куки для аутентификации");
                    }
                    var androidVersion = request.AndroidVersion ?? "9";
                    var manufacturer = request.DeviceManufacturer ?? "samsung";
                    var model = request.DeviceModel ?? "SM-G988N";

                    var csrfToken = await FetchCsrfToken(request.Cookies, androidVersion, manufacturer, model);
                    if (string.IsNullOrEmpty(csrfToken))
                    {
                        //_logger.LogError("Не удалось получить CSRF токен");
                        return StatusCode((int)HttpStatusCode.Unauthorized, "CSRF token failed");
                    }

                    var xToken = await FetchXToken(request.Cookies, csrfToken, androidVersion, manufacturer, model);
                    if (string.IsNullOrEmpty(xToken))
                    {
                        //_logger.LogError("Не удалось получить X-Token");
                        return StatusCode((int)HttpStatusCode.Unauthorized, "x-token failed");
                    }

                    var userId = await FetchUserId(xToken, androidVersion, manufacturer, model);
                    if (string.IsNullOrEmpty(userId))
                    {
                        //_logger.LogError("Не удалось получить UserId");
                        return StatusCode((int)HttpStatusCode.Unauthorized, "userId failed");
                    }

                    //_logger.LogInformation("Успешная аутентификация для пользователя {UserId}", userId);
                    return Ok(new AuthResponse { UserId = userId, AccessToken = xToken });
                });
            }
            catch (Exception ex)
            {
                //_logger.LogError(ex, "Ошибка при обработке запроса аутентификации");
                return StatusCode((int)HttpStatusCode.InternalServerError, "Internal server error");
            }
        }


        [HttpPost("fetch-csrf-token")]
        public async Task<string> FetchCsrfToken(string cookies, string androidVersion, string manufacturer, string model)
        {
            var url = "https://mobileproxy.passport.yandex.net/1/bundle/oauth/token_by_sessionid?app_id=ru.yandex.taxi&app_version_name=5.21.1&am_app=ru.yandex.taxi+5.21.1";

            var request = new HttpRequestMessage(HttpMethod.Post, url);

            // Формируем тело запроса
            var requestBody = "client_id=c0ebe342af7d48fbbbfcf2d2eedb8f9e&client_secret=ad0a908f0aa341a182a37ecd75bc319e";
            request.Content = new StringContent(requestBody, Encoding.UTF8, "application/x-www-form-urlencoded");
            string userAgent = $"com.yandex.mobile.auth.sdk/7.44.3.744033792 ({manufacturer} {model}; Android {androidVersion})";
            // Добавляем заголовки — строго так, как в Android-приложении
            request.Headers.TryAddWithoutValidation("Host", "mobileproxy.passport.yandex.net");
            request.Headers.TryAddWithoutValidation("Connection", "Keep-Alive");
            request.Headers.TryAddWithoutValidation("User-Agent", userAgent);
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


        private async Task<string> FetchXToken(string cookies, string accessToken, string androidVersion, string manufacturer, string model)
        {
            var body = $"grant_type=x-token&access_token={accessToken}&client_id=22d873ed2ea14b93a36a0f5a07026458&client_secret=203b2fbe3a6e4552be141195ee8b1eb9";
            var content = new StringContent(body, Encoding.UTF8, "application/x-www-form-urlencoded");

            var url = $"https://mobileproxy.passport.yandex.net/1/token" +
          $"?manufacturer={Uri.EscapeDataString(manufacturer)}" +
          $"&model={Uri.EscapeDataString(model)}" +
          $"&app_platform=Android+{Uri.EscapeDataString(androidVersion)}+(REL)" +
          $"&am_version_name=7.44.3(744033792)" +
          $"&app_id=ru.yandex.taxi" +
          $"&app_version_name=5.21.1" +
          $"&am_app=ru.yandex.taxi+5.21.1";

            var request = new HttpRequestMessage(HttpMethod.Post, url);
            request.Content = content;
            string userAgent = $"com.yandex.mobile.auth.sdk/7.44.3.744033792 ({manufacturer} {model}; Android {androidVersion})";
            request.Headers.Add("User-Agent", userAgent);
            request.Headers.Add("Cookie", cookies);

            var response = await _client.SendAsync(request);
            var json = await response.Content.ReadAsStringAsync();

            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.TryGetProperty("access_token", out var token) ? token.GetString() : "";
        }

        private async Task<string> FetchUserId(string accessToken, string androidVersion, string manufacturer, string model)
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
            string userAgent = $"yandex-taxi/5.21.1.126550 Android/{androidVersion} ({manufacturer}; {model})";
            request.Headers.Add("User-Agent", userAgent);
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
