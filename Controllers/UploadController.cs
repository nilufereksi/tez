using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;
using Newtonsoft.Json;
using System.IO;

namespace tezprojesi.Controllers
{
    // --- MODEL SINIFLARI (AYNEN KORUNDU) ---

    // Python'dan dönen ana yapı: { "results": [ ... ] }
    public class PythonResponse
    {
        [JsonProperty("table")]
        public string? table { get; set; }

        [JsonProperty("results")]
        public List<ResultItem>? results { get; set; }
    }

    // Tabloda gösterilecek her bir satırın modeli
    public class ResultItem
    {
        // Python'dan gelen ana veriler
        [JsonProperty("bulgu")]
        public string? Bulgu { get; set; }

        [JsonProperty("risk")]
        public string? Risk { get; set; }

        [JsonProperty("kb_cozum")]
        public string? Cozum { get; set; }

        [JsonProperty("color")]
        public string? Color { get; set; }

        [JsonProperty("kb_nedir")]
        public string? kb_nedir { get; set; }

        // Ekstra alanlar
        [JsonProperty("tip")]
        public string? Tip { get; set; }

        [JsonProperty("dosya")]
        public string? Dosya { get; set; }

        // View (Index.cshtml) Uyumluluğu İçin Köprüler
        public string? OrjinalMetin => Bulgu;
        public string? OrjinalCozum => Cozum;
        public string? RiskSeviyesi => Risk;
    }

    // --- CONTROLLER (DÜZELTİLMİŞ VERSİYON) ---

    public class UploadController : Controller
    {
        // Temel URL (Endpointleri aşağıda dinamik ekleyeceğiz)
        private readonly string _pythonBaseUrl = "http://127.0.0.1:5001/analyze/";

        [HttpGet]
        public IActionResult Index()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Image(IFormFile files)
        {
            // Resim ise 'image' parametresiyle gönder
            return await ProcessFile(files, "image");
        }

        [HttpPost]
        public async Task<IActionResult> Json(IFormFile files)
        {
            // JSON ise 'json' parametresiyle gönder
            return await ProcessFile(files, "json");
        }

        private async Task<IActionResult> ProcessFile(IFormFile files, string type)
        {
            if (files != null && files.Length > 0)
            {
                using (var client = new HttpClient())
                using (var content = new MultipartFormDataContent())
                {
                    // --- KRİTİK DÜZELTME BURADA ---
                    // Eğer type "json" ise URL: http://.../analyze/json olur
                    // Eğer type "image" ise URL: http://.../analyze/image olur
                    string endpoint = (type == "json") ? "json" : "image";
                    string targetUrl = $"{_pythonBaseUrl}{endpoint}";

                    using (var fileStream = files.OpenReadStream())
                    {
                        var fileContent = new StreamContent(fileStream);
                        
                        // Content-Type ayarı (Opsiyonel ama iyi uygulama)
                        var contentType = (type == "json") ? "application/json" : (files.ContentType ?? "application/octet-stream");
                        fileContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(contentType);

                        // Python API 'file' isminde bir parametre bekliyor
                        content.Add(fileContent, "file", files.FileName);

                        try
                        {
                            // Python API'ye doğru adrese istek gönderiyoruz
                            var response = await client.PostAsync(targetUrl, content);

                            if (response.IsSuccessStatusCode)
                            {
                                var jsonString = await response.Content.ReadAsStringAsync();

                                // JSON Ayarları
                                var settings = new JsonSerializerSettings
                                {
                                    NullValueHandling = NullValueHandling.Ignore,
                                    MissingMemberHandling = MissingMemberHandling.Ignore
                                };

                                // Gelen JSON'u C# nesnesine çeviriyoruz
                                var data = JsonConvert.DeserializeObject<PythonResponse>(jsonString, settings);

                                if (data != null && data.results != null && data.results.Count > 0)
                                {
                                    // Başarılı Sonuç
                                    ViewBag.Results = data.results;
                                    ViewBag.Message = "Analiz Başarıyla Tamamlandı!";
                                }
                                else
                                {
                                    // Python cevap verdi ama liste boş
                                    ViewBag.Error = "Analiz yapıldı ancak sonuç formatı beklenenden farklı. Ham Veri: " + jsonString;
                                }
                            }
                            else
                            {
                                // HTTP Hatası (örn: 500 Internal Server Error)
                                ViewBag.Error = "Python API Hatası (Kod): " + response.StatusCode;
                            }
                        }
                        catch (Exception ex)
                        {
                            // Bağlantı kopukluğu
                            ViewBag.Error = "Bağlantı Hatası (Python sunucusu açık mı?): " + ex.Message;
                        }
                    }
                }
            }
            else
            {
                ViewBag.Error = "Lütfen bir dosya seçin.";
            }

            return View("Index");
        }
    }
}