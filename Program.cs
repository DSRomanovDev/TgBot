using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace TgBot
{
    public enum LogLevel
    {
        DEBUG,
        INFO,
        WARNING,
        ERROR
    }

    public class Config
    {
        public string EncryptedBotToken { get; set; }
        public string TargetGroup { get; set; }
        public List<(string, string)> Keywords { get; set; }
        public List<long> AdminChatIds { get; set; }
        public string LogFile { get; set; }
        public int MessageQueueSize { get; set; } = 1000;
        public int WorkerThreads { get; set; } = 4;
        public int MaxProcessedMessages { get; set; } = 10000;
        public int StateBackupInterval { get; set; } = 3600;
        public LogLevel LogLevel { get; set; } = LogLevel.INFO;

        public static Config Load(string filename)
        {
            var configText = File.ReadAllText(filename);
            return JsonConvert.DeserializeObject<Config>(configText);
        }
    }

    public class Logger
    {
        private readonly string _logFile;
        private readonly LogLevel _logLevel;
        private readonly object _lock = new();

        public Logger(string logFile, LogLevel logLevel)
        {
            _logFile = logFile;
            _logLevel = logLevel;
        }

        public void Log(LogLevel severity, string message)
        {
            if (severity < _logLevel) return;

            lock (_lock)
            {
                var logEntry = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} [{severity}] {message}";
                File.AppendAllText(_logFile, logEntry + Environment.NewLine);
                Console.WriteLine(logEntry);
            }
        }
    }

    public class Message
    {
        public long ChatId { get; set; }
        public string Text { get; set; }
        public string Username { get; set; }
        public long MessageId { get; set; }
    }

    public static class Encryptor
    {
        private const int KeySize = 256;
        private const int BlockSize = 128;

        public static string Encrypt(string plainText, string key)
        {
            using var aes = Aes.Create();
            aes.KeySize = KeySize;
            aes.BlockSize = BlockSize;
            aes.GenerateIV();

            var iv = aes.IV;
            aes.Key = Encoding.UTF8.GetBytes(key);

            using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
            using var ms = new MemoryStream();
            using var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);
            using var sw = new StreamWriter(cs);
            sw.Write(plainText);

            var cipherText = ms.ToArray();
            var result = new byte[iv.Length + cipherText.Length];
            Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
            Buffer.BlockCopy(cipherText, 0, result, iv.Length, cipherText.Length);
            return Convert.ToBase64String(result);
        }

        public static string Decrypt(string cipherText, string key)
        {
            var fullCipher = Convert.FromBase64String(cipherText);
            using var aes = Aes.Create();
            aes.KeySize = KeySize;
            aes.BlockSize = BlockSize;

            var iv = new byte[aes.BlockSize / 8];
            var cipher = new byte[fullCipher.Length - iv.Length];

            Buffer.BlockCopy(fullCipher, 0, iv, 0, iv.Length);
            Buffer.BlockCopy(fullCipher, iv.Length, cipher, 0, cipher.Length);

            aes.Key = Encoding.UTF8.GetBytes(key);
            aes.IV = iv;

            using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
            using var ms = new MemoryStream(cipher);
            using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
            using var sr = new StreamReader(cs);
            return sr.ReadToEnd();
        }
    }

    public class TelegramBot
    {
        private readonly string _botToken;
        private readonly HttpClient _httpClient;
        private readonly Logger _logger;

        private readonly Dictionary<string, Action<Message>> _commandCallbacks = new();
        private Action<Message> _onAnyMessageCallback;

        public TelegramBot(string encryptedBotToken, string encryptionKey, Logger logger)
        {
            _botToken = Encryptor.Decrypt(encryptedBotToken, encryptionKey);
            _httpClient = new HttpClient();
            _logger = logger;
        }

        public async Task SendMessageAsync(long chatId, string message)
        {
            var url = $"https://api.telegram.org/bot{_botToken}/sendMessage";
            var payload = new Dictionary<string, string>
            {
                {"chat_id", chatId.ToString()},
                {"text", message}
            };

            try
            {
                var response = await _httpClient.PostAsync(url, new FormUrlEncodedContent(payload));
                response.EnsureSuccessStatusCode();
            }
            catch (Exception ex)
            {
                _logger.Log(LogLevel.ERROR, $"Failed to send message: {ex.Message}");
                throw;
            }
        }

        public async Task StartAsync()
        {
            while (true)
            {
                await PollUpdatesAsync();
                await Task.Delay(1000);
            }
        }

        public void Stop()
        {
            _httpClient.Dispose();
        }

        public void OnAnyMessage(Action<Message> callback)
        {
            _onAnyMessageCallback = callback;
        }

        public void OnCommand(string command, Action<Message> callback)
        {
            _commandCallbacks[command] = callback;
        }

        private async Task PollUpdatesAsync()
        {
            var url = $"https://api.telegram.org/bot{_botToken}/getUpdates";
            try
            {
                var response = await _httpClient.GetStringAsync(url);
                var updates = JToken.Parse(response)["result"];
                foreach (var update in updates)
                {
                    var message = new Message
                    {
                        ChatId = update["message"]["chat"]["id"].Value<long>(),
                        Text = update["message"]["text"].Value<string>(),
                        Username = update["message"]["from"]["username"].Value<string>(),
                        MessageId = update["message"]["message_id"].Value<long>()
                    };

                    HandleMessage(message);
                }
            }
            catch (Exception ex)
            {
                _logger.Log(LogLevel.ERROR, $"Polling failed: {ex.Message}");
            }
        }

        private void HandleMessage(Message message)
        {
            if (!string.IsNullOrEmpty(message.Text) && message.Text.StartsWith("/"))
            {
                var command = message.Text.Split(' ')[0].Substring(1);
                if (_commandCallbacks.TryGetValue(command, out var callback))
                {
                    callback(message);
                }
            }
            else
            {
                _onAnyMessageCallback?.Invoke(message);
            }
        }
    }

    public class BotManager
    {
        private readonly TelegramBot _bot;
        private Config _config;
        private readonly Logger _logger;

        private readonly List<Task> _workers = new();
        private readonly Queue<Message> _messageQueue = new();
        private readonly HashSet<long> _processedMessages = new();
        private readonly object _queueLock = new();
        private readonly object _processedLock = new();
        private bool _running;

        public BotManager(TelegramBot bot, Config config, Logger logger)
        {
            _bot = bot;
            _config = config;
            _logger = logger;

            _bot.OnAnyMessage(EnqueueMessage);
            _bot.OnCommand("update_config", UpdateConfig);
        }

        public async Task RunAsync()
        {
            _running = true;

            for (int i = 0; i < _config.WorkerThreads; i++)
            {
                _workers.Add(Task.Run(ProcessQueueAsync));
            }

            await _bot.StartAsync();
        }

        public void Stop()
        {
            _running = false;
            _bot.Stop();
        }

        private void EnqueueMessage(Message message)
        {
            lock (_queueLock)
            {
                if (_messageQueue.Count < _config.MessageQueueSize)
                {
                    _messageQueue.Enqueue(message);
                }
                else
                {
                    _logger.Log(LogLevel.WARNING, "Message queue is full, message skipped");
                }
            }
        }

        private async Task ProcessQueueAsync()
        {
            while (_running)
            {
                Message message = null;
                lock (_queueLock)
                {
                    if (_messageQueue.Any())
                    {
                        message = _messageQueue.Dequeue();
                    }
                }

                if (message != null)
                {
                    await ProcessMessageAsync(message);
                }

                await Task.Delay(100); // Adjust delay as needed
            }
        }

        private async Task ProcessMessageAsync(Message message)
        {
            lock (_processedLock)
            {
                if (_processedMessages.Contains(message.MessageId)) return;
                _processedMessages.Add(message.MessageId);
                if (_processedMessages.Count > _config.MaxProcessedMessages)
                {
                    _processedMessages.Remove(_processedMessages.First());
                }
            }

            foreach (var (word, pattern) in _config.Keywords)
            {
                if (Regex.IsMatch(message.Text, pattern, RegexOptions.IgnoreCase))
                {
                    _logger.Log(LogLevel.INFO, $"Keyword '{word}' found in message from @{message.Username}");
                    var response = GenerateAutoResponse(word);
                    await _bot.SendMessageAsync(message.ChatId, response);
                    break;
                }
            }
        }

        private async void UpdateConfig(Message message)
        {
            if (_config.AdminChatIds.Contains(message.ChatId))
            {
                try
                {
                    _config = Config.Load("config.json");
                    _logger.Log(LogLevel.INFO, "Configuration updated");
                    await _bot.SendMessageAsync(message.ChatId, "Configuration updated");
                }
                catch (Exception ex)
                {
                    _logger.Log(LogLevel.ERROR, $"Failed to update config: {ex.Message}");
                    await _bot.SendMessageAsync(message.ChatId, "Failed to update configuration");
                }
            }
            else
            {
                await _bot.SendMessageAsync(message.ChatId, "You don't have permission to update the configuration");
            }
        }

        private string GenerateAutoResponse(string keyword)
        {
            var responses = new[]
            {
                $"Interesting mention of {keyword}! Can you tell more about it?",
                $"I see you're talking about {keyword}. That's a very important topic!",
                $"{keyword} is a great topic for discussion. Do you have any specific thoughts on it?",
                $"Oh, {keyword}! I'm always glad to hear opinions on this matter.",
                $"Thanks for bringing up {keyword}. Let's discuss it in more detail!"
            };

            var rand = new Random();
            return responses[rand.Next(responses.Length)];
        }
    }

    class Program
    {
        static async Task Main(string[] args)
        {
            try
            {
                var config = Config.Load("config.json");
                if(config == null)
                    throw new Exception("Failed to load configuration");
                string encryptionKey = GetEncryptionKeyFromEnv();

                var logger = new Logger(config.LogFile, config.LogLevel);
                var bot = new TelegramBot(config.EncryptedBotToken, encryptionKey, logger);
                var botManager = new BotManager(bot, config, logger);

                Console.CancelKeyPress += (sender, e) => botManager.Stop();

                await botManager.RunAsync();

                logger.Log(LogLevel.INFO, "Bot stopped.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        static string GetEncryptionKeyFromEnv()
        {
            var key = Environment.GetEnvironmentVariable("BOT_ENCRYPTION_KEY");
            if (key == null)
                throw new Exception("Environment variable BOT_ENCRYPTION_KEY is not set");
            return key;
        }
    }
}