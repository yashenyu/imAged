using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ImAged.Services
{
    public class SecureProcessManager : IDisposable
    {
        private Process _pythonProcess;
        private StreamWriter _inputStream;
        private StreamReader _outputStream;
        private byte[] _sessionKey;
        private bool _isInitialized = false;
        private bool _disposed = false;

        public byte[] SessionKey => _sessionKey;

        private const int MaxMetaBase64Chars = 1 * 1024 * 1024;      // 1 MB line cap for metadata
        private const int MaxPayloadBase64Chars = 40 * 1024 * 1024;  // 40 MB line cap for payload

        public async Task InitializeAsync()
        {
            if (_isInitialized) return;

            // Get the correct path to the Python script
            var projectDir = Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..\\..\\.."));
            var pythonScriptPath = Path.Combine(projectDir, "ImAged", "pysrc", "secure_backend.py");

            // Start Python process
            var startInfo = new ProcessStartInfo
            {
                FileName = "python",
                Arguments = $"\"{pythonScriptPath}\"",
                UseShellExecute = false,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                WorkingDirectory = projectDir
            };

            _pythonProcess = Process.Start(startInfo);
            _inputStream = _pythonProcess.StandardInput;
            _outputStream = _pythonProcess.StandardOutput;

            // Add error monitoring
            _pythonProcess.ErrorDataReceived += (sender, e) =>
            {
                if (!string.IsNullOrEmpty(e.Data))
                {
                    System.Diagnostics.Debug.WriteLine($"Python Error: {e.Data}");
                }
            };
            _pythonProcess.BeginErrorReadLine();

            // Check if process started successfully
            if (_pythonProcess.HasExited)
            {
                throw new Exception("Python process failed to start");
            }

            // Establish secure channel
            await EstablishSecureChannelAsync();
            _isInitialized = true;
        }

        private async Task EstablishSecureChannelAsync()
        {
            // 1. Read Python public key (base64 PEM)
            string publicKeyBase64 = await _outputStream.ReadLineAsync();
            if (string.IsNullOrEmpty(publicKeyBase64))
                throw new SecurityException("No public key received from Python backend");
            byte[] publicKeyPem = Convert.FromBase64String(publicKeyBase64);

            // 2. Load public key
            using var rsa = RSA.Create();
            rsa.ImportFromPem(Encoding.UTF8.GetString(publicKeyPem));

            // 3. Generate session key
            _sessionKey = GenerateSecureRandomKey(32);
            System.Diagnostics.Debug.WriteLine($"Generated session key: {_sessionKey.Length} bytes");

            // 4. Encrypt session key with RSA
            byte[] encSessionKey = rsa.Encrypt(_sessionKey, RSAEncryptionPadding.OaepSHA256);

            // 5. Send encrypted session key (base64) to Python
            await _inputStream.WriteLineAsync(Convert.ToBase64String(encSessionKey));
            await _inputStream.FlushAsync();

            // 6. Wait for confirmation
            var confirmation = await _outputStream.ReadLineAsync();
            if (string.IsNullOrEmpty(confirmation))
                throw new SecurityException("No confirmation received from Python backend");
            System.Diagnostics.Debug.WriteLine($"Received confirmation: {confirmation.Length} chars");
            var confirmationData = Convert.FromBase64String(confirmation);
            if (!ValidateChannelConfirmation(confirmationData))
                throw new SecurityException("Invalid channel confirmation");
            System.Diagnostics.Debug.WriteLine("Secure channel established successfully");
        }

        private byte[] GenerateSecureRandomKey(int length)
        {
            var key = new byte[length];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(key);
            }
            return key;
        }

        private byte[] CreateHandshake(byte[] sessionKey)
        {
            // Fix: Use big-endian (network byte order) for consistency with Python
            var lengthBytes = BitConverter.GetBytes(sessionKey.Length);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(lengthBytes);
            }

            var handshake = new byte[4 + sessionKey.Length];
            Array.Copy(lengthBytes, 0, handshake, 0, 4);
            Array.Copy(sessionKey, 0, handshake, 4, sessionKey.Length);

            return handshake;
        }

        private bool ValidateChannelConfirmation(byte[] confirmationData)
        {
            try
            {
                // Decrypt confirmation
                var decrypted = DecryptData(confirmationData);
                var message = Encoding.UTF8.GetString(decrypted);
                return message == "CHANNEL_ESTABLISHED";
            }
            catch
            {
                return false;
            }
        }

        public async Task<SecureResponse> SendCommandAsync(SecureCommand command)
        {
            if (!_isInitialized)
                throw new InvalidOperationException("SecureProcessManager not initialized");

            // Serialize and encrypt command
            var commandJson = System.Text.Json.JsonSerializer.Serialize(command);
            var commandBytes = Encoding.UTF8.GetBytes(commandJson);
            var encryptedCommand = EncryptData(commandBytes);

            // Create payload
            var lengthBytes = BitConverter.GetBytes(encryptedCommand.Length);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(lengthBytes);

            var payload = new byte[4 + encryptedCommand.Length];
            Array.Copy(lengthBytes, 0, payload, 0, 4);
            Array.Copy(encryptedCommand, 0, payload, 4, encryptedCommand.Length);

            // Send command
            await _inputStream.WriteLineAsync(Convert.ToBase64String(payload));

            // Read first response line (metadata), then optionally a second line (payload)
            System.Diagnostics.Debug.WriteLine("Waiting for response from Python...");

            var metaLine = await Task.Run(async () =>
            {
                var timeout = Task.Delay(30000); // 30 second timeout
                var readTask = _outputStream.ReadLineAsync();
                var completedTask = await Task.WhenAny(readTask, timeout);
                if (completedTask == timeout) throw new TimeoutException("Timeout waiting for Python response (meta)");
                return await readTask;
            });

            if (string.IsNullOrEmpty(metaLine)) throw new Exception("No response received from Python backend");

            if (metaLine.Length > MaxMetaBase64Chars) throw new Exception("Response meta too large");
            var metaData = Convert.FromBase64String(metaLine);
            var metaJson = Encoding.UTF8.GetString(DecryptData(metaData));
            var meta = System.Text.Json.JsonSerializer.Deserialize<SecureResponse>(metaJson);

            // If there is an encrypted payload, read it on the next line
            if (meta != null && meta.Success && meta is { Result: not null })
            {
                var resultDict = meta.Result as System.Text.Json.Nodes.JsonObject;
                bool hasPayload = false;
                if (resultDict == null)
                {
                    // try generic parsing
                    var doc = System.Text.Json.JsonDocument.Parse(metaJson);
                    if (doc.RootElement.TryGetProperty("has_payload", out var hp) && hp.GetBoolean())
                    {
                        hasPayload = true;
                    }
                }
                else if (resultDict.ContainsKey("has_payload"))
                {
                    hasPayload = (bool)resultDict["has_payload"];
                }

                if (hasPayload)
                {
                    var payloadLine = await Task.Run(async () =>
                    {
                        var timeout = Task.Delay(30000);
                        var readTask = _outputStream.ReadLineAsync();
                        var completedTask = await Task.WhenAny(readTask, timeout);
                        if (completedTask == timeout) throw new TimeoutException("Timeout waiting for Python response (payload)");
                        return await readTask;
                    });

                    if (string.IsNullOrEmpty(payloadLine)) throw new Exception("No payload received from Python backend");
                    if (payloadLine.Length > MaxPayloadBase64Chars) throw new Exception("Response payload too large");
                    var encPayload = Convert.FromBase64String(payloadLine);
                    var pngBytes = DecryptData(encPayload);

                    // embed payload back into result for the caller
                    meta.Result = new Dictionary<string, object>
                    {
                        { "mime", "image/png" },
                        { "size", pngBytes.Length },
                        { "image_data_bytes", pngBytes }
                    };
                }
            }

            return meta;
        }

        private byte[] EncryptData(byte[] plaintext) {
            byte[] nonce = RandomNumberGenerator.GetBytes(12);
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[16];
            using var aesgcm = new AesGcm(_sessionKey);
            aesgcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData: null);
            // pack as nonce|ciphertext|tag
            var result = new byte[12 + ciphertext.Length + 16];
            Buffer.BlockCopy(nonce, 0, result, 0, 12);
            Buffer.BlockCopy(ciphertext, 0, result, 12, ciphertext.Length);
            Buffer.BlockCopy(tag, 0, result, 12 + ciphertext.Length, 16);
            return result;
        }

        private byte[] DecryptData(byte[] enc) {
            var nonce = new byte[12];
            var tag = new byte[16];
            var ciphertext = new byte[enc.Length - 12 - 16];
            Buffer.BlockCopy(enc, 0, nonce, 0, 12);
            Buffer.BlockCopy(enc, 12, ciphertext, 0, ciphertext.Length);
            Buffer.BlockCopy(enc, 12 + ciphertext.Length, tag, 0, 16);
            var plaintext = new byte[ciphertext.Length];
            using var aesgcm = new AesGcm(_sessionKey);
            aesgcm.Decrypt(nonce, ciphertext, tag, plaintext, associatedData: null);
            return plaintext;
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                try
                {
                    // Check if process is still running before trying to kill it
                    if (_pythonProcess != null && !_pythonProcess.HasExited)
                    {
                        _pythonProcess.Kill();
                    }
                }
                catch (InvalidOperationException)
                {
                    // Process has already exited, ignore the exception
                }
                catch (Exception ex)
                {
                    // Log other exceptions if needed
                    System.Diagnostics.Debug.WriteLine($"Error killing Python process: {ex.Message}");
                }
                finally
                {
                    try { if (_sessionKey != null) System.Security.Cryptography.CryptographicOperations.ZeroMemory(_sessionKey); } catch { }
                    _sessionKey = null;
                    _pythonProcess?.Dispose();
                    _inputStream?.Dispose();
                    _outputStream?.Dispose();
                    _disposed = true;
                }
            }
        }
    }

    public class SecureCommand
    {
        public string Command { get; set; }
        public Dictionary<string, object> Parameters { get; set; }

        public SecureCommand(string command, Dictionary<string, object> parameters = null)
        {
            Command = command;
            Parameters = parameters ?? new Dictionary<string, object>();
        }
    }

    public class SecureResponse
    {
        [System.Text.Json.Serialization.JsonPropertyName("success")]
        public bool Success { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("result")]
        public object Result { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("error")]
        public string Error { get; set; }
    }
}