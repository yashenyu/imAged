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
            // Generate session key
            _sessionKey = GenerateSecureRandomKey(32);
            System.Diagnostics.Debug.WriteLine($"Generated session key: {_sessionKey.Length} bytes");

            // Create handshake
            var handshake = CreateHandshake(_sessionKey);
            System.Diagnostics.Debug.WriteLine($"Handshake size: {handshake.Length} bytes");

            await _inputStream.WriteLineAsync(Convert.ToBase64String(handshake));

            // Wait for confirmation
            var confirmation = await _outputStream.ReadLineAsync();
            if (string.IsNullOrEmpty(confirmation))
            {
                throw new SecurityException("No confirmation received from Python backend");
            }

            System.Diagnostics.Debug.WriteLine($"Received confirmation: {confirmation.Length} chars");

            var confirmationData = Convert.FromBase64String(confirmation);
            if (!ValidateChannelConfirmation(confirmationData))
            {
                throw new SecurityException("Invalid channel confirmation");
            }

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

            // Read response with timeout
            System.Diagnostics.Debug.WriteLine("Waiting for response from Python...");

            // Use a timeout to prevent hanging
            var response = await Task.Run(async () =>
            {
                var timeout = Task.Delay(5000); // 5 second timeout
                var readTask = _outputStream.ReadLineAsync();

                var completedTask = await Task.WhenAny(readTask, timeout);
                if (completedTask == timeout)
                {
                    throw new TimeoutException("Timeout waiting for Python response");
                }

                return await readTask;
            });

            if (string.IsNullOrEmpty(response))
            {
                throw new Exception("No response received from Python backend");
            }

            System.Diagnostics.Debug.WriteLine($"Received response: {response.Length} chars");

            var responseData = Convert.FromBase64String(response);
            var decryptedResponse = DecryptData(responseData);
            var responseJson = Encoding.UTF8.GetString(decryptedResponse);

            System.Diagnostics.Debug.WriteLine($"Response JSON: {responseJson}");

            return System.Text.Json.JsonSerializer.Deserialize<SecureResponse>(responseJson);
        }

        private byte[] EncryptData(byte[] data)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = _sessionKey;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                // Generate random IV
                aes.GenerateIV();

                using (var encryptor = aes.CreateEncryptor())
                {
                    var encrypted = encryptor.TransformFinalBlock(data, 0, data.Length);

                    // Return IV + encrypted data (Python expects this format)
                    var result = new byte[aes.IV.Length + encrypted.Length];
                    Array.Copy(aes.IV, 0, result, 0, aes.IV.Length);
                    Array.Copy(encrypted, 0, result, aes.IV.Length, encrypted.Length);

                    return result;
                }
            }
        }

        private byte[] DecryptData(byte[] encryptedData)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = _sessionKey;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                // Extract IV (first 16 bytes)
                var iv = new byte[16];
                var ciphertext = new byte[encryptedData.Length - 16];
                Array.Copy(encryptedData, 0, iv, 0, 16);
                Array.Copy(encryptedData, 16, ciphertext, 0, ciphertext.Length);

                aes.IV = iv;

                using (var decryptor = aes.CreateDecryptor())
                {
                    return decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
                }
            }
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