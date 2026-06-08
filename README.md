🔍 Fuzzionyx

Fuzzionyx is a lightweight yet powerful web fuzzing tool designed for directory and file discovery. Built in Go, it combines performance with simplicity, making it ideal for penetration testing, bug bounty automation, and security assessments.

✨ Features
- Configurable thread pool for high-speed scanning
- Automatically discovers nested directories up to user-defined depth
- Test multiple file extensions
- Show only responses that matter
- Instant visual feedback with box-drawing UI
- Track scan status, requests per second, and findings
- Save discovered URLs to a text file
- Add authentication tokens, cookies, or custom headers
- Configurable delay between requests to avoid overwhelming targets
- Suppress progress bar for clean automation logs

🚀 Installation

git clone https://github.com/yourusername/fuzzionyx.git
cd fuzzionyx
go build -o fuzzionyx fuzzer.go
