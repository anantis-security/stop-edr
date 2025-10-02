# StopEDR

## ⚠️ IMPORTANT DISCLAIMER

**This tool is provided as-is without any warranties. Users are responsible for any consequences of using this tool. Always test in a controlled environment first and ensure you have a way to recover access if needed.**

**WARNING: It can potentially crash your computer or make it unresponsive. Use at your own risk.**

## Description

StopEDR temporarily suspends Windows processes by leveraging WerFaultSecure.exe to create a controlled suspension state. The technique works by:

1. Creating a Protected Process Light (PPL) WerFaultSecure.exe process
2. WerFaultSecure automatically suspends the target process for debugging purposes
3. The tool then suspends WerFaultSecure itself to maintain the target in a frozen state
4. After a specified duration, WerFaultSecure is resumed, allowing the target process to continue

## How It Works

### Technical Overview

StopEDR exploits Windows' error reporting mechanism:

1. **Privilege Escalation**: Enables SeDebugPrivilege using RtlAdjustPrivilege
2. **Thread Discovery**: Locates the primary thread of the target process
3. **Handle Creation**: Creates inheritable file and event handles required by WerFaultSecure
4. **PPL Process Creation**: Launches WerFaultSecure.exe as a Protected Process Light with WinTCB protection level
5. **Suspension Chain**:
   - WerFaultSecure suspends the target process
   - Tool suspends WerFaultSecure to maintain the freeze
6. **Recovery**: Resumes WerFaultSecure to automatically restore the target process

### Command Line Usage

```bash
# Suspend process with PID 1234 for 10 seconds (10000ms)
stop_edr.exe --pid 1234 --sleep-ms 10000

# Suspend process with PID 5678 for 30 seconds
stop_edr.exe -p 5678 -s 30000
```

### Parameters

- `--pid, -p`: Target process ID to suspend (required)
- `--sleep-ms, -s`: Duration to keep the process suspended in milliseconds (default: 10000)

## Building

```bash
# Debug build
cargo build

# Release build (optimized)
cargo build --release
```

## Educational Purpose

This implementation serves as a learning resource for understanding:

- Windows process architecture and protection mechanisms
- Protected Process Light (PPL) creation and management
- System-level debugging and error reporting mechanisms
- Low-level Windows API interactions from Rust

## Limitations

- Requires administrator privileges
- Only works on Windows systems

### EDR Process Creation Hooks

Some advanced EDR solutions implement hooks on process creation APIs that prevent new process execution until the EDR validates the process. In these specific cases, it may not be possible to create new processes while the antivirus is stopped.

However, this limitation does not prevent an attacker from executing malicious payloads. 

An attacker could still launch ransomware or other malicious payloads from a thread within the stop_edr process itself, or inject into any other running process on the system using well-known injection techniques.

## Responsible Usage

This tool is intended for:

- Security research and education
- Penetration testing in authorized environments
- Understanding Windows internals
- Developing defensive security measures

**Do not use this tool for malicious purposes or against systems you do not own or have explicit permission to test.**

## Credits

Original research and technique discovery: [TwoSevenOneT](https://github.com/TwoSevenOneT)

## Author

Theo Turletti

## License

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
