# IP Address Analysis Tool

This tool allows you to analyze the IP addresses connected to a specific process and check if they are listed as suspicious in the "malicious_ip.txt" file.

## Usage

1. **Prerequisites**

   - Visual Studio Community 2022 (or compatible C++ compiler)
   - Winsock2 library
   - Windows API

2. **Installation**

   - Clone or download this repository.

3. **Build**

   - Open the project in Visual Studio Community 2022.
   - Build the project to generate the executable file.

4. **Execution**

   - Open a command prompt or terminal.
   - Navigate to the directory where the executable file is located.
   - Run the tool with the following command: `pmic.exe <process_name>`
     - Replace `<process_name>` with the name of the process you want to analyze.

5. **Output**

   - The tool will display the IP addresses connected to the specified process.
   - It will compare these IP addresses with the ones listed in the "malicious_ip.txt" file.
   - If a match is found, it will be recorded in the "matched_ip.txt" file.

## Contributing

Contributions are welcome! If you find any issues or have suggestions for improvement, please feel free to open an issue or submit a pull request.