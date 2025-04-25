
---

# PhantomHash: Password Strength Analyzer

_PhantomHash_ is a robust password analysis tool designed to evaluate the strength and vulnerability of passwords. By leveraging entropy calculations, substring frequency analysis, and multi-threading, this tool helps users identify weak passwords and provides actionable recommendations for improvement.

---

## Table of Contents

1. [Features](#features)
2. [Installation](#installation)
3. [Usage](#usage)
4. [How It Works](#how-it-works)
5. [Contributing](#contributing)
6. [License](#license)

---

## Features

- **Password Entropy Calculation**: Measures the unpredictability of passwords using Shannon entropy.
- **Substring and Word Analysis**: Identifies common substrings and words in passwords, comparing them against a dictionary of known weak passwords.
- **Password Similarity Detection**: Detects highly similar passwords using Jaccard similarity and multi-threading.
- **Multi-Threading**: Optimizes performance by processing large datasets in parallel.
- **Caching Mechanism**: Reduces redundant computations by caching results for faster analysis.
- **User-Friendly Output**: Provides clear feedback on password weaknesses and actionable recommendations.
- **Secure Input Handling**: Ensures passwords are not displayed or saved during input.

---

## Installation

### Prerequisites

- Ruby 2.7 or higher
- Required libraries: `set`, `thread`, `csv`, `yaml`, `etc`

### Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/cilliapwndev/PhantomHash.git
   cd PhantomHash
   ```

2. Install dependencies (if any):
   - Ensure Ruby is installed on your system.
   - No additional gems are required as the script uses standard libraries.

3. Prepare the dictionary files:
   - Place your password dictionary files (e.g., `Ashley-Madison.txt`, `000webhost.txt`, `NordVPN.txt`) in the `dictionary/` folder.

4. Run the script:
   ```bash
   ruby PhantomHash.rb
   ```

---

## Usage

1. Launch the program:
   ```bash
   ruby PhantomHash.rb
   ```

2. Follow the prompts:
   - The program will load cached data (if available) or generate it from the dictionary files.
   - When prompted, enter your password securely. The input will not be echoed or saved.

3. View the analysis:
   - The program will display:
     - Entropy score and strength classification.
     - Detected weaknesses (e.g., missing character groups, repeated characters).
     - Substring and word matches against the dictionary.
     - Recommendations for improving your password.

4. Test additional passwords:
   - After the initial analysis, you can choose to test another password by entering `y`.

---

## How It Works

### Key Components

1. **Entropy Calculation**:
   - Measures the unpredictability of a password based on character frequency.
   - Higher entropy indicates stronger passwords.

2. **Substring and Word Frequency Analysis**:
   - Extracts common substrings and whole words from dictionary passwords.
   - Compares user-submitted passwords against these patterns to detect vulnerabilities.

3. **Password Similarity Detection**:
   - Uses Jaccard similarity to identify highly similar passwords.
   - Multi-threading ensures efficient processing of large datasets.

4. **Caching**:
   - Stores entropy calculations, common substrings, and words in a YAML file (`cache.yaml`) to avoid redundant computations.

5. **Secure Input Handling**:
   - Disables terminal echoing during password input to ensure privacy.

---

## Example Output

```
=== PhantomHash Password Analyzer ===

⠀⠀⠀⠀⠀⢀⣴⣿⣿⣿⣦⠀
⠀⠀⠀⠀⣰⣿⡟⢻⣿⡟⢻⣧
⠀⠀⠀⣰⣿⣿⣇⣸⣿⣇⣸⣿
⠀⠀⣴⣿⣿⣿⣿⠟⢻⣿⣿⣿
⣠⣾⣿⣿⣿⣿⣿⣤⣼⣿⣿⠇
⢿⡿⢿⣿⣿⣿⣿⣿⣿⣿⡿⠀
⠀⠀⠀⠀⠈⠿⠿⠋⠙⢿⣿⡿⠁⠀

Checking cache...
Loading data from cache...

Enter your password (your input will not be saved):

=== Your Password Analysis ===
- Entropy: 64.0 bits
- Strength (Threshold-Based): Moderate
- Weaknesses:
  - No special characters
✅ GOOD NEWS: Your password is not found in the dictionary. It is less likely to be guessed.

=== Password Improvement Recommendations ===
- Use a password with at least 12 characters.
- Include a mix of uppercase, lowercase, digits, and special characters.
- Avoid reusing passwords across multiple accounts.
- Consider using a password manager to generate and store strong passwords.
```

---

## Contributing

We welcome contributions to improve _PhantomHash_! Here’s how you can help:

1. **Bug Reports**: If you encounter any issues, please open an issue on GitHub with detailed steps to reproduce the problem.
2. **Feature Requests**: Suggest new features or improvements by opening an issue.
3. **Code Contributions**: Fork the repository, make your changes, and submit a pull request. Ensure your code adheres to Ruby best practices.

---

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE). Feel free to use, modify, and distribute it as long as you comply with the terms of the license.

---

## Acknowledgments

- Inspired by the need for better password security practices.
- Dictionary files sourced from publicly available password breach datasets.

---

Thank you for using _PhantomHash_! We hope it helps you create stronger, more secure passwords. If you find this project useful, please consider starring the repository and sharing it with others.
