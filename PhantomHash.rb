require 'set'
require 'thread'
require 'csv'
require 'yaml'

# Configuration
ENTROPY_THRESHOLDS = {
  'Very Weak' => 0,
  'Weak' => 40,
  'Moderate' => 72,
  'Strong' => 128,
  'Very Strong' => 256
}

# Cache for entropy calculations and other data
CACHE_FILE = 'cache.yaml'
CACHE = {}

# Main Program
def main
  puts "\n=== PhantomHash Password Analyzer ==="
  print_ghost_ascii_art

  # Load or generate cache
  puts "Checking cache..."
  if File.exist?(CACHE_FILE)
    puts "Loading data from cache..."
    CACHE.merge!(YAML.load_file(CACHE_FILE))
  else
    puts "Generating cache... This may take a while."
    generate_cache
    File.write(CACHE_FILE, CACHE.to_yaml)
    puts "Cache generated and saved to '#{CACHE_FILE}'."
  end

  # Load passwords from dictionary files
  puts "\nLoading dictionary passwords..."
  passwords_rockyou = load_passwords('dictionary/Ashley-Madison.txt')
  passwords_000webhost = load_passwords('dictionary/000webhost.txt')
  passwords_nordvpn = load_passwords('dictionary/NordVPN.txt')

  # Combine the datasets
  passwords = passwords_rockyou + passwords_000webhost + passwords_nordvpn

  # Preprocess passwords
  puts "Preprocessing passwords..."
  common_passwords = preprocess_passwords(passwords)

  # Perform frequency analysis on passwords using multi-threading
  puts "Extracting common substrings and whole words..."
  global_substrings, global_words = extract_common_substrings_and_words_with_threads(passwords)

  # Prompt user to test their password
  loop do
    check_user_password_vulnerability(common_passwords, global_substrings, global_words)

    print "\nWould you like to test another password? (y/n): "
    response = gets.chomp.downcase
    break unless response == 'y'
  end

  puts "\nThank you for using PhantomHash!"
end

# Print Static Ghost ASCII Art
def print_ghost_ascii_art
  puts <<~GHOST
    ⠀⠀⠀⠀⠀⢀⣴⣿⣿⣿⣦⠀
    ⠀⠀⠀⠀⣰⣿⡟⢻⣿⡟⢻⣧
    ⠀⠀⠀⣰⣿⣿⣇⣸⣿⣇⣸⣿
    ⠀⠀⣴⣿⣿⣿⣿⠟⢻⣿⣿⣿
    ⣠⣾⣿⣿⣿⣿⣿⣤⣼⣿⣿⠇
    ⢿⡿⢿⣿⣿⣿⣿⣿⣿⣿⡿⠀
    ⠀⠀⠀⠈⠿⠿⠋⠙⢿⣿⡿⠁⠀
  GHOST
end

# Step 1: Load Passwords
def load_passwords(file)
  File.readlines(file).map(&:chomp).reject(&:empty?) # Skip empty lines
rescue Errno::ENOENT
  puts "Could not open file '#{file}'"
  []
end

# Step 2: Preprocess Passwords into a Set for Fast Lookup
def preprocess_passwords(passwords)
  passwords.each_with_object(Set.new) do |password, set|
    next if password.nil? || password.strip.empty? # Skip empty or nil passwords
    set.add(password.strip)
  end
end

# Step 3: Generate Cache
def generate_cache
  # Load passwords
  passwords_rockyou = load_passwords('dictionary/Ashley-Madison.txt')
  passwords_000webhost = load_passwords('dictionary/000webhost.txt')
  passwords_nordvpn = load_passwords('dictionary/NordVPN.txt')
  passwords = passwords_rockyou + passwords_000webhost + passwords_nordvpn

  # Calculate entropy for all passwords and store in cache
  puts "Caching entropy calculations..."
  passwords.each do |password|
    CACHE[password] = calculate_entropy(password) unless CACHE.key?(password)
  end

  # Extract common substrings and whole words and store in cache
  puts "Caching common substrings and whole words..."
  substrings, words = extract_common_substrings_and_words(passwords)
  CACHE['common_substrings'] = substrings
  CACHE['common_words'] = words
end

# Step 4: Calculate Entropy with Caching
def calculate_entropy_with_cache(password)
  return CACHE[password] if CACHE.key?(password)

  entropy = calculate_entropy(password)
  CACHE[password] = entropy
  entropy
end

# Step 5: Calculate Entropy
def calculate_entropy(password)
  char_freq = Hash.new(0)
  total_chars = password.length.to_f

  # Count character frequencies
  password.chars.each { |char| char_freq[char] += 1 }

  # Calculate entropy
  entropy = 0
  char_freq.each_value do |freq|
    probability = freq / total_chars
    entropy -= probability * Math.log2(probability) if probability > 0 # Avoid log(0)
  end

  entropy
end

# Step 6: Extract Common Substrings and Whole Words
def extract_common_substrings_and_words(passwords)
  substring_freq = Hash.new(0)
  word_freq = Hash.new(0)

  passwords.each do |password|
    next if password.empty? # Skip empty passwords

    # Extract substrings of length ≥ 2
    (2..password.length).each do |length|
      password.chars.each_cons(length) do |substring|
        substring_freq[substring.join] += 1
      end
    end

    # Treat the entire password as a "word"
    word_freq[password] += 1
  end

  # Step 12: Analyze Password Similarity Using Multi-Threading
def analyze_password_similarity_with_threads(passwords)
  puts "Analyzing password similarity using multi-threading..."
  
  # Initialize shared data structures
  similar_pairs = Set.new
  mutex = Mutex.new

  # Determine the optimal number of threads (based on CPU cores)
  num_threads = [passwords.size / 1000, Etc.nprocessors].min
  num_threads = 1 if num_threads == 0 # Ensure at least one thread

  # Divide passwords into chunks for parallel processing
  chunks = passwords.each_slice((passwords.size / num_threads.to_f).ceil).to_a

  # Create and start threads
  threads = chunks.map do |chunk|
    Thread.new do
      chunk.each do |password1|
        next if password1.empty? # Skip empty passwords

        # Compare each password with others in the dataset
        passwords.each do |password2|
          next if password2.empty? || password1 == password2 # Skip self-comparison and empty passwords

          # Calculate similarity (e.g., Jaccard similarity for substrings)
          similarity_score = calculate_jaccard_similarity(password1, password2)

          # If similarity exceeds a threshold, record the pair
          if similarity_score > 0.7 # Example threshold (adjust as needed)
            mutex.synchronize do
              similar_pairs.add([password1, password2].sort)
            end
          end
        end
      end
    end
  end

  # Wait for all threads to finish
  threads.each(&:join)

  # Display results
  if similar_pairs.empty?
    puts "✅ GOOD NEWS: No highly similar password pairs were found."
  else
    puts "⚠️ WARNING: The following password pairs are highly similar:"
    similar_pairs.each do |pair|
      puts "- '#{pair[0]}' and '#{pair[1]}'"
    end
  end
end

# Helper Method: Calculate Jaccard Similarity Between Two Passwords
def calculate_jaccard_similarity(password1, password2)
  # Extract substrings of length ≥ 2 from both passwords
  substrings1 = extract_substrings(password1)
  substrings2 = extract_substrings(password2)

  # Calculate Jaccard similarity
  intersection = (substrings1 & substrings2).size
  union = (substrings1 | substrings2).size
  union.zero? ? 0 : intersection.to_f / union
end

# Helper Method: Extract Substrings of Length ≥ 2
def extract_substrings(password)
  substrings = Set.new
  (2..password.length).each do |length|
    password.chars.each_cons(length) { |substring| substrings.add(substring.join) }
  end
  substrings
end

  # Keep only substrings and words that appear more than a threshold (e.g., 100 times)
  common_substrings = substring_freq.select { |_substring, freq| freq > 100 }
  common_words = word_freq.select { |_word, freq| freq > 100 }

  [common_substrings, common_words]
end

# Step 7: Extract Common Substrings and Whole Words Using Multi-Threading
def extract_common_substrings_and_words_with_threads(passwords)
  if CACHE.key?('common_substrings') && CACHE.key?('common_words')
    puts "Loading common substrings and whole words from cache..."
    return CACHE['common_substrings'], CACHE['common_words']
  end

  substring_freq = Hash.new(0)
  word_freq = Hash.new(0)
  mutex = Mutex.new

  # Determine the optimal number of threads (based on CPU cores)
  num_threads = [passwords.size / 1000, Etc.nprocessors].min
  num_threads = 1 if num_threads == 0 # Ensure at least one thread

  # Divide passwords into chunks for parallel processing
  chunks = passwords.each_slice((passwords.size / num_threads.to_f).ceil).to_a

  # Create and start threads
  threads = chunks.map do |chunk|
    Thread.new do
      chunk.each do |password|
        next if password.empty? # Skip empty passwords

        # Extract substrings of length ≥ 3
        (3..password.length).each do |length|
          password.chars.each_cons(length) do |substring|
            mutex.synchronize do
              substring_freq[substring.join] += 1
            end
          end
        end

        # Treat the entire password as a "word"
        mutex.synchronize do
          word_freq[password] += 1
        end
      end
    end
  end

  # Wait for all threads to finish
  threads.each(&:join)

  # Keep only substrings and words that appear more than a threshold (e.g., 100 times)
  common_substrings = substring_freq.select { |_substring, freq| freq > 100 }
  common_words = word_freq.select { |_word, freq| freq > 100 }

  [common_substrings, common_words]
end

# Step 8: Check User Password Vulnerability
def check_user_password_vulnerability(common_passwords, global_substrings, global_words)
  system("clear") || system("cls")
  print "\nEnter your password (your input will not be saved): "
  system("stty -echo") # Disable echoing of input
  user_password = gets.chomp
  system("stty echo") # Re-enable echoing of input
  puts "\n"

  # Analyze user's password
  entropy = calculate_entropy_with_cache(user_password)
  strength = classify_password_strength(entropy)
  weaknesses = analyze_password_patterns(user_password)
  is_common = common_passwords.include?(user_password)

  # Perform user-specific substring and word analysis
  user_substring_and_word_analysis(user_password, global_substrings, global_words)

  # Display results
  display_password_analysis(entropy, strength, weaknesses, is_common)
end

# Step 9: User-Specific Substring and Word Analysis
def user_substring_and_word_analysis(password, global_substrings, global_words)
  puts "\n=== Substring and Word Analysis of Your Password Compared to Dictionary ==="

  # Extract substrings from the user's password
  user_substrings = Set.new
  (2..password.length).each do |length|
    password.chars.each_cons(length) { |substring| user_substrings.add(substring.join) }
  end

  # Compare user's substrings with global dictionary substrings
  matches_dictionary_pattern = false
  user_substrings.each do |substring|
    if global_substrings.key?(substring)
      matches_dictionary_pattern = true
      puts "⚠️ WARNING: The substring '#{substring}' appears frequently in dictionary passwords."
    end
  end

  # Check if the entire password matches a common word
  if global_words.key?(password)
    matches_dictionary_pattern = true
    puts "⚠️ WARNING: Your password '#{password}' is a common word in the dictionary."
  end

  if matches_dictionary_pattern
    puts "⚠️ WARNING: Your password contains substrings or words similar to dictionary entries. It may be vulnerable to pattern-based attacks [[1]]."
  else
    puts "✅ GOOD NEWS: Your password does not contain substrings or words similar to dictionary entries."
  end

  puts "\nUser-specific substring and word analysis completed.\n"
end

# Subroutine to Display Password Analysis
def display_password_analysis(entropy, strength, weaknesses, is_common)
  puts "=== Your Password Analysis ==="
  puts "- Entropy: #{entropy.round(2)} bits"
  puts "- Strength (Threshold-Based): #{strength}"
  if weaknesses.any?
    puts "- Weaknesses:"
    weaknesses.each { |weakness| puts "  - #{weakness}" }
  else
    puts "- No significant weaknesses detected."
  end
  if is_common
    puts "⚠️ WARNING: Your password is found in the dictionary. It is highly vulnerable to attacks [[1]]."
  else
    puts "✅ GOOD NEWS: Your password is not found in the dictionary. It is less likely to be guessed."
  end

  # Provide recommendations
  display_password_recommendations
end

# Subroutine to Display Password Recommendations
def display_password_recommendations
  puts "\n=== Password Improvement Recommendations ==="
  puts "- Use a password with at least 12 characters."
  puts "- Include a mix of uppercase, lowercase, digits, and special characters."
  puts "- Avoid reusing passwords across multiple accounts."
  puts "- Consider using a password manager to generate and store strong passwords."
end

# Step 10: Classify Password Strength
def classify_password_strength(entropy)
  case entropy
  when 0...ENTROPY_THRESHOLDS['Weak']
    'Very Weak'
  when ENTROPY_THRESHOLDS['Weak']...ENTROPY_THRESHOLDS['Moderate']
    'Weak'
  when ENTROPY_THRESHOLDS['Moderate']...ENTROPY_THRESHOLDS['Strong']
    'Moderate'
  when ENTROPY_THRESHOLDS['Strong']...ENTROPY_THRESHOLDS['Very Strong']
    'Strong'
  else
    'Very Strong'
  end
end

# Step 11: Analyze Patterns
def analyze_password_patterns(password)
  weaknesses = []
  # Check for short passwords
  weaknesses << "Too short (less than 8 characters)" if password.length < 8
  # Check for missing character groups
  weaknesses << "No digits" unless password.match?(/\d/)
  weaknesses << "No uppercase letters" unless password.match?(/[A-Z]/)
  weaknesses << "No special characters" unless password.match?(/[^a-zA-Z0-9]/)
  # Check for repeated characters
  weaknesses << "Repeated characters (e.g., 'aaa')" if password.match?(/(.)\1{2,}/)
  weaknesses
end

# Run the program
main