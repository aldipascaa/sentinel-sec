#include "sentinel/password.hpp"

namespace sentinel {

// A small bundled list of extremely common passwords (public knowledge; used only to flag weak input).
const std::unordered_set<std::string>& builtin_wordlist() {
    static const std::unordered_set<std::string> words = {
        "password", "123456", "123456789", "12345678", "12345", "1234567", "1234567890", "qwerty", "abc123",
        "111111", "123123", "000000", "iloveyou", "admin", "welcome", "monkey", "dragon", "letmein", "login",
        "princess", "football", "baseball", "master", "sunshine", "shadow", "superman", "batman", "trustno1",
        "passw0rd", "p@ssw0rd", "password1", "password123", "qwerty123", "qwertyuiop", "asdfghjkl", "zxcvbnm",
        "1q2w3e4r", "1qaz2wsx", "q1w2e3r4", "654321", "666666", "121212", "112233", "555555", "7777777",
        "mustang", "michael", "jennifer", "jordan", "harley", "ranger", "buster", "thomas", "tigger", "robert",
        "soccer", "hockey", "killer", "george", "charlie", "andrew", "michelle", "love", "secret", "summer",
        "winter", "spring", "autumn", "freedom", "whatever", "hello", "helloworld", "computer", "internet",
        "service", "access", "flower", "cheese", "pepper", "ginger", "banana", "cookie", "chocolate", "orange",
        "starwars", "pokemon", "matrix", "samsung", "google", "facebook", "youtube", "windows", "ubuntu",
        "changeme", "default", "guest", "root", "toor", "administrator", "test", "testing", "user", "temp",
        "qazwsx", "zaq12wsx", "pass", "pass123", "pass1234", "abcd1234", "abcdef", "abcdefg", "abc12345",
        "a1b2c3", "aaaaaa", "asdfgh", "asdf1234", "lovely", "babygirl", "angel", "angels", "jesus", "forever",
        "ashley", "nicole", "daniel", "hunter", "hunter2", "joshua", "maggie", "yankees", "cowboys", "liverpool",
        "arsenal", "chelsea", "barcelona", "ferrari", "porsche", "mercedes", "corvette", "diamond", "silver",
        "golden", "purple", "rainbow", "butterfly", "trouble", "nothing", "anything", "everything", "monster",
        "pass word", "master123", "admin123", "admin1234", "root123", "letmein123", "welcome1", "welcome123",
        "iloveyou1", "sunshine1", "princess1", "football1", "monkey123", "dragon123", "shadow123", "qwerty1",
        "qwerty12", "password!", "password12", "password2", "p4ssw0rd", "pa55word", "pa$$word", "secret123",
        "letmein1", "login123", "access14", "starwars1", "baseball1", "superman1", "batman123", "trustno",
    };
    return words;
}

}  // namespace sentinel
