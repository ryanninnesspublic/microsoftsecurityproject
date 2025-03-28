using NUnit.Framework;
using System.Collections.Generic;

[TestFixture]
public class TestInputValidation
{
    private InputValidator _validator;
    private UserInput _userInput;

    [SetUp]
    public void Setup()
    {
        _validator = new InputValidator();
        _userInput = new UserInput();
    }

    [Test]
    public void TestForSQLInjection()
    {
        // Test cases for common SQL injection patterns
        var sqlInjectionAttempts = new Dictionary<string, string>
        {
            // Basic SQL injection attempts
            { "' OR '1'='1", "username" },
            { "admin'--", "username" },
            { "'; DROP TABLE Users;--", "username" },
            { "' UNION SELECT * FROM Users--", "username" },
            { "' OR '1'='1' /*", "username" },
            
            // More sophisticated attempts
            { "admin' AND 1=CONVERT(int,(SELECT @@version))--", "username" },
            { "'; WAITFOR DELAY '0:0:10'--", "username" },
            { "'; exec xp_cmdshell('dir')--", "username" },
            
            // Attempts with different quotation marks
            { "\" OR \"1\"=\"1", "username" },
            { "`) OR 1=1--", "username" }
        };

        foreach (var attempt in sqlInjectionAttempts)
        {
            _userInput.Username = attempt.Key;
            _userInput.Email = "test@example.com";

            var result = InputValidator.ValidateUserInput(_userInput);

            Assert.IsFalse(result.IsValid,
                $"SQL injection attempt should be rejected: {attempt.Key}");
            Assert.That(result.Errors, Has.Count.GreaterThan(0),
                "Validation should return at least one error");
        }
    }

    [Test]
    public void TestForXSS()
    {
        // Test cases for common XSS attack patterns
        var xssAttempts = new Dictionary<string, string>
        {
            // Basic script injection
            { "<script>alert('xss')</script>", "username" },
            { "<img src='x' onerror='alert(1)'>", "username" },
            { "<svg onload='alert(1)'>", "username" },
            
            // Encoded attacks
            { "&#60;script&#62;alert('xss')&#60;/script&#62;", "username" },
            { "&lt;script&gt;alert('xss')&lt;/script&gt;", "username" },
            
            // Event handlers
            { "' onmouseover='alert(1)", "username" },
            { "\" onclick=\"alert(1)", "username" },
            
            // Style-based attacks
            { "<style>@import 'javascript:alert(1)'</style>", "username" },
            { "<div style='background:url(javascript:alert(1))'>", "username" },
            
            // Mixed case to evade filters
            { "<ScRiPt>alert('xss')</sCrIpT>", "username" },
            
            // Email field specific XSS attempts
            { "test+<script>alert('xss')</script>@example.com", "email" },
            { "><script>alert('xss')</script>@example.com", "email" }
        };

        foreach (var attempt in xssAttempts)
        {
            if (attempt.Value == "username")
            {
                _userInput.Username = attempt.Key;
                _userInput.Email = "test@example.com";
            }
            else
            {
                _userInput.Username = "validuser";
                _userInput.Email = attempt.Key;
            }

            var result = InputValidator.ValidateUserInput(_userInput);

            Assert.IsFalse(result.IsValid,
                $"XSS attempt should be rejected: {attempt.Key}");
            Assert.That(result.Errors, Has.Count.GreaterThan(0),
                "Validation should return at least one error");
        }
    }

    [Test]
    public void TestValidInputs()
    {
        // Test valid inputs should pass
        var validInputs = new List<(string username, string email)>
        {
            ("john_doe", "john@example.com"),
            ("user123", "user.name@domain.com"),
            ("test_user_2023", "test.user+label@company.co.uk")
        };

        foreach (var input in validInputs)
        {
            _userInput.Username = input.username;
            _userInput.Email = input.email;

            var result = InputValidator.ValidateUserInput(_userInput);

            Assert.IsTrue(result.IsValid,
                $"Valid input should be accepted: {input.username}, {input.email}");
            Assert.That(result.Errors, Is.Empty,
                "No validation errors should be present for valid input");
        }
    }

    [Test]
    public void TestInputSanitization()
    {
        // Test that inputs are properly sanitized
        var testCases = new Dictionary<string, string>
        {
            { "  user123  ", "user123" }, // Trim spaces
            { "user@123", null }, // Invalid characters
            { "ab", null }, // Too short
            { "useruseruseruseruser123456", null } // Too long
        };

        foreach (var test in testCases)
        {
            _userInput.Username = test.Key;
            _userInput.Email = "test@example.com";

            var result = InputValidator.ValidateUserInput(_userInput);

            if (test.Value == null)
            {
                Assert.IsFalse(result.IsValid,
                    $"Invalid input should be rejected: {test.Key}");
            }
            else
            {
                Assert.AreEqual(test.Value,
                    _userInput.Username.Trim(),
                    "Input should be properly sanitized");
            }
        }
    }

    [Test]
    public void TestEdgeCases()
    {
        // Test edge cases
        var edgeCases = new Dictionary<string, string>
        {
            { "", "username" },
            { null, "username" },
            { new string('a', 21), "username" }, // Exceeds max length
            { "a", "email" }, // Invalid email
            { "@domain.com", "email" }, // Invalid email
            { "user@", "email" } // Invalid email
        };

        foreach (var case_ in edgeCases)
        {
            if (case_.Value == "username")
            {
                _userInput.Username = case_.Key;
                _userInput.Email = "test@example.com";
            }
            else
            {
                _userInput.Username = "validuser";
                _userInput.Email = case_.Key;
            }

            var result = InputValidator.ValidateUserInput(_userInput);

            Assert.IsFalse(result.IsValid,
                $"Edge case should be rejected: {case_.Key}");
            Assert.That(result.Errors, Has.Count.GreaterThan(0),
                "Validation should return at least one error");
        }
    }
}
