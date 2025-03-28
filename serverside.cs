public class UserInput
{
    public string Username { get; set; }
    public string Email { get; set; }
}

public class InputValidator
{
    public static ValidationResult ValidateUserInput(UserInput input)
    {
        var result = new ValidationResult();

        // Sanitize and validate username
        if (string.IsNullOrWhiteSpace(input.Username))
        {
            result.AddError("Username is required");
        }
        else
        {
            // Remove any whitespace
            input.Username = input.Username.Trim();

            // Validate username format
            if (!Regex.IsMatch(input.Username, @"^[a-zA-Z0-9_]{3,20}$"))
            {
                result.AddError("Username must be 3-20 characters and contain only letters, numbers, and underscores");
            }
        }

        // Sanitize and validate email
        if (string.IsNullOrWhiteSpace(input.Email))
        {
            result.AddError("Email is required");
        }
        else
        {
            // Remove any whitespace
            input.Email = input.Email.Trim();

            // Validate email format
            if (!IsValidEmail(input.Email))
            {
                result.AddError("Invalid email format");
            }
        }

        return result;
    }

    private static bool IsValidEmail(string email)
    {
        try
        {
            // Use built-in email validation
            var addr = new System.Net.Mail.MailAddress(email);
            return addr.Address == email;
        }
        catch
        {
            return false;
        }
    }
}

public class ValidationResult
{
    public List<string> Errors { get; } = new List<string>();
    public bool IsValid => !Errors.Any();

    public void AddError(string error)
    {
        Errors.Add(error);
    }
}

// Controller endpoint
[HttpPost]
public IActionResult Submit([FromBody] UserInput input)
{
    // Validate input
    var validationResult = InputValidator.ValidateUserInput(input);

    if (!validationResult.IsValid)
    {
        return BadRequest(validationResult.Errors);
    }

    // Encode data before storing or using
    var sanitizedUsername = HttpUtility.HtmlEncode(input.Username);
    var sanitizedEmail = HttpUtility.HtmlEncode(input.Email);

    // Process the validated and sanitized input
    // ... store in database or perform other operations

    return Ok(new { message = "Data processed successfully" });
}
