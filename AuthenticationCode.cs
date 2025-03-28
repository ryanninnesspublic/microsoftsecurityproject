public class User
{
    public int Id { get; set; }
    public string Username { get; set; }
    public string Email { get; set; }
    public string PasswordHash { get; set; }
    public DateTime LastLoginDate { get; set; }
    public int LoginAttempts { get; set; }
    public DateTime? LockoutEnd { get; set; }
}

public class AuthenticationResult
{
    public bool Success { get; set; }
    public string Message { get; set; }
    public User User { get; set; }
}

public class AuthenticationService
{
    private readonly IConfiguration _configuration;
    private readonly IUserRepository _userRepository;
    private const int MaxLoginAttempts = 5;
    private const int LockoutMinutes = 30;

    public AuthenticationService(IConfiguration configuration, IUserRepository userRepository)
    {
        _configuration = configuration;
        _userRepository = userRepository;
    }

    public async Task<AuthenticationResult> AuthenticateUser(string username, string password)
    {
        try
        {
            // Input validation
            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
            {
                return new AuthenticationResult
                {
                    Success = false,
                    Message = "Username and password are required"
                };
            }

            // Get user from database
            var user = await _userRepository.GetUserByUsername(username);
            if (user == null)
            {
                // Use constant time comparison to prevent timing attacks
                BCrypt.Net.BCrypt.Verify(password, BCrypt.Net.BCrypt.HashPassword("dummy"));
                return new AuthenticationResult
                {
                    Success = false,
                    Message = "Invalid username or password"
                };
            }

            // Check for account lockout
            if (user.LockoutEnd.HasValue && user.LockoutEnd > DateTime.UtcNow)
            {
                return new AuthenticationResult
                {
                    Success = false,
                    Message = $"Account is locked. Try again after {user.LockoutEnd}"
                };
            }

            // Verify password
            if (!BCrypt.Net.BCrypt.Verify(password, user.PasswordHash))
            {
                await HandleFailedLogin(user);
                return new AuthenticationResult
                {
                    Success = false,
                    Message = "Invalid username or password"
                };
            }

            // Reset login attempts on successful login
            await ResetLoginAttempts(user);

            return new AuthenticationResult
            {
                Success = true,
                Message = "Authentication successful",
                User = user
            };
        }
        catch (Exception ex)
        {
            // Log the error securely
            throw new AuthenticationException("Authentication failed", ex);
        }
    }

    private async Task HandleFailedLogin(User user)
    {
        user.LoginAttempts++;

        if (user.LoginAttempts >= MaxLoginAttempts)
        {
            user.LockoutEnd = DateTime.UtcNow.AddMinutes(LockoutMinutes);
            user.LoginAttempts = 0;
        }

        await _userRepository.UpdateUser(user);
    }

    private async Task ResetLoginAttempts(User user)
    {
        user.LoginAttempts = 0;
        user.LastLoginDate = DateTime.UtcNow;
        user.LockoutEnd = null;
        await _userRepository.UpdateUser(user);
    }

    public async Task<AuthenticationResult> RegisterUser(string username, string email, string password)
    {
        try
        {
            // Validate password strength
            if (!IsPasswordStrong(password))
            {
                return new AuthenticationResult
                {
                    Success = false,
                    Message = "Password does not meet security requirements"
                };
            }

            // Check if user already exists
            if (await _userRepository.GetUserByUsername(username) != null)
            {
                return new AuthenticationResult
                {
                    Success = false,
                    Message = "Username already exists"
                };
            }

            // Hash password with BCrypt
            string passwordHash = BCrypt.Net.BCrypt.HashPassword(password, workFactor: 12);

            var user = new User
            {
                Username = username,
                Email = email,
                PasswordHash = passwordHash,
                LastLoginDate = DateTime.UtcNow,
                LoginAttempts = 0
            };

            await _userRepository.CreateUser(user);

            return new AuthenticationResult
            {
                Success = true,
                Message = "Registration successful",
                User = user
            };
        }
        catch (Exception ex)
        {
            // Log the error securely
            throw new RegistrationException("Registration failed", ex);
        }
    }

    private bool IsPasswordStrong(string password)
    {
        return password.Length >= 12 &&
               password.Any(char.IsUpper) &&
               password.Any(char.IsLower) &&
               password.Any(char.IsDigit) &&
               password.Any(c => !char.IsLetterOrDigit(c));
    }
}

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly AuthenticationService _authService;
    private readonly IConfiguration _configuration;

    public AuthController(AuthenticationService authService, IConfiguration configuration)
    {
        _authService = authService;
        _configuration = configuration;
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        try
        {
            var result = await _authService.AuthenticateUser(request.Username, request.Password);

            if (!result.Success)
            {
                return BadRequest(new { message = result.Message });
            }

            // Generate JWT token
            var token = GenerateJwtToken(result.User);

            return Ok(new
            {
                token,
                user = new
                {
                    result.User.Id,
                    result.User.Username,
                    result.User.Email
                }
            });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { message = "An error occurred during authentication" });
        }
    }

    private string GenerateJwtToken(User user)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(Environment.GetEnvironmentVariable("JWT_SECRET"));

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Email, user.Email)
            }),
            Expires = DateTime.UtcNow.AddHours(1),
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha256Signature
            )

