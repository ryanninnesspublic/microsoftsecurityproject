public class User
{
    public int Id { get; set; }
    public string Username { get; set; }
    public string Email { get; set; }
    public string PasswordHash { get; set; }
    public List<UserRole> Roles { get; set; } = new List<UserRole>();
    public DateTime LastLoginDate { get; set; }
    public int LoginAttempts { get; set; }
    public DateTime? LockoutEnd { get; set; }
}

public class UserRole
{
    public int Id { get; set; }
    public string Name { get; set; }
    public string Description { get; set; }
    public List<string> Permissions { get; set; } = new List<string>();
}

public static class Roles
{
    public const string Admin = "Admin";
    public const string Manager = "Manager";
    public const string User = "User";
}

public static class Permissions
{
    public const string ViewUsers = "Users.View";
    public const string CreateUsers = "Users.Create";
    public const string EditUsers = "Users.Edit";
    public const string DeleteUsers = "Users.Delete";
    public const string ViewDashboard = "Dashboard.View";
    public const string ManageSettings = "Settings.Manage";
}

public interface IRoleAuthorizationService
{
    Task<bool> HasPermissionAsync(int userId, string permission);
    Task<bool> IsInRoleAsync(int userId, string role);
    Task<IEnumerable<string>> GetUserRolesAsync(int userId);
    Task<IEnumerable<string>> GetUserPermissionsAsync(int userId);
}

public class RoleAuthorizationService : IRoleAuthorizationService
{
    private readonly IUserRepository _userRepository;
    private readonly IMemoryCache _cache;

    public RoleAuthorizationService(IUserRepository userRepository, IMemoryCache cache)
    {
        _userRepository = userRepository;
        _cache = cache;
    }

    public async Task<bool> HasPermissionAsync(int userId, string permission)
    {
        var permissions = await GetUserPermissionsAsync(userId);
        return permissions.Contains(permission);
    }

    public async Task<bool> IsInRoleAsync(int userId, string role)
    {
        var roles = await GetUserRolesAsync(userId);
        return roles.Contains(role);
    }

    public async Task<IEnumerable<string>> GetUserRolesAsync(int userId)
    {
        string cacheKey = $"user_roles_{userId}";

        return await _cache.GetOrCreateAsync(cacheKey, async entry =>
        {
            entry.SlidingExpiration = TimeSpan.FromMinutes(10);
            var user = await _userRepository.GetUserByIdAsync(userId);
            return user?.Roles.Select(r => r.Name) ?? new List<string>();
        });
    }

    public async Task<IEnumerable<string>> GetUserPermissionsAsync(int userId)
    {
        string cacheKey = $"user_permissions_{userId}";

        return await _cache.GetOrCreateAsync(cacheKey, async entry =>
        {
            entry.SlidingExpiration = TimeSpan.FromMinutes(10);
            var user = await _userRepository.GetUserByIdAsync(userId);
            return user?.Roles
                .SelectMany(r => r.Permissions)
                .Distinct()
                ?? new List<string>();
        });
    }
}

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true)]
public class RequirePermissionAttribute : AuthorizeAttribute
{
    public RequirePermissionAttribute(string permission)
        : base($"Permission:{permission}")
    {
    }
}

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true)]
public class RequireRoleAttribute : AuthorizeAttribute
{
    public RequireRoleAttribute(string role)
        : base($"Role:{role}")
    {
    }
}

public class PermissionAuthorizationHandler : AuthorizationHandler<PermissionRequirement>
{
    private readonly IRoleAuthorizationService _roleAuthService;

    public PermissionAuthorizationHandler(IRoleAuthorizationService roleAuthService)
    {
        _roleAuthService = roleAuthService;
    }

    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        PermissionRequirement requirement)
    {
        if (!context.User.Identity.IsAuthenticated)
        {
            return;
        }

        var userId = int.Parse(context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value);

        if (await _roleAuthService.HasPermissionAsync(userId, requirement.Permission))
        {
            context.Succeed(requirement);
        }
    }
}

public class PermissionRequirement : IAuthorizationRequirement
{
    public string Permission { get; }

    public PermissionRequirement(string permission)
    {
        Permission = permission;
    }
}

private async Task<string> GenerateJwtTokenAsync(User user)
{
    var tokenHandler = new JwtSecurityTokenHandler();
    var key = Encoding.ASCII.GetBytes(Environment.GetEnvironmentVariable("JWT_SECRET"));

    var roles = await _roleAuthService.GetUserRolesAsync(user.Id);
    var permissions = await _roleAuthService.GetUserPermissionsAsync(user.Id);

    var claims = new List<Claim>
    {
        new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
        new Claim(ClaimTypes.Name, user.Username),
        new Claim(ClaimTypes.Email, user.Email)
    };

    // Add roles to claims
    claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

    // Add permissions to claims
    claims.AddRange(permissions.Select(permission =>
        new Claim("permission", permission)));

    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(claims),
        Expires = DateTime.UtcNow.AddHours(1),
        SigningCredentials = new SigningCredentials(
            new SymmetricSecurityKey(key),
            SecurityAlgorithms.HmacSha256Signature
        )
    };

    var token = tokenHandler.CreateToken(tokenDescriptor);
    return tokenHandler.WriteToken(token);
}

[ApiController]
[Route("api/[controller]")]
[Authorize] // Requires authentication for all endpoints
public class AdminController : ControllerBase
{
    private readonly IRoleAuthorizationService _roleAuthService;

    public AdminController(IRoleAuthorizationService roleAuthService)
    {
        _roleAuthService = roleAuthService;
    }

    [HttpGet("dashboard")]
    [RequirePermission(Permissions.ViewDashboard)]
    public IActionResult GetDashboard()
    {
        return Ok(new { message = "Admin dashboard data" });
    }

    [HttpGet("users")]
    [RequirePermission(Permissions.ViewUsers)]
    public async Task<IActionResult> GetUsers()
    {
        return Ok(new { message = "Users list" });
    }

    [HttpPost("users")]
    [RequirePermission(Permissions.CreateUsers)]
    public async Task<IActionResult> CreateUser([FromBody] CreateUserRequest request)
    {
        // Implementation
        return Ok(new { message = "User created" });
    }

    [HttpPut("settings")]
    [RequireRole(Roles.Admin)] // Only admin can access
    public async Task<IActionResult> UpdateSettings([FromBody] SettingsRequest request)
    {
        return Ok(new { message = "Settings updated" });
    }
}

public void ConfigureServices(IServiceCollection services)
{
    // Existing configurations...

    services.AddMemoryCache();
    services.AddScoped<IRoleAuthorizationService, RoleAuthorizationService>();

    services.AddAuthorization(options =>
    {
        // Add policies for permissions
        foreach (var permission in typeof(Permissions)
            .GetFields(BindingFlags.Public | BindingFlags.Static | BindingFlags.FlattenHierarchy)
            .Where(fi => fi.IsLiteral && !fi.IsInitOnly)
            .Select(fi => fi.GetValue(null).ToString()))
        {
            options.AddPolicy($"Permission:{permission}",
                policy => policy.Requirements.Add(new PermissionRequirement(permission)));
        }
    });

    services.AddScoped<IAuthorizationHandler, PermissionAuthorizationHandler>();
}
