using NUnit.Framework;
using Moq;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using System.Security.Authentication;

[TestFixture]
public class AuthenticationTests
{
    private Mock<IUserRepository> _userRepositoryMock;
    private Mock<IRoleAuthorizationService> _roleAuthServiceMock;
    private Mock<IPasswordHasher> _passwordHasherMock;
    private AuthenticationService _authService;
    private TestUserData _testData;

    [SetUp]
    public void Setup()
    {
        _userRepositoryMock = new Mock<IUserRepository>();
        _roleAuthServiceMock = new Mock<IRoleAuthorizationService>();
        _passwordHasherMock = new Mock<IPasswordHasher>();
        _authService = new AuthenticationService(
            _userRepositoryMock.Object,
            _roleAuthServiceMock.Object,
            _passwordHasherMock.Object);

        _testData = new TestUserData();
        SetupTestData();
    }

    private void SetupTestData()
    {
        // Setup test users with different roles
        _testData.AdminUser = new User
        {
            Id = 1,
            Username = "admin",
            Email = "admin@test.com",
            PasswordHash = "hashedPassword123",
            Roles = new List<UserRole> { new UserRole { Name = Roles.Admin } },
            LoginAttempts = 0
        };

        _testData.RegularUser = new User
        {
            Id = 2,
            Username = "user",
            Email = "user@test.com",
            PasswordHash = "hashedPassword456",
            Roles = new List<UserRole> { new UserRole { Name = Roles.User } },
            LoginAttempts = 0
        };

        _testData.LockedUser = new User
        {
            Id = 3,
            Username = "locked",
            Email = "locked@test.com",
            PasswordHash = "hashedPassword789",
            Roles = new List<UserRole> { new UserRole { Name = Roles.User } },
            LoginAttempts = 5,
            LockoutEnd = DateTime.UtcNow.AddHours(1)
        };
    }

    [Test]
    public async Task Login_WithValidCredentials_ReturnsValidToken()
    {
        // Arrange
        var loginRequest = new LoginRequest
        {
            Username = "admin",
            Password = "correctPassword"
        };

        _userRepositoryMock.Setup(x => x.GetUserByUsernameAsync(loginRequest.Username))
            .ReturnsAsync(_testData.AdminUser);

        _passwordHasherMock.Setup(x => x.VerifyPassword(
            loginRequest.Password,
            _testData.AdminUser.PasswordHash))
            .Returns(true);

        // Act
        var result = await _authService.LoginAsync(loginRequest);

        // Assert
        Assert.That(result.Success, Is.True);
        Assert.That(result.Token, Is.Not.Null);
        Assert.That(result.User.Username, Is.EqualTo(loginRequest.Username));
    }

    [Test]
    public async Task Login_WithInvalidCredentials_ReturnsFailure()
    {
        // Arrange
        var loginRequest = new LoginRequest
        {
            Username = "admin",
            Password = "wrongPassword"
        };

        _userRepositoryMock.Setup(x => x.GetUserByUsernameAsync(loginRequest.Username))
            .ReturnsAsync(_testData.AdminUser);

        _passwordHasherMock.Setup(x => x.VerifyPassword(
            loginRequest.Password,
            _testData.AdminUser.PasswordHash))
            .Returns(false);

        // Act
        var result = await _authService.LoginAsync(loginRequest);

        // Assert
        Assert.That(result.Success, Is.False);
        Assert.That(result.Token, Is.Null);
        Assert.That(result.ErrorMessage, Does.Contain("Invalid credentials"));
    }

    [Test]
    public async Task Login_WithLockedAccount_ReturnsFailure()
    {
        // Arrange
        var loginRequest = new LoginRequest
        {
            Username = "locked",
            Password = "password"
        };

        _userRepositoryMock.Setup(x => x.GetUserByUsernameAsync(loginRequest.Username))
            .ReturnsAsync(_testData.LockedUser);

        // Act
        var result = await _authService.LoginAsync(loginRequest);

        // Assert
        Assert.That(result.Success, Is.False);
        Assert.That(result.ErrorMessage, Does.Contain("Account is locked"));
    }

    [Test]
    public async Task Login_ExceedsMaxAttempts_LocksAccount()
    {
        // Arrange
        var loginRequest = new LoginRequest
        {
            Username = "user",
            Password = "wrongPassword"
        };

        var user = _testData.RegularUser;
        _userRepositoryMock.Setup(x => x.GetUserByUsernameAsync(loginRequest.Username))
            .ReturnsAsync(user);

        _passwordHasherMock.Setup(x => x.VerifyPassword(It.IsAny<string>(), It.IsAny<string>()))
            .Returns(false);

        // Act
        for (int i = 0; i < 5; i++)
        {
            await _authService.LoginAsync(loginRequest);
        }

        // Assert
        _userRepositoryMock.Verify(x => x.UpdateUserAsync(
            It.Is<User>(u => u.LoginAttempts >= 5 && u.LockoutEnd.HasValue)),
            Times.Once);
    }
}

[TestFixture]
public class AuthorizationTests
{
    private Mock<IRoleAuthorizationService> _roleAuthServiceMock;
    private Mock<IHttpContextAccessor> _httpContextMock;
    private AuthorizationHandler _authHandler;

    [SetUp]
    public void Setup()
    {
        _roleAuthServiceMock = new Mock<IRoleAuthorizationService>();
        _httpContextMock = new Mock<IHttpContextAccessor>();
        _authHandler = new AuthorizationHandler(
            _roleAuthServiceMock.Object,
            _httpContextMock.Object);
    }

    [Test]
    public async Task HasPermission_AdminUser_ReturnsTrue()
    {
        // Arrange
        var userId = 1;
        SetupUserContext(userId, Roles.Admin);
        _roleAuthServiceMock.Setup(x => x.HasPermissionAsync(userId, Permissions.ViewDashboard))
            .ReturnsAsync(true);

        // Act
        var result = await _authHandler.HasPermissionAsync(Permissions.ViewDashboard);

        // Assert
        Assert.That(result, Is.True);
    }

    [Test]
    public async Task HasPermission_RegularUser_ReturnsFalse()
    {
        // Arrange
        var userId = 2;
        SetupUserContext(userId, Roles.User);
        _roleAuthServiceMock.Setup(x => x.HasPermissionAsync(userId, Permissions.ManageSettings))
            .ReturnsAsync(false);

        // Act
        var result = await _authHandler.HasPermissionAsync(Permissions.ManageSettings);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public async Task IsInRole_CorrectRole_ReturnsTrue()
    {
        // Arrange
        var userId = 1;
        SetupUserContext(userId, Roles.Admin);
        _roleAuthServiceMock.Setup(x => x.IsInRoleAsync(userId, Roles.Admin))
            .ReturnsAsync(true);

        // Act
        var result = await _authHandler.IsInRoleAsync(Roles.Admin);

        // Assert
        Assert.That(result, Is.True);
    }

    [Test]
    public void AuthorizeEndpoint_UnauthorizedUser_ThrowsException()
    {
        // Arrange
        var userId = 2;
        SetupUserContext(userId, Roles.User);
        _roleAuthServiceMock.Setup(x => x.HasPermissionAsync(userId, Permissions.ManageSettings))
            .ReturnsAsync(false);

        // Act & Assert
        Assert.ThrowsAsync<UnauthorizedAccessException>(async () =>
            await _authHandler.AuthorizeEndpointAsync(Permissions.ManageSettings));
    }

    private void SetupUserContext(int userId, string role)
    {
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
            new Claim(ClaimTypes.Role, role)
        };

        var identity = new ClaimsIdentity(claims, "TestAuth");
        var principal = new ClaimsPrincipal(identity);
        var context = new DefaultHttpContext
        {
            User = principal
        };

        _httpContextMock.Setup(x => x.HttpContext).Returns(context);
    }
}

[TestFixture]
public class IntegrationTests
{
    private TestServer _server;
    private HttpClient _client;
    private IServiceProvider _serviceProvider;

    [OneTimeSetUp]
    public void Setup()
    {
        var builder = new WebHostBuilder()
            .UseStartup<TestStartup>();
        _server = new TestServer(builder);
        _client = _server.CreateClient();
        _serviceProvider = _server.Services;
    }

    [Test]
    public async Task AdminEndpoint_WithAdminRole_ReturnsSuccess()
    {
        // Arrange
        var token = await GetAuthTokenAsync("admin", "password");
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", token);

        // Act
        var response = await _client.GetAsync("/api/admin/dashboard");

        // Assert
        Assert.That(response.IsSuccessStatusCode, Is.True);
    }

    [Test]
    public async Task AdminEndpoint_WithUserRole_ReturnsForbidden()
    {
        // Arrange
        var token = await GetAuthTokenAsync("user", "password");
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", token);

        // Act
        var response = await _client.GetAsync("/api/admin/dashboard");

        // Assert
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
    }

    private async Task<string> GetAuthTokenAsync(string username, string password)
    {
        var loginRequest = new LoginRequest
        {
            Username = username,
            Password = password
        };

        var response = await _client.PostAsJsonAsync("/api/auth/login", loginRequest);
        var result = await response.Content.ReadFromJsonAsync<LoginResult>();
        return result.Token;
    }

    [OneTimeTearDown]
    public void TearDown()
    {
        _client.Dispose();
        _server.Dispose();
    }
}

public class TestUserData
{
    public User AdminUser { get; set; }
    public User RegularUser { get; set; }
    public User LockedUser { get; set; }
}
