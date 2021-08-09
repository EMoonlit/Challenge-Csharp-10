using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Codenation.Challenge.Models;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Validation;

namespace Codenation.Challenge.Services
{
    public class UserProfileService : IProfileService
    {
        public CodenationContext _dbContext;
        public UserProfileService(CodenationContext dbContext)
        {
            _dbContext = dbContext;
        }

        public Task GetProfileDataAsync(ProfileDataRequestContext context)
        {
            var request = context.ValidatedRequest as ValidatedTokenRequest;
            if (request != null)
            {
                // implementa��o
                var user = _dbContext.Users.FirstOrDefault(x => x.Nickname == request.UserName);
                if (user != null)    
                    context.IssuedClaims = GetUserClaims(user)
                        .Where(x => 
                        context.RequestedClaimTypes.Contains(x.Type)).ToList();
            }

            return Task.CompletedTask;
        }

        public Task IsActiveAsync(IsActiveContext context)
        {
            context.IsActive = true;
            return Task.CompletedTask;
        }

        public static Claim[] GetUserClaims(User user)
        {
            return new []
            {
                new Claim(ClaimTypes.Name, user.Nickname),
                new Claim("Email", user.Email),
                new Claim(ClaimTypes.Role, "User")
            };
        }
    }
}