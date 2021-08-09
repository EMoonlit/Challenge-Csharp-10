using Codenation.Challenge.Models;
using IdentityServer4.Models;
using IdentityServer4.Validation;
using System.Linq;
using System.Threading.Tasks;
 
namespace Codenation.Challenge.Services
{
    public class PasswordValidatorService: IResourceOwnerPasswordValidator
    {
        private CodenationContext _dbContext;
        public PasswordValidatorService(CodenationContext dbContext)
        {
            _dbContext = dbContext;
        }

        public Task ValidateAsync(ResourceOwnerPasswordValidationContext context)
        {
            context.Result = new GrantValidationResult(
                TokenRequestErrors.InvalidGrant, "Invalid username or password");

            //implementação
            if (_dbContext.Users.Any(u => u.Email == context.UserName && u.Password == context.Password))
            {
                User user = _dbContext.Users.Where(x => x.Nickname == context.UserName).FirstOrDefault();

                //if (user != null && user.Password == context.Password)
                    context.Result = new GrantValidationResult(subject: user.Id.ToString(),
                        authenticationMethod: "custom",
                        claims: UserProfileService.GetUserClaims(user));
                //else
                  //  context.Result = new GrantValidationResult(TokenRequestErrors.InvalidGrant, "Invalid username or password");
            }
            return Task.CompletedTask;
        }
     
    }
}