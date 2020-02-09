/*
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 * 
 * http://github.com/piranhacms/piranha.core
 * 
 */

using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Piranha.AspNetCore.Identity.Models;

namespace Piranha.AspNetCore.Identity
{
    /// <summary>
    /// Interface for managing the Users and Roles
    /// </summary>
    public interface IIdentityService
    {
        Task<RoleListModel> GetRoleListAsync(CancellationToken cancellationToken);
        RoleEditModel CreateRole();
        Task<RoleEditModel> GetRoleByIdAsync(string roleId, CancellationToken cancellationToken);
        Task<bool> SaveRoleAsync(RoleEditModel model, CancellationToken cancellationToken);
        Task<bool> DeleteRoleAsync(string roleId, CancellationToken cancellationToken);


        Task<UserListModel> GetUserListAsync(CancellationToken cancellationToken);
        UserEditModel CreateUser();
        Task<UserEditModel> GetUserByIdAsync(string userId, CancellationToken cancellationToken);
        Task<IdentityResult> SaveUserAsync(UserEditModel model, CancellationToken cancellationToken);
        Task<bool> DeleteUserAsync(string userId, CancellationToken cancellationToken);

        string GetUserId(ClaimsPrincipal principal);
    }
}