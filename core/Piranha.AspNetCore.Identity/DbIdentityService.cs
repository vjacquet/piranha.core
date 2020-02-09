/*
 * Copyright (c) 2018 Håkan Edling
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 * 
 * http://github.com/piranhacms/piranha.core
 * 
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Piranha.AspNetCore.Identity.Data;
using Piranha.AspNetCore.Identity.Models;

namespace Piranha.AspNetCore.Identity
{
    public class DbIdentityService : IIdentityService
    {
        private readonly IDb _db;
        private readonly UserManager<User> _userManager;

        public DbIdentityService(IDb db, UserManager<User> userManager)
        {
            _db = db;
            _userManager = userManager;
        }

        public RoleEditModel CreateRole()
        {
            return RoleEditModel.Create();
        }

        public Task<RoleListModel> GetRoleListAsync(CancellationToken cancellationToken)
        {
            return Task.FromResult(GetRoleListModel(_db));
        }

        static RoleListModel GetRoleListModel(IDb db)
        {
            var model = new RoleListModel
            {
                Roles = db.Roles
                    .OrderBy(r => r.Name)
                    .Select(r => new RoleListModel.ListItem
                    {
                        Id = r.Id.ToString(),
                        Name = r.Name
                    }).ToList()
            };

            foreach (var role in model.Roles)
            {
                var id = new Guid(role.Id);
                role.UserCount = db.UserRoles
                    .Count(r => r.RoleId == id);
            }
            return model;
        }

        RoleEditModel GetRoleById(Guid id)
        {
            var role = _db.Roles.FirstOrDefault(r => r.Id == id);

            if (role != null)
            {
                var model = new RoleEditModel
                {
                    Id = id.ToString(),
                    Name = role.Name,
                    NormalizedName = role.NormalizedName,
                };

                var roleClaims = _db.RoleClaims.Where(r => r.RoleId == id).ToList();
                foreach (var claim in roleClaims)
                {
                    model.SelectedClaims.Add(claim.ClaimType);
                }
                return model;
            }

            return null;
        }

        public Task<RoleEditModel> GetRoleByIdAsync(string roleId, CancellationToken cancellationToken)
        {
            var id = new Guid(roleId);
            return Task.FromResult(GetRoleById(id));
        }

        public Task<bool> SaveRoleAsync(RoleEditModel model, CancellationToken cancellationToken)
        {
            var id = new Guid(model.Id);
            var role = id == Guid.Empty
                ? new Role()
                : _db.Roles.FirstOrDefault(r => r.Id == id);
            if (role == null)
            {
                return Task.FromResult(false);
            }
            else if (id == Guid.Empty)
            {
                _db.Roles.Add(role);
            }

            role.Name = model.Name;
            role.NormalizedName = !string.IsNullOrEmpty(model.NormalizedName)
                    ? model.NormalizedName.ToUpper()
                    : model.Name.ToUpper();
            var claims = _db.RoleClaims.Where(r => r.RoleId == role.Id).ToList();
            var delete = new List<IdentityRoleClaim<Guid>>();
            var add = new List<IdentityRoleClaim<Guid>>();

            foreach (var old in claims)
            {
                if (!model.SelectedClaims.Contains(old.ClaimType))
                {
                    delete.Add(old);
                }
            }

            foreach (var selected in model.SelectedClaims)
            {
                if (!claims.Any(c => c.ClaimType == selected))
                {
                    add.Add(new IdentityRoleClaim<Guid>
                    {
                        RoleId = role.Id,
                        ClaimType = selected,
                        ClaimValue = selected
                    });
                }
            }

            _db.RoleClaims.RemoveRange(delete);
            _db.RoleClaims.AddRange(add);

            _db.SaveChanges();

            model.Id = role.Id.ToString();
            return Task.FromResult(true);
        }

        public Task<bool> DeleteRoleAsync(string roleId, CancellationToken cancellationToken)
        {
            var id = new Guid(roleId);

            var role = _db.Roles
                .FirstOrDefault(r => r.Id == id);

            if (role != null)
            {
                _db.Roles.Remove(role);
                _db.SaveChanges();

                return Task.FromResult(true);
            }

            return Task.FromResult(false);
        }

        public Task<UserListModel> GetUserListAsync(CancellationToken cancellationToken)
        {
            return Task.FromResult(GetUserListModel(_db));
        }

        static UserListModel GetUserListModel(IDb db)
        {
            var model = new UserListModel
            {
                Users = db.Users
                    .OrderBy(u => u.UserName)
                    .Select(u => new UserListModel.ListItem
                    {
                        Id = u.Id.ToString(),
                        UserName = u.UserName,
                        Email = u.Email,
                        GravatarUrl = !string.IsNullOrWhiteSpace(u.Email) ? Utils.GetGravatarUrl(u.Email, 25) : null
                    }).ToList()
            };

            var roles = db.Roles
                .ToList();

            foreach (var user in model.Users)
            {
                var id = new Guid(user.Id);
                var userRoles = db.UserRoles
                    .Where(r => r.UserId == id)
                    .ToList();

                foreach (var userRole in userRoles)
                {
                    var role = roles.FirstOrDefault(r => r.Id == userRole.RoleId);
                    if (role != null)
                    {
                        user.Roles.Add(role.Name);
                    }
                }
            }

            return model;
        }

        public UserEditModel CreateUser()
        {
            return new UserEditModel
            {
                Roles = _db.Roles.OrderBy(r => r.Name).Select(r => r.Name).ToList()
            };
        }

        public Task<UserEditModel> GetUserByIdAsync(string userId, CancellationToken cancellationToken)
        {
            var id = new Guid(userId);
            return Task.FromResult(GetUserEditModelById(_db, id));
        }

        static UserEditModel GetUserEditModelById(IDb db, Guid id)
        {
            var user = db.Users.FirstOrDefault(u => u.Id == id);
            if (user != null)
            {
                var roles = db.Roles.ToDictionary(r => r.Id, r => r.Name);
                var model = new UserEditModel
                {
                    Id = user.Id.ToString(),
                    UserName = user.UserName,
                    Email = user.Email,
                    Roles = roles.Values.OrderBy(r => r).ToList()
                };

                var userRoles = db.UserRoles.Where(r => r.UserId == id).ToList();
                foreach (var role in userRoles)
                {
                    model.SelectedRoles.Add(roles[role.RoleId]);
                }
                return model;
            }

            return null;
        }

        public async Task<IdentityResult> SaveUserAsync(UserEditModel model, CancellationToken cancellationToken)
        {
            var user = string.IsNullOrEmpty(model.Id)
                ? new User
                {
                    UserName = model.UserName,
                    Email = model.Email,
                }
                : await _userManager.FindByIdAsync(model.Id);

            IdentityResult result;
            if (user == null)
            {
                return IdentityResult.Failed(_userManager.ErrorDescriber.DefaultError());

            }
            else if (user.Id == Guid.Empty)
            {
                result = await _userManager.CreateAsync(user, model.Password);
                if (!result.Succeeded)
                {
                    return result;
                }
                model.Id = user.Id.ToString();
            }
            else
            {
                result = await _userManager.SetUserNameAsync(user, model.UserName);
                if (!result.Succeeded)
                {
                    return result;
                }

                result = await _userManager.SetEmailAsync(user, model.Email);
                if (!result.Succeeded)
                {
                    return result;
                }
            }

            // Remove old roles
            var roles = await _userManager.GetRolesAsync(user);
            result = await _userManager.RemoveFromRolesAsync(user, roles);
            if (!result.Succeeded)
            {
                return result;
            }

            // Add current roles
            result = await _userManager.AddToRolesAsync(user, model.SelectedRoles);
            if (!result.Succeeded)
            {
                return result;
            }

            if (!string.IsNullOrWhiteSpace(model.Password))
            {
                result = await _userManager.RemovePasswordAsync(user);
                if (!result.Succeeded)
                {
                    return result;
                }
                result = await _userManager.AddPasswordAsync(user, model.Password);
                if (!result.Succeeded)
                {
                    return result;
                }
            }

            return result;
        }

        public Task<bool> DeleteUserAsync(string userId, CancellationToken cancellationToken)
        {
            var id = new Guid(userId);
            var user = _db.Users
                .FirstOrDefault(u => u.Id == id);
            if (user != null)
            {
                _db.Users.Remove(user);
                _db.SaveChanges();

                return Task.FromResult(true);
            }

            return Task.FromResult(false);
        }

        public string GetUserId(ClaimsPrincipal principal)
        {
            return _userManager.GetUserId(principal);
        }
    }
}