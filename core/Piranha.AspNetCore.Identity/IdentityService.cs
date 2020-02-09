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
using Microsoft.EntityFrameworkCore;
using Piranha.AspNetCore.Identity.Models;

namespace Piranha.AspNetCore.Identity
{
    public class IdentityService<TUser, TRole> : IIdentityService
        where TUser : class
        where TRole : class
    {
        private readonly UserManager<TUser> _userManager;
        private readonly IUserStore<TUser> _userStore;
        private readonly RoleManager<TRole> _roleManager;
        private readonly IRoleStore<TRole> _roleStore;

        public IdentityService(UserManager<TUser> userManager, IUserStore<TUser> userStore, RoleManager<TRole> roleManager, IRoleStore<TRole> roleStore)
        {
            _userManager = userManager;
            _userStore = userStore;
            _roleManager = roleManager;
            _roleStore = roleStore;
        }

        public RoleEditModel CreateRole()
        {
            return new RoleEditModel
            {
            };
        }

        public async Task<RoleListModel> GetRoleListAsync(CancellationToken cancellationToken)
        {
            var roles = new List<RoleListModel.ListItem>();
            foreach (var role in await _roleManager.Roles.AsNoTracking().ToListAsync(cancellationToken))
            {
                roles.Add(new RoleListModel.ListItem
                {
                    Id = await _roleManager.GetRoleIdAsync(role),
                    Name = await _roleManager.GetRoleNameAsync(role),
                });
            }

            foreach (var role in roles)
            {
                var users = await _userManager.GetUsersInRoleAsync(role.Name);
                role.UserCount = users.Count;
            }

            return new RoleListModel
            {
                Roles = roles
            };
        }

        public async Task<RoleEditModel> GetRoleByIdAsync(string roleId, CancellationToken cancellationToken)
        {
            var role = await _roleManager.FindByIdAsync(roleId);
            if (role != null)
            {
                var name = await _roleManager.GetRoleNameAsync(role);
                var model = new RoleEditModel
                {
                    Id = await _roleManager.GetRoleIdAsync(role),
                    Name = name,
                    NormalizedName = _roleManager.NormalizeKey(name),
                };

                var roleClaims = await _roleManager.GetClaimsAsync(role);
                foreach (var claim in roleClaims)
                {
                    model.SelectedClaims.Add(claim.Type);
                }
                return model;
            }

            return null;
        }

        public async Task<bool> SaveRoleAsync(RoleEditModel model, CancellationToken cancellationToken)
        {
            var store = (IRoleClaimStore<TRole>)_roleStore;

            var roleId = model.Id;
            if (string.IsNullOrEmpty(roleId))
            {
                var role = Activator.CreateInstance<TRole>();
                await _roleManager.SetRoleNameAsync(role, model.Name);
                foreach (var selected in model.SelectedClaims)
                {
                    await store.AddClaimAsync(role, new Claim(selected, selected));
                }

                var result = await _roleManager.CreateAsync(role);
                if (!result.Succeeded)
                {
                    return false;
                }
            }
            else
            {
                var role = await _roleManager.FindByIdAsync(roleId);
                if (role == null)
                {
                    return false;
                }
                await _roleManager.SetRoleNameAsync(role, model.Name);
                var claims = await store.GetClaimsAsync(role);

                foreach (var old in claims)
                {
                    if (!model.SelectedClaims.Contains(old.Type))
                    {
                        await store.RemoveClaimAsync(role, old);
                    }
                }

                foreach (var selected in model.SelectedClaims)
                {
                    if (!claims.Any(c => c.Type == selected))
                    {
                        await store.AddClaimAsync(role, new Claim(selected, selected));
                    }
                }

                var result = await _roleManager.UpdateAsync(role);
                if (!result.Succeeded)
                {
                    return false;
                }
            }

            return true;
        }

        public async Task<bool> DeleteRoleAsync(string roleId, CancellationToken cancellationToken)
        {
            var role = await _roleManager.FindByIdAsync(roleId);
            if (role != null)
            {
                var result = await _roleManager.DeleteAsync(role);
                return result.Succeeded;
            }

            return false;
        }

        public async Task<UserListModel> GetUserListAsync(CancellationToken cancellationToken)
        {
            var store = (IUserEmailStore<TUser>)_userStore;
            var users = new List<UserListModel.ListItem>();
            foreach (var user in await _userManager.Users.AsNoTracking().ToListAsync(cancellationToken))
            {
                var email = await store.GetEmailAsync(user, cancellationToken);
                var roles = await _userManager.GetRolesAsync(user);
                users.Add(new UserListModel.ListItem
                {
                    Id = await store.GetUserIdAsync(user, cancellationToken),
                    UserName = await store.GetUserNameAsync(user, cancellationToken),
                    Email = email,
                    GravatarUrl = !string.IsNullOrWhiteSpace(email) ? Utils.GetGravatarUrl(email, 25) : null,
                    Roles = roles
                }); ;
            };
            var model = new UserListModel
            {
                Users = users
            };
            return model;
        }

        public UserEditModel CreateUser()
        {
            var roles = _roleManager.Roles.AsNoTracking().ToList().ConvertAll(r => _roleStore.GetRoleNameAsync(r, CancellationToken.None).GetAwaiter().GetResult());
            roles.Sort();

            return new UserEditModel
            {
                Roles = roles
            };
        }

        public async Task<UserEditModel> GetUserByIdAsync(string userId, CancellationToken cancellationToken)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user != null)
            {
                var store = (IUserEmailStore<TUser>)_userStore;

                var model = CreateUser();
                model.Id = await _userStore.GetUserIdAsync(user, cancellationToken);
                model.UserName = await _userStore.GetUserNameAsync(user, cancellationToken);
                model.Email = await store.GetEmailAsync(user, cancellationToken);

                foreach (var role in await _userManager.GetRolesAsync(user))
                {
                    model.SelectedRoles.Add(role);
                }
                return model;
            }

            return null;
        }

        public async Task<IdentityResult> SaveUserAsync(UserEditModel model, CancellationToken cancellationToken)
        {
            var store = (IUserEmailStore<TUser>)_userStore;
            var userId = model.Id;
            IdentityResult result;
            TUser user;
            if (string.IsNullOrEmpty(userId))
            {
                user = Activator.CreateInstance<TUser>();
                await store.SetUserNameAsync(user, model.UserName, cancellationToken);
                await store.SetEmailAsync(user, model.Email, cancellationToken);
                await store.SetEmailConfirmedAsync(user, true, cancellationToken);

                result = await _userManager.CreateAsync(user, model.Password);
                if (!result.Succeeded)
                {
                    return result;
                }
                model.Id = await store.GetUserIdAsync(user, cancellationToken);
            }
            else
            {
                user = await _userManager.FindByIdAsync(userId);
                if (user == null)
                {
                    return IdentityResult.Failed(_userManager.ErrorDescriber.DefaultError());
                }

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

        public async Task<bool> DeleteUserAsync(string userId, CancellationToken cancellationToken)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user != null)
            {
                var result = await _userManager.DeleteAsync(user);
                return result.Succeeded;
            }

            return false;
        }

        public string GetUserId(ClaimsPrincipal principal)
        {
            return _userManager.GetUserId(principal);
        }
    }
}