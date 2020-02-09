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
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Piranha.AspNetCore.Identity.Data;

namespace Piranha.AspNetCore.Identity
{
    /// <summary>
    /// Default identity security seed.
    /// </summary>
    public class DefaultIdentitySeed : IIdentitySeed
    {
        /// <summary>
        /// The private DbContext.
        /// </summary>
        private readonly IDb _db;

        /// <summary>
        /// The private user manager.
        /// </summary>
        private readonly UserManager<User> _userManager;

        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="db">The current DbContext</param>
        /// <param name="userManager">The current UserManager</param>
        public DefaultIdentitySeed(IDb db, UserManager<User> userManager)
        {
            _db = db;
            _userManager = userManager;
        }

        /// <summary>
        /// Create the seed data.
        /// </summary>
        public async Task CreateAsync()
        {
            if (!_db.Users.Any())
            {
                var user = new User
                {
                    UserName = "admin",
                    Email = "admin@piranhacms.org",
                    SecurityStamp = Guid.NewGuid().ToString()
                };
                var createResult = await _userManager.CreateAsync(user, "password");

                if (createResult.Succeeded)
                {
                    await _userManager.AddToRoleAsync(user, "SysAdmin");
                }
            }
        }
    }

    /// <summary>
    /// Default identity security seed.
    /// </summary>
    public class DefaultIdentitySeed<TUser, TRole> : IIdentitySeed
        where TUser : class
        where TRole : class
    {
        private readonly UserManager<TUser> _userManager;
        private readonly IUserEmailStore<TUser> _userEmailStore;
        private readonly RoleManager<TRole> _roleManager;
        private readonly IRoleStore<TRole> _roleStore;

        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="userManager">The current UserManager</param>
        public DefaultIdentitySeed(UserManager<TUser> userManager, IUserStore<TUser> userStore, RoleManager<TRole> roleManager, IRoleStore<TRole> roleStore)
        {
            _userManager = userManager;
            _userEmailStore = (IUserEmailStore<TUser>)userStore;
            _roleManager = roleManager;
            _roleStore = roleStore;
        }

        /// <summary>
        /// Create the seed data.
        /// </summary>
        public async Task CreateAsync()
        {
            var cancellationToken = CancellationToken.None;
            if (!await _roleManager.RoleExistsAsync("SysAdmin"))
            {
                var role = Activator.CreateInstance<TRole>();
                await _roleStore.SetRoleNameAsync(role, "SysAdmin", cancellationToken);
                var result = await _roleStore.CreateAsync(role, cancellationToken);
                if (result.Succeeded)
                {
                    foreach (var permission in App.Permissions.GetPermissions())
                    {
                        await _roleManager.AddClaimAsync(role, new Claim(permission.Name, permission.Name));
                    }
                }
            }

            if (!_userManager.Users.Any())
            {
                await CreateUserAsync("admin", "admin@piranhacms.org", "password", "SysAdmin", cancellationToken);
            }
        }

        async Task CreateUserAsync(string userName, string email, string password, string role, CancellationToken cancellationToken)
        {
            var user = Activator.CreateInstance<TUser>();
            await _userEmailStore.SetUserNameAsync(user, userName, cancellationToken);
            await _userEmailStore.SetEmailAsync(user, email, cancellationToken);
            await _userEmailStore.SetEmailConfirmedAsync(user, true, cancellationToken);
            var createResult = await _userManager.CreateAsync(user, password);

            if (createResult.Succeeded)
            {
                await _userManager.AddToRoleAsync(user, role);
            }
        }
    }
}