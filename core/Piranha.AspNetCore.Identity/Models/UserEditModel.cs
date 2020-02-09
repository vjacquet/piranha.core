/*
 * Copyright (c) 2018 Håkan Edling
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 * 
 * http://github.com/piranhacms/piranha
 * 
 */

using System.Collections.Generic;
using Piranha.AspNetCore.Identity.Data;

namespace Piranha.AspNetCore.Identity.Models
{
    public class UserEditModel
    {
        public IList<string> Roles { get; set; } = new List<string>();
        public IList<string> SelectedRoles { get; set; } = new List<string>();
        public string Password { get; set; }
        public string PasswordConfirm { get; set; }

        public string Id { get; set; }
        public string UserName { get; set; }
        public string Email { get; set; }
    }
}