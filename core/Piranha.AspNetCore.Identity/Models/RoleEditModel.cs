/*
 * Copyright (c) 2018 Håkan Edling
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 * 
 * http://github.com/piranhacms/piranha
 * 
 */

using System;
using System.Collections.Generic;

namespace Piranha.AspNetCore.Identity.Models
{
    public class RoleEditModel
    {
        public RoleEditModel()
        {
            SelectedClaims = new List<string>();
        }

        public string Id { get; set; }
        public string Name { get; set; }
        public string NormalizedName { get; set; }
        public IList<string> SelectedClaims { get; set; }

        public static RoleEditModel Create()
        {
            return new RoleEditModel
            {
                Id = Guid.Empty.ToString()
            };
        }
    }
}