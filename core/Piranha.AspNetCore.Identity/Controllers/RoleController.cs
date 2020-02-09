/*
 * Copyright (c) 2018-2019 Håkan Edling
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 *
 * http://github.com/piranhacms/piranha
 *
 */

using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Piranha.AspNetCore.Identity.Models;
using Piranha.Manager.Controllers;

namespace Piranha.AspNetCore.Identity.Controllers
{
    [Area("Manager")]
    public class RoleController : ManagerController
    {
        private readonly IIdentityService _service;

        public RoleController(IIdentityService service)
        {
            _service = service;
        }

        [Route("/manager/roles")]
        [Authorize(Policy = Permissions.Roles)]
        public async Task<IActionResult> List()
        {
            var model = await _service.GetRoleListAsync(HttpContext.RequestAborted);
            return View(model);
        }

        [Route("/manager/role/{id}")]
        [Authorize(Policy = Permissions.RolesEdit)]
        public async Task<IActionResult> Edit(string id)
        {
            var model = await _service.GetRoleByIdAsync(id, HttpContext.RequestAborted);
            return View("Edit", model);
        }

        [Route("/manager/role")]
        [Authorize(Policy = Permissions.RolesAdd)]
        public IActionResult Add()
        {
            return View("Edit", _service.CreateRole());
        }

        [HttpPost]
        [Route("/manager/role/save")]
        [Authorize(Policy = Permissions.RolesSave)]
        public async Task<IActionResult> Save(RoleEditModel model)
        {
            var result = await _service.SaveRoleAsync(model, HttpContext.RequestAborted);
            if (result)
            {
                SuccessMessage("The role has been saved.");
                return RedirectToAction("Edit", new { id = model.Id });
            }

            ErrorMessage("The role could not be saved.", false);
            return View("Edit", model);
        }

        [Route("/manager/role/delete")]
        [Authorize(Policy = Permissions.RolesDelete)]
        public async Task<IActionResult> Delete(string id)
        {
            var result = await _service.DeleteRoleAsync(id, HttpContext.RequestAborted);
            if (result)
            {
                SuccessMessage("The role has been deleted.");
                return RedirectToAction("List");
            }

            ErrorMessage("The role could not be deleted.", false);
            return RedirectToAction("List");
        }
    }
}